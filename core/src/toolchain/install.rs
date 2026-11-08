// Download, verify, and install extension binaries (and the crossfyre binary
// itself) from the release CDN. Every artifact is resolved through manifest.json,
// which maps component -> version -> per-platform artifact file + SHA256, and
// nothing is installed without a checksum match.
//
// The checksum proves the artifact matches what the manifest says. It proves
// nothing about the manifest, so in a build carrying CROSSFYRE_MANIFEST_PUBKEY
// the manifest itself must also carry a valid ed25519 signature. See
// `release_sig` for why the key's presence is the switch and why that makes the
// rollout safe. This comment used to describe the file as a "signed-by-checksum
// manifest", which conflated the two and read as a stronger guarantee than the
// code gave.

use super::config::{
    ext_bin_path, ext_file_name, file_name, get_bin_dir, is_regular_file, legacy_bin_path,
};
use super::packaging::{self, Manager, remove_note, update_note};
use super::service;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The helper that runs .cfx scripts (see `crate::executor`). It goes beside node, where
/// node and the CLI look for it. It is the one component that links libpython, so it is
/// optional: on a host without the Python it was built against it cannot start, and
/// then only .cfx scripts are unavailable.
const CFX_SCRIPT: &str = "cfx-script";

// The bins origin this binary fetches releases from. Baked at build time so a
// dev/staging build pulls from its own bucket: crossfyre_build sets
// CROSSFYRE_BINS_ORIGIN per --env. Defaults to prod when built without it.
pub const BASE_URL: &str = match option_env!("CROSSFYRE_BINS_ORIGIN") {
    Some(o) => o,
    None => "https://bins.crossfyre.io",
};

// Terminal styling now lives in the shared `super::ui` module so every command
// renders with the same look; `update` uses `use super::ui::*` below.

/// Host portion of the bins origin, for display (e.g. "bins-dev.crossfyre.io").
fn origin_host() -> &'static str {
    BASE_URL
        .trim_start_matches("https://")
        .trim_start_matches("http://")
}

/// Sidecar recording an installed extension's version (mirrors node.version),
/// so `update` can tell "already current" from "needs update" without a reinstall.
/// Named by the public name, as the binary is.
fn ext_version_file(ext: &str) -> std::path::PathBuf {
    get_bin_dir().join(format!("{}.version", super::public_name(ext)))
}

/// The sidecar an engine's binary had under its legacy name, if it was renamed.
fn legacy_version_file(ext: &str) -> Option<std::path::PathBuf> {
    let legacy = super::engine(ext)?.legacy?;
    Some(get_bin_dir().join(format!("{legacy}.version")))
}

fn installed_ext_version(ext: &str) -> Option<String> {
    let read = |p: std::path::PathBuf| fs::read_to_string(p).ok().map(|s| s.trim().to_string());
    if ext_bin_path(ext).exists() {
        return read(ext_version_file(ext));
    }
    // Installed under the legacy name only: the migration has not run here yet.
    match (legacy_bin_path(ext), legacy_version_file(ext)) {
        (Some(bin), Some(v)) if is_regular_file(&bin) => read(v),
        _ => read(ext_version_file(ext)),
    }
}

/// The version in `sidecar`, or when there is none, the version the binary at `bin`
/// reports. The installer places the CLI, the node and cfx-script without a sidecar, and
/// an update that read the missing record as an old binary downloaded the same version
/// again and counted it as updated.
fn recorded_or_reported(
    sidecar: &Path,
    bin: &Path,
    name: &str,
    envs: Vec<(std::ffi::OsString, std::ffi::OsString)>,
) -> Option<String> {
    let recorded = fs::read_to_string(sidecar)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    recorded.or_else(|| reported_version(bin, name, envs))
}

/// What `<bin> --version` says the version is, when it answers `<name> <version>` and
/// exits 0 within a few seconds. A cfx-script from before it took `--version` reads the
/// flag as no job, and refuses the empty stdin it is given with status 2, so it has no
/// version to report.
fn reported_version(
    bin: &Path,
    name: &str,
    envs: Vec<(std::ffi::OsString, std::ffi::OsString)>,
) -> Option<String> {
    let mut command = Command::new(bin);
    command
        .arg("--version")
        .envs(envs)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut busy = 0;
    let mut child = loop {
        match command.spawn() {
            // As in `helper_starts`: a process forked while the file was open for writing
            // holds it until it execs.
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && busy < 100 => {
                busy += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => return None,
            Ok(child) => break child,
        }
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    parse_reported_version(&String::from_utf8_lossy(&out.stdout), name)
}

/// The version in a `--version` line that names `name`, as clap writes it.
fn parse_reported_version(stdout: &str, name: &str) -> Option<String> {
    let mut words = stdout.lines().next()?.split_whitespace();
    if words.next()? != name {
        return None;
    }
    let version = words.next()?;
    version
        .starts_with(|c: char| c.is_ascii_digit())
        .then(|| version.to_string())
}

/// The version of the node worker in the bin directory, if there is one.
fn installed_node_version() -> Option<String> {
    let bin = ext_bin_path("node");
    if !bin.exists() {
        return None;
    }
    recorded_or_reported(
        &get_bin_dir().join("node.version"),
        &bin,
        "node",
        Vec::new(),
    )
}

/// The version of the cfx-script in the bin directory, if there is one.
fn installed_helper_version() -> Option<String> {
    let bin = ext_bin_path(CFX_SCRIPT);
    if !bin.exists() {
        return None;
    }
    let envs = crate::executor::python_env(&bin);
    recorded_or_reported(&ext_version_file(CFX_SCRIPT), &bin, CFX_SCRIPT, envs)
}

/// The record of a cfx-script release that was downloaded and could not start on this
/// host: its version on the first line, then what it wrote. While the release is still
/// that version, an update does not download it again only to find the same thing, each
/// time, unless what it lacked is here now or `--force` is given. A cfx-script that starts
/// removes the record.
fn cannot_start_file() -> PathBuf {
    get_bin_dir().join(format!("{CFX_SCRIPT}.cannot-start"))
}

fn record_cannot_start(version: &str, output: &str) {
    let _ = fs::write(cannot_start_file(), format!("{version}\n{output}\n"));
}

/// What the cfx-script of `version` wrote when it could not start here, if one did and
/// nothing has changed since that would let it start now.
fn still_cannot_start(version: &str) -> Option<String> {
    let text = fs::read_to_string(cannot_start_file()).ok()?;
    let (recorded, output) = text.split_once('\n')?;
    if recorded.trim() != version {
        return None;
    }
    let output = output.trim();
    // A libpython3 the loader could not find is the one a release's python folder brings.
    // A CLI from before the folder staged the helper without it and recorded that, and
    // this one stages the two together, so it tries that release again.
    let retry = |lib: &str| lib.starts_with("libpython3.") || library_loads(lib);
    if missing_library(output).is_some_and(retry) {
        return None;
    }
    Some(output.to_string())
}

/// The shared library that the dynamic loader could not find, from what it wrote:
/// `error while loading shared libraries: libpython3.11.so.1.0: cannot open ...`.
fn missing_library(output: &str) -> Option<&str> {
    let (_, rest) = output.split_once("error while loading shared libraries: ")?;
    let name = rest.split(':').next()?.trim();
    (!name.is_empty() && !name.contains('/')).then_some(name)
}

/// Can this process load the shared library `name`, from wherever the dynamic loader
/// would look for it? It is loaded and let go again; libpython does nothing when loaded.
#[cfg(unix)]
fn library_loads(name: &str) -> bool {
    let Ok(name) = std::ffi::CString::new(name) else {
        return false;
    };
    // SAFETY: a valid C string, and the handle is closed only when the load succeeded.
    unsafe {
        let handle = libc::dlopen(name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        if handle.is_null() {
            return false;
        }
        libc::dlclose(handle);
    }
    true
}

#[cfg(not(unix))]
fn library_loads(_name: &str) -> bool {
    false
}

/// Why a cfx-script could not start here, and what would let it, from what it wrote.
fn cannot_start_note(output: &str) -> String {
    let Some(lib) = missing_library(output) else {
        return format!("{output}. `crossfyre update --force` downloads it and tries it again.");
    };
    let mut note = format!("It needs {lib}, which this host does not have.");
    if lib.starts_with("libpython3.") {
        // A release's cfx-script brings its own libpython, in the python folder beside
        // it, and loads no other: one the host installed would be refused.
        note.push_str(&format!(
            " cfx-script brings its own in the {} folder beside it, which did not come \
             with this one. `crossfyre update --force` downloads the two again.",
            crate::executor::BUNDLED_PYTHON_DIR
        ));
    }
    note
}

/// The manifest keys `component` may be published under, in the order to try them: an
/// engine's public name first, then its legacy name and its id. A manifest from before
/// the rename has only the legacy key, and one from after it has both, so the CLI does
/// not depend on the order in which the manifest gains keys. Any other component is
/// published under its own name.
fn manifest_keys(component: &str) -> Vec<&str> {
    keys_for(super::engine(component), component)
}

fn keys_for<'a>(engine: Option<&'a super::Engine>, component: &'a str) -> Vec<&'a str> {
    let Some(e) = engine else {
        return vec![component];
    };
    let mut keys = vec![e.name];
    for k in e.legacy.into_iter().chain([e.id]) {
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    keys
}

/// The file inside an unpacked artifact that is `component`'s binary: one named by any
/// of its manifest keys, public name first. An alias artifact published under the
/// legacy key carries the binary under the legacy name.
fn find_member(extract_dir: &Path, keys: &[&str]) -> Option<PathBuf> {
    keys.iter()
        .map(|k| extract_dir.join(file_name(k)))
        .find(|p| p.exists())
}

/// The version string in `resolve_artifact` for a component, or "" if absent.
fn manifest_version(manifest: &Manifest, comp: &str) -> String {
    resolve_artifact(manifest, comp)
        .map(|(c, _)| c.version.clone())
        .unwrap_or_default()
}

#[derive(serde::Deserialize, Debug)]
pub struct Manifest {
    pub components: HashMap<String, Component>,
}

#[derive(serde::Deserialize, Debug)]
pub struct Component {
    pub version: String,
    /// Keyed by platform: "linux-x86_64", "darwin-aarch64", "windows-x86_64", ...
    pub artifacts: HashMap<String, Artifact>,
}

#[derive(serde::Deserialize, Debug)]
pub struct Artifact {
    pub file: String,
    pub sha256: String,
}

/// "linux-x86_64" style key for the running host.
pub fn platform_key() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    format!("{}-{}", os, std::env::consts::ARCH)
}

pub async fn fetch_manifest() -> Result<Manifest, Box<dyn std::error::Error>> {
    let url = format!("{BASE_URL}/manifest.json");
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("could not fetch release manifest ({url}): {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "release manifest fetch failed: {} returned {}",
            url,
            resp.status()
        )
        .into());
    }
    // The BYTES, not a parsed value: the signature is over what was served, and
    // re-serialising a parsed manifest reorders keys and rewrites whitespace.
    let body = resp
        .bytes()
        .await
        .map_err(|e| format!("could not read release manifest body: {e}"))?;

    if super::release_sig::required() {
        let sig_url = format!("{url}{}", super::release_sig::SIG_SUFFIX);
        let sig = fetch_signature(&sig_url).await?;
        super::release_sig::verify(&body, &sig)?;
    }

    let manifest: Manifest =
        serde_json::from_slice(&body).map_err(|e| format!("release manifest is malformed: {e}"))?;
    Ok(manifest)
}

/// Fetch the detached signature. Only called by a build that requires one, so a 404 here
/// is a release-pipeline failure and the message says so rather than reading as a
/// network problem.
async fn fetch_signature(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let resp = reqwest::get(url)
        .await
        .map_err(|e| format!("could not fetch the release manifest signature ({url}): {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "this build requires a signed release manifest and {} returned {}. Nothing will \
             be installed. If you built this binary yourself, build without \
             CROSSFYRE_MANIFEST_PUBKEY to use an unsigned manifest.",
            url,
            resp.status()
        )
        .into());
    }
    Ok(resp
        .text()
        .await
        .map_err(|e| format!("could not read the release manifest signature: {e}"))?)
}

fn resolve_artifact<'m>(
    manifest: &'m Manifest,
    component: &str,
) -> Result<(&'m Component, &'m Artifact), Box<dyn std::error::Error>> {
    resolve_keys(manifest, &manifest_keys(component))
}

/// The first of `keys` the manifest has a component for, and that component's artifact
/// for this platform. The error names the first key, which is the public name.
fn resolve_keys<'m>(
    manifest: &'m Manifest,
    keys: &[&str],
) -> Result<(&'m Component, &'m Artifact), Box<dyn std::error::Error>> {
    let shown = keys.first().copied().unwrap_or("");
    let comp = keys
        .iter()
        .find_map(|k| manifest.components.get(*k))
        .ok_or_else(|| format!("component '{shown}' not in release manifest"))?;
    let key = platform_key();
    let artifact = comp
        .artifacts
        .get(&key)
        .ok_or_else(|| format!("no '{shown}' artifact for platform {key} in release manifest"))?;
    Ok((comp, artifact))
}

/// Download an artifact to `dest` and verify its SHA256 against the manifest.
async fn download_verified(
    artifact: &Artifact,
    dest: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/{}", BASE_URL, artifact.file);
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("download failed ({url}): {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("download failed: {} returned {}", url, resp.status()).into());
    }
    let bytes = resp.bytes().await?;
    verify_artifact_bytes(artifact, &bytes)?;
    // Written only after the checksum agrees, so a rejected artifact leaves nothing
    // behind that a later run could mistake for an install.
    fs::write(dest, &bytes)?;
    Ok(())
}

/// Does `bytes` match the SHA256 the manifest recorded for this artifact?
///
/// Split out of the download because this is the decision, and `BASE_URL` is a build-time
/// constant, so nothing that goes through `reqwest` can be reached from a test. Keeping
/// the check pure means the refusal is testable and the download stays thin glue.
fn verify_artifact_bytes(artifact: &Artifact, bytes: &[u8]) -> Result<(), String> {
    // An artifact with no recorded checksum is refused rather than waved through. A
    // manifest can be hand-edited and a missing field deserialises to an empty string;
    // comparing against it would otherwise mean "no checksum, no check".
    if artifact.sha256.trim().is_empty() {
        return Err(format!(
            "release manifest records no sha256 for {} - refusing to install an \
             unverifiable artifact",
            artifact.file
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let got = format!("{:x}", hasher.finalize());
    if !got.eq_ignore_ascii_case(artifact.sha256.trim()) {
        return Err(format!(
            "checksum mismatch for {} (expected {}, got {}) - refusing to install",
            artifact.file, artifact.sha256, got
        ));
    }
    Ok(())
}

/// Unzip `zip_path` into `extract_dir` (shells out to `unzip`, which the
/// installer checks for). Windows has no unzip, and has had bsdtar, which reads zip
/// archives, in System32 since Windows 10 1803; it is named by its full path so that
/// another `tar` on PATH, which may not read zip at all, is not the one run.
fn extract_zip(zip_path: &Path, extract_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(extract_dir)?;
    #[cfg(windows)]
    let status = {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        Command::new(Path::new(&root).join("System32").join("tar.exe"))
            .arg("-x")
            .arg("-f")
            .arg(zip_path)
            .arg("-C")
            .arg(extract_dir)
            .status()
            .map_err(|e| format!("tar.exe not found or failed to execute: {e}"))?
    };
    #[cfg(not(windows))]
    let status = Command::new("unzip")
        .args([
            "-q",
            &zip_path.to_string_lossy(),
            "-d",
            &extract_dir.to_string_lossy(),
        ])
        .status()
        .map_err(|e| format!("unzip not found or failed to execute: {e}"))?;
    if !status.success() {
        return Err(format!("Failed to extract {}", zip_path.display()).into());
    }
    Ok(())
}

/// Atomically place `src` at `dest` (write-next-to + rename), 0755 on unix.
///
/// The mode is set on the temporary file BEFORE the rename, which is what makes the claim
/// in that first line true. Doing it after left a window in which `dest` existed carrying
/// whatever mode `fs::copy` brought over from the archive, and an artifact unpacked as
/// 0644 is the normal case rather than a strange one. A process killed in that window, or
/// an update interrupted by a reboot, leaves a binary that is installed, current, and not
/// executable, and the next run reports it as missing rather than as broken.
fn place_binary(src: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let staged = stage_binary(src, dest)?;
    commit_staged(&staged, dest)
}

/// Copy `src` beside `dest` as `<name>.new`, 0755 on unix, and return that path. Renaming
/// it over `dest` is `commit_staged`.
fn stage_binary(src: &Path, dest: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    // Appended, not `with_extension`, which REPLACES whatever follows the last dot:
    // a component placed as `plessor-0.1.2` would stage itself at `plessor-0.1.new` and
    // collide with any sibling that differs only after that dot.
    let tmp_path = match dest.file_name() {
        Some(name) => dest.with_file_name(format!("{}.new", name.to_string_lossy())),
        None => return Err(format!("{} is not a file path", dest.display()).into()),
    };
    fs::copy(src, &tmp_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755)) {
            // Leave nothing half-staged behind for a later run to trip over.
            let _ = fs::remove_file(&tmp_path);
            return Err(e.into());
        }
    }
    Ok(tmp_path)
}

/// Move a binary that `stage_binary` staged into place at `dest`.
fn commit_staged(staged: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    move_aside_if_running(dest);
    if let Err(e) = fs::rename(staged, dest) {
        let _ = fs::remove_file(staged);
        return Err(e.into());
    }
    Ok(())
}

/// Windows will not let a running program's file be replaced or removed, which is what
/// updating the CLI from itself, or the node from the node service, does. It does let
/// the file be renamed, so a program that is running is moved to `<name>.old` and the
/// new one takes its name; the old one finishes from where it was moved to. A `.old`
/// that a previous update left is removed first, once nothing runs it any more.
#[cfg(windows)]
fn move_aside_if_running(dest: &Path) {
    let Some(name) = dest.file_name() else {
        return;
    };
    let mut old_name = name.to_os_string();
    old_name.push(".old");
    let old = dest.with_file_name(old_name);
    let _ = fs::remove_file(&old);
    if !dest.exists() {
        return;
    }
    // Opening for writing is refused while the file is being run.
    if fs::OpenOptions::new().write(true).open(dest).is_err() {
        let _ = fs::rename(dest, &old);
    }
}

/// The folder of the Python a release's cfx-script comes with, beside `src`, when there is
/// one: python.org's embeddable package on Windows, with python3.dll in it, and on Linux
/// a CPython with its libpython and standard library under lib/ (see
/// `executor::BUNDLED_PYTHON_DIR`).
fn bundled_python_beside(src: &Path) -> Option<PathBuf> {
    let dir = src.parent()?.join(crate::executor::BUNDLED_PYTHON_DIR);
    let there = if cfg!(windows) {
        dir.join("python3.dll").is_file()
    } else {
        dir.join("lib").is_dir()
    };
    there.then_some(dir)
}

/// Put the folder `staged` at `<dir>/python`, in place of whatever is there. A script
/// running now holds the old files open, which stops them being removed on Windows but
/// not their folder being renamed, so the old folder is moved aside first and removed
/// after.
fn swap_bundled_python(staged: &Path, dir: &Path) -> std::io::Result<()> {
    let to = dir.join(crate::executor::BUNDLED_PYTHON_DIR);
    let old = dir.join(format!(
        "{}.old-{}",
        crate::executor::BUNDLED_PYTHON_DIR,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&old);
    if to.exists() {
        fs::rename(&to, &old)?;
    }
    fs::rename(staged, &to)?;
    let _ = fs::remove_dir_all(&old);
    Ok(())
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Does the cfx-script at `path` start on this host? Given an empty stdin it refuses the
/// job with exit status 2, which proves that the binary and its libpython loaded. Any
/// other status, usually 127 from the dynamic loader, is a failure, returned with what
/// it wrote to stderr. The installer makes the same check.
fn helper_starts(path: &Path) -> Result<(), String> {
    let mut busy = 0;
    let out = loop {
        let run = Command::new(path)
            .envs(crate::executor::python_env(path))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output();
        match run {
            // The copy was open for writing a moment ago, and a process that another
            // thread forked in that moment holds it open until it execs.
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && busy < 100 => {
                busy += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e.to_string()),
            Ok(out) => break out,
        }
    };
    if out.status.code() == Some(2) {
        return Ok(());
    }
    let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if said.is_empty() {
        Err(format!("it exited with {}", out.status))
    } else {
        Err(said)
    }
}

/// Put the cfx-script at `src` at `dest`, but only if it starts here. It is staged
/// beside `dest` and run from there, as the installer does, because the temp directory
/// may be on a filesystem mounted noexec. `Some(output)` when it cannot start: what was
/// staged is removed and `dest` is left as it was.
///
/// A cfx-script with a python folder beside it (`bundled_python_beside`) is staged with
/// a copy of that folder, in a directory of their own beside `dest`, and run there. On
/// Linux it loads libpython from `$ORIGIN/python/lib`, so only a helper run beside the
/// new folder proves that the two start together. Once it has, the folder replaces the
/// one beside `dest`, then the helper replaces `dest`.
fn place_helper_if_it_starts(
    src: &Path,
    dest: &Path,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(python) = bundled_python_beside(src) else {
        let staged = stage_binary(src, dest)?;
        if let Err(output) = helper_starts(&staged) {
            let _ = fs::remove_file(&staged);
            return Ok(Some(output));
        }
        commit_staged(&staged, dest)?;
        return Ok(None);
    };
    let (Some(dir), Some(name)) = (dest.parent(), dest.file_name()) else {
        return Err(format!("{} is not a file path", dest.display()).into());
    };
    let mut staging_name = name.to_os_string();
    staging_name.push(".new.d");
    let staging = dir.join(staging_name);
    let _ = fs::remove_dir_all(&staging);
    let placed = (|| -> Result<Option<String>, Box<dyn std::error::Error>> {
        fs::create_dir_all(&staging)?;
        let staged = stage_binary(src, &staging.join(name))?;
        let staged_python = staging.join(crate::executor::BUNDLED_PYTHON_DIR);
        copy_dir(&python, &staged_python)?;
        if let Err(output) = helper_starts(&staged) {
            return Ok(Some(output));
        }
        swap_bundled_python(&staged_python, dir)?;
        commit_staged(&staged, dest)?;
        Ok(None)
    })();
    let _ = fs::remove_dir_all(&staging);
    placed
}

/// What `install_cfx_script` did.
#[derive(Debug)]
pub enum HelperOutcome {
    /// The release has no cfx-script for this platform, so nothing changed.
    NotInRelease,
    /// The installed cfx-script is the release's version.
    Current { version: String },
    /// The release's cfx-script was installed. `replaced` is the version recorded for the
    /// one it replaced, if there was one.
    Installed {
        version: String,
        replaced: Option<String>,
    },
    /// The release's cfx-script cannot start on this host, so it was not installed and
    /// whatever was there before is left as it was. `output` is what it wrote.
    CannotStart { version: String, output: String },
    /// A package manager installed cfx-script, so it is that manager's to update.
    Owned(Manager),
}

/// Install or refresh the cfx-script helper from the release manifest: download it,
/// check its sha256, unpack it beside node and run it once before it replaces anything.
/// Its version is recorded in `cfx-script.version`, as node's is in `node.version`, so a
/// later update can tell whether it is current; one with no record is asked for its
/// version. A release that could not start here is not downloaded again while nothing
/// has changed (`still_cannot_start`).
pub async fn install_cfx_script(
    manifest: &Manifest,
    force: bool,
) -> Result<HelperOutcome, Box<dyn std::error::Error>> {
    if let Some(m) = packaging::owner(CFX_SCRIPT) {
        return Ok(HelperOutcome::Owned(m));
    }
    let Ok((comp, artifact)) = resolve_artifact(manifest, CFX_SCRIPT) else {
        return Ok(HelperOutcome::NotInRelease);
    };
    let version = comp.version.clone();
    let dest = ext_bin_path(CFX_SCRIPT);
    let replaced = installed_helper_version();
    if replaced.as_deref() == Some(version.as_str()) && !force {
        return Ok(HelperOutcome::Current { version });
    }
    if !force && let Some(output) = still_cannot_start(&version) {
        return Ok(HelperOutcome::CannotStart { version, output });
    }

    let tmp_dir = tempfile::tempdir()?;
    let zip_path = tmp_dir.path().join(&artifact.file);
    download_verified(artifact, &zip_path).await?;
    let extract_dir = tmp_dir.path().join("extracted");
    extract_zip(&zip_path, &extract_dir)?;
    let extracted = extract_dir.join(ext_file_name(CFX_SCRIPT));
    if !extracted.exists() {
        return Err("cfx-script binary not found inside its zip".into());
    }
    if let Some(output) = place_helper_if_it_starts(&extracted, &dest)? {
        record_cannot_start(&version, &output);
        return Ok(HelperOutcome::CannotStart { version, output });
    }
    let _ = fs::write(ext_version_file(CFX_SCRIPT), &version);
    let _ = fs::remove_file(cannot_start_file());
    Ok(HelperOutcome::Installed { version, replaced })
}

/// What is left to run .cfx scripts when a new cfx-script was not installed.
fn without_new_helper() -> &'static str {
    if ext_bin_path(CFX_SCRIPT).exists() {
        "the cfx-script already installed stays in use"
    } else {
        ".cfx scripts will not run; scans and everything else work"
    }
}

/// Say what became of the cfx-script helper, in the plain lines `node init` and the node's
/// own update print.
fn report_cfx_script(result: Result<HelperOutcome, Box<dyn std::error::Error>>) {
    match result {
        Ok(HelperOutcome::Installed { version, .. }) => println!(
            "[+] Installed cfx-script {version} to {} (runs .cfx scripts)",
            ext_bin_path(CFX_SCRIPT).display()
        ),
        Ok(HelperOutcome::CannotStart { version, output }) => eprintln!(
            "[!] cfx-script {version} cannot start here, so it was not installed and {}. {}",
            without_new_helper(),
            cannot_start_note(&output)
        ),
        Ok(
            HelperOutcome::Current { .. } | HelperOutcome::NotInRelease | HelperOutcome::Owned(_),
        ) => {}
        Err(e) => eprintln!(
            "[!] could not install cfx-script: {e}. Until it installs, {}.",
            without_new_helper()
        ),
    }
}

/// Install one or more extensions ("ambulo" | "all"). Download + verify +
/// register the daemon service. The service is created but only started by
/// `install_and_start` (or an explicit `crossfyre service start`).
pub async fn install(extension: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Before anything is placed: an engine still installed under its legacy name
    // would otherwise end up with a second unit on its port.
    super::migrate::renamed_engines();
    // Fetched only for an engine that is ours to download: one a package installed needs
    // nothing from the release.
    let mut manifest = None;
    for ext in super::resolve_extensions(extension)? {
        if let Some(m) = packaging::owner(ext) {
            adopt_packaged(ext, m, false)?;
            continue;
        }
        if manifest.is_none() {
            manifest = Some(fetch_manifest().await?);
        }
        if let Some(manifest) = &manifest {
            install_one(manifest, ext, force, false).await?;
        }
    }
    Ok(())
}

/// An engine a package manager put in place: its binary is the package's, and the unit
/// that runs it, which no package writes, is still ours to register.
fn adopt_packaged(ext: &str, m: Manager, quiet: bool) -> Result<(), Box<dyn std::error::Error>> {
    use super::ui::*;
    let bin_path = ext_bin_path(ext);
    let name = super::public_name(ext);
    if !bin_path.exists() {
        return Err(format!(
            "{name} is installed by {m}, but {} is missing; reinstall it with {m}",
            bin_path.display()
        )
        .into());
    }
    if !service::has_service_file(ext) {
        service::create_service_file(ext)?;
    }
    if !quiet {
        title("Crossfyre extension install", name);
        ok(&format!("{name} is {}", update_note(m)));
        end();
    }
    Ok(())
}

async fn install_one(
    manifest: &Manifest,
    ext: &str,
    force: bool,
    quiet: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use super::ui::*;
    let bin_path = ext_bin_path(ext);
    let name = super::public_name(ext);

    if let Some(m) = packaging::owner(ext) {
        return adopt_packaged(ext, m, quiet);
    }

    if !quiet {
        title("Crossfyre extension install", name);
    }

    if super::config::is_extension_installed(ext) && !force {
        if !quiet {
            warn(&format!(
                "{name} is already installed {}",
                dim("(use --force to reinstall)")
            ));
            end();
        }
        return Ok(());
    }

    let keys = manifest_keys(ext);
    let (comp, artifact) = resolve_keys(manifest, &keys)?;
    if !quiet {
        working(&format!("Downloading {name} {}", dim(&comp.version)));
    }

    let tmp_dir = tempfile::tempdir().map_err(|e| format!("Failed to create temp dir: {e}"))?;
    let zip_path = tmp_dir.path().join(&artifact.file);
    download_verified(artifact, &zip_path).await?;

    if !quiet {
        working("Installing");
    }
    let extract_dir = tmp_dir.path().join("extracted");
    extract_zip(&zip_path, &extract_dir)?;

    let Some(extracted_binary) = find_member(&extract_dir, &keys) else {
        return Err(format!("Binary '{}' not found inside zip", ext_file_name(ext)).into());
    };

    // Stop the running daemon (if any) before replacing the binary - on
    // Windows the file is locked while the task runs. Best-effort, OS-aware.
    if super::config::is_extension_installed(ext) {
        service::try_stop(ext);
    }

    place_binary(&extracted_binary, &bin_path)?;
    // Record the installed version so `update` can skip it next time (mirrors
    // node.version). Best-effort: a missing sidecar just triggers one reinstall.
    let _ = fs::write(ext_version_file(ext), &comp.version);
    if !quiet {
        ok(&format!("{name} {} installed", comp.version));
    }

    if let Err(e) = service::create_service_file(ext)
        && !quiet
    {
        fail(&format!(
            "Failed to create service: {}",
            dim(&e.to_string())
        ));
    }

    if !quiet {
        end();
    }

    Ok(())
}

/// One-step install used by `crossfyre install`, `init`, and the dashboard's
/// install-extension path: download + verify + enable + start.
pub async fn install_and_start(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
    install(ext, false).await?;
    for e in super::resolve_extensions(ext)? {
        service::enable(e)?;
        service::start(e)?;
    }
    Ok(())
}

/// Remove one or more extensions: stop + disable + deregister + delete binary.
pub fn remove(extension: &str) -> Result<(), Box<dyn std::error::Error>> {
    for ext in super::resolve_extensions(extension)? {
        remove_one(ext)?;
    }
    Ok(())
}

fn remove_one(ext: &str) -> Result<(), Box<dyn std::error::Error>> {
    use super::ui::*;
    let bin_path = ext_bin_path(ext);
    let name = super::public_name(ext);
    // The legacy path, whether it is the binary itself (not migrated yet) or the
    // link an earlier migration left there.
    let legacy = legacy_bin_path(ext).filter(|p| fs::symlink_metadata(p).is_ok());

    title("Crossfyre extension remove", name);

    if !bin_path.exists() && legacy.is_none() {
        warn(&format!("{name} is not installed, nothing to remove"));
        end();
        return Ok(());
    }

    step(&format!("Stopping and disabling {name} service"));
    service::try_stop_and_disable_all(ext);
    service::remove_service_file(ext)?;

    if let Some(m) = packaging::owner(ext) {
        warn(&format!(
            "{name}'s service is removed and its binary stays: {}",
            remove_note(m)
        ));
        end();
        return Ok(());
    }

    if bin_path.exists() {
        remove_stopped_binary(&bin_path)?;
    }
    if let Some(p) = &legacy {
        remove_stopped_binary(p)?;
    }
    for v in std::iter::once(ext_version_file(ext)).chain(legacy_version_file(ext)) {
        let _ = fs::remove_file(v);
    }
    ok(&format!("{name} removed"));
    end();
    Ok(())
}

/// Remove the binary of a service that has just been stopped. On Windows stopping the
/// task ends the engine through its job object, and Windows lets go of a program's file
/// only once the process has fully exited, which can take a moment after the stop
/// returns, so the delete is tried again for up to 10 seconds before it gives up.
fn remove_stopped_binary(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let mut tries = 0;
        loop {
            match fs::remove_file(path) {
                Err(_) if tries < 40 && path.exists() => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                other => return other,
            }
        }
    }
    #[cfg(not(windows))]
    {
        fs::remove_file(path)
    }
}

/// What `update` did with each component it looked at. A component that is not installed
/// here, such as the node on a host that never ran `node init`, is in none of the counts.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Updated {
    /// The CLI or the node worker was replaced, and the node service should restart.
    pub restart: bool,
    pub changed: usize,
    pub current: usize,
    /// Left as they were for a reason no update can change, such as a cfx-script that
    /// this host cannot start. Not a failure, but not up to date either.
    pub skipped: usize,
    /// Needed an update that this user may not write, because the bin directory belongs
    /// to root (or on Windows, to administrators).
    pub need_rights: usize,
    /// Needed an update, and it failed.
    pub failed: usize,
}

impl Updated {
    /// Did every component that needed an update get one? `crossfyre update` exits
    /// non-zero when not.
    pub fn succeeded(&self) -> bool {
        self.need_rights == 0 && self.failed == 0
    }

    /// The line that closes the update. It says "up to date" only when nothing was
    /// skipped, refused or failed: printing it under a row that said a component failed
    /// is what made a failed update read as a successful one.
    fn summary(&self) -> String {
        if self.changed == 0 && self.skipped == 0 && self.succeeded() {
            return "Everything is up to date.".to_string();
        }
        let mut parts = Vec::new();
        if self.changed > 0 {
            let s = if self.changed == 1 { "" } else { "s" };
            parts.push(format!("Updated {} component{s}", self.changed));
        }
        if self.current > 0 {
            parts.push(format!("{} already current", self.current));
        }
        if self.skipped > 0 {
            parts.push(format!("{} skipped", self.skipped));
        }
        if self.need_rights > 0 {
            let s = if self.need_rights == 1 { "s" } else { "" };
            parts.push(format!("{} need{s} {}", self.need_rights, RIGHTS));
        }
        if self.failed > 0 {
            parts.push(format!("{} failed", self.failed));
        }
        let line = parts.join(", ");
        if self.changed == 0 {
            format!("Nothing was updated: {line}.")
        } else {
            format!("{line}.")
        }
    }
}

/// What a user who may not write the bin directory lacks.
const RIGHTS: &str = if cfg!(windows) {
    "an elevated prompt"
} else {
    "root"
};

/// Can this process create files in `dir`, or create `dir` itself? Asked before anything
/// is downloaded, so that an update run by a user who may not write the bin directory
/// says what it needs at once. Without it, each component was downloaded and then failed
/// with a bare "Permission denied (os error 13)" when it was moved into place.
fn can_write_in(dir: &Path) -> bool {
    let mut at = dir;
    while !at.is_dir() {
        match at.parent() {
            Some(parent) => at = parent,
            None => return false,
        }
    }
    tempfile::Builder::new()
        .prefix(".crossfyre-")
        .tempfile_in(at)
        .is_ok()
}

/// Show that `name` is being updated, on a terminal, where its result line replaces it.
/// Anywhere else the `\r` replaces nothing, and the two ran together on one line.
fn show_progress(name: &str) {
    use super::ui::*;
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        print!("    {} {name:<10} {}", dot(), dim("updating\u{2026}"));
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }
}

/// The result line for a component whose progress `show_progress` showed.
fn show_result(line: &str) {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        println!("\r{line}          ");
    } else {
        println!("{line}");
    }
}

/// A second line under a component's row, for what a short status cannot say.
fn show_detail(text: &str) {
    println!("      {}", super::ui::dim(text));
}

/// `old -> new`, or just `new`, in the column the other rows put their version in, when
/// the old version is not known or is the same.
fn version_change(old: Option<&str>, new: &str) -> String {
    use super::ui::*;
    match old {
        Some(old) if !old.is_empty() && old != new => format!("{DIM}{old} \u{2192}{RESET} {new}"),
        _ => ver(new),
    }
}

/// The row for a component this user may not update.
fn needs_rights_row(name: &str, mid: &str) -> String {
    use super::ui::*;
    row(
        &bang(),
        name,
        mid,
        &format!("{YELLOW}needs {RIGHTS}{RESET}"),
    )
}

/// `crossfyre update [self|<ext>|all]`. With no target: update self plus
/// every installed extension.
pub async fn update(
    target: Option<&str>,
    current_version: &str,
    force: bool,
) -> Result<Updated, Box<dyn std::error::Error>> {
    // First, so what follows sees every engine under its public name.
    super::migrate::renamed_engines();
    let manifest = fetch_manifest().await?;
    update_with(&manifest, target, current_version, force).await
}

/// `update` against a manifest already fetched.
async fn update_with(
    manifest: &Manifest,
    target: Option<&str>,
    current_version: &str,
    force: bool,
) -> Result<Updated, Box<dyn std::error::Error>> {
    let (do_self, exts): (bool, Vec<&str>) = match target {
        Some("self") => (true, vec![]),
        Some("all") | None => (true, installed_extensions()),
        Some(ext) => (false, super::resolve_extensions(ext)?),
    };

    use super::ui::*;
    println!();
    println!("  {BOLD}Crossfyre update{RESET}   {}", dim(origin_host()));
    println!();

    let mut out = Updated::default();
    let bin_dir = get_bin_dir();
    let writable = can_write_in(&bin_dir);

    // Suppress the per-service status lines from install/service ops - this
    // command renders its own summary. No `?` runs between the toggle pair, so
    // it is always restored before returning.
    service::set_quiet(true);

    // ── Extensions ────────────────────────────────────────────────────
    if !exts.is_empty() {
        println!("  {}", dim("Extensions"));
        for ext in &exts {
            let name = super::public_name(ext);
            if let Some(m) = packaging::owner(ext) {
                println!("{}", row(&check(), name, "", &dim(&update_note(m))));
                out.current += 1;
                continue;
            }
            let want = manifest_version(manifest, ext);
            let have = installed_ext_version(ext);
            let up_to_date = ext_bin_path(ext).exists()
                && !want.is_empty()
                && have.as_deref() == Some(want.as_str());
            if up_to_date && !force {
                println!("{}", row(&check(), name, &ver(&want), &dim("up to date")));
                out.current += 1;
                continue;
            }
            if !writable {
                println!(
                    "{}",
                    needs_rights_row(name, &version_change(have.as_deref(), &want))
                );
                out.need_rights += 1;
                continue;
            }
            show_progress(name);
            match install_one(manifest, ext, true, true).await {
                Ok(()) => {
                    let _ = service::start(ext);
                    let mid = version_change(have.as_deref(), &want);
                    show_result(&row(
                        &check(),
                        name,
                        &mid,
                        &format!("{GREEN}updated{RESET}"),
                    ));
                    out.changed += 1;
                }
                Err(e) => {
                    show_result(&row(
                        &bang(),
                        name,
                        "",
                        &format!("{YELLOW}failed{RESET} {}", dim(&e.to_string())),
                    ));
                    out.failed += 1;
                }
            }
        }
        println!();
    }

    // ── Core: crossfyre CLI + node worker ─────────────────────────────
    if do_self {
        println!("  {}", dim("Core"));

        let want = manifest_version(manifest, "crossfyre");
        // Where the update writes the CLI first (see `cli_targets`).
        let cli_dir = std::env::current_exe()
            .ok()
            .and_then(|exe| {
                let stable = bin_dir.join(ext_file_name("crossfyre"));
                cli_targets(&exe, &stable).into_iter().next()
            })
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| bin_dir.clone());
        if let Some(m) = packaging::owner("crossfyre") {
            println!(
                "{}",
                row(
                    &check(),
                    "crossfyre",
                    &ver(current_version),
                    &dim(&update_note(m))
                )
            );
            out.current += 1;
        } else if !want.is_empty() && want == current_version && !force {
            println!(
                "{}",
                row(&check(), "crossfyre", &ver(&want), &dim("up to date"))
            );
            out.current += 1;
        } else if !can_write_in(&cli_dir) {
            println!(
                "{}",
                needs_rights_row("crossfyre", &version_change(Some(current_version), &want))
            );
            out.need_rights += 1;
        } else {
            show_progress("crossfyre");
            match self_update(manifest, current_version, true, force).await {
                Ok(true) => {
                    let mid = version_change(Some(current_version), &want);
                    show_result(&row(
                        &check(),
                        "crossfyre",
                        &mid,
                        &format!("{GREEN}updated{RESET}"),
                    ));
                    out.restart = true;
                    out.changed += 1;
                }
                Ok(false) => {
                    show_result(&row(&check(), "crossfyre", &ver(&want), &dim("up to date")));
                    out.current += 1;
                }
                Err(e) => {
                    show_result(&row(
                        &bang(),
                        "crossfyre",
                        "",
                        &format!("{YELLOW}failed{RESET} {}", dim(&e.to_string())),
                    ));
                    out.failed += 1;
                }
            }
        }

        // The node worker. One that is not here is not installed by an update: `node
        // init` sets a node up, and a CLI that Homebrew or apt installed runs without one.
        let nwant = manifest_version(manifest, "node");
        let node_installed = ext_bin_path("node").exists();
        if let Some(m) = packaging::owner("node") {
            println!("{}", row(&check(), "node", "", &dim(&update_note(m))));
            out.current += 1;
        } else if !node_installed {
            println!("{}", row(&dot(), "node", "", &dim("not installed")));
        } else {
            let nhave = installed_node_version();
            if !nwant.is_empty() && nhave.as_deref() == Some(nwant.as_str()) && !force {
                println!(
                    "{}",
                    row(&check(), "node", &ver(&nwant), &dim("up to date"))
                );
                out.current += 1;
            } else if !writable {
                println!(
                    "{}",
                    needs_rights_row("node", &version_change(nhave.as_deref(), &nwant))
                );
                out.need_rights += 1;
            } else {
                show_progress("node");
                match download_node(manifest, true, force).await {
                    Ok(true) => {
                        let mid = version_change(nhave.as_deref(), &nwant);
                        show_result(&row(
                            &check(),
                            "node",
                            &mid,
                            &format!("{GREEN}updated{RESET}"),
                        ));
                        out.restart = true;
                        out.changed += 1;
                    }
                    Ok(false) => {
                        show_result(&row(&check(), "node", &ver(&nwant), &dim("up to date")));
                        out.current += 1;
                    }
                    Err(e) => {
                        show_result(&row(
                            &bang(),
                            "node",
                            "",
                            &format!("{YELLOW}failed{RESET} {}", dim(&e.to_string())),
                        ));
                        out.failed += 1;
                    }
                }
            }
        }

        // The cfx-script helper beside node. Optional, as in the installer, and a release
        // without one is passed over in silence. A new one needs no restart: every job
        // starts it afresh.
        let hwant = manifest_version(manifest, CFX_SCRIPT);
        let helper_installed = ext_bin_path(CFX_SCRIPT).exists();
        // The row and the note for a cfx-script this host cannot start.
        let skipped_row = row(
            &bang(),
            CFX_SCRIPT,
            &ver(&hwant),
            &format!(
                "{YELLOW}skipped{RESET} {}",
                dim("cannot start on this host")
            ),
        );
        let skipped_note = |output: &str| {
            format!(
                "{} Until it can, {}.",
                cannot_start_note(output),
                without_new_helper()
            )
        };
        if let Some(m) = packaging::owner(CFX_SCRIPT) {
            println!("{}", row(&check(), CFX_SCRIPT, "", &dim(&update_note(m))));
            out.current += 1;
        } else if !hwant.is_empty() && !helper_installed && !node_installed {
            println!("{}", row(&dot(), CFX_SCRIPT, "", &dim("not installed")));
        } else if !hwant.is_empty() {
            let hhave = installed_helper_version();
            if hhave.as_deref() == Some(hwant.as_str()) && !force {
                println!(
                    "{}",
                    row(&check(), CFX_SCRIPT, &ver(&hwant), &dim("up to date"))
                );
                out.current += 1;
            } else if let Some(output) = still_cannot_start(&hwant).filter(|_| !force) {
                println!("{skipped_row}");
                show_detail(&skipped_note(&output));
                out.skipped += 1;
            } else if !writable {
                println!(
                    "{}",
                    needs_rights_row(CFX_SCRIPT, &version_change(hhave.as_deref(), &hwant))
                );
                out.need_rights += 1;
            } else {
                show_progress(CFX_SCRIPT);
                match install_cfx_script(manifest, force).await {
                    Ok(HelperOutcome::Installed { version, replaced }) => {
                        let mid = version_change(replaced.as_deref(), &version);
                        show_result(&row(
                            &check(),
                            CFX_SCRIPT,
                            &mid,
                            &format!("{GREEN}updated{RESET}"),
                        ));
                        out.changed += 1;
                    }
                    Ok(HelperOutcome::Current { .. } | HelperOutcome::NotInRelease) => {
                        show_result(&row(&check(), CFX_SCRIPT, &ver(&hwant), &dim("up to date")));
                        out.current += 1;
                    }
                    Ok(HelperOutcome::Owned(m)) => {
                        show_result(&row(&check(), CFX_SCRIPT, "", &dim(&update_note(m))));
                        out.current += 1;
                    }
                    Ok(HelperOutcome::CannotStart { output, .. }) => {
                        show_result(&skipped_row);
                        show_detail(&skipped_note(&output));
                        out.skipped += 1;
                    }
                    Err(e) => {
                        show_result(&row(
                            &bang(),
                            CFX_SCRIPT,
                            "",
                            &format!(
                                "{YELLOW}failed{RESET} {}",
                                dim(&format!("{e}. Until it installs, {}", without_new_helper()))
                            ),
                        ));
                        out.failed += 1;
                    }
                }
            }
        }
        println!();
    }

    service::set_quiet(false);

    // ── Summary ───────────────────────────────────────────────────────
    let colour = if out.succeeded() && out.skipped == 0 {
        GREEN
    } else {
        YELLOW
    };
    println!("  {BOLD}{colour}{}{RESET}", out.summary());
    if out.need_rights > 0 {
        let mut again = String::from("crossfyre update");
        if let Some(t) = target {
            again.push(' ');
            again.push_str(t);
        }
        if force {
            again.push_str(" --force");
        }
        let them = if out.need_rights == 1 { "it" } else { "them" };
        println!(
            "  Run {} to update {them}.",
            bold(&crate::os::elevated(&again))
        );
    }
    println!();

    Ok(out)
}

fn installed_extensions() -> Vec<&'static str> {
    super::EXTENSIONS
        .iter()
        .copied()
        .filter(|e| super::config::is_extension_installed(e))
        .collect()
}

/// Replace the running crossfyre binary with the manifest version. Linux
/// keeps the old inode mapped, so the running process is unaffected until
/// restart. Returns true if a new version was written.
pub async fn self_update(
    manifest: &Manifest,
    current_version: &str,
    quiet: bool,
    force: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some(m) = packaging::owner("crossfyre") {
        return Err(format!("crossfyre is {}", update_note(m)).into());
    }
    let (comp, artifact) = resolve_artifact(manifest, "crossfyre")?;

    // `current_version` is supplied by the caller: the crossfyre CLI passes its
    // own env!("CARGO_PKG_VERSION"); the node worker passes the recorded sidecar
    // value (installed_cli_version). It must NOT be read from env! here - this
    // code lives in cfx_core, so env! resolves to cfx_core's version (0.1.0), not
    // the CLI's. That mismatch made every `crossfyre update` re-run forever.
    if comp.version == current_version && !force {
        if !quiet {
            println!("crossfyre is already at {current_version} - nothing to update.");
        }
        return Ok(false);
    }

    if !quiet {
        println!(
            "[*] Updating crossfyre {} -> {} ...",
            current_version, comp.version
        );
    }
    let tmp_dir = tempfile::tempdir()?;
    let zip_path = tmp_dir.path().join(&artifact.file);
    download_verified(artifact, &zip_path).await?;

    let extract_dir = tmp_dir.path().join("extracted");
    extract_zip(&zip_path, &extract_dir)?;
    let extracted = extract_dir.join(ext_file_name("crossfyre"));
    if !extracted.exists() {
        return Err("crossfyre binary not found inside update zip".into());
    }

    let exe = std::env::current_exe()?;
    let stable = get_bin_dir().join(ext_file_name("crossfyre"));
    let mut targets = cli_targets(&exe, &stable).into_iter();
    if let Some(first) = targets.next() {
        place_binary(&extracted, &first)?;
    }
    // Keep the stable /opt path in sync too, in case the process was started
    // from somewhere else (e.g. a dev checkout).
    for also in targets {
        let _ = place_binary(&extracted, &also);
    }

    // Record the installed CLI version (mirrors node.version). The next update -
    // and the node worker, which can't read the CLI's env! - compares against
    // what's actually on disk instead of a compile-time constant.
    let _ = std::fs::write(get_bin_dir().join("crossfyre.version"), &comp.version);

    if !quiet {
        println!(
            "[+] crossfyre updated to {} - restart the node to run it.",
            comp.version
        );
    }
    Ok(true)
}

/// Where an update of the CLI is written, in order: over the running binary when that
/// is the CLI, then at the stable path in the bin directory. The node daemon runs this
/// for the dashboard's update too, and there the running binary is the node worker.
/// Writing the CLI over it left a unit that ran `crossfyre supervise`, which exits with
/// a usage error, so the node restarted into the same failure every few seconds and
/// stayed offline, while node.version still said it was current.
fn cli_targets(exe: &Path, stable: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if exe.file_name() == stable.file_name() {
        out.push(exe.to_path_buf());
    }
    if !out.iter().any(|p| p == stable) {
        out.push(stable.to_path_buf());
    }
    out
}

/// The version of the crossfyre CLI in the bin directory: the one `self_update` recorded,
/// or, with no record, the one it reports. Empty when neither is known. Used by callers
/// that cannot read the running CLI's env! version (e.g. the node worker's
/// dashboard-triggered self-update).
pub fn installed_cli_version() -> String {
    let dir = get_bin_dir();
    let bin = dir.join(ext_file_name("crossfyre"));
    recorded_or_reported(
        &dir.join("crossfyre.version"),
        &bin,
        "crossfyre",
        Vec::new(),
    )
    .unwrap_or_default()
}

/// Copy the running binary to the stable install path
/// (`/opt/crossfyre/bin/crossfyre`) so OS services have a fixed ExecStart.
/// No-op when already running from there, and when a package manager installed this
/// CLI: a copy beside the engines would be one that no package upgrade replaces. The
/// path returned is the one to name the CLI by.
pub fn ensure_self_installed() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    if super::packaging::owner("crossfyre").is_some() {
        return Ok(super::packaging::cli_path_for(&exe));
    }
    let stable = get_bin_dir().join(ext_file_name("crossfyre"));
    if exe == stable {
        return Ok(stable);
    }
    place_binary(&exe, &stable)?;
    println!("[+] Installed crossfyre binary to {}", stable.display());
    Ok(stable)
}

/// Download + install the `node` worker binary to the stable bin dir. The
/// crossfyre CLI and the OS service exec it (ExecStart=/opt/crossfyre/bin/node),
/// so it must sit next to crossfyre.
/// Returns true when the node binary was (re)written, i.e. the caller should
/// restart the node service. Skips the download when the installed version
/// already matches the manifest: the one its sidecar records, or the one it reports.
pub async fn download_node(
    manifest: &Manifest,
    quiet: bool,
    force: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some(m) = packaging::owner("node") {
        return Err(format!("node is {}", update_note(m)).into());
    }
    let (comp, artifact) = resolve_artifact(manifest, "node")?;
    let stable = get_bin_dir().join(ext_file_name("node"));
    let ver_file = get_bin_dir().join("node.version");
    if installed_node_version().as_deref() == Some(comp.version.as_str()) && !force {
        return Ok(false); // already current
    }

    let tmp_dir = tempfile::tempdir()?;
    let zip_path = tmp_dir.path().join(&artifact.file);
    download_verified(artifact, &zip_path).await?;
    let extract_dir = tmp_dir.path().join("extracted");
    extract_zip(&zip_path, &extract_dir)?;
    let extracted = extract_dir.join(ext_file_name("node"));
    if !extracted.exists() {
        return Err("node binary not found inside the node zip".into());
    }
    place_binary(&extracted, &stable)?;
    let _ = std::fs::write(&ver_file, &comp.version);
    if !quiet {
        println!(
            "[+] node worker updated to {} at {}",
            comp.version,
            stable.display()
        );
    }
    Ok(true)
}

/// Ensure the `node` worker binary is present next to crossfyre, and the cfx-script
/// helper next to it. A missing one is copied from beside the running binary when it is
/// there (fresh install, release tarball, dev checkout) and downloaded from the release
/// manifest when it is not. An installed helper is also refreshed from the manifest when
/// its recorded version is not the release's. Called during `node init` so the
/// service's ExecStart resolves. A helper that cannot be installed is a warning, not an
/// error, since only .cfx scripts need it.
pub async fn ensure_node_installed() -> Result<(), Box<dyn std::error::Error>> {
    let stable = get_bin_dir().join(ext_file_name("node"));
    let mut manifest = None;
    if let Some(m) = packaging::owner("node") {
        if !stable.exists() {
            return Err(format!(
                "node is installed by {m}, but {} is missing; reinstall it with {m}",
                stable.display()
            )
            .into());
        }
    } else if !stable.exists() {
        if let Some(sib) = sibling_of_this_binary("node") {
            place_binary(&sib, &stable)?;
            println!("[+] Installed node binary to {}", stable.display());
        } else {
            let m = fetch_manifest().await?;
            download_node(&m, false, false).await?;
            manifest = Some(m);
        }
    }

    if packaging::owner(CFX_SCRIPT).is_some() {
        return Ok(());
    }
    let helper = ext_bin_path(CFX_SCRIPT);
    if !helper.exists()
        && let Some(sib) = sibling_of_this_binary(CFX_SCRIPT)
    {
        // From the same build as a node beside it. Its version is unknown, so none is
        // recorded, and the next update replaces it with the manifest's.
        let _ = fs::remove_file(ext_version_file(CFX_SCRIPT));
        match place_helper_if_it_starts(&sib, &helper) {
            Ok(None) => println!(
                "[+] Installed cfx-script to {} (runs .cfx scripts)",
                helper.display()
            ),
            Ok(Some(output)) => eprintln!(
                "[!] {} cannot start here, so it was not installed and {}. {}",
                sib.display(),
                without_new_helper(),
                cannot_start_note(&output)
            ),
            Err(e) => report_cfx_script(Err(e)),
        }
        return Ok(());
    }
    let manifest = match manifest {
        Some(m) => m,
        None => match fetch_manifest().await {
            Ok(m) => m,
            Err(e) => {
                report_cfx_script(Err(e));
                return Ok(());
            }
        },
    };
    report_cfx_script(install_cfx_script(&manifest, false).await);
    Ok(())
}

/// `name` in the directory of the running binary, when it is there and is not the
/// installed copy itself. Never for a packaged CLI: its directory belongs to the package,
/// and in /usr/bin a file called `node` is Node.js.
fn sibling_of_this_binary(name: &str) -> Option<PathBuf> {
    if super::packaging::current().is_some() {
        return None;
    }
    let installed = get_bin_dir().join(ext_file_name(name));
    let exe = std::env::current_exe().ok()?;
    let sib = exe.parent()?.join(ext_file_name(name));
    (sib.exists() && sib != installed).then_some(sib)
}

/// What the dashboard's update did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DashboardUpdate {
    /// The CLI was replaced, and the node should restart to run it.
    pub restart: bool,
    /// The package manager the CLI belongs to, when one does. The update left the CLI
    /// alone, and the dashboard can say which manager updates it.
    pub cli_managed_by: Option<Manager>,
}

/// The update the dashboard asks a node for: the crossfyre CLI and the cfx-script helper,
/// from the release manifest. A component a package manager installed is left to it. A
/// new helper needs no restart, since every job starts it afresh.
pub async fn update_for_dashboard() -> Result<DashboardUpdate, Box<dyn std::error::Error>> {
    let manifest = fetch_manifest().await?;
    report_cfx_script(install_cfx_script(&manifest, false).await);
    if let Some(m) = packaging::owner("crossfyre") {
        println!("[update] crossfyre is {}", update_note(m));
        return Ok(DashboardUpdate {
            restart: false,
            cli_managed_by: Some(m),
        });
    }
    let restart = self_update(&manifest, &installed_cli_version(), false, false).await?;
    Ok(DashboardUpdate {
        restart,
        cli_managed_by: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest as it arrives: parsed from JSON, because the types only derive
    /// `Deserialize` and because the parse is part of what is being checked.
    fn manifest(json: &str) -> Manifest {
        serde_json::from_str(json).expect("manifest parses")
    }

    fn artifact(file: &str, sha: &str) -> Artifact {
        serde_json::from_value(serde_json::json!({"file": file, "sha256": sha}))
            .expect("artifact parses")
    }

    /// sha256 of `b"hello"`, so the expectation in these tests is a value an operator
    /// could reproduce with `sha256sum` rather than one copied out of a failure.
    const HELLO_SHA: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn matching_bytes_are_accepted_and_one_changed_byte_is_not() {
        let a = artifact("ambulo-linux-x86_64.zip", HELLO_SHA);
        assert!(verify_artifact_bytes(&a, b"hello").is_ok());

        let err = verify_artifact_bytes(&a, b"hellp").expect_err("one byte changed");
        assert!(err.contains("checksum mismatch"), "got: {err}");
        assert!(
            err.contains("refusing to install"),
            "the message has to say what it did, not only what it saw: {err}"
        );
    }

    #[test]
    fn an_uppercase_checksum_in_the_manifest_still_matches() {
        // The publish pipeline writes lowercase hex, but a hand-edited manifest or a
        // different tool may not, and a case mismatch refusing a correct artifact would
        // look exactly like a compromised bucket.
        let a = artifact("ambulo.zip", &HELLO_SHA.to_ascii_uppercase());
        assert!(verify_artifact_bytes(&a, b"hello").is_ok());
    }

    #[test]
    fn an_artifact_with_no_checksum_is_refused_rather_than_trusted() {
        // The failure mode this guards: `sha256` absent or blanked in the manifest
        // deserialises to an empty string, and a plain comparison against it means every
        // byte sequence is wrong, which is correct by accident. Being explicit also makes
        // the message say why instead of printing a mismatch against nothing.
        for blank in ["", "   "] {
            let a = artifact("ambulo.zip", blank);
            let err = verify_artifact_bytes(&a, b"hello")
                .expect_err("an artifact with no checksum must be refused");
            assert!(
                err.contains("records no sha256"),
                "expected the message to name the missing checksum, got: {err}"
            );
        }
    }

    #[test]
    fn an_empty_artifact_is_still_checked() {
        // Zero bytes has a sha256 like anything else. A truncated download that arrives
        // as an empty 200 must not pass because there is nothing to hash.
        let empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let a = artifact("ambulo.zip", empty_sha);
        assert!(verify_artifact_bytes(&a, b"").is_ok());
        let b = artifact("ambulo.zip", HELLO_SHA);
        assert!(verify_artifact_bytes(&b, b"").is_err());
    }

    #[test]
    fn a_manifest_missing_the_component_or_the_platform_says_which() {
        let key = platform_key();
        let m = manifest(&format!(
            r#"{{"components":{{"ambulo":{{"version":"0.0.14","artifacts":{{"{key}":{{"file":"f","sha256":"{HELLO_SHA}"}}}}}}}}}}"#
        ));
        assert!(resolve_artifact(&m, "ambulo").is_ok());

        let err = resolve_artifact(&m, "plessor")
            .expect_err("a component that is not there")
            .to_string();
        assert!(err.contains("plessor"), "got: {err}");

        // A component that exists with no artifact for this host is a different problem
        // from one that does not exist, and the two messages were worth separating.
        let other = manifest(
            r#"{"components":{"ambulo":{"version":"0.0.14","artifacts":{"solaris-sparc":{"file":"f","sha256":"x"}}}}}"#,
        );
        let err = resolve_artifact(&other, "ambulo")
            .expect_err("no artifact for this platform")
            .to_string();
        assert!(err.contains(&key), "the message names the platform: {err}");
    }

    #[test]
    fn a_manifest_with_fields_we_do_not_know_still_parses() {
        // Forward compatibility, and it is load bearing: the publish pipeline adding a
        // field must not stop older installed binaries from reading the manifest, or an
        // additive change becomes a fleet-wide update failure.
        let key = platform_key();
        let m = manifest(&format!(
            r#"{{"generated":"2026-10-03","components":{{"ambulo":{{"version":"0.0.14","channel":"stable","artifacts":{{"{key}":{{"file":"f","sha256":"{HELLO_SHA}","size":1234}}}}}}}}}}"#
        ));
        let (c, a) = resolve_artifact(&m, "ambulo").expect("unknown fields are ignored");
        assert_eq!(c.version, "0.0.14");
        assert_eq!(a.sha256, HELLO_SHA);
        assert_eq!(manifest_version(&m, "ambulo"), "0.0.14");
        assert_eq!(
            manifest_version(&m, "nope"),
            "",
            "an absent component reports no version rather than panicking"
        );
    }

    #[test]
    fn an_engine_resolves_under_its_new_key_and_falls_back_to_its_old_one() {
        let key = platform_key();
        let entry = |v: &str| {
            format!(
                r#"{{"version":"{v}","artifacts":{{"{key}":{{"file":"f-{v}","sha256":"{HELLO_SHA}"}}}}}}"#
            )
        };
        // The release manifest carries the new key and, for one release, the old one
        // as an alias. The new key is the one taken.
        let both = manifest(&format!(
            r#"{{"components":{{"cortex":{},"plessor":{}}}}}"#,
            entry("0.0.22"),
            entry("0.0.23")
        ));
        assert_eq!(manifest_version(&both, "cortex"), "0.0.23");
        assert_eq!(manifest_version(&both, "plessor"), "0.0.23");
        // A manifest that has not gained the new key yet still installs the engine.
        let old = manifest(&format!(
            r#"{{"components":{{"cortex":{}}}}}"#,
            entry("0.0.22")
        ));
        assert_eq!(manifest_version(&old, "cortex"), "0.0.22");
        assert_eq!(manifest_version(&old, "plessor"), "0.0.22");
    }

    /// An engine that was renamed, as the table describes one.
    const RENAMED: crate::toolchain::Engine = crate::toolchain::Engine {
        id: "cortex",
        name: "fresh",
        legacy: Some("cortex"),
        port: 4445,
        about: "",
    };

    #[test]
    fn a_renamed_engine_is_looked_up_under_its_public_name_then_its_legacy_one() {
        assert_eq!(keys_for(Some(&RENAMED), "cortex"), ["fresh", "cortex"]);
        assert_eq!(keys_for(None, "crossfyre"), ["crossfyre"]);
        let key = platform_key();
        let entry = |v: &str| {
            format!(
                r#"{{"version":"{v}","artifacts":{{"{key}":{{"file":"f-{v}","sha256":"{HELLO_SHA}"}}}}}}"#
            )
        };

        // A manifest from before the rename has only the legacy key.
        let old = manifest(&format!(
            r#"{{"components":{{"cortex":{}}}}}"#,
            entry("0.0.22")
        ));
        let (c, _) = resolve_keys(&old, &keys_for(Some(&RENAMED), "cortex")).expect("falls back");
        assert_eq!(c.version, "0.0.22");

        // One from after it carries both, and the public name is taken.
        let both = manifest(&format!(
            r#"{{"components":{{"cortex":{},"fresh":{}}}}}"#,
            entry("0.0.22"),
            entry("0.0.23")
        ));
        let (c, a) = resolve_keys(&both, &keys_for(Some(&RENAMED), "cortex")).expect("found");
        assert_eq!(
            (c.version.as_str(), a.file.as_str()),
            ("0.0.23", "f-0.0.23")
        );

        let err = resolve_keys(&manifest(r#"{"components":{}}"#), &["fresh", "cortex"])
            .expect_err("in neither")
            .to_string();
        assert!(
            err.contains("'fresh'"),
            "the public name is the one reported: {err}"
        );
    }

    #[test]
    fn the_binary_inside_an_artifact_may_carry_either_name() {
        let s = Scratch::new("member");
        let keys = keys_for(Some(&RENAMED), "cortex");
        assert_eq!(find_member(&s.0, &keys), None);
        fs::write(s.join(&file_name("cortex")), b"alias").expect("legacy member");
        assert_eq!(find_member(&s.0, &keys), Some(s.join(&file_name("cortex"))));
        fs::write(s.join(&file_name("fresh")), b"new").expect("public member");
        assert_eq!(
            find_member(&s.0, &keys),
            Some(s.join(&file_name("fresh"))),
            "the public name first"
        );
    }

    #[test]
    fn the_platform_key_is_one_of_the_shapes_the_manifest_uses() {
        let key = platform_key();
        let (os, arch) = key.split_once('-').expect("os-arch");
        assert!(
            ["linux", "darwin", "windows"].contains(&os),
            "unexpected os segment in {key}"
        );
        assert!(!arch.is_empty(), "no arch segment in {key}");
        assert!(
            !key.contains("macos"),
            "macos must be spelled darwin in a manifest key, got {key}"
        );
    }

    // ---------------------------------------------------------------------------
    // A packaged install
    // ---------------------------------------------------------------------------

    /// Have this test's thread run as if a package with this packaging.json installed it.
    fn packaged(json: &str) {
        let p = packaging::Packaging::parse(
            json,
            PathBuf::from("/usr/lib/crossfyre/packaging.json"),
            true,
        )
        .expect("parses");
        packaging::pretend(packaging::Found::Packaged(p));
    }

    /// A manifest with every component at `v` for this platform.
    fn full_manifest(v: &str) -> Manifest {
        let key = platform_key();
        let entry = format!(
            r#"{{"version":"{v}","artifacts":{{"{key}":{{"file":"f","sha256":"{HELLO_SHA}"}}}}}}"#
        );
        let body: Vec<String> = [
            "crossfyre",
            "node",
            "cfx-script",
            "ambulo",
            "voyage",
            "doorward",
            "toolmark",
            "plessor",
        ]
        .iter()
        .map(|n| format!(r#""{n}":{entry}"#))
        .collect();
        manifest(&format!(r#"{{"components":{{{}}}}}"#, body.join(",")))
    }

    #[tokio::test]
    async fn a_cli_that_apt_installed_is_left_to_apt_and_apt_is_named() {
        packaged(r#"{"manager":"apt","owns":["crossfyre"]}"#);
        let err = self_update(&full_manifest("0.1.33"), "0.1.33", true, false)
            .await
            .expect_err("refused even when current");
        assert_eq!(
            err.to_string(),
            "crossfyre is installed by apt; update it with apt"
        );
        // A newer release, or --force, does not make apt's file the CLI's to replace.
        assert!(
            self_update(&full_manifest("9.9.9"), "0.1.33", true, true)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_node_and_a_helper_a_package_owns_are_left_to_it() {
        packaged(r#"{"manager":"container","owns":["crossfyre","node","cfx-script"]}"#);
        let err = download_node(&full_manifest("9.9.9"), true, true)
            .await
            .expect_err("refused");
        assert!(err.to_string().contains("installed by container"), "{err}");
        let out = install_cfx_script(&full_manifest("9.9.9"), true)
            .await
            .expect("not an error");
        assert!(
            matches!(out, HelperOutcome::Owned(Manager::Container)),
            "{out:?}"
        );
    }

    // Unix only: packaged installs and their systemd units are a Linux and macOS layout.
    #[cfg(unix)]
    #[test]
    fn a_packaged_cli_is_not_copied_into_the_bin_dir_and_takes_nothing_from_beside_it() {
        packaged(
            r#"{"manager":"brew","owns":["crossfyre"],
                "cli_path":"/home/linuxbrew/.linuxbrew/bin/crossfyre"}"#,
        );
        assert_eq!(
            ensure_self_installed().expect("nothing to copy"),
            PathBuf::from("/home/linuxbrew/.linuxbrew/bin/crossfyre"),
            "named by the path brew keeps across upgrades"
        );
        assert_eq!(sibling_of_this_binary("node"), None);
        assert_eq!(sibling_of_this_binary(CFX_SCRIPT), None);
    }

    // Unix only: packaged installs and their systemd units are a Linux and macOS layout.
    #[cfg(unix)]
    #[test]
    fn the_bin_dir_a_package_names_is_where_everything_else_is() {
        packaged(
            r#"{"manager":"nix","owns":["crossfyre","node","cfx-script","ambulo","voyage",
                "doorward","toolmark","plessor"],"bin_dir":"/nix/store/x-crossfyre/libexec"}"#,
        );
        let dir = PathBuf::from("/nix/store/x-crossfyre/libexec");
        assert_eq!(get_bin_dir(), dir);
        assert_eq!(ext_bin_path("cortex"), dir.join("plessor"));
        assert_eq!(service::node_binary(), dir.join("node"));
    }

    // ---------------------------------------------------------------------------
    // Placing a binary
    // ---------------------------------------------------------------------------

    /// A scratch directory under the system temp dir, removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "cfx-install-test-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).expect("scratch dir");
            Self(p)
        }
        fn join(&self, n: &str) -> std::path::PathBuf {
            self.0.join(n)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).expect("metadata").permissions().mode() & 0o777
    }

    /// Note what this does and does not check. It pins the end state, that an artifact
    /// unpacked 0644 is installed 0755, which is worth a regression test on its own. It
    /// does NOT check that the mode is set before the rename rather than after, because
    /// both orders reach the same end state and the difference is only visible to a
    /// process that dies inside the window. That reasoning lives on `place_binary`.
    #[test]
    fn a_placed_binary_is_executable_even_when_the_archive_was_not() {
        let s = Scratch::new("mode");
        let src = s.join("ambulo-unpacked");
        fs::write(&src, b"#!/bin/sh\necho hi\n").expect("write src");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // What an artifact unpacked out of a zip normally looks like.
            fs::set_permissions(&src, fs::Permissions::from_mode(0o644)).expect("chmod src");
        }

        let dest = s.join("bin").join("ambulo");
        place_binary(&src, &dest).expect("place");
        assert!(dest.exists(), "the parent directory is created");
        #[cfg(unix)]
        assert_eq!(mode_of(&dest), 0o755, "an 0644 artifact is installed 0755");
        assert_eq!(
            fs::read(&dest).expect("read"),
            fs::read(&src).expect("read")
        );
        assert!(
            !s.join("bin").join("ambulo.new").exists(),
            "nothing is left staged next to the destination"
        );
    }

    #[test]
    fn the_dashboard_update_writes_the_cli_beside_the_node_and_never_over_it() {
        let stable = Path::new("/opt/crossfyre/bin/crossfyre");
        // The node daemon runs the dashboard's update, and its own binary is the worker.
        assert_eq!(
            cli_targets(Path::new("/opt/crossfyre/bin/node"), stable),
            [stable.to_path_buf()]
        );
        // The CLI run from a checkout updates itself and the installed copy.
        let dev = Path::new("/home/op/src/target/release/crossfyre");
        assert_eq!(
            cli_targets(dev, stable),
            [dev.to_path_buf(), stable.to_path_buf()]
        );
        assert_eq!(cli_targets(stable, stable), [stable.to_path_buf()]);
    }

    #[test]
    fn placing_over_an_existing_binary_replaces_it() {
        let s = Scratch::new("replace");
        let dest = s.join("ambulo");
        fs::write(&dest, b"the-old-one").expect("write old");
        let src = s.join("new-ambulo");
        fs::write(&src, b"the-new-one").expect("write new");

        place_binary(&src, &dest).expect("place");
        assert_eq!(fs::read(&dest).expect("read"), b"the-new-one");
        #[cfg(unix)]
        assert_eq!(mode_of(&dest), 0o755);
    }

    #[test]
    fn staging_appends_to_the_name_instead_of_replacing_its_extension() {
        // `with_extension("new")` does not append, it REPLACES whatever follows the last
        // dot, so placing `plessor-0.1.2` used to stage through `plessor-0.1.new`. That is
        // a path belonging to something else.
        //
        // The oracle is a bystander: a real file already sitting at the old staging name.
        // Staging through it copies over the bystander and then renames it away, so the
        // file is destroyed. Asserting the placement succeeded would not have caught
        // this, and did not: an earlier version of this test passed against the unfixed
        // code because both placements still worked.
        let s = Scratch::new("stage");
        let src = s.join("payload");
        fs::write(&src, b"x").expect("write src");

        let bystander = s.join("plessor-0.1.new");
        fs::write(&bystander, b"somebody-elses-file").expect("write bystander");

        let dest = s.join("plessor-0.1.2");
        place_binary(&src, &dest).expect("place");

        assert!(dest.exists(), "the binary was placed");
        assert_eq!(
            fs::read(&bystander).ok().as_deref(),
            Some(&b"somebody-elses-file"[..]),
            "staging must not go through a path that belongs to another name"
        );
    }

    // ---------------------------------------------------------------------------
    // Placing cfx-script
    // ---------------------------------------------------------------------------

    /// A stand-in cfx-script: a shell script that reads its stdin and exits as told.
    #[cfg(unix)]
    fn fake_helper(s: &Scratch, name: &str, body: &str) -> std::path::PathBuf {
        let p = s.join(name);
        fs::write(&p, format!("#!/bin/sh\ncat >/dev/null\n{body}\n")).expect("write helper");
        p
    }

    #[cfg(unix)]
    #[test]
    fn a_helper_that_refuses_an_empty_job_is_placed() {
        // Exit status 2 on an empty stdin is how cfx-script refuses a job that is not
        // there, and getting that far means it loaded.
        let s = Scratch::new("helper-ok");
        let src = fake_helper(&s, "unpacked", "exit 2");
        let dest = s.join("bin").join("cfx-script");
        let failed = place_helper_if_it_starts(&src, &dest).expect("place");
        assert_eq!(failed, None);
        assert_eq!(
            fs::read(&dest).expect("read"),
            fs::read(&src).expect("read")
        );
        assert_eq!(mode_of(&dest), 0o755);
        assert!(!s.join("bin").join("cfx-script.new").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_helper_that_cannot_start_is_not_placed_and_the_old_one_stays() {
        let s = Scratch::new("helper-broken");
        let src = fake_helper(
            &s,
            "unpacked",
            "echo 'cfx-script: error while loading shared libraries: libpython3.11.so.1.0' >&2\nexit 127",
        );
        let dest = s.join("cfx-script");
        fs::write(&dest, b"the-old-one").expect("write old");
        let failed = place_helper_if_it_starts(&src, &dest).expect("place");
        let output = failed.expect("a helper exiting 127 cannot start");
        assert!(output.contains("libpython3.11.so.1.0"), "{output}");
        assert_eq!(fs::read(&dest).expect("read"), b"the-old-one");
        assert!(!s.join("cfx-script.new").exists(), "nothing is left staged");
    }

    #[cfg(unix)]
    #[test]
    fn a_helper_that_ran_a_job_it_was_never_given_is_not_placed() {
        // Exit 0 on an empty stdin is not cfx-script refusing a missing job, so it is
        // not proof that it loaded. Whatever it printed is all there is to say.
        let s = Scratch::new("helper-zero");
        let src = fake_helper(&s, "unpacked", "exit 0");
        let dest = s.join("cfx-script");
        let output = place_helper_if_it_starts(&src, &dest)
            .expect("place")
            .expect("exit 0 is not the refusal");
        assert!(output.contains("exit status: 0"), "{output}");
        assert!(!dest.exists());
    }

    /// A release's python folder beside `src`, as its zip unpacks: lib/ with a file that
    /// says which one it is.
    #[cfg(unix)]
    fn python_beside(src: &Path, which: &str) {
        let lib = src.parent().unwrap().join("python").join("lib");
        fs::create_dir_all(lib.join("python3.13")).expect("mkdir");
        fs::write(lib.join("which"), which).expect("write");
        fs::write(lib.join("python3.13").join("os.py"), "").expect("write");
    }

    /// A stand-in for a Linux cfx-script, which loads libpython from the python folder
    /// beside wherever it is run: it starts only when that folder is the new release's.
    #[cfg(unix)]
    const STARTS_BESIDE_NEW: &str = r#"[ "$(cat "$(dirname "$0")/python/lib/which" 2>/dev/null)" = new ] && exit 2
echo "cfx-script: error while loading shared libraries: libpython3.13.so.1.0: cannot open shared object file" >&2
exit 127"#;

    #[cfg(unix)]
    #[test]
    fn a_helper_with_a_python_folder_is_tried_beside_that_folder_and_placed_with_it() {
        let s = Scratch::new("helper-bundled");
        fs::create_dir_all(s.join("unpacked")).expect("mkdir");
        let src = fake_helper(&s, "unpacked/cfx-script", STARTS_BESIDE_NEW);
        python_beside(&src, "new");
        let bin = s.join("bin");
        let dest = bin.join("cfx-script");
        // What an earlier release left: its helper and its Python.
        fs::create_dir_all(bin.join("python").join("lib")).expect("mkdir");
        fs::write(bin.join("python").join("lib").join("which"), "old").expect("write");
        fs::write(bin.join("python").join("lib").join("stale"), "x").expect("write");
        fs::write(&dest, b"the-old-one").expect("write");

        let failed = place_helper_if_it_starts(&src, &dest).expect("place");
        assert_eq!(failed, None, "the staged helper ran beside the new folder");
        assert_eq!(
            fs::read(&dest).expect("read"),
            fs::read(&src).expect("read")
        );
        assert_eq!(mode_of(&dest), 0o755);
        let lib = bin.join("python").join("lib");
        assert_eq!(fs::read_to_string(lib.join("which")).expect("read"), "new");
        assert!(lib.join("python3.13").join("os.py").is_file());
        assert!(
            !lib.join("stale").exists(),
            "the old folder is replaced, not merged"
        );
        let mut left: Vec<_> = fs::read_dir(&bin)
            .expect("read")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            ["cfx-script", "python"],
            "nothing staged or old is left"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_helper_that_cannot_start_beside_its_python_leaves_the_old_helper_and_python() {
        let s = Scratch::new("helper-bundled-broken");
        fs::create_dir_all(s.join("unpacked")).expect("mkdir");
        let src = fake_helper(&s, "unpacked/cfx-script", STARTS_BESIDE_NEW);
        // A folder that is not what this helper needs.
        python_beside(&src, "broken");
        let bin = s.join("bin");
        let dest = bin.join("cfx-script");
        fs::create_dir_all(bin.join("python").join("lib")).expect("mkdir");
        fs::write(bin.join("python").join("lib").join("which"), "old").expect("write");
        fs::write(&dest, b"the-old-one").expect("write");

        let output = place_helper_if_it_starts(&src, &dest)
            .expect("place")
            .expect("it cannot start");
        assert!(output.contains("libpython3.13.so.1.0"), "{output}");
        assert_eq!(fs::read(&dest).expect("read"), b"the-old-one");
        assert_eq!(
            fs::read_to_string(bin.join("python").join("lib").join("which")).expect("read"),
            "old"
        );
        assert!(
            !bin.join("cfx-script.new.d").exists(),
            "nothing is left staged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_helper_with_a_python_folder_is_placed_where_none_was_before() {
        let s = Scratch::new("helper-bundled-fresh");
        fs::create_dir_all(s.join("unpacked")).expect("mkdir");
        let src = fake_helper(&s, "unpacked/cfx-script", STARTS_BESIDE_NEW);
        python_beside(&src, "new");
        let dest = s.join("bin").join("cfx-script");
        assert_eq!(place_helper_if_it_starts(&src, &dest).expect("place"), None);
        assert_eq!(
            fs::read_to_string(s.join("bin").join("python").join("lib").join("which"))
                .expect("read"),
            "new"
        );
    }

    // ---------------------------------------------------------------------------
    // Updating what the installer placed
    // ---------------------------------------------------------------------------

    /// Have this test's thread keep everything but the engine named in it in `dir`, as a
    /// package with that bin_dir would, and own nothing else.
    fn bin_dir_at(dir: &Path) {
        packaged(&format!(
            r#"{{"manager":"nix","owns":["ambulo"],"bin_dir":"{}"}}"#,
            dir.display()
        ));
    }

    /// A stand-in for a binary that prints `<name> <version>` for `--version`, as the CLI,
    /// the node and cfx-script do, and otherwise reads its stdin and exits 2.
    #[cfg(unix)]
    fn reports(dir: &Path, name: &str, version: &str) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        fs::write(
            &p,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then echo '{name} {version}'; exit 0; fi\n\
                 cat >/dev/null\nexit 2\n"
            ),
        )
        .expect("write");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    /// A cfx-script from before it took `--version`: it reads the flag as no job.
    #[cfg(unix)]
    fn old_helper(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(CFX_SCRIPT);
        fs::write(&p, "#!/bin/sh\ncat >/dev/null\nexit 2\n").expect("write");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    /// What a cfx-script built against Python 3.11 writes on a host without it.
    const NO_LIBPYTHON: &str = "/opt/crossfyre/bin/cfx-script.new: error while loading \
        shared libraries: libpython3.11.so.1.0: cannot open shared object file: No such \
        file or directory";

    #[cfg(unix)]
    #[tokio::test]
    async fn a_node_with_no_version_record_is_asked_for_its_version() {
        // The installer writes no node.version. The first update took that for an old
        // node, downloaded the same version again and reported it as updated.
        let s = Scratch::new("node-reports");
        bin_dir_at(&s.0);
        reports(&s.0, "node", "9.9.9");
        let replaced = download_node(&full_manifest("9.9.9"), true, false)
            .await
            .expect("nothing to download");
        assert!(
            !replaced,
            "a node that reports the release's version is current"
        );
        assert_eq!(installed_node_version().as_deref(), Some("9.9.9"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_update_right_after_the_installer_changes_nothing() {
        let s = Scratch::new("fresh-install");
        bin_dir_at(&s.0);
        reports(&s.0, "crossfyre", "9.9.9");
        reports(&s.0, "node", "9.9.9");
        reports(&s.0, CFX_SCRIPT, "9.9.9");
        let out = update_with(&full_manifest("9.9.9"), Some("self"), "9.9.9", false)
            .await
            .expect("runs");
        assert_eq!(
            out,
            Updated {
                current: 3,
                ..Updated::default()
            }
        );
        assert_eq!(out.summary(), "Everything is up to date.");
        assert_eq!(installed_cli_version(), "9.9.9");
    }

    #[cfg(unix)]
    #[test]
    fn a_helper_that_reports_no_version_is_not_taken_for_the_release() {
        let s = Scratch::new("old-helper");
        bin_dir_at(&s.0);
        old_helper(&s.0);
        assert_eq!(installed_helper_version(), None);
        fs::write(s.join("cfx-script.version"), "9.9.9\n").expect("write");
        assert_eq!(installed_helper_version().as_deref(), Some("9.9.9"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_user_who_may_not_write_the_bin_directory_is_told_it_needs_root() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root writes it regardless
        }
        let s = Scratch::new("read-only");
        bin_dir_at(&s.0);
        reports(&s.0, "node", "0.0.1");
        reports(&s.0, CFX_SCRIPT, "9.9.9");
        fs::set_permissions(&s.0, fs::Permissions::from_mode(0o555)).expect("lock");
        let out = update_with(&full_manifest("9.9.9"), Some("self"), "9.9.9", false).await;
        fs::set_permissions(&s.0, fs::Permissions::from_mode(0o755)).expect("unlock");
        let out = out.expect("runs");
        // Said before anything is downloaded, rather than a Permission denied after.
        assert_eq!(
            out,
            Updated {
                current: 2,
                need_rights: 1,
                ..Updated::default()
            }
        );
        assert!(!out.succeeded());
        assert_eq!(
            out.summary(),
            "Nothing was updated: 2 already current, 1 needs root."
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_update_installs_no_node_and_no_helper_that_are_not_there() {
        // A CLI from Homebrew or apt, on a host that never ran `node init`. The update
        // used to fetch a node into /opt/crossfyre/bin, which as the brew user failed with
        // Permission denied, and then said everything was up to date.
        let s = Scratch::new("cli-only");
        packaged(&format!(
            r#"{{"manager":"brew","owns":["crossfyre"],"bin_dir":"{}"}}"#,
            s.join("bin").display()
        ));
        let out = update_with(&full_manifest("9.9.9"), None, "9.9.8", false)
            .await
            .expect("runs");
        assert_eq!(
            out,
            Updated {
                current: 1,
                ..Updated::default()
            }
        );
        assert!(!s.join("bin").exists(), "nothing was put anywhere");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_helper_that_could_not_start_is_not_downloaded_again() {
        let s = Scratch::new("cannot-start");
        bin_dir_at(&s.0);
        reports(&s.0, "node", "9.9.9");
        let missing = NO_LIBPYTHON.replace("libpython3.11", "libpython0.0");
        fs::write(
            s.join("cfx-script.cannot-start"),
            format!("9.9.9\n{missing}\n"),
        )
        .expect("write");
        // There is no artifact to download in this test, so getting as far as a download
        // is an error rather than this.
        let outcome = install_cfx_script(&full_manifest("9.9.9"), false)
            .await
            .expect("decided without a download");
        let HelperOutcome::CannotStart { version, output } = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(version, "9.9.9");
        assert_eq!(output, missing);

        let out = update_with(&full_manifest("9.9.9"), Some("self"), "9.9.9", false)
            .await
            .expect("runs");
        assert_eq!(
            out,
            Updated {
                current: 2,
                skipped: 1,
                ..Updated::default()
            }
        );
        assert!(
            out.succeeded(),
            "a host without the Python is not a failure"
        );
        assert_eq!(
            out.summary(),
            "Nothing was updated: 2 already current, 1 skipped."
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_record_holds_back_only_its_own_version_and_only_while_the_library_is_missing() {
        let s = Scratch::new("record");
        bin_dir_at(&s.0);
        let missing = NO_LIBPYTHON.replace("libpython3.11", "libpython0.0");
        fs::write(cannot_start_file(), format!("1.0.0\n{missing}\n")).expect("write");
        assert_eq!(
            still_cannot_start("1.0.0").as_deref(),
            Some(missing.as_str())
        );
        assert_eq!(still_cannot_start("1.0.1"), None, "a new release is tried");

        // The library it lacked is here now: libc stands in for a libpython installed
        // since, and is on every Unix this runs on.
        let libc = if cfg!(target_os = "macos") {
            "libSystem.B.dylib"
        } else {
            "libc.so.6"
        };
        let found = NO_LIBPYTHON.replace("libpython3.11.so.1.0", libc);
        fs::write(cannot_start_file(), format!("1.0.0\n{found}\n")).expect("write");
        assert_eq!(still_cannot_start("1.0.0"), None);

        // A libpython3 it lacked is the one its python folder brings, which a CLI from
        // before the folder did not stage with it, so the release is tried again.
        let unstaged = NO_LIBPYTHON.replace("libpython3.11", "libpython3.99");
        fs::write(cannot_start_file(), format!("1.0.0\n{unstaged}\n")).expect("write");
        assert_eq!(still_cannot_start("1.0.0"), None);

        // Anything else holds until the release changes, or --force.
        fs::write(cannot_start_file(), "1.0.0\nKilled\n").expect("write");
        assert_eq!(still_cannot_start("1.0.0").as_deref(), Some("Killed"));
    }

    #[test]
    fn the_note_names_the_missing_library_and_the_package_with_it() {
        assert_eq!(missing_library(NO_LIBPYTHON), Some("libpython3.11.so.1.0"));
        assert_eq!(missing_library("Killed"), None);
        let note = cannot_start_note(NO_LIBPYTHON);
        assert!(
            note.starts_with("It needs libpython3.11.so.1.0, which this host does not have."),
            "{note}"
        );
        // The release's own Python is what is missing, not a package of the host's.
        assert!(note.contains("python folder beside it"), "{note}");
        assert!(note.contains("update --force"), "{note}");
        assert!(!note.contains("apt install"), "{note}");
        let other = cannot_start_note("Killed");
        assert!(other.contains("--force"), "{other}");
    }

    #[test]
    fn a_version_is_read_only_from_a_line_that_names_the_binary() {
        assert_eq!(
            parse_reported_version("node 0.1.48\n", "node").as_deref(),
            Some("0.1.48")
        );
        assert_eq!(parse_reported_version("crossfyre 0.1.38\n", "node"), None);
        assert_eq!(parse_reported_version("node\n", "node"), None);
        assert_eq!(
            parse_reported_version(r#"{"type":"log","job_id":""}"#, CFX_SCRIPT),
            None
        );
    }

    #[test]
    fn up_to_date_is_said_only_when_nothing_was_skipped_refused_or_failed() {
        let current = Updated {
            current: 3,
            ..Updated::default()
        };
        assert_eq!(current.summary(), "Everything is up to date.");
        for (out, said) in [
            (
                Updated {
                    current: 2,
                    skipped: 1,
                    ..Updated::default()
                },
                "Nothing was updated: 2 already current, 1 skipped.",
            ),
            (
                Updated {
                    current: 1,
                    failed: 2,
                    ..Updated::default()
                },
                "Nothing was updated: 1 already current, 2 failed.",
            ),
            (
                Updated {
                    changed: 1,
                    current: 1,
                    need_rights: 2,
                    ..Updated::default()
                },
                "Updated 1 component, 1 already current, 2 need root.",
            ),
        ] {
            assert_eq!(out.summary().replace("an elevated prompt", "root"), said);
        }
        assert!(current.succeeded());
        assert!(
            !Updated {
                failed: 1,
                ..Updated::default()
            }
            .succeeded()
        );
    }
}
