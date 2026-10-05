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

use super::config::{ext_bin_path, ext_file_name, get_bin_dir};
use super::service;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

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
fn ext_version_file(ext: &str) -> std::path::PathBuf {
    get_bin_dir().join(format!("{ext}.version"))
}

fn installed_ext_version(ext: &str) -> Option<String> {
    fs::read_to_string(ext_version_file(ext))
        .ok()
        .map(|s| s.trim().to_string())
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
    let comp = manifest
        .components
        .get(component)
        .ok_or_else(|| format!("component '{component}' not in release manifest"))?;
    let key = platform_key();
    let artifact = comp.artifacts.get(&key).ok_or_else(|| {
        format!("no '{component}' artifact for platform {key} in release manifest")
    })?;
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
/// installer checks for).
fn extract_zip(zip_path: &Path, extract_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(extract_dir)?;
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
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    // Appended, not `with_extension`, which REPLACES whatever follows the last dot:
    // a component placed as `cortex-0.1.2` would stage itself at `cortex-0.1.new` and
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
    if let Err(e) = fs::rename(&tmp_path, dest) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }
    Ok(())
}

/// Install one or more extensions ("mach" | "all"). Download + verify +
/// register the daemon service. The service is created but only started by
/// `install_and_start` (or an explicit `crossfyre service start`).
pub async fn install(extension: &str, force: bool) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = fetch_manifest().await?;
    for ext in super::resolve_extensions(extension)? {
        install_one(&manifest, ext, force, false).await?;
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

    if !quiet {
        title("Crossfyre extension install", ext);
    }

    if bin_path.exists() && !force {
        if !quiet {
            warn(&format!(
                "{ext} is already installed {}",
                dim("(use --force to reinstall)")
            ));
            end();
        }
        return Ok(());
    }

    let (comp, artifact) = resolve_artifact(manifest, ext)?;
    if !quiet {
        working(&format!("Downloading {ext} {}", dim(&comp.version)));
    }

    let tmp_dir = tempfile::tempdir().map_err(|e| format!("Failed to create temp dir: {e}"))?;
    let zip_path = tmp_dir.path().join(&artifact.file);
    download_verified(artifact, &zip_path).await?;

    if !quiet {
        working("Installing");
    }
    let extract_dir = tmp_dir.path().join("extracted");
    extract_zip(&zip_path, &extract_dir)?;

    let extracted_binary = extract_dir.join(ext_file_name(ext));
    if !extracted_binary.exists() {
        return Err(format!("Binary '{}' not found inside zip", ext_file_name(ext)).into());
    }

    // Stop the running daemon (if any) before replacing the binary - on
    // Windows the file is locked while the task runs. Best-effort, OS-aware.
    if bin_path.exists() {
        service::try_stop(ext);
    }

    place_binary(&extracted_binary, &bin_path)?;
    // Record the installed version so `update` can skip it next time (mirrors
    // node.version). Best-effort: a missing sidecar just triggers one reinstall.
    let _ = fs::write(ext_version_file(ext), &comp.version);
    if !quiet {
        ok(&format!("{ext} {} installed", comp.version));
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

    title("Crossfyre extension remove", ext);

    if !bin_path.exists() {
        warn(&format!("{ext} is not installed, nothing to remove"));
        end();
        return Ok(());
    }

    step(&format!("Stopping {ext} service"));
    let _ = service::stop(ext);
    step(&format!("Disabling {ext} service"));
    let _ = service::disable(ext);
    service::remove_service_file(ext)?;

    fs::remove_file(&bin_path)?;
    ok(&format!("{ext} removed"));
    end();
    Ok(())
}

/// `crossfyre update [self|<ext>|all]`. With no target: update self plus
/// every installed extension. Returns true if the crossfyre binary itself
/// was replaced (caller should restart).
pub async fn update(
    target: Option<&str>,
    current_version: &str,
    force: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let manifest = fetch_manifest().await?;
    let mut self_updated = false;

    let (do_self, exts): (bool, Vec<&str>) = match target {
        Some("self") => (true, vec![]),
        Some("all") | None => (true, installed_extensions()),
        Some(ext) => (false, super::resolve_extensions(ext)?),
    };

    use super::ui::*;
    println!();
    println!("  {BOLD}Crossfyre update{RESET}   {}", dim(origin_host()));
    println!();

    let mut changed = 0usize;
    let mut current = 0usize;

    // Suppress the per-service status lines from install/service ops - this
    // command renders its own summary. No `?` runs between the toggle pair, so
    // it is always restored before returning.
    service::set_quiet(true);

    // ── Extensions ────────────────────────────────────────────────────
    if !exts.is_empty() {
        println!("  {}", dim("Extensions"));
        for ext in &exts {
            let want = manifest_version(&manifest, ext);
            let have = installed_ext_version(ext);
            let up_to_date = ext_bin_path(ext).exists()
                && !want.is_empty()
                && have.as_deref() == Some(want.as_str());
            if up_to_date && !force {
                println!("{}", row(&check(), ext, &ver(&want), &dim("up to date")));
                current += 1;
                continue;
            }
            print!("    {} {ext:<10} {}", dot(), dim("updating…"));
            let _ = std::io::Write::flush(&mut std::io::stdout());
            match install_one(&manifest, ext, true, true).await {
                Ok(()) => {
                    let _ = service::start(ext);
                    let mid = match &have {
                        Some(old) if !old.is_empty() && *old != want => {
                            format!("{DIM}{old} \u{2192}{RESET} {want}")
                        }
                        _ => want.clone(),
                    };
                    println!(
                        "\r{}          ",
                        row(&check(), ext, &mid, &format!("{GREEN}updated{RESET}"))
                    );
                    changed += 1;
                }
                Err(e) => {
                    println!(
                        "\r{}          ",
                        row(
                            &bang(),
                            ext,
                            "",
                            &format!("{YELLOW}failed{RESET} {}", dim(&e.to_string()))
                        )
                    );
                }
            }
        }
        println!();
    }

    // ── Core: crossfyre CLI + node worker ─────────────────────────────
    if do_self {
        println!("  {}", dim("Core"));

        let want = manifest_version(&manifest, "crossfyre");
        if !want.is_empty() && want == current_version && !force {
            println!(
                "{}",
                row(&check(), "crossfyre", &ver(&want), &dim("up to date"))
            );
            current += 1;
        } else {
            print!("    {} {:<10} {}", dot(), "crossfyre", dim("updating…"));
            let _ = std::io::Write::flush(&mut std::io::stdout());
            match self_update(&manifest, current_version, true, force).await {
                Ok(true) => {
                    let mid = format!("{DIM}{current_version} \u{2192}{RESET} {want}");
                    println!(
                        "\r{}          ",
                        row(
                            &check(),
                            "crossfyre",
                            &mid,
                            &format!("{GREEN}updated{RESET}")
                        )
                    );
                    self_updated = true;
                    changed += 1;
                }
                Ok(false) => {
                    println!(
                        "\r{}          ",
                        row(&check(), "crossfyre", &ver(&want), &dim("up to date"))
                    );
                    current += 1;
                }
                Err(e) => {
                    println!(
                        "\r{}          ",
                        row(
                            &bang(),
                            "crossfyre",
                            "",
                            &format!("{YELLOW}failed{RESET} {}", dim(&e.to_string()))
                        )
                    );
                }
            }
        }

        // node worker (version tracked via the node.version sidecar).
        let nwant = manifest_version(&manifest, "node");
        let nhave = fs::read_to_string(get_bin_dir().join("node.version"))
            .ok()
            .map(|s| s.trim().to_string());
        let node_ok = get_bin_dir().join(ext_file_name("node")).exists()
            && !nwant.is_empty()
            && nhave.as_deref() == Some(nwant.as_str());
        if node_ok && !force {
            println!(
                "{}",
                row(&check(), "node", &ver(&nwant), &dim("up to date"))
            );
            current += 1;
        } else {
            print!("    {} {:<10} {}", dot(), "node", dim("updating…"));
            let _ = std::io::Write::flush(&mut std::io::stdout());
            match download_node(&manifest, true, force).await {
                Ok(true) => {
                    let mid = match &nhave {
                        Some(old) if !old.is_empty() && *old != nwant => {
                            format!("{DIM}{old} \u{2192}{RESET} {nwant}")
                        }
                        _ => nwant.clone(),
                    };
                    println!(
                        "\r{}          ",
                        row(&check(), "node", &mid, &format!("{GREEN}updated{RESET}"))
                    );
                    self_updated = true;
                    changed += 1;
                }
                Ok(false) => {
                    println!(
                        "\r{}          ",
                        row(&check(), "node", &ver(&nwant), &dim("up to date"))
                    );
                    current += 1;
                }
                Err(e) => {
                    println!(
                        "\r{}          ",
                        row(
                            &bang(),
                            "node",
                            "",
                            &format!("{YELLOW}skipped{RESET} {}", dim(&e.to_string()))
                        )
                    );
                }
            }
        }
        println!();
    }

    service::set_quiet(false);

    // ── Summary ───────────────────────────────────────────────────────
    if changed == 0 {
        println!("  {GREEN}Everything is up to date.{RESET}");
    } else {
        let plural = if changed == 1 { "" } else { "s" };
        println!(
            "  {BOLD}{GREEN}Updated {changed} component{plural}{RESET}{}",
            dim(&format!(", {current} already current"))
        );
    }
    println!();

    // Returns true when the node service should be restarted (CLI and/or node
    // worker binary changed).
    Ok(self_updated)
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
    place_binary(&extracted, &exe)?;

    // Keep the stable /opt path in sync too, in case the process was started
    // from somewhere else (e.g. a dev checkout).
    let stable = get_bin_dir().join(ext_file_name("crossfyre"));
    if stable != exe {
        let _ = place_binary(&extracted, &stable);
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

/// The crossfyre CLI version recorded on disk by `self_update`. Empty when never
/// recorded. Used by callers that cannot read the running CLI's env! version
/// (e.g. the node worker's dashboard-triggered self-update).
pub fn installed_cli_version() -> String {
    std::fs::read_to_string(get_bin_dir().join("crossfyre.version"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Copy the running binary to the stable install path
/// (`/opt/crossfyre/bin/crossfyre`) so OS services have a fixed ExecStart.
/// No-op when already running from there.
pub fn ensure_self_installed() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
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
/// already matches the manifest (tracked via a sidecar version file).
pub async fn download_node(
    manifest: &Manifest,
    quiet: bool,
    force: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    let (comp, artifact) = resolve_artifact(manifest, "node")?;
    let stable = get_bin_dir().join(ext_file_name("node"));
    let ver_file = get_bin_dir().join("node.version");
    let installed = std::fs::read_to_string(&ver_file)
        .ok()
        .map(|s| s.trim().to_string());
    if stable.exists() && installed.as_deref() == Some(comp.version.as_str()) && !force {
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

/// Ensure the `node` worker binary is present next to crossfyre. Prefers a
/// sibling of the running binary (fresh install / dev checkout) and falls back
/// to downloading it from the release manifest. Called during `node init` so
/// the service's ExecStart resolves.
pub async fn ensure_node_installed() -> Result<(), Box<dyn std::error::Error>> {
    let stable = get_bin_dir().join(ext_file_name("node"));
    if stable.exists() {
        return Ok(());
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(sib) = exe.parent().map(|d| d.join(ext_file_name("node")))
        && sib.exists()
        && sib != stable
    {
        place_binary(&sib, &stable)?;
        println!("[+] Installed node binary to {}", stable.display());
        return Ok(());
    }
    let manifest = fetch_manifest().await?;
    download_node(&manifest, false, false).await?;
    Ok(())
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
        let a = artifact("mach-linux-x86_64.zip", HELLO_SHA);
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
        let a = artifact("mach.zip", &HELLO_SHA.to_ascii_uppercase());
        assert!(verify_artifact_bytes(&a, b"hello").is_ok());
    }

    #[test]
    fn an_artifact_with_no_checksum_is_refused_rather_than_trusted() {
        // The failure mode this guards: `sha256` absent or blanked in the manifest
        // deserialises to an empty string, and a plain comparison against it means every
        // byte sequence is wrong, which is correct by accident. Being explicit also makes
        // the message say why instead of printing a mismatch against nothing.
        for blank in ["", "   "] {
            let a = artifact("mach.zip", blank);
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
        let a = artifact("mach.zip", empty_sha);
        assert!(verify_artifact_bytes(&a, b"").is_ok());
        let b = artifact("mach.zip", HELLO_SHA);
        assert!(verify_artifact_bytes(&b, b"").is_err());
    }

    #[test]
    fn a_manifest_missing_the_component_or_the_platform_says_which() {
        let key = platform_key();
        let m = manifest(&format!(
            r#"{{"components":{{"mach":{{"version":"0.0.14","artifacts":{{"{key}":{{"file":"f","sha256":"{HELLO_SHA}"}}}}}}}}}}"#
        ));
        assert!(resolve_artifact(&m, "mach").is_ok());

        let err = resolve_artifact(&m, "cortex")
            .expect_err("a component that is not there")
            .to_string();
        assert!(err.contains("cortex"), "got: {err}");

        // A component that exists with no artifact for this host is a different problem
        // from one that does not exist, and the two messages were worth separating.
        let other = manifest(
            r#"{"components":{"mach":{"version":"0.0.14","artifacts":{"solaris-sparc":{"file":"f","sha256":"x"}}}}}"#,
        );
        let err = resolve_artifact(&other, "mach")
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
            r#"{{"generated":"2026-10-03","components":{{"mach":{{"version":"0.0.14","channel":"stable","artifacts":{{"{key}":{{"file":"f","sha256":"{HELLO_SHA}","size":1234}}}}}}}}}}"#
        ));
        let (c, a) = resolve_artifact(&m, "mach").expect("unknown fields are ignored");
        assert_eq!(c.version, "0.0.14");
        assert_eq!(a.sha256, HELLO_SHA);
        assert_eq!(manifest_version(&m, "mach"), "0.0.14");
        assert_eq!(
            manifest_version(&m, "nope"),
            "",
            "an absent component reports no version rather than panicking"
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
        let src = s.join("mach-unpacked");
        fs::write(&src, b"#!/bin/sh\necho hi\n").expect("write src");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // What an artifact unpacked out of a zip normally looks like.
            fs::set_permissions(&src, fs::Permissions::from_mode(0o644)).expect("chmod src");
        }

        let dest = s.join("bin").join("mach");
        place_binary(&src, &dest).expect("place");
        assert!(dest.exists(), "the parent directory is created");
        #[cfg(unix)]
        assert_eq!(mode_of(&dest), 0o755, "an 0644 artifact is installed 0755");
        assert_eq!(
            fs::read(&dest).expect("read"),
            fs::read(&src).expect("read")
        );
        assert!(
            !s.join("bin").join("mach.new").exists(),
            "nothing is left staged next to the destination"
        );
    }

    #[test]
    fn placing_over_an_existing_binary_replaces_it() {
        let s = Scratch::new("replace");
        let dest = s.join("mach");
        fs::write(&dest, b"the-old-one").expect("write old");
        let src = s.join("new-mach");
        fs::write(&src, b"the-new-one").expect("write new");

        place_binary(&src, &dest).expect("place");
        assert_eq!(fs::read(&dest).expect("read"), b"the-new-one");
        #[cfg(unix)]
        assert_eq!(mode_of(&dest), 0o755);
    }

    #[test]
    fn staging_appends_to_the_name_instead_of_replacing_its_extension() {
        // `with_extension("new")` does not append, it REPLACES whatever follows the last
        // dot, so placing `cortex-0.1.2` used to stage through `cortex-0.1.new`. That is
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

        let bystander = s.join("cortex-0.1.new");
        fs::write(&bystander, b"somebody-elses-file").expect("write bystander");

        let dest = s.join("cortex-0.1.2");
        place_binary(&src, &dest).expect("place");

        assert!(dest.exists(), "the binary was placed");
        assert_eq!(
            fs::read(&bystander).ok().as_deref(),
            Some(&b"somebody-elses-file"[..]),
            "staging must not go through a path that belongs to another name"
        );
    }
}
