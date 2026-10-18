//! `crossfyre oast` self-host helpers.
//!
//! Stands up the operator's OWN OAST server on their OWN box + domain: writes an
//! `/etc/oast/oast.env` config, a `cf-oast.service` systemd unit that runs
//! `crossfyre oast serve`, obtains a wildcard TLS cert via ACME DNS-01 (the box is
//! authoritative for the delegated zone, so cf_oast answers its own challenge), and
//! prints the DNS-delegation records the operator must add at their DNS provider.
//!
//! The server itself is the `oast` crate, run in-process by `crossfyre oast serve`.
//! Self-hosting is Linux/systemd only (like the node service).

use crate::toolchain::ui::{hint, ok, step, warn};
use std::path::Path;
use std::process::Command;

const OAST_DIR: &str = "/etc/oast";
const ENV_PATH: &str = "/etc/oast/oast.env";
const ACME_TXT: &str = "/etc/oast/acme_txt";
const ACME_HOOK: &str = "/usr/local/bin/oast-acme-hook.sh";
const LEGO_PATH: &str = "/etc/oast/lego";
const UNIT_PATH: &str = "/etc/systemd/system/cf-oast.service";
const RENEW_SVC: &str = "/etc/systemd/system/cf-oast-renew.service";
const RENEW_TIMER: &str = "/etc/systemd/system/cf-oast-renew.timer";

pub struct SetupOpts {
    /// The delegated zone callbacks arrive on (e.g. "oob.acme.com").
    pub domain: String,
    /// This box's public IP (auto-detected when None).
    pub public_ip: Option<String>,
    /// ACME account email (required to obtain TLS).
    pub email: Option<String>,
    /// Skip the wildcard-cert step (HTTP/DNS only).
    pub no_tls: bool,
}

fn require_root() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("setting up an OAST server needs root - re-run with sudo".into());
    }
    Ok(())
}

fn cert_paths(domain: &str) -> (String, String) {
    // lego sanitises the wildcard "*" to "_".
    let base = format!("{LEGO_PATH}/certificates/_.{domain}");
    (format!("{base}.crt"), format!("{base}.key"))
}

/// Best-effort public IP detection via a couple of plain-text echo services.
async fn detect_public_ip() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .ok()?;
    for url in [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ] {
        if let Ok(resp) = client.get(url).send().await
            && let Ok(text) = resp.text().await
        {
            let ip = text.trim().to_string();
            if ip.split('.').count() == 4 && ip.split('.').all(|o| o.parse::<u8>().is_ok()) {
                return Some(ip);
            }
        }
    }
    None
}

/// Is the delegated zone live and pointing at this box? Resolve a random label and
/// check it comes back as `ip` (our DNS answers A for any name with our public IP).
async fn delegation_live(domain: &str, ip: &str) -> bool {
    let probe = format!("cfxprobe{}.{}:80", rand_label(), domain);
    match tokio::net::lookup_host(&probe).await {
        Ok(addrs) => addrs
            .filter_map(|a| match a.ip() {
                std::net::IpAddr::V4(v4) => Some(v4.to_string()),
                _ => None,
            })
            .any(|got| got == ip),
        Err(_) => false,
    }
}

fn rand_label() -> String {
    // A unique-enough probe label (no crypto needed): low bits of the clock.
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", (n as u64) & 0xffff_ffff)
}

/// Write /etc/oast/oast.env. Includes TLS vars only when the cert already exists.
fn write_env(domain: &str, ip: &str) -> std::io::Result<()> {
    let (crt, key) = cert_paths(domain);
    let mut body = format!(
        "# Crossfyre OAST server config (managed by `crossfyre oast setup`).\n\
         OAST_DOMAIN={domain}\n\
         OAST_PUBLIC_IP={ip}\n\
         OAST_ACME_TXT_FILE={ACME_TXT}\n"
    );
    if Path::new(&crt).exists() && Path::new(&key).exists() {
        body.push_str(&format!(
            "OAST_HTTPS_ADDR=0.0.0.0:443\nOAST_TLS_CERT={crt}\nOAST_TLS_KEY={key}\n"
        ));
    }
    std::fs::write(ENV_PATH, body)
}

fn write_unit(exe: &Path) -> std::io::Result<()> {
    let body = format!(
        "[Unit]\n\
         Description=Crossfyre OAST server\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         EnvironmentFile={ENV_PATH}\n\
         ExecStart={exe} oast serve\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe = exe.display(),
    );
    std::fs::write(UNIT_PATH, body)
}

fn systemctl(args: &[&str]) -> bool {
    Command::new("systemctl")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Print the DNS records the operator must add at their DNS provider to delegate
/// the zone to this box.
fn print_delegation(domain: &str, ip: &str) {
    let parent = domain.split_once('.').map(|x| x.1).unwrap_or(domain);
    let sub = domain.strip_suffix(&format!(".{parent}")).unwrap_or(domain);
    println!();
    step(&format!(
        "Delegate {domain} to this box. In your DNS provider for {parent}, add:"
    ));
    println!("      ns1.{domain}   A    {ip}          (glue: the box's authoritative NS)");
    println!("      {sub}          NS   ns1.{domain}   (delegate the zone to it)");
    println!();
    hint("Delegation can take a few minutes to propagate.");
}

pub async fn setup(exe: &Path, opts: SetupOpts) -> Result<(), Box<dyn std::error::Error>> {
    require_root()?;
    let domain = opts.domain.trim().trim_matches('.').to_ascii_lowercase();
    if domain.split('.').count() < 2 {
        return Err("--domain must be a delegated zone like oob.example.com".into());
    }

    step("Resolving this box's public IP...");
    let ip = match opts.public_ip {
        Some(x) => x.trim().to_string(),
        None => detect_public_ip()
            .await
            .ok_or("could not auto-detect public IP; pass --public-ip")?,
    };
    ok(&format!("Public IP: {ip}"));

    std::fs::create_dir_all(format!("{LEGO_PATH}/certificates"))?;
    let _ = std::fs::write(ACME_TXT, "");
    write_env(&domain, &ip)?;
    write_unit(exe)?;
    systemctl(&["daemon-reload"]);
    systemctl(&["enable", "cf-oast"]);
    systemctl(&["restart", "cf-oast"]);
    ok("cf-oast service installed and started (DNS :53, HTTP :80).");

    // TLS needs the delegation live so Let's Encrypt can read our challenge.
    let (crt, _key) = cert_paths(&domain);
    if Path::new(&crt).exists() {
        ok("Wildcard certificate already present; HTTPS is enabled.");
    } else if opts.no_tls {
        print_delegation(&domain, &ip);
        hint("Skipping TLS (--no-tls). Re-run without it once delegation is live to get HTTPS.");
    } else {
        step("Checking DNS delegation to this box...");
        if delegation_live(&domain, &ip).await {
            ok("Delegation is live.");
            match opts.email.as_deref() {
                Some(email) if !email.is_empty() => {
                    obtain_cert(&domain, email).await?;
                    write_env(&domain, &ip)?; // now includes TLS paths
                    systemctl(&["restart", "cf-oast"]);
                    install_renewal(email, &domain)?;
                    ok("Wildcard TLS obtained; HTTPS (443) is live; auto-renewal installed.");
                }
                _ => {
                    warn("Delegation is live but no --email given; cannot obtain TLS.");
                    hint("Re-run: crossfyre oast setup --domain <d> --email you@example.com");
                }
            }
        } else {
            warn("Delegation not visible yet.");
            print_delegation(&domain, &ip);
            hint("After adding the records, re-run this command to obtain wildcard TLS.");
        }
    }

    print_endpoint(&domain, Path::new(&crt).exists());
    Ok(())
}

/// Obtain a `*.<domain>` cert via lego DNS-01, serving the challenge from cf_oast.
async fn obtain_cert(domain: &str, email: &str) -> Result<(), Box<dyn std::error::Error>> {
    let lego = ensure_lego().await?;
    // The exec hook writes the DNS-01 TXT value to the file cf_oast serves.
    std::fs::write(
        ACME_HOOK,
        "#!/usr/bin/env bash\n\
         action=\"${1:-}\"; value=\"${3:-}\"\n\
         case \"$action\" in\n\
         \x20 present) printf '%s' \"$value\" > /etc/oast/acme_txt ;;\n\
         \x20 cleanup) : > /etc/oast/acme_txt ;;\n\
         esac\n",
    )?;
    let _ = Command::new("chmod").args(["755", ACME_HOOK]).status();

    step("Obtaining wildcard certificate (Let's Encrypt, DNS-01)...");
    let status = Command::new(lego)
        .env("EXEC_PATH", ACME_HOOK)
        .args([
            "--accept-tos",
            "--email",
            email,
            "--dns",
            "exec",
            "--dns.disable-cp",
            "--domains",
            &format!("*.{domain}"),
            "--path",
            LEGO_PATH,
            "run",
        ])
        .status()?;
    if !status.success() {
        return Err(
            "lego failed to obtain the certificate (check delegation + that port 53 is reachable)"
                .into(),
        );
    }
    Ok(())
}

/// Where `ensure_lego` installs lego when it is not already on PATH.
const LEGO_BIN: &str = "/usr/local/bin/lego";

/// The lego release `ensure_lego` installs.
const LEGO_VERSION: &str = "4.17.4";

/// One platform's lego release: the tarball on GitHub, the sha256 that lego's checksums
/// file gives for it, and the sha256 of the `lego` binary inside it.
#[derive(Debug, PartialEq, Eq)]
struct LegoRelease {
    url: String,
    tarball_sha256: &'static str,
    binary_sha256: &'static str,
}

/// The lego release for a CPU as `std::env::consts::ARCH` names it, or `None` for one
/// that no release is pinned for.
fn lego_release(arch: &str) -> Option<LegoRelease> {
    // The tarball sums are from lego_4.17.4_checksums.txt in the v4.17.4 release. The
    // binary sums are of the `lego` member of each tarball that matched it.
    let (goarch, tarball_sha256, binary_sha256) = match arch {
        "x86_64" => (
            "amd64",
            "f362d59ff5b6f92c599e3151dcf7b6ed853de05533be179b306ca40a7b67fb47",
            "bf38173345391d760dda7bf7360984df5719a7800876629bdd9ab980cf2aa63a",
        ),
        "aarch64" => (
            "arm64",
            "b79c3a2bad15c2359524a3372361377e09c15d0efe6a51223cdccf036d3f6e98",
            "bd868a3a354c8d6a44f08a10b2da707853d18a616f90f980f8ee63afd0994ae0",
        ),
        _ => return None,
    };
    Some(LegoRelease {
        url: format!(
            "https://github.com/go-acme/lego/releases/download/v{LEGO_VERSION}/\
             lego_v{LEGO_VERSION}_linux_{goarch}.tar.gz"
        ),
        tarball_sha256,
        binary_sha256,
    })
}

/// Ensure the `lego` ACME client is installed, downloading the pinned release if it is
/// not, and return the program to run.
///
/// This runs as root. It used to download into /tmp under fixed names, extract there and
/// install what it found, so a local user who planted /tmp/lego.tgz or /tmp/lego first
/// had root install their file, and it took the amd64 build on every CPU. The release
/// is now chosen for this CPU, held in memory, checked against its pinned sha256, and
/// the binary taken out of it is checked again before it is written, and once more
/// where it was written.
async fn ensure_lego() -> Result<String, Box<dyn std::error::Error>> {
    if Command::new("lego")
        .arg("--version")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Ok("lego".to_string());
    }
    let arch = std::env::consts::ARCH;
    let release = lego_release(arch).ok_or_else(|| {
        format!("no lego release is pinned for {arch}; install lego yourself and re-run")
    })?;
    step(&format!("Installing lego {LEGO_VERSION} (ACME client)..."));
    let resp = reqwest::get(&release.url)
        .await
        .map_err(|e| format!("could not download lego ({}): {e}", release.url))?;
    if !resp.status().is_success() {
        return Err(format!(
            "could not download lego: {} returned {}",
            release.url,
            resp.status()
        )
        .into());
    }
    let tarball = resp.bytes().await?;
    let binary = lego_from_tarball(&tarball, release.tarball_sha256, release.binary_sha256)?;
    install_checked(&binary, Path::new(LEGO_BIN), release.binary_sha256)?;
    ok(&format!("lego {LEGO_VERSION} installed to {LEGO_BIN}"));
    Ok(LEGO_BIN.to_string())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Refuse `bytes` unless their sha256 is `want`.
fn check_sha256(bytes: &[u8], want: &str, what: &str) -> Result<(), String> {
    let got = sha256_hex(bytes);
    if !got.eq_ignore_ascii_case(want) {
        return Err(format!(
            "{what} has sha256 {got}, not the pinned {want}; refusing to install it"
        ));
    }
    Ok(())
}

/// The `lego` binary from a release tarball, once the tarball and then the binary have
/// each matched their pinned sha256.
fn lego_from_tarball(
    tarball: &[u8],
    tarball_sha256: &str,
    binary_sha256: &str,
) -> Result<Vec<u8>, String> {
    check_sha256(tarball, tarball_sha256, "the lego tarball")?;
    let mut tar = Vec::new();
    std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(tarball), &mut tar)
        .map_err(|e| format!("the lego tarball does not decompress: {e}"))?;
    let binary = tar_member(&tar, "lego")?;
    check_sha256(&binary, binary_sha256, "the lego binary")?;
    Ok(binary)
}

/// The contents of the regular file `name` in a ustar archive, at its top level.
fn tar_member(tar: &[u8], name: &str) -> Result<Vec<u8>, String> {
    // A NUL-terminated field of a header, or all of it when it fills the field.
    fn field(header: &[u8], range: std::ops::Range<usize>) -> &[u8] {
        let f = &header[range];
        &f[..f.iter().position(|b| *b == 0).unwrap_or(f.len())]
    }
    let mut at = 0;
    while at + 512 <= tar.len() {
        let header = &tar[at..at + 512];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let size_field = String::from_utf8_lossy(field(header, 124..136))
            .trim()
            .to_string();
        let size = usize::from_str_radix(&size_field, 8)
            .map_err(|_| format!("a tar header gives its size as {size_field:?}"))?;
        let mut entry = field(header, 0..100).to_vec();
        let prefix = field(header, 345..500);
        if &header[257..262] == b"ustar" && !prefix.is_empty() {
            entry = [prefix, b"/", &entry].concat();
        }
        let body = at + 512;
        let end = body
            .checked_add(size)
            .filter(|end| *end <= tar.len())
            .ok_or("the archive ends inside a file")?;
        let regular = matches!(header[156], b'0' | 0);
        if regular && entry.strip_prefix(b"./").unwrap_or(&entry) == name.as_bytes() {
            return Ok(tar[body..end].to_vec());
        }
        at = body + size.div_ceil(512) * 512;
    }
    Err(format!("{name} is not in the archive"))
}

/// Write `bytes` to `dest` as an executable, through a file beside it that is created
/// fresh and renamed over `dest`, then read `dest` back and refuse it, removing it,
/// unless it hashes to `sha256`.
fn install_checked(
    bytes: &[u8],
    dest: &Path,
    sha256: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let staged = dest.with_file_name(format!(
        "{}.new",
        dest.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default()
    ));
    let _ = std::fs::remove_file(&staged);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o755);
    let mut file = options.open(&staged)?;
    let written = file.write_all(bytes).and_then(|_| file.sync_all());
    drop(file);
    if let Err(e) = written.and_then(|_| std::fs::rename(&staged, dest)) {
        let _ = std::fs::remove_file(&staged);
        return Err(e.into());
    }
    if let Err(e) = check_sha256(&std::fs::read(dest)?, sha256, &dest.display().to_string()) {
        let _ = std::fs::remove_file(dest);
        return Err(e.into());
    }
    Ok(())
}

/// A daily renewal timer that renews < 30 days out and restarts cf-oast on a roll.
fn install_renewal(email: &str, domain: &str) -> Result<(), Box<dyn std::error::Error>> {
    let renew_sh = "/usr/local/bin/oast-renew.sh";
    std::fs::write(
        renew_sh,
        format!(
            "#!/usr/bin/env bash\nset -e\nEXEC_PATH={ACME_HOOK} \\\n\
             lego --accept-tos --email {email} --dns exec --dns.disable-cp \\\n\
             \x20 --domains '*.{domain}' --path {LEGO_PATH} \\\n\
             \x20 renew --days 30 --renew-hook 'systemctl restart cf-oast'\n"
        ),
    )?;
    let _ = Command::new("chmod").args(["755", renew_sh]).status();
    std::fs::write(
        RENEW_SVC,
        "[Unit]\nDescription=Renew Crossfyre OAST wildcard TLS certificate\nAfter=network-online.target\n\
         [Service]\nType=oneshot\nExecStart=/usr/local/bin/oast-renew.sh\n",
    )?;
    std::fs::write(
        RENEW_TIMER,
        "[Unit]\nDescription=Daily Crossfyre OAST cert renewal check\n\
         [Timer]\nOnCalendar=*-*-* 03:30:00\nRandomizedDelaySec=1h\nPersistent=true\n\
         [Install]\nWantedBy=timers.target\n",
    )?;
    systemctl(&["daemon-reload"]);
    systemctl(&["enable", "--now", "cf-oast-renew.timer"]);
    Ok(())
}

/// Print the values the operator pastes into the dashboard (Arsenal -> OAST endpoints).
fn print_endpoint(domain: &str, tls: bool) {
    println!();
    if tls {
        ok(
            "Your OAST endpoint is ready. Add it in the dashboard (OAST Endpoints -> Add endpoint):",
        );
        println!("      Callback domain :  {domain}");
        println!("      Poll API URL    :  https://api.{domain}");
    } else {
        warn(
            "HTTPS is not enabled yet, so the endpoint is not usable by scans until TLS is obtained.",
        );
        hint("Complete DNS delegation, then re-run `crossfyre oast setup` to finish TLS.");
    }
}

/// Show local OAST server status.
pub fn status() -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new(UNIT_PATH).exists() {
        warn("No OAST server configured on this host.");
        hint("Run `crossfyre oast setup --domain oob.example.com` to stand one up.");
        return Ok(());
    }
    let active = Command::new("systemctl")
        .args(["is-active", "cf-oast"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    if active == "active" {
        ok("cf-oast: active");
    } else {
        warn(&format!("cf-oast: {active}"));
    }
    if let Ok(env) = std::fs::read_to_string(ENV_PATH) {
        for line in env.lines() {
            if let Some(d) = line.strip_prefix("OAST_DOMAIN=") {
                step(&format!("domain: {d}"));
            }
            if line.starts_with("OAST_TLS_CERT=") {
                ok("TLS: enabled (HTTPS on 443)");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_cpu_gets_its_own_lego_build_and_others_get_none() {
        let amd = lego_release("x86_64").expect("x86_64");
        assert!(
            amd.url
                .ends_with("/v4.17.4/lego_v4.17.4_linux_amd64.tar.gz"),
            "{}",
            amd.url
        );
        let arm = lego_release("aarch64").expect("aarch64");
        assert!(
            arm.url
                .ends_with("/v4.17.4/lego_v4.17.4_linux_arm64.tar.gz"),
            "{}",
            arm.url
        );
        assert_ne!(amd.tarball_sha256, arm.tarball_sha256);
        assert_ne!(amd.binary_sha256, arm.binary_sha256);
        for other in ["x86", "riscv64", "arm", "powerpc64"] {
            assert_eq!(lego_release(other), None, "{other}");
        }
    }

    /// A ustar header for a regular file.
    fn header(name: &str, size: usize) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000755");
        h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        // The checksum is computed over the header with its own field as spaces.
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|b| *b as u32).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        h
    }

    fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, body) in files {
            out.extend(header(name, body.len()));
            out.extend_from_slice(body);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.extend([0u8; 1024]);
        out
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(bytes).expect("gzip");
        enc.finish().expect("gzip")
    }

    /// An archive shaped like lego's: two text files, then the binary.
    fn release_like(binary: &[u8]) -> Vec<u8> {
        gzip(&tar(&[
            ("CHANGELOG.md", b"changes"),
            ("LICENSE", b"MIT"),
            ("lego", binary),
        ]))
    }

    #[test]
    fn the_binary_comes_out_of_a_tarball_whose_sums_match() {
        let tarball = release_like(b"the lego binary");
        let got = lego_from_tarball(
            &tarball,
            &sha256_hex(&tarball),
            &sha256_hex(b"the lego binary"),
        )
        .expect("matching sums");
        assert_eq!(got, b"the lego binary");
    }

    #[test]
    fn a_tarball_that_is_not_the_pinned_one_is_refused() {
        let tarball = release_like(b"the lego binary");
        let pinned = sha256_hex(&tarball);
        let mut other = tarball.clone();
        let last = other.len() - 1;
        other[last] ^= 1;
        let err = lego_from_tarball(&other, &pinned, &sha256_hex(b"the lego binary"))
            .expect_err("one byte changed");
        assert!(
            err.contains("the lego tarball") && err.contains("refusing"),
            "{err}"
        );
    }

    #[test]
    fn a_binary_that_is_not_the_pinned_one_is_refused_even_from_a_matching_tarball() {
        let tarball = release_like(b"something else");
        let err = lego_from_tarball(
            &tarball,
            &sha256_hex(&tarball),
            &sha256_hex(b"the lego binary"),
        )
        .expect_err("wrong binary");
        assert!(err.contains("the lego binary"), "{err}");
    }

    #[test]
    fn only_a_regular_file_at_the_top_counts_as_the_member() {
        let archive = tar(&[("docs/lego", b"not this"), ("./lego", b"this")]);
        assert_eq!(tar_member(&archive, "lego").expect("found"), b"this");
        let err = tar_member(&tar(&[("LICENSE", b"MIT")]), "lego").expect_err("absent");
        assert!(err.contains("not in the archive"), "{err}");
        let mut cut = tar(&[("lego", &[7u8; 2000])]);
        cut.truncate(1024);
        assert!(tar_member(&cut, "lego").is_err(), "an archive cut short");
    }

    #[cfg(unix)]
    #[test]
    fn the_installed_file_is_checked_where_it_was_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("scratch");
        let dest = dir.path().join("lego");
        install_checked(b"binary", &dest, &sha256_hex(b"binary")).expect("installs");
        assert_eq!(std::fs::read(&dest).expect("read"), b"binary");
        let mode = std::fs::metadata(&dest).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
        assert!(
            !dir.path().join("lego.new").exists(),
            "nothing is left staged"
        );

        let err = install_checked(b"binary", &dest, &sha256_hex(b"other")).expect_err("mismatch");
        assert!(err.to_string().contains("refusing"), "{err}");
        assert!(!dest.exists(), "a file that does not match is removed");
    }
}
