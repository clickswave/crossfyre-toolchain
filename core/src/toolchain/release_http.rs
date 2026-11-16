//! The HTTP client for the release origin (`install::BASE_URL`): the manifest, its
//! signature and the release zips.
//!
//! Each request carries a User-Agent of the form
//! `crossfyre-cli/<version> (<platform>; <purpose>)`, such as
//! `crossfyre-cli/0.1.42 (linux-x86_64; update)`: the CLI's version, the platform key
//! the manifest is read with, and whether the request installs a component, replaces
//! an installed one, or only checks what the release holds. Nothing else is sent.

use std::sync::OnceLock;

/// Why a request to the release origin is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A component that is not installed yet.
    Install,
    /// A component that is installed and is being replaced.
    Update,
    /// The manifest, its signature, or `crossfyre doctor`'s reachability check.
    Check,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Install => "install",
            Purpose::Update => "update",
            Purpose::Check => "check",
        }
    }

    /// `Update` when a copy is already in place, `Install` when there is none.
    pub fn replacing(installed: bool) -> Self {
        if installed {
            Purpose::Update
        } else {
            Purpose::Install
        }
    }
}

static VERSION: OnceLock<String> = OnceLock::new();

/// Record the CLI's version for the User-Agent. The crossfyre binary calls this at start
/// with its own `env!("CARGO_PKG_VERSION")`: in this crate env! is cfx_core's version.
/// A later call is ignored.
pub fn set_version(version: &str) {
    let _ = VERSION.set(version.to_string());
}

/// The version set at start, or, in a process that set none (the node worker), the
/// version of the CLI in the bin directory.
fn version() -> &'static str {
    VERSION.get_or_init(|| {
        let v = super::install::installed_cli_version();
        if v.is_empty() { "unknown".into() } else { v }
    })
}

/// The User-Agent for `version` on `platform` making a request for `purpose`.
pub fn agent_for(version: &str, platform: &str, purpose: Purpose) -> String {
    format!("crossfyre-cli/{version} ({platform}; {})", purpose.as_str())
}

/// The User-Agent this process sends for `purpose`.
pub fn agent(purpose: Purpose) -> String {
    agent_for(version(), &super::install::platform_key(), purpose)
}

/// A client for one request to the release origin. Built as `reqwest::Client::new()`
/// builds one, which is what `reqwest::get` used, with the User-Agent set.
pub fn http_client(purpose: Purpose) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(agent(purpose))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SHAPE: &str = r"^crossfyre-cli/[0-9A-Za-z.+-]+ \((linux|darwin|windows)-(x86_64|aarch64); (install|update|check)\)$";

    #[test]
    fn the_agent_has_the_name_version_platform_and_purpose_and_nothing_else() {
        let shape = regex::Regex::new(SHAPE).unwrap();
        for (purpose, word) in [
            (Purpose::Install, "install"),
            (Purpose::Update, "update"),
            (Purpose::Check, "check"),
        ] {
            let a = agent_for("0.1.42", "linux-x86_64", purpose);
            assert_eq!(a, format!("crossfyre-cli/0.1.42 (linux-x86_64; {word})"));
            assert!(shape.is_match(&a), "{a}");
        }
        assert_eq!(
            agent_for("0.1.42", "darwin-aarch64", Purpose::Update),
            "crossfyre-cli/0.1.42 (darwin-aarch64; update)"
        );
    }

    #[test]
    fn a_component_already_in_place_is_an_update() {
        assert_eq!(Purpose::replacing(true), Purpose::Update);
        assert_eq!(Purpose::replacing(false), Purpose::Install);
    }

    /// A loopback origin that answers every request with `reply` and keeps the
    /// User-Agent of each.
    async fn origin(reply: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let agents = Arc::new(Mutex::new(Vec::new()));
        let seen = agents.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let agent = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.eq_ignore_ascii_case("user-agent")
                                .then(|| v.trim().to_string())
                        })
                        .unwrap_or_default();
                    seen.lock().unwrap().push(agent);
                    let _ = s.write_all(reply.as_bytes()).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        (base, agents)
    }

    #[tokio::test]
    async fn a_manifest_fetch_names_the_client_and_says_it_is_a_check() {
        set_version("9.9.9");
        let (base, agents) = origin(
            "HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n{\"components\":{}}",
        )
        .await;
        // A build that requires a signed manifest also asks for the signature, which
        // this origin does not have; the manifest request is the one looked at.
        let _ = super::super::install::fetch_manifest_from(&base).await;
        let agents = agents.lock().unwrap().clone();
        let first = agents.first().expect("the manifest was requested");
        assert_eq!(*first, agent(Purpose::Check));
        assert!(first.ends_with("; check)"), "{first}");
        assert!(regex::Regex::new(SHAPE).unwrap().is_match(first), "{first}");
        assert!(
            agents.iter().all(|a| *a == agent(Purpose::Check)),
            "{agents:?}"
        );
    }
}
