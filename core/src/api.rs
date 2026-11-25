//! Calls to the Crossfyre API.
//!
//! Every call this program makes to the API goes through a client made here, which names
//! the program and its version first in its User-Agent: `crossfyre/0.1.45
//! (linux-x86_64)` from the CLI, `crossfyre-node/0.1.55 (linux-x86_64)` from the node
//! worker. The website holds a minimum version for each and refuses an older one on
//! every /api/v1 route with 426 and a message saying how to update. [`SendApi`] prints
//! that message and stops, so an install that is too old says so instead of failing in
//! some other way.
//!
//! These clients are for the API alone. A request to anything else, a scan target above
//! all, goes through a client of its own, which carries none of this.

use std::future::Future;
use std::sync::OnceLock;

/// What this program calls itself to the API, set once by its main.
static CLIENT: OnceLock<String> = OnceLock::new();

/// Name this program in the User-Agent of every API call: `crossfyre` for the CLI and
/// `crossfyre-node` for the node worker, each with its own version, not this crate's.
/// Called first thing in main. A later call changes nothing.
pub fn name_client(name: &str, version: &str) {
    let _ = CLIENT.set(agent(name, version));
}

fn agent(name: &str, version: &str) -> String {
    format!(
        "{name}/{version} ({}-{})",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// The User-Agent of an API call. Before [`name_client`], as in this crate's tests, it
/// names this crate, which the server holds to no minimum.
pub fn user_agent() -> String {
    CLIENT
        .get()
        .cloned()
        .unwrap_or_else(|| agent("cfx_core", env!("CARGO_PKG_VERSION")))
}

/// A client for the API.
pub fn client() -> reqwest::Client {
    builder()
        .build()
        // Only fails where `Client::new()` would panic too: no TLS backend.
        .expect("the API client builds")
}

/// The builder [`client`] finishes, for a call that needs more set on it.
///
/// It follows no redirect. Calls carry the account's key, a password or a pairing token
/// in their bodies, and a 307 or 308 would have that body sent on to wherever the answer
/// points, another host or plain http included. The API answers no call with one.
pub fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent(user_agent())
        .redirect(reqwest::redirect::Policy::none())
}

/// Sending a request to the API, in place of `send`.
pub trait SendApi {
    /// Send the request. A 426 means the server no longer supports this version: its
    /// message is printed and the program exits 1.
    fn send_api(self) -> impl Future<Output = reqwest::Result<reqwest::Response>> + Send;
}

impl SendApi for reqwest::RequestBuilder {
    async fn send_api(self) -> reqwest::Result<reqwest::Response> {
        let resp = self.send().await?;
        if resp.status() == reqwest::StatusCode::UPGRADE_REQUIRED {
            let body = resp.text().await.unwrap_or_default();
            eprintln!("{}", refusal(&body));
            std::process::exit(1);
        }
        Ok(resp)
    }
}

/// What to print for a 426: the server's message, or a line of our own when it sent none.
fn refusal(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["message"].as_str().map(str::trim).map(str::to_string))
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| {
            "The server no longer supports this version. Run crossfyre update.".to_string()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};

    #[test]
    fn a_client_names_itself_and_its_version_first_then_the_platform() {
        let ua = agent("crossfyre-node", "0.1.55");
        let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        assert_eq!(ua, format!("crossfyre-node/0.1.55 ({platform})"));
    }

    /// The website reads the first product token, as `crossfyre/0.1.45`.
    #[tokio::test]
    async fn an_api_call_carries_the_user_agent() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut ua = String::new();
            let mut reader = BufReader::new(conn.try_clone().unwrap());
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("user-agent:") {
                    ua = v.trim().to_string();
                }
            }
            let _ = conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
            ua
        });
        client()
            .get(format!("http://127.0.0.1:{port}/api/v1"))
            .send_api()
            .await
            .unwrap();
        assert_eq!(seen.join().unwrap(), user_agent().to_ascii_lowercase());
    }

    /// A loopback listener that answers every request with `reply` and keeps what it read,
    /// head and body.
    fn answering(reply: String) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = std::sync::Arc::clone(&seen);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut conn) = conn else { return };
                let mut reader = BufReader::new(conn.try_clone().unwrap());
                let mut req = String::new();
                let mut len = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    req.push_str(&line);
                    if line == "\r\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; len];
                let _ = std::io::Read::read_exact(&mut reader, &mut body);
                req.push_str(&String::from_utf8_lossy(&body));
                log.lock().unwrap().push(req);
                let _ = conn.write_all(reply.as_bytes());
            }
        });
        (port, seen)
    }

    /// A call carries the account's key or password in its body, and a 307 or 308 would
    /// have the client send that body on to wherever the answer points. The API answers
    /// no call with a redirect, so none is followed.
    #[tokio::test]
    async fn an_api_call_does_not_follow_a_redirect() {
        let (elsewhere, seen) =
            answering("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n".to_string());
        for status in [
            "307 Temporary Redirect",
            "308 Permanent Redirect",
            "302 Found",
        ] {
            let (api, _) = answering(format!(
                "HTTP/1.1 {status}\r\nlocation: http://127.0.0.1:{elsewhere}/collect\r\n\
                 content-length: 0\r\nconnection: close\r\n\r\n"
            ));
            let resp = client()
                .post(format!("http://127.0.0.1:{api}/api/v1/authorize-node"))
                .json(&serde_json::json!({ "api_key": "cfk_saved_key" }))
                .send()
                .await
                .unwrap();
            assert!(
                resp.status().is_redirection(),
                "{status}: {}",
                resp.status()
            );
        }
        assert!(
            seen.lock().unwrap().is_empty(),
            "a redirect was followed: {:?}",
            seen.lock().unwrap()
        );
    }

    #[test]
    fn a_refusal_prints_the_server_s_message() {
        let body = r#"{"status":426,"message":"This crossfyre is 0.1.44, and the server needs 0.1.45 or newer. Run crossfyre update.","errors":[],"data":{}}"#;
        assert_eq!(
            refusal(body),
            "This crossfyre is 0.1.44, and the server needs 0.1.45 or newer. Run crossfyre update."
        );
    }

    #[test]
    fn a_refusal_without_a_message_still_says_to_update() {
        for body in [
            "",
            "upgrade required",
            r#"{"status":426}"#,
            r#"{"message":"  "}"#,
        ] {
            assert_eq!(
                refusal(body),
                "The server no longer supports this version. Run crossfyre update.",
                "{body:?}"
            );
        }
    }
}
