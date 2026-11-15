//! A client that carries a saved credential or an attribution token must not
//! follow a redirect to another origin. Both backends drop only a fixed handful of
//! header names on a host change, so a custom auth header (`x-api-key` and the
//! like) would reach the redirect target, and the reqwest backend restores the
//! original request's headers on every hop, so a second hop on the other host got
//! `Authorization` and `Cookie` back as well.
//!
//! Each test runs two loopback listeners. They differ in port, and a port is part
//! of an origin, so a hop from one to the other is a hop to another origin.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use transport::{
    AuthSpec, ClientConfig, Egress, HeaderMap, HeaderName, HeaderValue, Redirect, ScanClient,
    build_client, build_scan_client,
};

/// What a listener saw: the request head of every request, lowercased.
type Seen = Arc<Mutex<Vec<String>>>;

/// A loopback listener that answers every request with `reply(path)` and keeps the
/// request heads it read.
fn listener(reply: impl Fn(&str) -> String + Send + 'static) -> (u16, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let mut head = Vec::new();
            let mut buf = [0u8; 4096];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
            let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
            log.lock().unwrap().push(head);
            let _ = s.write_all(reply(&path).as_bytes());
        }
    });
    (port, seen)
}

fn ok() -> String {
    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".into()
}

fn found(location: &str) -> String {
    format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n"
    )
}

/// A host that sends its first path on to its second, then answers.
fn other_origin() -> (u16, Seen) {
    listener(|path| {
        if path == "/first" {
            found("/second")
        } else {
            ok()
        }
    })
}

/// The scanned host, which sends everything to `to`.
fn redirecting_to(to: String) -> (u16, Seen) {
    listener(move |_| found(&to))
}

fn saved_auth() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        HeaderName::from_static("authorization"),
        HeaderValue::from_static("Bearer saved-token"),
    );
    h.insert(
        HeaderName::from_static("cookie"),
        HeaderValue::from_static("session=saved-cookie"),
    );
    h.insert(
        HeaderName::from_static("x-api-key"),
        HeaderValue::from_static("saved-api-key"),
    );
    h
}

fn config(extra_headers: HeaderMap) -> ClientConfig {
    ClientConfig {
        timeout: Some(Duration::from_secs(5)),
        redirect: Redirect::Limited(5),
        extra_headers,
        ..Default::default()
    }
}

fn assert_nothing_reached(seen: &Seen) {
    let seen = seen.lock().unwrap();
    assert!(
        seen.is_empty(),
        "the other origin was sent {} request(s), carrying: {:?}",
        seen.len(),
        seen.iter()
            .map(|h| h
                .lines()
                .filter(|l| l.contains("saved-"))
                .map(|l| l.split(':').next().unwrap_or(""))
                .collect::<Vec<_>>())
            .collect::<Vec<_>>(),
    );
}

#[tokio::test]
async fn saved_headers_stop_at_a_redirect_to_another_origin() {
    let (b, b_seen) = other_origin();
    let (a, a_seen) = redirecting_to(format!("http://127.0.0.1:{b}/first"));
    let client = build_client(config(saved_auth()), &Egress::Direct).unwrap();

    let r = client
        .get(format!("http://127.0.0.1:{a}/out"))
        .send()
        .await
        .unwrap();

    // The caller gets the redirect itself, as with `Redirect::None`.
    assert_nothing_reached(&b_seen);
    assert_eq!(r.status().as_u16(), 302);
    assert_eq!(a_seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_scan_client_with_a_credential_stops_at_another_origin() {
    let (b, b_seen) = other_origin();
    let (a, _) = redirecting_to(format!("http://127.0.0.1:{b}/first"));
    let auth = AuthSpec {
        headers: [("X-Api-Key".to_string(), "saved-api-key".to_string())].into(),
        cookies: "session=saved-cookie".into(),
    };
    let client = build_scan_client(
        ScanClient {
            auth: Some(&auth),
            user_agent: "Crossfyre-Test/1.0",
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        },
        &Egress::Direct,
    )
    .unwrap();

    let r = client
        .get(format!("http://127.0.0.1:{a}/out"))
        .send()
        .await
        .unwrap();

    assert_nothing_reached(&b_seen);
    assert_eq!(r.status().as_u16(), 302);
}

#[tokio::test]
async fn an_attribution_token_stops_at_another_origin() {
    let (b, b_seen) = other_origin();
    let (a, _) = redirecting_to(format!("http://127.0.0.1:{b}/first"));
    let client = build_scan_client(
        ScanClient {
            attribution_token: Some("saved-attribution"),
            user_agent: "Crossfyre-Test/1.0",
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        },
        &Egress::Direct,
    )
    .unwrap();

    let r = client
        .get(format!("http://127.0.0.1:{a}/out"))
        .send()
        .await
        .unwrap();

    assert_nothing_reached(&b_seen);
    assert_eq!(r.status().as_u16(), 302);
}

#[tokio::test]
async fn headers_set_per_request_stop_when_the_client_is_asked_to() {
    // A recorded flow carries its headers on each request rather than on the
    // client, so the client has to be told.
    let (b, b_seen) = other_origin();
    let (a, _) = redirecting_to(format!("http://127.0.0.1:{b}/first"));
    let client = build_client(
        ClientConfig {
            same_origin_redirects: true,
            ..config(HeaderMap::new())
        },
        &Egress::Direct,
    )
    .unwrap();

    let r = client
        .get(format!("http://127.0.0.1:{a}/out"))
        .header("x-api-key", "saved-api-key")
        .send()
        .await
        .unwrap();

    assert_nothing_reached(&b_seen);
    assert_eq!(r.status().as_u16(), 302);
}

#[tokio::test]
async fn saved_headers_still_follow_a_redirect_on_the_same_origin() {
    let (a, a_seen) = listener(|path| {
        if path == "/start" {
            found("/landing")
        } else {
            ok()
        }
    });
    let client = build_client(config(saved_auth()), &Egress::Direct).unwrap();

    let r = client
        .get(format!("http://127.0.0.1:{a}/start"))
        .send()
        .await
        .unwrap();

    assert_eq!(r.status().as_u16(), 200);
    let seen = a_seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen[1].contains("x-api-key: saved-api-key"), "{}", seen[1]);
}

#[tokio::test]
async fn a_client_with_nothing_to_leak_still_follows_another_origin() {
    let (b, b_seen) = other_origin();
    let (a, _) = redirecting_to(format!("http://127.0.0.1:{b}/first"));
    let client = build_client(config(HeaderMap::new()), &Egress::Direct).unwrap();

    let r = client
        .get(format!("http://127.0.0.1:{a}/out"))
        .send()
        .await
        .unwrap();

    assert_eq!(r.status().as_u16(), 200);
    assert_eq!(b_seen.lock().unwrap().len(), 2);
}
