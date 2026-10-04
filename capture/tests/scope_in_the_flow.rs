//! Scope inside the flow itself, with no proxy session in front of it.
//!
//! `cfx_session` refuses an out-of-scope CONNECT before the flow is ever reached, so the
//! session's own tests cannot see this ordering: remove the check here and they all still
//! pass. The mobile netstack has no CONNECT to be gated at, and neither will anything else
//! that hands a flow straight to the capture core, so the check inside the flow is the
//! only one those paths get.
//!
//! The ordering under test is scope BEFORE bypass. `bypass_hosts` says "do not intercept
//! this" and scope says "do not reach this". The bypass branch relays with
//! `copy_bidirectional` and returns, so there is no per-request gate behind it and nothing
//! is recorded. Bypass winning would make it the one path in the product that carries
//! invisible traffic to a destination nobody authorised.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use cfx_capture::cfx_scope::{Guard, Point, Policy};
use cfx_capture::{CaptureCfg, Egress, TraceEvent, generate_ca, serve_mitm_flow};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// An origin that counts connections. Zero is the assertion.
async fn counting_origin() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            drop(sock);
        }
    });
    (port, hits)
}

/// The flow's result, not unwrapped.
///
/// A flow that is admitted goes on to a real MITM handshake, and the hand-built hello
/// below is not one, so "admitted" ends in a handshake error here. That is fine and it is
/// the point: what these tests ask is whether the destination was reached, which is
/// answered by the origin's counter and the guard's, not by how the TLS ended.
async fn flow_with(
    cfg: CaptureCfg,
    authority: &str,
    port: u16,
    sni: &str,
) -> Result<cfx_capture::FlowOutcome, String> {
    // Process-global, and only the ADMITTED flows reach the handshake that needs it. Left
    // out, this file passed or panicked depending on which test ran first and whether some
    // other test in the binary had installed it: three of the four return before the
    // handshake, so the one that does not was flaky rather than wrong.
    cfx_capture::install_default_crypto_provider();
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
    let ca = Arc::new(generate_ca().unwrap());
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_port = front.local_addr().unwrap().port();
    let host = authority.to_string();
    let flow = tokio::spawn(async move {
        let (client, _) = front.accept().await.unwrap();
        serve_mitm_flow(client, host, port, ca, Egress::Direct, tx, cfg).await
    });

    let mut sock = TcpStream::connect(("127.0.0.1", front_port)).await.unwrap();
    sock.write_all(&client_hello(sni)).await.unwrap();
    sock.flush().await.unwrap();
    // The write half closes once the hello is out. A bypassed flow is relayed with
    // `copy_bidirectional`, which runs until BOTH directions end: without this the client
    // half never does and the test hangs rather than failing.
    sock.shutdown().await.unwrap();

    tokio::time::timeout(Duration::from_secs(5), flow)
        .await
        .expect("the flow finished")
        .expect("no panic")
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn scope_beats_bypass() {
    let (origin_port, hits) = counting_origin().await;
    let guard = Guard::new(Policy::from_entries(&["in.example".to_string()]).0);
    let cfg = CaptureCfg {
        full: true,
        bypass_hosts: vec!["pinned.example".to_string()],
        scope: Some(guard.clone()),
        ..Default::default()
    };

    let outcome = flow_with(cfg, "pinned.example", origin_port, "pinned.example")
        .await
        .expect("a refusal is not an error");

    assert!(outcome.refused, "refused: {outcome:?}");
    assert!(!outcome.bypassed, "and not reported as a bypass");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the origin was never dialled. The bypass branch relays with no gate behind it, so \
         reaching it at all is the whole defect"
    );
    assert_eq!(guard.refused_total(), 1);
    assert_eq!(guard.recent(1)[0].point, Point::Connect);
}

#[tokio::test]
async fn a_bypassed_host_that_is_in_scope_is_still_bypassed() {
    // The ordering must not turn scope into a second bypass list. An in-scope pinned host
    // is exactly what bypass exists for.
    let (origin_port, hits) = counting_origin().await;
    let guard = Guard::new(Policy::from_entries(&["pinned.example".to_string()]).0);
    let cfg = CaptureCfg {
        full: true,
        bypass_hosts: vec!["pinned.example".to_string()],
        scope: Some(guard.clone()),
        ..Default::default()
    };

    // The authority is the address the flow dials; the bypassed NAME is in the hello,
    // which is where `is_bypassed` reads it from.
    let outcome = flow_with(cfg, "127.0.0.1", origin_port, "pinned.example")
        .await
        .expect("a bypass relays and returns cleanly");

    assert!(outcome.bypassed, "carried through untouched: {outcome:?}");
    assert!(!outcome.refused);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "and it reached the origin");
    assert_eq!(guard.refused_total(), 0);
}

#[tokio::test]
async fn the_name_the_client_asked_for_is_what_is_judged() {
    // Behind a CDN one address serves thousands of names, so the destination address says
    // almost nothing about what is being reached. The SNI is the only thing that does.
    let (origin_port, hits) = counting_origin().await;
    let guard = Guard::new(Policy::from_entries(&["allowed.example".to_string()]).0);
    let cfg = CaptureCfg {
        full: true,
        scope: Some(guard.clone()),
        ..Default::default()
    };

    // The flow's destination is an address that no rule names; the SNI is in scope. The
    // address is the resolver's answer for an admitted name and is not judged separately,
    // or every flow on a front end that resolves before capturing would be refused.
    let outcome = flow_with(cfg, "127.0.0.1", origin_port, "allowed.example").await;
    // Admitted, so it went on to the handshake, which the hand-built hello cannot finish.
    // The assertion is that it was not REFUSED, and the guard is where that is visible.
    assert_eq!(
        guard.refused_total(),
        0,
        "the address was not judged on its own account: {outcome:?}"
    );
    let _ = hits;
}

#[tokio::test]
async fn a_destination_name_that_differs_from_the_sni_is_judged_too() {
    // Both are destinations. An admitted SNI pointed at a different NAME is a second
    // thing being reached, and it has to clear the list on its own account.
    let (origin_port, hits) = counting_origin().await;
    let guard = Guard::new(Policy::from_entries(&["allowed.example".to_string()]).0);
    let cfg = CaptureCfg {
        full: true,
        scope: Some(guard.clone()),
        ..Default::default()
    };

    let outcome = flow_with(cfg, "elsewhere.example", origin_port, "allowed.example")
        .await
        .expect("a refusal is not an error");
    assert!(outcome.refused, "refused: {outcome:?}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        guard.recent(1)[0].detail.as_deref(),
        Some("asked for allowed.example"),
        "and the record says which name was claimed, because that is the interesting half"
    );
}

/// A minimal TLS 1.2 ClientHello carrying one server name.
///
/// Hand-built rather than taken from a client library: the flow reads the SNI out of raw
/// bytes, and a library that reordered extensions or added padding would be testing the
/// library. Nothing past the hello is needed, because every path under test returns
/// before the handshake.
fn client_hello(name: &str) -> Vec<u8> {
    let n = name.as_bytes();
    let mut sni = Vec::new();
    sni.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
    sni.push(0); // host_name
    sni.extend_from_slice(&(n.len() as u16).to_be_bytes());
    sni.extend_from_slice(n);

    let mut ext = Vec::new();
    ext.extend_from_slice(&0u16.to_be_bytes()); // server_name
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x2f]);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}
