//! A capture session recording to a local project, end to end.
//!
//! This is the join decision 3.1 of the desktop plan is about: with a sink attached, a
//! flow through `serve_mitm_flow` lands in a file on the operator's machine and the
//! control plane is not involved at all. Driven with raw sockets on both sides, so the
//! test has no HTTP client of its own to be wrong about.

use std::sync::Arc;
use std::time::Duration;

use cfx_capture::{CaptureCfg, Egress, TraceEvent, generate_ca, serve_mitm_flow};
use cfx_project::{Cap, Project, ProjectSink};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "cfx-capture-project-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&p);
        Self(p)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn read_until_quiet<S: AsyncReadExt + Unpin>(s: &mut S, idle: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match tokio::time::timeout(idle, s.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => return out,
            Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => return out,
        }
    }
}

/// Bytes no UTF-8 decoder can round trip: the thing a Repeater has to be able to replay
/// and the thing `String::from_utf8_lossy` destroys.
fn binary_payload(tag: u8) -> Vec<u8> {
    let mut v = vec![
        0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0xff, 0xfe, 0x80, 0xc0,
    ];
    v.push(tag);
    v
}

#[tokio::test]
async fn a_captured_exchange_lands_in_the_project_with_its_bytes_intact() {
    cfx_capture::install_default_crypto_provider();
    let s = Scratch::new("e2e");

    let req_payload = binary_payload(0x11);
    let resp_payload = binary_payload(0x22);

    // An origin that answers with a binary body.
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let seen_req = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
    let seen_req2 = seen_req.clone();
    let resp_for_origin = resp_payload.clone();
    tokio::spawn(async move {
        let (mut sock, _) = origin.accept().await.unwrap();
        let got = read_until_quiet(&mut sock, Duration::from_millis(100)).await;
        *seen_req2.lock().await = got;
        let mut reply = format!(
            "HTTP/1.1 201 Created\r\nContent-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\r\n",
            resp_for_origin.len()
        )
        .into_bytes();
        reply.extend_from_slice(&resp_for_origin);
        let _ = sock.write_all(&reply).await;
        let _ = sock.flush().await;
    });

    // The project, and the capture session recording into it.
    let project = Arc::new(Project::open(s.path(), Cap::default()).await.expect("open"));
    let sink = Arc::new(ProjectSink::new(project.clone()));
    let cfg = CaptureCfg {
        full: true,
        sink: Some(sink),
        ..Default::default()
    };

    let (tx, mut events) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_port = front.local_addr().unwrap().port();
    let ca = Arc::new(generate_ca().unwrap());
    let flow = tokio::spawn(async move {
        let (client, _) = front.accept().await.unwrap();
        serve_mitm_flow(
            client,
            "127.0.0.1".into(),
            origin_port,
            ca,
            Egress::Direct,
            tx,
            cfg,
        )
        .await
        .map_err(|e| e.to_string())
    });

    // A client carrying a binary request body, written as raw bytes.
    let mut tcp = TcpStream::connect(("127.0.0.1", front_port)).await.unwrap();
    let mut wire = format!(
        "POST /upload?name=photo HTTP/1.1\r\nHost: files.example.test\r\n\
         Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        req_payload.len()
    )
    .into_bytes();
    wire.extend_from_slice(&req_payload);
    tcp.write_all(&wire).await.unwrap();
    tcp.flush().await.unwrap();

    let raw_resp = read_until_quiet(&mut tcp, Duration::from_millis(1500)).await;
    assert!(
        String::from_utf8_lossy(&raw_resp).starts_with("HTTP/1.1 201"),
        "the client got its response: {:?}",
        String::from_utf8_lossy(&raw_resp[..raw_resp.len().min(80)])
    );

    let outcome = tokio::time::timeout(Duration::from_secs(10), flow)
        .await
        .expect("the flow finished")
        .expect("no panic");
    assert!(outcome.is_ok(), "flow: {outcome:?}");

    // The origin really did receive the binary body, so the proxy is not the only thing
    // being asked about here.
    let at_origin = seen_req.lock().await.clone();
    assert!(
        at_origin.ends_with(&req_payload),
        "the origin received the binary request body"
    );

    // And now the point: it is in the project, byte for byte.
    //
    // Waited for rather than asserted outright, because responses stream now. The record
    // is written when the response body ends, and hyper does not always poll a body it
    // already knows the length of to its final frame: it writes the bytes and drops it.
    // So the write lands on the drop path, a moment after the client has everything. The
    // contract is "recorded shortly after the response completes", measured at a sixth of
    // a millisecond, not "recorded before the client sees the last byte".
    for _ in 0..50 {
        if project.count().await.unwrap_or(0) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(project.count().await.expect("count"), 1);
    let stored = project
        .get(1)
        .await
        .expect("get")
        .expect("the exchange was recorded");

    assert_eq!(stored.exchange.method, "POST");
    assert_eq!(
        stored.exchange.url, "http://files.example.test/upload?name=photo",
        "the full URL, query values included, because this is the full-capture surface"
    );
    assert_eq!(stored.exchange.host, "files.example.test");
    assert_eq!(stored.exchange.status, Some(201));
    assert_eq!(
        stored.exchange.req_body, req_payload,
        "the request body round tripped through the store"
    );
    assert_eq!(
        stored.exchange.resp_body, resp_payload,
        "and so did the response body"
    );
    assert!(
        stored
            .exchange
            .req_headers
            .iter()
            .any(|[k, v]| k.eq_ignore_ascii_case("content-type")
                && v == "application/octet-stream"),
        "headers came across: {:?}",
        stored.exchange.req_headers
    );

    // The comparison that justifies `RawExchange` existing at all. The trace event for the
    // same exchange carries its bodies as lossily-converted strings, so the bytes in it are
    // not the bytes that crossed the wire and cannot be replayed. The store has the real
    // ones. If these two ever agree, the event has started carrying bytes and this design
    // can be simplified.
    let ev = events.recv().await.expect("an event too");
    let from_event = ev.req_body.clone().unwrap_or_default().into_bytes();
    assert_ne!(
        from_event, req_payload,
        "the event's body is expected to be lossy; if it is not, revisit RawExchange"
    );
    assert!(
        from_event.len() > req_payload.len(),
        "lossy conversion lengthens: each bad byte becomes a three-byte replacement \
         character. got {} from {}",
        from_event.len(),
        req_payload.len()
    );
}

#[tokio::test]
async fn the_sink_enforces_the_cap_without_being_asked_every_request() {
    // The sink checks the cap on an interval rather than per exchange, because checking
    // means two pragmas and a SUM and a capture does hundreds of requests a second. With
    // the interval set to 4 here, the check is observable.
    let s = Scratch::new("cap");
    let project = Arc::new(
        Project::open(
            s.path(),
            Cap {
                max_exchanges: Some(3),
                max_bytes: None,
            },
        )
        .await
        .expect("open"),
    );
    let sink = ProjectSink::with_check_interval(project.clone(), 4);

    use cfx_capture::{ExchangeSink, RawExchange};
    for i in 0..4 {
        let ex = RawExchange {
            at_ms: 1_700_000_000_000 + i,
            method: "GET".into(),
            url: format!("https://x.test/{i}"),
            host: "x.test".into(),
            status: 200,
            duration_ms: 1,
            ..Default::default()
        };
        sink.record(&ex).await;
    }

    // Four went in, the cap is three, and the fourth record triggered the check.
    assert_eq!(
        project.count().await.expect("count"),
        3,
        "the cap was enforced once the interval came round"
    );
    // The oldest is the one that went.
    assert!(project.get(1).await.expect("get").is_none());
    assert!(project.get(4).await.expect("get").is_some());
}
