use super::*;
use crate::egress::testkit::{recorder_upstream, refusing_port, resolver};
use cfx_tunnel::recorder::{Fixture, Recorder, to_loopback};
use cfx_tunnel::socks5_server::CONNECTION_REFUSED;

/// An address no test resolves into and nothing dials: the recorder joins every
/// destination to the same port on loopback, whatever address it is asked for.
const PUBLIC: &str = "93.184.216.34";

async fn gateway(names: &[(&str, &[&str])]) -> Arc<Gateway> {
    Gateway::bind(resolver(names)).await.unwrap()
}

/// What an engine does with the URL it is handed: open a tunnel through it.
async fn through(lease: &Lease, host: &str, port: u16) -> Result<Tunnel, TunnelError> {
    let up = Upstream::parse(&lease.proxy_url()).unwrap();
    cfx_tunnel::connect(&up, &Target::new(host, port), Timeouts::default()).await
}

fn shown(r: &Result<Tunnel, TunnelError>) -> String {
    match r {
        Ok(_) => "an open tunnel".into(),
        Err(e) => format!("{e:?}"),
    }
}

async fn http_get(mut t: Tunnel, host: &str) -> String {
    t.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), t.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// With `block_internal`, a destination that is or resolves to a
/// private address is refused at the gateway, before the team proxy is asked for
/// anything. Forwarding the name, which is what turning a client's proxy on would
/// do, lets the proxy resolve it on the far side and reach whatever it names there.
#[tokio::test]
async fn block_internal_refuses_before_any_upstream_dial() {
    let rec = Recorder::start(to_loopback).await;
    let gw = gateway(&[
        ("localhost", &["127.0.0.1", "::1"]),
        ("intranet.example.test", &["10.0.0.5"]),
        ("mapped.example.test", &["::ffff:192.168.1.1"]),
    ])
    .await;
    let lease = gw
        .lease("op-7", "proxy-1", Arc::new(recorder_upstream(&rec)), true)
        .unwrap();
    for (host, port) in [
        ("localhost", 80),
        ("127.0.0.1", 80),
        ("169.254.169.254", 80),
        ("intranet.example.test", 443),
        ("mapped.example.test", 443),
        ("::1", 22),
    ] {
        match through(&lease, host, port).await {
            Err(TunnelError::Refused(0x02)) => {}
            Err(e) => panic!("{host}:{port} gave {e}, not the gateway's refusal"),
            Ok(_) => panic!("{host}:{port} was let through"),
        }
    }
    assert_eq!(
        rec.connections(),
        0,
        "the team proxy was asked: {:?}",
        rec.seen()
    );
    assert_eq!(lease.last_error().as_deref(), Some(PRIVATE));
    let s = lease.summary();
    assert_eq!(s["connections"], 6, "{s}");
    assert_eq!(s["refused"], 6, "{s}");
    assert_eq!(s["failed"], 0, "{s}");
    assert_eq!(s["hosts"][0]["host"], "localhost", "{s}");
    assert_eq!(s["hosts"][0]["refused"], 1, "{s}");
}

/// A name with a public address goes on as that address, so the proxy cannot answer
/// it differently from what the node vetted; the private address it also has is
/// never used.
#[tokio::test]
async fn block_internal_sends_the_vetted_address_on() {
    let rec = Recorder::start(to_loopback).await;
    let fx = Fixture::http("text/plain", "hello".into()).await;
    let gw = gateway(&[("app.example.test", &["10.1.2.3", PUBLIC])]).await;
    let lease = gw
        .lease("op", "proxy-1", Arc::new(recorder_upstream(&rec)), true)
        .unwrap();
    let t = through(&lease, "app.example.test", fx.port).await.unwrap();
    assert!(http_get(t, "app.example.test").await.contains("hello"));
    assert_eq!(
        rec.seen(),
        vec![Target {
            host: Host::Ip(PUBLIC.parse().unwrap()),
            port: fx.port
        }]
    );
    assert_eq!(fx.connections(), 1);
    assert_eq!(rec.joined(), 1);
}

/// Without `block_internal`, the node does not look the name up. The
/// proxy does, so geo answers and split-horizon names come out as they would from
/// the proxy's side.
#[tokio::test]
async fn without_block_internal_the_name_goes_to_the_proxy_unresolved() {
    let rec = Recorder::start(to_loopback).await;
    let fx = Fixture::http("text/plain", "hello".into()).await;
    // A resolver that knows nothing: asking it would fail the connection.
    let gw = gateway(&[]).await;
    let lease = gw
        .lease("op", "proxy-1", Arc::new(recorder_upstream(&rec)), false)
        .unwrap();
    let t = through(&lease, "only-the-proxy-knows.invalid", fx.port)
        .await
        .unwrap();
    assert!(
        http_get(t, "only-the-proxy-knows.invalid")
            .await
            .contains("hello")
    );
    assert_eq!(
        rec.seen(),
        vec![Target {
            host: Host::Name("only-the-proxy-knows.invalid".into()),
            port: fx.port
        }]
    );
    assert_eq!(fx.connections(), rec.joined());
    assert_eq!(fx.connections(), 1);
}

/// A lease ends with its op. Its engine's later connections are
/// refused at authentication, and a tunnel it still has open is closed.
#[tokio::test]
async fn an_ended_lease_is_refused_and_its_tunnels_close() {
    let rec = Recorder::start(to_loopback).await;
    let fx = Fixture::banner(b"220 ready\r\n").await;
    let gw = gateway(&[]).await;
    let lease = gw
        .lease("op", "proxy-1", Arc::new(recorder_upstream(&rec)), false)
        .unwrap();
    let url = Upstream::parse(&lease.proxy_url()).unwrap();
    let mut open = through(&lease, "svc.example.test", fx.port).await.unwrap();
    let mut banner = [0u8; 11];
    open.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"220 ready\r\n");

    drop(lease);
    let again = cfx_tunnel::connect(
        &url,
        &Target::new("svc.example.test", fx.port),
        Timeouts::default(),
    )
    .await;
    assert!(matches!(again, Err(TunnelError::Auth)), "{}", shown(&again));
    // The banner fixture waits half a second for input; the gateway closes first.
    let mut rest = Vec::new();
    let closed =
        tokio::time::timeout(Duration::from_millis(300), open.read_to_end(&mut rest)).await;
    assert!(
        closed.is_ok(),
        "the tunnel stayed open after its lease ended"
    );
    assert_eq!(fx.connections(), 1);
}

/// When the team proxy cannot be reached, the engine gets a SOCKS
/// failure, and nothing reaches the destination by any other way.
#[tokio::test]
async fn a_dead_upstream_fails_and_nothing_reaches_the_target() {
    let fx = Fixture::http("text/plain", "hello".into()).await;
    let (_held, dead) = refusing_port();
    let gw = gateway(&[("app.example.test", &[PUBLIC])]).await;
    for block_internal in [false, true] {
        let up = Upstream {
            kind: Kind::Socks5,
            host: "127.0.0.1".into(),
            port: dead,
            auth: None,
        };
        let lease = gw
            .lease("op", "proxy-1", Arc::new(up), block_internal)
            .unwrap();
        for host in ["127.0.0.1", "app.example.test"] {
            let got = through(&lease, host, fx.port).await;
            // 127.0.0.1 under block_internal is refused by policy instead.
            let want = if block_internal && host == "127.0.0.1" {
                0x02
            } else {
                GENERAL_FAILURE
            };
            match got {
                Err(TunnelError::Refused(c)) if c == want => {}
                other => panic!(
                    "{host} (block_internal={block_internal}) gave {}",
                    shown(&other)
                ),
            }
        }
        let s = lease.summary();
        assert_eq!(s["connections"], 2, "{s}");
        assert!(
            lease
                .last_error()
                .unwrap()
                .contains("could not connect to the proxy")
        );
    }
    assert_eq!(fx.connections(), 0);
}

/// An onward refusal keeps its meaning: a proxy that refuses the destination is
/// passed on as the same SOCKS reply, and counted as a failure.
#[tokio::test]
async fn an_upstream_refusal_is_passed_on() {
    let rec = Recorder::start(|_: &Target| None).await;
    let gw = gateway(&[]).await;
    let lease = gw
        .lease("op", "proxy-1", Arc::new(recorder_upstream(&rec)), false)
        .unwrap();
    let got = through(&lease, "app.example.test", 443).await;
    assert!(
        matches!(got, Err(TunnelError::Refused(0x02))),
        "{}",
        shown(&got)
    );
    assert_eq!(lease.summary()["failed"], 1);

    let rec = Recorder::start(|_: &Target| Some("127.0.0.1:1".parse().unwrap())).await;
    let lease = gw
        .lease("op", "proxy-1", Arc::new(recorder_upstream(&rec)), false)
        .unwrap();
    let got = through(&lease, "app.example.test", 443).await;
    assert!(
        matches!(got, Err(TunnelError::Refused(CONNECTION_REFUSED))),
        "{}",
        shown(&got)
    );
}

/// The summary counts every connection once, by destination, with
/// the bytes each way.
#[tokio::test]
async fn the_summary_counts_each_destination() {
    let rec = Recorder::start(to_loopback).await;
    let fx = Fixture::http("text/plain", "x".repeat(1000)).await;
    let gw = gateway(&[("app.example.test", &[PUBLIC])]).await;
    let lease = gw
        .lease("op", "proxy-9", Arc::new(recorder_upstream(&rec)), true)
        .unwrap();
    for _ in 0..2 {
        let t = through(&lease, "app.example.test", fx.port).await.unwrap();
        assert!(
            http_get(t, "app.example.test")
                .await
                .ends_with(&"x".repeat(1000))
        );
    }
    assert!(through(&lease, "10.0.0.1", fx.port).await.is_err());
    // The byte counts land as the bytes pass.
    for _ in 0..50 {
        if lease.summary()["bytes_down"].as_u64().unwrap_or(0) >= 2000 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let s = lease.summary();
    assert_eq!(s["mode"], "proxy");
    assert_eq!(s["proxy_id"], "proxy-9");
    assert_eq!(s["connections"], 3, "{s}");
    assert_eq!(s["refused"], 1, "{s}");
    assert_eq!(s["failed"], 0, "{s}");
    assert_eq!(s["hosts_truncated"], false, "{s}");
    assert_eq!(
        s["hosts"],
        serde_json::json!([
            {"host": "app.example.test", "port": fx.port, "ok": 2, "refused": 0, "failed": 0},
            {"host": "10.0.0.1", "port": fx.port, "ok": 0, "refused": 1, "failed": 0},
        ])
    );
    assert!(s["bytes_up"].as_u64().unwrap() > 0, "{s}");
    assert!(s["bytes_down"].as_u64().unwrap() >= 2000, "{s}");
    assert_eq!(rec.joined(), 2);
    assert_eq!(fx.connections(), 2);

    // Published once, whichever path ends the op.
    assert!(lease.take_summary().is_some());
    assert!(lease.take_summary().is_none());
}

#[test]
fn destinations_past_the_cap_are_counted_but_not_listed() {
    let mut log = EgressLog::default();
    for i in 0..=MAX_HOSTS {
        log.record(format!("h{i}.example.test"), 443, Outcome::Ok);
    }
    log.record("h0.example.test".into(), 443, Outcome::Failed);
    assert_eq!(log.hosts.len(), MAX_HOSTS);
    assert_eq!(log.unlisted, 1);
    assert_eq!(log.connections, MAX_HOSTS as u64 + 2);
    assert_eq!(log.failed, 1);
    assert_eq!(log.hosts[0].1.failed, 1);
}

#[tokio::test]
async fn a_wrong_secret_is_refused() {
    let rec = Recorder::start(to_loopback).await;
    let gw = gateway(&[]).await;
    let lease = gw
        .lease("op", "proxy-1", Arc::new(recorder_upstream(&rec)), false)
        .unwrap();
    let mut up = Upstream::parse(&lease.proxy_url()).unwrap();
    let (user, pass) = up.auth.clone().unwrap();
    assert_eq!(user.len(), 16);
    assert_eq!(pass.len(), 64);
    up.auth = Some((user, "0".repeat(64)));
    let got =
        cfx_tunnel::connect(&up, &Target::new("a.example.test", 80), Timeouts::default()).await;
    assert!(matches!(got, Err(TunnelError::Auth)), "{}", shown(&got));
    assert_eq!(rec.connections(), 0);
    // A lease's URL and wire object name only the gateway.
    assert!(lease.proxy_url().ends_with(&format!("@{}", gw.addr())));
    assert_eq!(lease.wire()["v"], 1);
    assert!(!format!("{lease:?}").contains(&pass_of(&lease)));
}

fn pass_of(lease: &Lease) -> String {
    Upstream::parse(&lease.proxy_url()).unwrap().auth.unwrap().1
}

#[test]
fn a_socks4_upstream_gets_only_ipv4_addresses() {
    let v6: IpAddr = "2606:4700::1111".parse().unwrap();
    let v4: IpAddr = PUBLIC.parse().unwrap();
    let v4b: IpAddr = "104.16.132.229".parse().unwrap();
    let private: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(vetted(&[v6, v4], true).ok(), Some(vec![v4]));
    assert_eq!(vetted(&[v6, v4], false).ok(), Some(vec![v4, v6]));
    assert_eq!(vetted(&[v4b, v6, v4], false).ok(), Some(vec![v4b, v4, v6]));
    assert_eq!(vetted(&[private, v4], false).ok(), Some(vec![v4]));
    assert_eq!(
        vetted(&[v4; 9], false).map(|v| v.len()).ok(),
        Some(MAX_ADDRESSES)
    );
    assert!(matches!(
        vetted(&[v6], true),
        Err(Verdict::Failed(ADDRESS_TYPE_NOT_SUPPORTED, _))
    ));
    assert!(matches!(
        vetted(&[private], false),
        Err(Verdict::Refused(PRIVATE))
    ));
    assert!(matches!(vetted(&[], false), Err(Verdict::Refused(PRIVATE))));
}

/// Over the gateway's connection cap, a connection is closed before anything is read
/// from it, and once an open one ends the next goes through.
#[tokio::test]
async fn connections_over_the_cap_are_closed_unanswered() {
    let rec = Recorder::start(to_loopback).await;
    let fx = Fixture::banner(b"hi\r\n").await;
    let gw = Gateway::bind_with(resolver(&[]), Timeouts::default(), IDLE, 1)
        .await
        .unwrap();
    let lease = gw
        .lease("op", "proxy-1", Arc::new(recorder_upstream(&rec)), false)
        .unwrap();
    let held = through(&lease, "a.example.test", fx.port).await.unwrap();
    let got = through(&lease, "b.example.test", fx.port).await;
    // Closed with the greeting unread, which the client sees as an end or a reset
    // depending on when its next read lands.
    assert!(
        matches!(got, Err(TunnelError::Protocol(_) | TunnelError::Connect(_))),
        "{}",
        shown(&got)
    );
    assert_eq!(rec.seen().len(), 1, "the proxy was asked: {:?}", rec.seen());
    drop(held);
    let mut again = Err(TunnelError::Timeout);
    for _ in 0..50 {
        again = through(&lease, "c.example.test", fx.port).await;
        if again.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(again.is_ok(), "{}", shown(&again));
}

/// Connections count against the cap from the moment they are accepted. One that
/// never authenticates would otherwise keep a descriptor in the node's process for the
/// whole handshake deadline, outside the cap, and enough of them leave the node unable
/// to open anything else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_that_never_authenticate_count_against_the_cap() {
    let gw = Gateway::bind_with(resolver(&[]), Timeouts::default(), IDLE, 1)
        .await
        .unwrap();
    let mut held = Vec::new();
    for _ in 0..300 {
        // Connect and send nothing: no greeting, no credentials.
        held.push(TcpStream::connect(gw.addr()).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    // A connection the gateway has closed reads as ended at once; one it still holds
    // has nothing to read.
    let mut open = 0;
    for s in held.iter_mut() {
        let mut b = [0u8; 1];
        if tokio::time::timeout(Duration::from_millis(5), s.read(&mut b))
            .await
            .is_err()
        {
            open += 1;
        }
    }
    assert!(
        open <= 1,
        "the gateway holds {open} connections that never authenticated, under a cap of 1"
    );
}

/// A certificate for `name` and the TLS configs of a server presenting it and a client
/// trusting only it.
fn tls_pair(name: &str) -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let cert = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
    let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let prov = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(Arc::clone(&prov))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key)
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(prov)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

/// A tunnel to an HTTPS proxy is a TLS stream, which can keep the end of what it was
/// given in its own buffer when the socket under it is full. The gateway has to flush
/// it, or the tail of a large upload never reaches the proxy and the engine waits for
/// an answer that cannot come. Small socket buffers make the last write meet a full
/// socket, as a slow link to the proxy does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_end_of_an_upload_reaches_an_https_proxy() {
    const TOTAL: usize = 4 * 1024 * 1024;
    let (server_cfg, client_cfg) = tls_pair("proxy.test");

    // The far side of the proxy: reads everything at a modest pace, then answers.
    let seen = Arc::new(AtomicU64::new(0));
    let far = {
        let seen = Arc::clone(&seen);
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.set_recv_buffer_size(4096).unwrap();
        sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let l = sock.listen(8).unwrap();
        let addr = l.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        let task = tokio::spawn(async move {
            let (tcp, _) = l.accept().await.unwrap();
            let mut s = acceptor.accept(tcp).await.unwrap();
            let mut buf = vec![0u8; 16 * 1024];
            let mut got = 0usize;
            while got < TOTAL {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        got += n;
                        seen.store(got as u64, Ordering::Relaxed);
                    }
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if got == TOTAL {
                let _ = s.write_all(b"OK").await;
                let _ = s.flush().await;
            }
        });
        (addr, task)
    };

    // The gateway's connection to the proxy, as an https upstream is opened: TLS over
    // TCP.
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.set_send_buffer_size(4096).unwrap();
    let tcp = sock.connect(far.0).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(client_cfg)
        .connect(
            rustls::pki_types::ServerName::try_from("proxy.test").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let tunnel: Tunnel = Box::new(tls);

    // The engine's connection to the gateway.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut engine = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
    let (gw_side, _) = l.accept().await.unwrap();
    let (_alive, ended) = watch::channel(false);
    let pumping = tokio::spawn(async move {
        let (up, down) = (AtomicU64::new(0), AtomicU64::new(0));
        pump(gw_side, tunnel, IDLE, ended, (&up, &down)).await
    });

    // A request body, then the answer read with the connection still open, as an HTTP
    // client waits for one.
    engine.write_all(&vec![b'x'; TOTAL]).await.unwrap();
    let mut answer = [0u8; 2];
    let got = tokio::time::timeout(Duration::from_secs(20), engine.read_exact(&mut answer)).await;
    let reached = seen.load(Ordering::Relaxed);
    far.1.abort();
    pumping.abort();
    assert!(
        matches!(got, Ok(Ok(_))) && &answer == b"OK",
        "no answer within 20 s; the proxy side read {reached} of {TOTAL} bytes"
    );
}

/// The bytes of a connection that is still open are in the summary. An engine's client
/// keeps its connections in a pool after the op's last request, and the op's summary is
/// taken as soon as the engine says it is done, before the pool closes them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_summary_counts_the_bytes_of_open_connections() {
    let rec = Recorder::start(to_loopback).await;
    let fx = Fixture::http("text/plain", "x".repeat(5000)).await;
    let gw = gateway(&[]).await;
    let lease = gw
        .lease("op", "proxy-1", Arc::new(recorder_upstream(&rec)), false)
        .unwrap();
    // An engine's client: a keep-alive pool, sending through the lease's URL.
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(lease.proxy_url()).unwrap())
        .build()
        .unwrap();
    for _ in 0..3 {
        let body = client
            .get(format!("http://app.example.test:{}/", fx.port))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body.len(), 5000);
    }
    let mut s = lease.summary();
    for _ in 0..50 {
        if s["bytes_down"].as_u64().unwrap_or(0) >= 15000 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        s = lease.summary();
    }
    assert_eq!(
        s["connections"], 1,
        "the pool did not keep its connection: {s}"
    );
    assert!(s["bytes_up"].as_u64().unwrap() > 0, "{s}");
    assert!(
        s["bytes_down"].as_u64().unwrap() >= 15000,
        "15000 body bytes came back through the open connection: {s}"
    );
    drop(client);
}

/// A team proxy that reaches only one kind of address: the other kind is answered
/// "host unreachable". Returns its port and every destination it was asked for.
async fn one_kind_proxy(v6: bool) -> (u16, Arc<Mutex<Vec<Target>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let keep = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let seen = Arc::clone(&keep);
            tokio::spawn(async move {
                let Ok(((), t)) =
                    socks5_server::accept(&mut s, Duration::from_secs(5), |_, _| Some(())).await
                else {
                    return;
                };
                seen.lock().unwrap().push(t.clone());
                let reaches = matches!(t.host, Host::Ip(ip) if ip.is_ipv6() == v6);
                let code = if reaches { SUCCEEDED } else { HOST_UNREACHABLE };
                let _ = socks5_server::reply(&mut s, code).await;
                if reaches {
                    let mut b = [0u8; 1];
                    let _ = s.read(&mut b).await;
                }
            });
        }
    });
    (port, seen)
}

/// With `block_internal` the node hands the proxy an address it vetted. A name with
/// both kinds opens through a proxy that reaches only one of them, whichever order the
/// node's resolver gives them in, as it would for a client sending directly.
#[tokio::test]
async fn a_dual_stack_name_opens_through_a_proxy_that_reaches_one_kind() {
    const V6: &str = "2606:4700::6810:84e5";
    const V4: &str = "104.16.132.229";
    for v6_proxy in [false, true] {
        for order in [[V6, V4], [V4, V6]] {
            let (port, seen) = one_kind_proxy(v6_proxy).await;
            let gw = gateway(&[("dual.example.test", &order)]).await;
            let up = Upstream {
                kind: Kind::Socks5,
                host: "127.0.0.1".into(),
                port,
                auth: Some(("u".into(), "p".into())),
            };
            let lease = gw.lease("op", "proxy-1", Arc::new(up), true).unwrap();
            let got = through(&lease, "dual.example.test", 443).await;
            let asked = seen.lock().unwrap().clone();
            let case = format!("v6 proxy {v6_proxy}, {order:?}");
            assert!(
                got.is_ok(),
                "{case}: {}; the proxy was asked for {asked:?}",
                shown(&got)
            );
            let opened = if v6_proxy { V6 } else { V4 };
            assert_eq!(asked.last(), Some(&Target::new(opened, 443)), "{case}");
            let s = lease.summary();
            assert_eq!(s["connections"], 1, "{case}: {s}");
            assert_eq!(s["hosts"][0]["host"], "dual.example.test", "{case}: {s}");
            assert_eq!(s["hosts"][0]["ok"], 1, "{case}: {s}");
        }
    }
}

/// A proxy that fails the connection as a whole is not asked again for the name's
/// other addresses: it would fail them the same way. This one refuses the
/// credentials.
#[tokio::test]
async fn a_proxy_that_refuses_the_credentials_is_asked_once() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let asked = Arc::new(AtomicU64::new(0));
    let count = Arc::clone(&asked);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ =
                    socks5_server::accept(&mut s, Duration::from_secs(5), |_, _| None::<()>).await;
            });
        }
    });
    let gw = gateway(&[("dual.example.test", &["2606:4700::6810:84e5", PUBLIC])]).await;
    let up = Upstream {
        kind: Kind::Socks5,
        host: "127.0.0.1".into(),
        port,
        auth: Some(("u".into(), "wrong".into())),
    };
    let lease = gw.lease("op", "proxy-1", Arc::new(up), true).unwrap();
    let got = through(&lease, "dual.example.test", 443).await;
    assert!(
        matches!(got, Err(TunnelError::Refused(GENERAL_FAILURE))),
        "{}",
        shown(&got)
    );
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    let s = lease.summary();
    assert_eq!(s["connections"], 1, "{s}");
    assert_eq!(s["failed"], 1, "{s}");
}

#[test]
fn the_cap_leaves_room_under_the_descriptor_limit() {
    assert_eq!(connection_cap(None), MAX_CONNECTIONS);
    assert_eq!(connection_cap(Some(65536)), MAX_CONNECTIONS);
    assert_eq!(connection_cap(Some(512 + 2 * 2048)), MAX_CONNECTIONS);
    // A service's usual soft limit, where 2048 tunnels would need four times as many.
    assert_eq!(connection_cap(Some(1024)), 256);
    assert_eq!(connection_cap(Some(100)), MIN_CONNECTIONS);
    assert_eq!(connection_cap(Some(u64::MAX)), MAX_CONNECTIONS);
}
