use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

fn up(url: &str) -> Upstream {
    Upstream::parse(url).unwrap_or_else(|e| panic!("{url}: {e}"))
}

#[test]
fn every_scheme_parses_with_its_default_port() {
    let cases = [
        ("http://p.example", Kind::Http, 80),
        ("https://p.example", Kind::Https, 443),
        ("socks4://p.example", Kind::Socks4, 1080),
        ("socks4a://p.example", Kind::Socks4, 1080),
        ("socks5://p.example", Kind::Socks5, 1080),
        ("socks5h://p.example", Kind::Socks5, 1080),
        ("SOCKS5H://p.example:9050/", Kind::Socks5, 9050),
    ];
    for (url, kind, port) in cases {
        let u = up(url);
        assert_eq!(
            (u.kind, u.host.as_str(), u.port, &u.auth),
            (kind, "p.example", port, &None),
            "{url}"
        );
    }
}

#[test]
fn hosts_parse_as_names_and_addresses() {
    assert_eq!(up("socks5://[::1]:1080").host, "::1");
    assert_eq!(up("socks5://[2001:db8::7]").port, 1080);
    assert_eq!(up("http://192.0.2.4:3128").host, "192.0.2.4");
    assert_eq!(
        up("http://gw_1.proxy-provider.example:8000").host,
        "gw_1.proxy-provider.example"
    );
}

#[test]
fn credentials_are_percent_decoded() {
    let u = up("socks5://us%40er:p%3Ass%25w%2Frd@p.example:1080");
    assert_eq!(u.auth, Some(("us@er".into(), "p:ss%w/rd".into())));
    // An unescaped @ in the password still reads whole: the host starts after the last.
    let u = up("http://u:p@ss@p.example:3128");
    assert_eq!(u.auth, Some(("u".into(), "p@ss".into())));
    assert_eq!(u.host, "p.example");
    // A user name alone means an empty password, which is what SOCKS4 needs.
    assert_eq!(
        up("socks4://ident@p.example").auth,
        Some(("ident".into(), String::new()))
    );
    // Multi-byte UTF-8 survives decoding.
    assert_eq!(
        up("http://%C3%A9:x@p.example").auth,
        Some(("\u{e9}".into(), "x".into()))
    );
}

#[test]
fn bad_urls_are_refused_without_quoting_them() {
    let bad = [
        "p.example:1080",
        "ftp://hunter2@p.example",
        "socks5://u:hunter2@p.example:1080/path",
        "socks5://u:hunter2@p.example:1080?x=1",
        "socks5://u:hunter2@p.example:1080#f",
        "socks5://u:hunter2@p.example:0",
        "socks5://u:hunter2@p.example:65536",
        "socks5://u:hunter2@p.example:",
        "socks5://u:hunter2@p.example:12ab",
        "socks5://u:hunter2@:1080",
        "socks5://u:hunter2@::1:1080",
        "socks5://u:hunter2@[::1:1080",
        "socks5://u:hunter2@[not-v6]:1080",
        "socks5://u:hunter2@[::1]x:1080",
        "socks5://u:hunter2@p example:1080",
        "socks5://u:hunter2@p\r\nexample:1080",
        "socks5://u:hunter2%zz@p.example",
        "socks5://u:hunter2%ff@p.example",
        "socks5://:hunter2@p.example",
        "socks4://u:hunter2@p.example",
        "http://u%3Ax:hunter2@p.example",
        "https://u%3Ax:hunter2@p.example",
    ];
    for url in bad {
        let err = Upstream::parse(url).expect_err(url);
        assert!(
            !err.contains("hunter2"),
            "{url}: the error quotes the password: {err}"
        );
        assert!(
            !err.contains("p.example"),
            "{url}: the error quotes the URL: {err}"
        );
    }
}

#[test]
fn credential_lengths_follow_each_protocol() {
    let long = |n: usize| "a".repeat(n);
    // SOCKS5 has one length byte for each.
    assert!(Upstream::parse(&format!("socks5://{}:{}@p.example", long(255), long(255))).is_ok());
    assert!(Upstream::parse(&format!("socks5://{}:x@p.example", long(256))).is_err());
    assert!(Upstream::parse(&format!("socks5://u:{}@p.example", long(256))).is_err());
    // HTTP takes longer ones, up to its own cap.
    let ok = format!("http://u:{}@p.example", long(MAX_HTTP_CREDENTIAL));
    assert!(Upstream::parse(&ok).is_ok());
    let over = format!("http://u:{}@p.example", long(MAX_HTTP_CREDENTIAL + 1));
    assert!(Upstream::parse(&over).is_err());
    // A user id with a NUL in it would end the SOCKS4 field early.
    let nul = Upstream {
        kind: Kind::Socks4,
        host: "p.example".into(),
        port: 1080,
        auth: Some(("a\0b".into(), String::new())),
    };
    assert!(nul.check().is_err());
}

#[test]
fn label_and_debug_never_show_credentials() {
    let u = up("socks5h://customer-7781:hunter2@[2001:db8::1]:1080");
    assert_eq!(u.label(), "socks5://[2001:db8::1]:1080");
    let dbg = format!("{u:?}");
    assert!(
        !dbg.contains("hunter2") && !dbg.contains("customer-7781"),
        "{dbg}"
    );
    assert!(dbg.contains("<hidden>"), "{dbg}");
    assert_eq!(
        up("http://u:p@p.example:3128").label(),
        "http://p.example:3128"
    );
}

#[test]
fn targets_classify_and_print() {
    assert_eq!(
        Target::new("10.0.0.5", 80).host,
        Host::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
    );
    assert_eq!(
        Target::new("[::1]", 80).host,
        Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
    );
    assert_eq!(
        Target::new("::1", 80).host,
        Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
    );
    assert_eq!(
        Target::new("app.example.com", 80).host,
        Host::Name("app.example.com".into())
    );
    assert_eq!(Target::new("::1", 443).to_string(), "[::1]:443");
    assert_eq!(
        Target::new("app.example.com", 8443).to_string(),
        "app.example.com:8443"
    );
}

#[test]
fn target_names_are_host_names_only() {
    for ok in [
        "a",
        "app.example.com",
        "xn--bcher-kva.example",
        "_srv.my_host-1.example.",
        &"a".repeat(255),
    ] {
        assert!(Target::new(ok, 443).check().is_ok(), "{ok}");
    }
    let bad = [
        String::new(),
        "a".repeat(256),
        "evil.example HTTP/1.1\r\nX-Injected: 1".into(),
        "a b".into(),
        "a\0b".into(),
        "a/b".into(),
        "a@b".into(),
        "a:b".into(),
        "b\u{fc}cher.example".into(),
    ];
    for b in bad {
        assert!(Target::new(&b, 443).check().is_err(), "{b:?}");
    }
    assert!(Target::new("app.example.com", 0).check().is_err());
}

#[test]
fn base64_matches_rfc_4648() {
    let cases: [(&[u8], &str); 8] = [
        (b"", ""),
        (b"f", "Zg=="),
        (b"fo", "Zm8="),
        (b"foo", "Zm9v"),
        (b"foob", "Zm9vYg=="),
        (b"fooba", "Zm9vYmE="),
        (b"foobar", "Zm9vYmFy"),
        (b"Aladdin:open sesame", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
    ];
    for (raw, want) in cases {
        assert_eq!(http::base64(raw), want);
    }
    assert_eq!(http::base64(&[0xfb, 0xff, 0xbf]), "+/+/");
}

#[test]
fn failures_map_to_socks_replies() {
    use socks5_server::*;
    assert_eq!(TunnelError::Refused(0x02).reply_code(), NOT_ALLOWED);
    assert_eq!(TunnelError::Refused(0x04).reply_code(), HOST_UNREACHABLE);
    assert_eq!(TunnelError::Refused(0x5B).reply_code(), CONNECTION_REFUSED);
    assert_eq!(TunnelError::Refused(0x42).reply_code(), CONNECTION_REFUSED);
    assert_eq!(TunnelError::Http(403).reply_code(), NOT_ALLOWED);
    assert_eq!(TunnelError::Http(502).reply_code(), HOST_UNREACHABLE);
    assert_eq!(TunnelError::Timeout.reply_code(), HOST_UNREACHABLE);
    assert_eq!(TunnelError::Auth.reply_code(), GENERAL_FAILURE);
    assert_eq!(
        TunnelError::Connect("x".into()).reply_code(),
        GENERAL_FAILURE
    );
    assert_eq!(
        TunnelError::Protocol("x".into()).reply_code(),
        GENERAL_FAILURE
    );
}

/// An HTTPS proxy on loopback with a certificate made here. It answers CONNECT with
/// 200 and echoes what follows, and sends back the request it read.
async fn https_proxy() -> (
    u16,
    rustls::pki_types::CertificateDer<'static>,
    tokio::task::JoinHandle<Vec<u8>>,
) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der.clone()], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        let (tcp, _) = l.accept().await.unwrap();
        let Ok(mut s) = acceptor.accept(tcp).await else {
            return Vec::new();
        };
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read(&mut b).await.unwrap_or(0) == 0 {
                return head;
            }
            head.push(b[0]);
        }
        s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(&buf).await.unwrap();
        s.flush().await.unwrap();
        head
    });
    (port, der, h)
}

fn quick() -> Timeouts {
    Timeouts {
        connect: Duration::from_secs(2),
        handshake: Duration::from_secs(2),
    }
}

#[tokio::test]
async fn https_proxy_gets_connect_inside_tls() {
    let (port, der, seen) = https_proxy().await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let tls = Arc::new(client_config(roots));
    let u = up(&format!("https://u:p@127.0.0.1:{port}"));
    let mut t = connect_with(
        &u,
        &Target::new("only-the-proxy-knows.invalid", 443),
        quick(),
        &tls,
    )
    .await
    .unwrap();
    t.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    t.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
    let head = String::from_utf8(seen.await.unwrap()).unwrap();
    assert_eq!(
        head,
        "CONNECT only-the-proxy-knows.invalid:443 HTTP/1.1\r\n\
         Host: only-the-proxy-knows.invalid:443\r\n\
         Proxy-Authorization: Basic dTpw\r\n\r\n"
    );
}

#[tokio::test]
async fn https_proxy_with_an_unknown_certificate_is_never_sent_the_request() {
    let (port, _, seen) = https_proxy().await;
    // The public roots, as `connect` uses: a self-signed certificate is not in them.
    let u = up(&format!("https://u:hunter2@127.0.0.1:{port}"));
    let err = connect(&u, &Target::new("app.example.com", 443), quick())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(&err, TunnelError::Connect(m) if m.contains("TLS")),
        "{err:?}"
    );
    assert!(
        seen.await.unwrap().is_empty(),
        "the proxy read a request over an untrusted TLS session"
    );
}
