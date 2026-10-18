//! What the impersonate backend sends on the wire, captured by a local TLS
//! origin and checked against published fingerprints of the browsers it
//! presents. Where each expected value comes from is cited at the test, and the
//! profiles themselves cite the browser sources in src/emulation.rs.

#![cfg(feature = "impersonate")]

mod wire;

use std::time::Duration;

use wire::{ClientHello, Encoding, H2Preface, Origin};

// The identity User-Agents the engines pass. They only pick the family: the
// profile sends its own.
const CHROME_IDENTITY: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";
const EDGE_IDENTITY: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0";
const FIREFOX_IDENTITY: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";
const SAFARI_IDENTITY: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
     AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";

const H2_AND_H1: &[&[u8]] = &[b"h2", b"http/1.1"];

struct Seen {
    hello: ClientHello,
    alpn: Option<Vec<u8>>,
    request: Vec<u8>,
    body: String,
}

impl Seen {
    fn h2(&self) -> H2Preface {
        assert_eq!(self.alpn.as_deref(), Some(&b"h2"[..]));
        H2Preface::parse(&self.request)
    }
}

/// One request from an emulating client to a fresh origin.
async fn fetch(identity: &str, alpn: &[&[u8]], encoding: Encoding) -> Seen {
    let origin = Origin::start(alpn, encoding);
    let client = transport::build_client(transport::ClientConfig {
        user_agent: Some(identity.to_string()),
        emulate: true,
        accept_invalid_certs: true,
        resolve: vec![(wire::HOST.to_string(), origin.addr)],
        timeout: Some(Duration::from_secs(20)),
        ..Default::default()
    })
    .unwrap();
    let resp = client.get(origin.url()).send().await.expect("request");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.expect("body");
    drop(client);
    let capture = origin.finish();
    Seen {
        hello: ClientHello::parse(&capture.client_hello),
        alpn: capture.alpn,
        request: capture.request,
        body,
    }
}

fn hex(v: &[u16]) -> Vec<String> {
    v.iter().map(|x| format!("{x:04x}")).collect()
}

fn no_grease(v: Vec<u16>) -> Vec<u16> {
    v.into_iter().filter(|x| !wire::is_grease(*x)).collect()
}

#[test]
fn ja4_reproduces_the_specifications_worked_example() {
    // github.com/FoxIO-LLC/ja4, technical_details/JA4.md, "Example".
    let ciphers = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ];
    let extensions = [
        0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
        0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
    ];
    let sigalgs = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];
    assert_eq!(
        wire::ja4(0x0304, true, Some("h2"), &ciphers, &extensions, &sigalgs),
        "t13d1516h2_8daaf6152771_e5627efa2ab1"
    );
    // GREASE is ignored wherever it appears.
    let mut greased = vec![0x5a5a];
    greased.extend_from_slice(&ciphers);
    assert_eq!(
        wire::ja4(0x0304, true, Some("h2"), &greased, &extensions, &sigalgs),
        "t13d1516h2_8daaf6152771_e5627efa2ab1"
    );
}

#[tokio::test]
async fn chrome_profile_matches_chrome_148() {
    let seen = fetch(CHROME_IDENTITY, H2_AND_H1, Encoding::Identity).await;
    let hello = &seen.hello;

    // Published JA4 for Chrome 133 to 148 (scrapfly.io JA4 database: Chrome 148
    // on Windows and macOS; krowdev.com, "How Websites Detect Bots in 2026").
    assert_eq!(hello.ja4(), "t13d1516h2_8daaf6152771_d8a2da3f94cd");
    // GREASE leads the cipher suites, the extensions, the groups and the
    // versions, and closes the extensions.
    assert!(wire::is_grease(hello.ciphers[0]));
    let types = hello.extension_types();
    assert!(wire::is_grease(types[0]) && wire::is_grease(*types.last().unwrap()));
    assert!(wire::is_grease(hello.u16_list(10)[0]));
    assert!(wire::is_grease(hello.versions()[0]));
    assert_eq!(no_grease(hello.versions()), [0x0304, 0x0303]);
    assert_eq!(
        no_grease(hello.u16_list(10)),
        [0x11ec, 0x001d, 0x0017, 0x0018]
    );
    assert_eq!(no_grease(hello.key_shares()), [0x11ec, 0x001d]);
    assert_eq!(hello.protocol_list(16), ["h2", "http/1.1"]);
    assert_eq!(hello.protocol_list(17613), ["h2"]);
    assert_eq!(hello.cert_compression(), [2]);
    assert!(hello.extension(0xfe0d).is_some(), "ECH GREASE");
    assert_eq!(hello.session_id_len, 32);

    let h2 = seen.h2();
    // Published Akamai fingerprint for Chrome (krowdev.com, as above), and what
    // Chromium's own source sets (see src/emulation.rs).
    assert_eq!(
        h2.akamai(),
        "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    );
    assert_eq!(h2.headers_stream, 1);
    assert_eq!(h2.headers_priority, Some((true, 0, 255)));
    assert_eq!(
        h2.header_names(),
        [
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "upgrade-insecure-requests",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-user",
            "sec-fetch-dest",
            "accept-encoding",
            "accept-language",
            "priority",
        ]
    );
    assert_eq!(
        h2.header("user-agent"),
        Some(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/148.0.0.0 Safari/537.36"
        )
    );
    assert_eq!(
        h2.header("sec-ch-ua"),
        Some("\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\"")
    );
    assert_eq!(seen.body, wire::BODY);
}

#[tokio::test]
async fn chrome_shuffles_its_extensions_on_every_connection() {
    // SSL_set_permute_extensions: the set stays, the order does not. Two
    // orders out of 16! agreeing is not a real risk; four tries make it none.
    let mut orders = Vec::new();
    for _ in 0..4 {
        let seen = fetch(CHROME_IDENTITY, H2_AND_H1, Encoding::Identity).await;
        orders.push(no_grease(seen.hello.extension_types()));
    }
    let mut sets: Vec<Vec<u16>> = orders.clone();
    for s in &mut sets {
        s.sort();
    }
    assert!(sets.windows(2).all(|w| w[0] == w[1]), "{sets:x?}");
    assert!(orders.windows(2).any(|w| w[0] != w[1]), "{orders:x?}");
}

#[tokio::test]
async fn edge_profile_is_chrome_148_with_edge_headers() {
    let seen = fetch(EDGE_IDENTITY, H2_AND_H1, Encoding::Identity).await;
    assert_eq!(seen.hello.ja4(), "t13d1516h2_8daaf6152771_d8a2da3f94cd");
    let h2 = seen.h2();
    assert_eq!(
        h2.akamai(),
        "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    );
    assert_eq!(
        h2.header("sec-ch-ua"),
        Some("\"Chromium\";v=\"148\", \"Microsoft Edge\";v=\"148\", \"Not/A)Brand\";v=\"99\"")
    );
    assert!(h2.header("user-agent").unwrap().ends_with("Edg/148.0.0.0"));
}

#[tokio::test]
async fn firefox_profile_matches_firefox_158() {
    let seen = fetch(FIREFOX_IDENTITY, H2_AND_H1, Encoding::Identity).await;
    let hello = &seen.hello;

    // Published JA4 for Firefox 154 to 158 (scrapfly.io JA4 database).
    assert_eq!(hello.ja4(), "t13d1517h2_8daaf6152771_3cbfd9057e0d");
    // Firefox does not shuffle or GREASE, so the whole order is fixed: NSS's
    // cipherSuites table and clientHelloSendersTLS, X25519MLKEM768 first among
    // the groups. A capture of Firefox 158.0 sent the same string.
    assert_eq!(
        hello.ja3_text(),
        "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,\
         0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,4588-29-23-24-25,0"
    );
    assert!(!hello.ciphers.iter().any(|c| wire::is_grease(*c)));
    assert!(!hello.extension_types().iter().any(|e| wire::is_grease(*e)));
    assert_eq!(hello.versions(), [0x0304, 0x0303]);
    assert_eq!(hello.key_shares(), [0x11ec, 0x001d, 0x0017]);
    assert_eq!(
        hex(&hello.u16_list(34)),
        ["0403", "0503", "0603", "0203"],
        "delegated_credentials"
    );
    assert_eq!(hello.extension(28), Some(&16_385u16.to_be_bytes()[..]));
    assert_eq!(hello.cert_compression(), [1, 2, 3]);
    assert_eq!(hello.protocol_list(16), ["h2", "http/1.1"]);
    assert_eq!(hello.session_id_len, 32);

    let h2 = seen.h2();
    // Published Akamai fingerprint for Firefox (krowdev.com, as above).
    assert_eq!(
        h2.akamai(),
        "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"
    );
    assert_eq!(h2.headers_stream, 3);
    assert_eq!(h2.headers_priority, Some((false, 0, 41)));
    assert_eq!(
        h2.header_names(),
        [
            "user-agent",
            "accept",
            "accept-language",
            "accept-encoding",
            "upgrade-insecure-requests",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "priority",
            "te",
        ]
    );
    assert_eq!(
        h2.header("user-agent"),
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0")
    );
}

#[tokio::test]
async fn safari_profile_matches_safari_26() {
    let seen = fetch(SAFARI_IDENTITY, H2_AND_H1, Encoding::Identity).await;
    let hello = &seen.hello;

    // Published JA4 for Safari 26 and 27 on macOS and iOS (scrapfly.io and
    // usefoil.com JA4 databases).
    assert_eq!(hello.ja4(), "t13d2013h2_a09f3c656075_7f0f34a4126d");
    // Safari GREASEs but does not shuffle, so the order is fixed. The string
    // is the ClientHello of Safari 26.0.1 on macOS as curl-impersonate recorded
    // it (tests/signatures/safari_26.0.1_macOS.yaml).
    assert_eq!(
        hello.ja3_text(),
        "771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-\
         156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0"
    );
    let types = hello.extension_types();
    assert!(wire::is_grease(types[0]) && wire::is_grease(*types.last().unwrap()));
    assert_eq!(
        hex(&hello.u16_list(13)),
        [
            "0403", "0804", "0401", "0503", "0805", "0805", "0501", "0806", "0601", "0201"
        ]
    );
    assert_eq!(no_grease(hello.key_shares()), [0x11ec, 0x001d]);
    assert_eq!(no_grease(hello.versions()), [0x0304, 0x0303]);
    assert_eq!(hello.cert_compression(), [1]);
    assert_eq!(hello.protocol_list(16), ["h2", "http/1.1"]);

    let h2 = seen.h2();
    // Published Akamai fingerprint of Safari 26.3 on a Mac, and the same values
    // in the 26.0.1 capture (curl-impersonate issue 220 and the file above).
    assert_eq!(h2.akamai(), "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p");
    assert_eq!(h2.headers_stream, 1);
    assert_eq!(h2.headers_priority, None);
    assert_eq!(
        h2.header_names(),
        [
            "sec-fetch-dest",
            "user-agent",
            "accept",
            "sec-fetch-site",
            "sec-fetch-mode",
            "accept-language",
            "priority",
            "accept-encoding",
        ]
    );
}

#[tokio::test]
async fn compressed_bodies_come_back_decoded() {
    // Chrome, Firefox and Safari all advertise brotli, so a server may answer
    // with it and the engines have to get text back, not compressed bytes.
    for identity in [CHROME_IDENTITY, FIREFOX_IDENTITY, SAFARI_IDENTITY] {
        let seen = fetch(identity, H2_AND_H1, Encoding::Brotli).await;
        assert_eq!(seen.body, wire::BODY, "{identity}");
    }
}

#[tokio::test]
async fn http1_requests_keep_the_profile_order() {
    // Over HTTP/1.1 the same headers go out in the same order, with the names
    // in title case as browsers write them.
    let seen = fetch(FIREFOX_IDENTITY, &[b"http/1.1"], Encoding::Identity).await;
    assert_eq!(seen.alpn.as_deref(), Some(&b"http/1.1"[..]));
    let head = String::from_utf8(seen.request).unwrap();
    let names: Vec<&str> = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':').map(|(n, _)| n))
        .filter(|n| !n.eq_ignore_ascii_case("host"))
        .collect();
    assert_eq!(
        names,
        [
            "User-Agent",
            "Accept",
            "Accept-Language",
            "Accept-Encoding",
            "Upgrade-Insecure-Requests",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Site",
            "Sec-Fetch-User",
            "Priority",
            "Te",
        ]
    );
    assert_eq!(seen.body, wire::BODY);
}
