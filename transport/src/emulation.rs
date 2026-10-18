//! Browser profiles for the `impersonate` backend.
//!
//! A profile is what one browser release sends on a fresh connection: the TLS
//! ClientHello (cipher suites, extensions and their order, groups, key shares,
//! signature algorithms), the HTTP/2 preface (SETTINGS and their order, the
//! connection WINDOW_UPDATE, the priority on HEADERS, the pseudo-header order),
//! and the headers of a top-level navigation in the order the browser writes
//! them. A WAF compares all three with the User-Agent, so each profile carries
//! its own User-Agent and the caller's is used only to pick the family.
//!
//! Every value is taken from the browser's own source where it is open, and from
//! published captures of the real browser where it is not. Each block below says
//! where its values come from. `tests/emulation_wire.rs` captures what this
//! client sends to a local listener and checks the JA4 and the HTTP/2
//! fingerprint against published values for each browser.
//!
//! The newest Chrome cannot be matched. Chrome 149 and later put ML-DSA-44, -65
//! and -87 first in signature_algorithms, and Chrome 152 and later also GREASE
//! that list; the BoringSSL that boring2 4.15 builds can do neither. So the
//! Chrome and Edge profiles are Chrome 148, the newest release whose ClientHello
//! this library reproduces, and they send Chrome 148's User-Agent so the two
//! agree. Firefox 158 and Safari 26 are reproduced as they ship.

use wreq::header::{HeaderMap, HeaderName, HeaderValue};
use wreq::{
    AlpnProtos, AlpsProtos, CertCompressionAlgorithm, EmulationProvider, ExtensionType,
    Http1Config, Http2Config, PseudoOrder, SettingsOrder, SslCurve, StreamDependency, StreamId,
    TlsConfig, TlsVersion,
};

/// A browser family the impersonate backend can present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Browser {
    Chrome,
    Edge,
    Firefox,
    Safari,
}

impl Browser {
    /// The family a User-Agent names, or `None` when it names no browser this
    /// backend can present. Checked in the order that tells them apart: an Edge
    /// User-Agent also carries `Chrome/`, and a Chrome one also carries `Safari/`.
    pub(crate) fn from_user_agent(ua: &str) -> Option<Browser> {
        if ua.contains("Firefox/") {
            Some(Browser::Firefox)
        } else if ua.contains("Edg/") {
            Some(Browser::Edge)
        } else if ua.contains("Version/") && ua.contains("Safari/") && !ua.contains("Chrome/") {
            Some(Browser::Safari)
        } else if ua.contains("Chrome/") {
            Some(Browser::Chrome)
        } else {
            None
        }
    }

    /// The User-Agent this profile sends. It names the release the handshake is
    /// taken from, so the two describe the same browser.
    pub(crate) fn user_agent(self) -> &'static str {
        match self {
            Browser::Chrome => CHROME_UA,
            Browser::Edge => EDGE_UA,
            Browser::Firefox => FIREFOX_UA,
            Browser::Safari => SAFARI_UA,
        }
    }

    /// The navigation headers this browser sends, User-Agent included.
    pub(crate) fn default_headers(self) -> HeaderMap {
        let pairs: &[(&str, &str)] = match self {
            Browser::Chrome => &CHROME_HEADERS,
            Browser::Edge => &EDGE_HEADERS,
            Browser::Firefox => &FIREFOX_HEADERS,
            Browser::Safari => &SAFARI_HEADERS,
        };
        let mut map = HeaderMap::with_capacity(pairs.len() + 1);
        map.insert(
            wreq::header::USER_AGENT,
            HeaderValue::from_static(self.user_agent()),
        );
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        map
    }

    /// The order the browser writes its request headers in. A header not named
    /// here goes after these, in the order it was added.
    pub(crate) fn header_order(self) -> &'static [HeaderName] {
        match self {
            Browser::Chrome | Browser::Edge => &CHROMIUM_HEADER_ORDER,
            Browser::Firefox => &FIREFOX_HEADER_ORDER,
            Browser::Safari => &SAFARI_HEADER_ORDER,
        }
    }

    pub(crate) fn tls(self) -> TlsConfig {
        match self {
            Browser::Chrome | Browser::Edge => chromium_tls(),
            Browser::Firefox => firefox_tls(),
            Browser::Safari => safari_tls(),
        }
    }

    /// HTTP/1.1 settings. Browsers write the standard header names in title
    /// case, where this client would otherwise write them in lower case.
    /// Chromium's `sec-ch-ua*` names, which it keeps in lower case, come out as
    /// `Sec-Ch-Ua*` over HTTP/1.1; HTTP/2 sends every name in lower case.
    pub(crate) fn http1(self) -> Http1Config {
        Http1Config::builder().title_case_headers(true).build()
    }

    pub(crate) fn http2(self) -> Http2Config {
        match self {
            Browser::Chrome | Browser::Edge => chromium_http2(),
            Browser::Firefox => firefox_http2(),
            Browser::Safari => safari_http2(),
        }
    }

    /// The TLS, HTTP/1.1, HTTP/2 and header-order settings as one value for
    /// `ClientBuilder::emulation`. The default headers are left out because the
    /// caller lays its own over them first; see `build_client`.
    pub(crate) fn emulation(self) -> EmulationProvider {
        EmulationProvider::builder()
            .tls_config(self.tls())
            .http1_config(self.http1())
            .http2_config(self.http2())
            .headers_order(self.header_order())
            .build()
    }
}

/// Every `SettingsOrder` variant appears once in an order, and only the settings
/// a profile sets are sent, so the unset ones can follow in any order.
const SETTINGS_BY_ID: [SettingsOrder; 8] = [
    SettingsOrder::HeaderTableSize,
    SettingsOrder::EnablePush,
    SettingsOrder::MaxConcurrentStreams,
    SettingsOrder::InitialWindowSize,
    SettingsOrder::MaxFrameSize,
    SettingsOrder::MaxHeaderListSize,
    SettingsOrder::UnknownSetting8,
    SettingsOrder::UnknownSetting9,
];

/// Positions in BoringSSL's extension table, for a fixed extension order.
/// BoringSSL sends exactly the listed extensions, in this order, with GREASE
/// (when on) first and last and pre_shared_key after everything.
const fn extension_order<const N: usize>(order: [ExtensionType; N]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = match ExtensionType::index_of(order[i]) {
            Some(index) => index as u8,
            None => panic!("BoringSSL cannot send this extension"),
        };
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Chrome 148 and Edge 148
//
// TLS, from Chromium 148.0.7778.56, net/socket/ssl_client_socket_impl.cc
// (SSLContext and SSLClientSocketImpl::Init), net/ssl/ssl_config_service.cc
// (kDefaultSSLSupportedGroups), net/ssl/cert_compression.cc and
// net/http/http_network_session.cc (ALPN and ALPS), with BoringSSL at
// d8be2b4a71155bf82da092ef543176351eeb59ff, the revision that release's DEPS
// pins:
//   * GREASE on, and the extension order shuffled on every connection
//     (SSL_CTX_set_grease_enabled, SSL_set_permute_extensions).
//   * Cipher suites "ALL:!aPSK:!ECDSA+SHA1:!3DES" over BoringSSL's default
//     order, which is the list below. The worked example in the FoxIO JA4
//     specification uses the same list in the same order.
//   * Groups X25519MLKEM768, X25519, P-256, P-384, with key shares for the first
//     two.
//   * The eight verify preferences in kVerifyPrefs.
//   * ALPN h2 then http/1.1; ALPS for h2 on the new codepoint (17613), because
//     kUseNewAlpsCodepointHttp2 is enabled by default; brotli certificate
//     compression; ECH GREASE; OCSP stapling and SCTs requested; TLS 1.2 to 1.3.
//
// Published JA4 for this handshake: t13d1516h2_8daaf6152771_d8a2da3f94cd. The
// scrapfly.io JA4 database attributes it to Chrome, with Chrome 148 on Windows
// and macOS among its largest entries (retrieved 2026-10-17).
//
// HTTP/2, from the same release: net/http/http_network_session.h and .cc
// (AddDefaultHttp2Settings, kSpdySessionMaxRecvWindowSize = 15 MB,
// kSpdyStreamMaxRecvWindowSize = 6 MB, kSpdyMaxHeaderTableSize = 64 KiB,
// kSpdyMaxHeaderListSize = 256 KiB, push disabled), net/spdy/spdy_session.cc
// (only non-default settings are sent, from a std::map, so in ascending id
// order), net/spdy/http2_priority_dependencies.cc (the first stream depends on
// stream 0, exclusive, with Spdy3PriorityToHttp2Weight(HIGHEST) = 256) and
// net/spdy/spdy_http_utils.cc (:method, :authority, :scheme, :path, then the
// request headers, then `priority`). Published Akamai fingerprint for Chrome:
// 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p (krowdev.com, "How
// Websites Detect Bots in 2026").
//
// Headers: a navigation captured from Chrome 150 on macOS
// (lexiforest/curl-impersonate, tests/signatures/chrome_150.0.7871.127_macOS.yaml)
// gives the names, values and order. The User-Agent is Chromium's reduced form
// for Windows (components/embedder_support/user_agent_utils.cc,
// GetUnifiedPlatform), and sec-ch-ua is GenerateBrandVersionList in the same
// file, seeded with 148: "Not/A)Brand" at version 99, in the third place. Cookie
// is added after Accept-Language (net/url_request/url_request_http_job.cc,
// Start calls AddExtraHeaders before AddCookieHeaderAndStart). Edge sends the
// same handshake and headers with "Microsoft Edge" as the brand and an Edg/
// token after Safari/ (learn.microsoft.com, "Detecting Microsoft Edge from your
// website").
// ---------------------------------------------------------------------------

const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

const EDGE_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0";

const CHROMIUM_CIPHERS: [&str; 15] = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
];

const CHROMIUM_GROUPS: &[SslCurve] = &[
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
];

const CHROMIUM_SIGALGS: [&str; 8] = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
];

fn chromium_tls() -> TlsConfig {
    TlsConfig::builder()
        .grease_enabled(true)
        .permute_extensions(true)
        .cipher_list(CHROMIUM_CIPHERS.join(":"))
        .curves(CHROMIUM_GROUPS)
        .sigalgs_list(CHROMIUM_SIGALGS.join(":"))
        .cert_compression_algorithm(CertCompressionAlgorithm::Brotli)
        .alpn_protos(AlpnProtos::ALL)
        .alps_protos(AlpsProtos::HTTP2)
        .alps_use_new_codepoint(true)
        .enable_ech_grease(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        // Chrome keeps sessions (SSLClientSessionCache) and resumes them.
        .pre_shared_key(true)
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .build()
}

fn chromium_http2() -> Http2Config {
    Http2Config::builder()
        .header_table_size(64 * 1024_u32)
        .enable_push(false)
        .initial_stream_window_size(6 * 1024 * 1024_u32)
        .max_header_list_size(256 * 1024_u32)
        .initial_connection_window_size(15 * 1024 * 1024_u32)
        .settings_order(SETTINGS_BY_ID)
        // The wire carries weight minus one: 255 is weight 256.
        .headers_priority(StreamDependency::new(StreamId::zero(), 255, true))
        .headers_pseudo_order([
            PseudoOrder::Method,
            PseudoOrder::Authority,
            PseudoOrder::Scheme,
            PseudoOrder::Path,
        ])
        .build()
}

const CHROME_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,\
     image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";

const CHROME_HEADERS: [(&str, &str); 12] = [
    (
        "sec-ch-ua",
        "\"Chromium\";v=\"148\", \"Google Chrome\";v=\"148\", \"Not/A)Brand\";v=\"99\"",
    ),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", "\"Windows\""),
    ("upgrade-insecure-requests", "1"),
    ("accept", CHROME_ACCEPT),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-user", "?1"),
    ("sec-fetch-dest", "document"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("accept-language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
];

const EDGE_HEADERS: [(&str, &str); 12] = [
    (
        "sec-ch-ua",
        "\"Chromium\";v=\"148\", \"Microsoft Edge\";v=\"148\", \"Not/A)Brand\";v=\"99\"",
    ),
    ("sec-ch-ua-mobile", "?0"),
    ("sec-ch-ua-platform", "\"Windows\""),
    ("upgrade-insecure-requests", "1"),
    ("accept", CHROME_ACCEPT),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-user", "?1"),
    ("sec-fetch-dest", "document"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("accept-language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
];

static CHROMIUM_HEADER_ORDER: [HeaderName; 14] = [
    HeaderName::from_static("sec-ch-ua"),
    HeaderName::from_static("sec-ch-ua-mobile"),
    HeaderName::from_static("sec-ch-ua-platform"),
    HeaderName::from_static("upgrade-insecure-requests"),
    HeaderName::from_static("user-agent"),
    HeaderName::from_static("accept"),
    HeaderName::from_static("sec-fetch-site"),
    HeaderName::from_static("sec-fetch-mode"),
    HeaderName::from_static("sec-fetch-user"),
    HeaderName::from_static("sec-fetch-dest"),
    HeaderName::from_static("accept-encoding"),
    HeaderName::from_static("accept-language"),
    HeaderName::from_static("cookie"),
    HeaderName::from_static("priority"),
];

// ---------------------------------------------------------------------------
// Firefox 158
//
// TLS, from Firefox 158.0 (tag FIREFOX_158_0_RELEASE) and the NSS it bundles:
//   * Cipher suites: the pref-enabled entries of sCipherPrefs
//     (security/manager/ssl/nsNSSComponent.cpp, defaults in
//     modules/libpref/init/StaticPrefList.yaml; both ECDHE_ECDSA CBC suites and
//     the DHE suites are off), sent in the order of NSS's cipherSuites table
//     (security/nss/lib/ssl/ssl3con.c). That puts ChaCha20 before AES-256 among
//     the TLS 1.3 suites.
//   * Extensions in the fixed order of clientHelloSendersTLS
//     (security/nss/lib/ssl/ssl3ext.c), with ECH GREASE last
//     (security.tls.ech.grease_probability = 100). No GREASE, no shuffling.
//   * Groups X25519MLKEM768, X25519, P-256, P-384, P-521, and key shares for the
//     first three (nsSSLIOLayerSetOptions in security/manager/ssl/nsNSSIOLayer.cpp;
//     FFDHE is left out because no DHE suite is on).
//   * Signature algorithms FOR_EACH_ENABLED_SIGNATURE_SCHEME
//     (security/manager/ssl/EnabledSignatureSchemes.h) as NSS filters them. The
//     ML-DSA entries at the end of that list are not sent by release builds: the
//     published JA4 below has none.
//   * Delegated credentials for the schemes left after NSS drops PKCS#1 and
//     RSAE for TLS 1.3 (tls13_ClientSendDelegatedCredentialsXtn in
//     security/nss/lib/ssl/tls13exthandle.c); record_size_limit 16385
//     (MAX_FRAGMENT_LENGTH + 1, security/nss/lib/ssl/sslsock.c); certificate
//     compression zlib, brotli, zstd; OCSP stapling and SCTs requested.
//
// A capture of Firefox 158.0 on Linux made for this module sent exactly this
// ClientHello. Published JA4: t13d1517h2_8daaf6152771_3cbfd9057e0d, which the
// scrapfly.io JA4 database attributes to Firefox 154 to 158 on Windows, macOS
// and Linux (retrieved 2026-10-17).
//
// HTTP/2, from netwerk/protocol/http/Http2Session.cpp (SendHello and the
// constructor) and netwerk/protocol/http/ASpdySession.h: HEADER_TABLE_SIZE
// 65536, ENABLE_PUSH 0, INITIAL_WINDOW_SIZE 131072 (network.http.http2.push-allowance),
// MAX_FRAME_SIZE 16384, in that order; the session window raised to 12 MB
// (network.http.http2.pull-allowance); no PRIORITY frames, because
// network.http.http2.enabled.deps is false; the first stream is 3, because 1 is
// reserved for an Upgrade. HEADERS always carries a priority
// (netwerk/protocol/http/Http2StreamBase.cpp): stream 0, not exclusive, and a
// weight byte of 41 for a top-level load at PRIORITY_HIGHEST. Pseudo-headers
// :method, :path, :authority, :scheme (netwerk/protocol/http/Http2Compression.cpp).
// Published Akamai fingerprint for Firefox:
// 1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s (krowdev.com, as above).
//
// Headers: the Firefox 158.0 capture, with Sec-Fetch-User added after
// Sec-Fetch-Site the way a user-started navigation sends it (curl-impersonate,
// tests/signatures/firefox_144.0.0_linux.yaml). Accept comes from
// nsHttpHandler.cpp, Accept-Encoding from network.http.accept-encoding.secure in
// modules/libpref/init/all.js, and the User-Agent from nsHttpHandler.cpp
// (OSCPU_WIN64 and "rv:" with the frozen Gecko/20100101).
// ---------------------------------------------------------------------------

const FIREFOX_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0";

const FIREFOX_CIPHERS: [&str; 15] = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
];

const FIREFOX_GROUPS: &[SslCurve] = &[
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
    SslCurve::SECP521R1,
];

const FIREFOX_SIGALGS: [&str; 11] = [
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "ecdsa_sha1",
    "rsa_pkcs1_sha1",
];

const FIREFOX_DELEGATED_CREDENTIALS: [&str; 4] = [
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "ecdsa_sha1",
];

static FIREFOX_EXTENSIONS: [u8; 17] = extension_order([
    ExtensionType::SERVER_NAME,
    ExtensionType::EXTENDED_MASTER_SECRET,
    ExtensionType::RENEGOTIATE,
    ExtensionType::SUPPORTED_GROUPS,
    ExtensionType::EC_POINT_FORMATS,
    ExtensionType::SESSION_TICKET,
    ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
    ExtensionType::STATUS_REQUEST,
    ExtensionType::DELEGATED_CREDENTIAL,
    ExtensionType::CERTIFICATE_TIMESTAMP,
    ExtensionType::KEY_SHARE,
    ExtensionType::SUPPORTED_VERSIONS,
    ExtensionType::SIGNATURE_ALGORITHMS,
    ExtensionType::PSK_KEY_EXCHANGE_MODES,
    ExtensionType::RECORD_SIZE_LIMIT,
    ExtensionType::CERT_COMPRESSION,
    ExtensionType::ENCRYPTED_CLIENT_HELLO,
]);

const FIREFOX_CERT_COMPRESSION: &[CertCompressionAlgorithm] = &[
    CertCompressionAlgorithm::Zlib,
    CertCompressionAlgorithm::Brotli,
    CertCompressionAlgorithm::Zstd,
];

fn firefox_tls() -> TlsConfig {
    TlsConfig::builder()
        .grease_enabled(false)
        .permute_extensions(false)
        .extension_permutation_indices(&FIREFOX_EXTENSIONS[..])
        .cipher_list(FIREFOX_CIPHERS.join(":"))
        .curves(FIREFOX_GROUPS)
        .key_shares_limit(3_u8)
        .sigalgs_list(FIREFOX_SIGALGS.join(":"))
        .delegated_credentials(FIREFOX_DELEGATED_CREDENTIALS.join(":"))
        .record_size_limit(0x4001_u16)
        .cert_compression_algorithm(FIREFOX_CERT_COMPRESSION)
        .alpn_protos(AlpnProtos::ALL)
        .enable_ech_grease(true)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        // Firefox resumes sessions (security.ssl.disable_session_identifiers is
        // false by default).
        .pre_shared_key(true)
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .build()
}

fn firefox_http2() -> Http2Config {
    Http2Config::builder()
        .initial_stream_id(3_u32)
        .header_table_size(65_536_u32)
        .enable_push(false)
        .initial_stream_window_size(131_072_u32)
        .max_frame_size(16_384_u32)
        .initial_connection_window_size(12 * 1024 * 1024_u32)
        .settings_order(SETTINGS_BY_ID)
        .headers_priority(StreamDependency::new(StreamId::zero(), 41, false))
        .headers_pseudo_order([
            PseudoOrder::Method,
            PseudoOrder::Path,
            PseudoOrder::Authority,
            PseudoOrder::Scheme,
        ])
        .build()
}

const FIREFOX_HEADERS: [(&str, &str); 10] = [
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ),
    ("accept-language", "en-US,en;q=0.9"),
    ("accept-encoding", "gzip, deflate, br, zstd"),
    ("upgrade-insecure-requests", "1"),
    ("sec-fetch-dest", "document"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-site", "none"),
    ("sec-fetch-user", "?1"),
    ("priority", "u=0, i"),
    ("te", "trailers"),
];

static FIREFOX_HEADER_ORDER: [HeaderName; 11] = [
    HeaderName::from_static("user-agent"),
    HeaderName::from_static("accept"),
    HeaderName::from_static("accept-language"),
    HeaderName::from_static("accept-encoding"),
    HeaderName::from_static("upgrade-insecure-requests"),
    HeaderName::from_static("sec-fetch-dest"),
    HeaderName::from_static("sec-fetch-mode"),
    HeaderName::from_static("sec-fetch-site"),
    HeaderName::from_static("sec-fetch-user"),
    HeaderName::from_static("priority"),
    HeaderName::from_static("te"),
];

// ---------------------------------------------------------------------------
// Safari 26 on macOS 26
//
// Safari's TLS and HTTP/2 stack is closed, so every value here is from
// published captures of the real browser:
//   * The ClientHello and the HTTP/2 frames of Safari 26.0.1 on macOS
//     (lexiforest/curl-impersonate, tests/signatures/safari_26.0.1_macOS.yaml,
//     MIT): GREASE on; cipher suites in the order below, AES-256 first among
//     the TLS 1.3 suites as on macOS (safari_26.0_macOS.yaml has the same);
//     extensions in a fixed order with no session_ticket and no padding, which
//     the 1216-byte X25519MLKEM768 key share makes unnecessary; groups
//     X25519MLKEM768, X25519, P-256, P-384, P-521 with key shares for the first
//     two; signature algorithms with rsa_pss_rsae_sha384 twice, as Safari sends
//     them; zlib certificate compression; TLS 1.2 to 1.3.
//   * JA4 t13d2013h2_a09f3c656075_7f0f34a4126d, which the scrapfly.io JA4
//     database attributes to Safari 26 and 27 on macOS and iOS and the
//     usefoil.com JA4 database lists as Safari (both retrieved 2026-10-17).
//   * Akamai fingerprint 2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p, from Safari
//     26.3 on a Mac observed on tls.browserleaks.com (lexiforest/curl-impersonate
//     issue 220), the same SETTINGS, window and pseudo-header order as the
//     26.0.1 capture.
//
// SETTINGS_NO_RFC7540_PRIORITIES (9) = 1 tells the server the client does not
// use RFC 7540 priority signals (RFC 9218 section 2.1), so HEADERS carries no
// priority. The headers, their values and their order are the 26.0.1 capture's.
// The User-Agent names Safari 26.6, which shipped with macOS 26.6 on 2026-07-27
// (support.apple.com/en-us/100100), and keeps the capture's 10_15_7 as the macOS
// version.
// ---------------------------------------------------------------------------

const SAFARI_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
     (KHTML, like Gecko) Version/26.6 Safari/605.1.15";

const SAFARI_CIPHERS: [&str; 20] = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
];

const SAFARI_GROUPS: &[SslCurve] = &[
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
    SslCurve::SECP521R1,
];

const SAFARI_SIGALGS: [&str; 10] = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512",
    "rsa_pkcs1_sha1",
];

static SAFARI_EXTENSIONS: [u8; 13] = extension_order([
    ExtensionType::SERVER_NAME,
    ExtensionType::EXTENDED_MASTER_SECRET,
    ExtensionType::RENEGOTIATE,
    ExtensionType::SUPPORTED_GROUPS,
    ExtensionType::EC_POINT_FORMATS,
    ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
    ExtensionType::STATUS_REQUEST,
    ExtensionType::SIGNATURE_ALGORITHMS,
    ExtensionType::CERTIFICATE_TIMESTAMP,
    ExtensionType::KEY_SHARE,
    ExtensionType::PSK_KEY_EXCHANGE_MODES,
    ExtensionType::SUPPORTED_VERSIONS,
    ExtensionType::CERT_COMPRESSION,
]);

fn safari_tls() -> TlsConfig {
    TlsConfig::builder()
        .grease_enabled(true)
        .permute_extensions(false)
        .extension_permutation_indices(&SAFARI_EXTENSIONS[..])
        .cipher_list(SAFARI_CIPHERS.join(":"))
        .curves(SAFARI_GROUPS)
        .sigalgs_list(SAFARI_SIGALGS.join(":"))
        .cert_compression_algorithm(CertCompressionAlgorithm::Zlib)
        .alpn_protos(AlpnProtos::ALL)
        .enable_ocsp_stapling(true)
        .enable_signed_cert_timestamps(true)
        .pre_shared_key(true)
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .build()
}

fn safari_http2() -> Http2Config {
    Http2Config::builder()
        .enable_push(false)
        .max_concurrent_streams(100_u32)
        .initial_stream_window_size(2 * 1024 * 1024_u32)
        .unknown_setting9(true)
        .initial_connection_window_size(10 * 1024 * 1024_u32)
        .settings_order([
            SettingsOrder::EnablePush,
            SettingsOrder::MaxConcurrentStreams,
            SettingsOrder::InitialWindowSize,
            SettingsOrder::UnknownSetting9,
            SettingsOrder::HeaderTableSize,
            SettingsOrder::MaxFrameSize,
            SettingsOrder::MaxHeaderListSize,
            SettingsOrder::UnknownSetting8,
        ])
        .headers_pseudo_order([
            PseudoOrder::Method,
            PseudoOrder::Scheme,
            PseudoOrder::Authority,
            PseudoOrder::Path,
        ])
        .build()
}

const SAFARI_HEADERS: [(&str, &str); 7] = [
    ("sec-fetch-dest", "document"),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("accept-language", "en-US,en;q=0.9"),
    ("priority", "u=0, i"),
    ("accept-encoding", "gzip, deflate, br"),
];

static SAFARI_HEADER_ORDER: [HeaderName; 8] = [
    HeaderName::from_static("sec-fetch-dest"),
    HeaderName::from_static("user-agent"),
    HeaderName::from_static("accept"),
    HeaderName::from_static("sec-fetch-site"),
    HeaderName::from_static("sec-fetch-mode"),
    HeaderName::from_static("accept-language"),
    HeaderName::from_static("priority"),
    HeaderName::from_static("accept-encoding"),
];

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Browser; 4] = [
        Browser::Chrome,
        Browser::Edge,
        Browser::Firefox,
        Browser::Safari,
    ];

    /// RFC 9113 section 6.9.2: a connection's flow-control window starts at
    /// 65,535 octets, and the WINDOW_UPDATE on stream 0 raises it from there.
    const H2_DEFAULT_WINDOW: u32 = 65_535;

    #[test]
    fn user_agent_picks_the_family() {
        let cases = [
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/138.0.0.0 Safari/537.36",
                Some(Browser::Chrome),
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
                Some(Browser::Edge),
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
                Some(Browser::Firefox),
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
                 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
                Some(Browser::Safari),
            ),
            // An Android WebView carries both Version/ and Chrome/.
            (
                "Mozilla/5.0 (Linux; Android 10; K; wv) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Version/4.0 Chrome/138.0.0.0 Mobile Safari/537.36",
                Some(Browser::Chrome),
            ),
            ("Crossfyre-FreeTools/1.0", None),
            ("", None),
        ];
        for (ua, want) in cases {
            assert_eq!(Browser::from_user_agent(ua), want, "{ua}");
        }
    }

    #[test]
    fn each_profile_names_the_family_it_emulates() {
        for b in ALL {
            assert_eq!(Browser::from_user_agent(b.user_agent()), Some(b), "{b:?}");
        }
        assert!(CHROME_UA.contains("Chrome/148.0.0.0") && !CHROME_UA.contains("Edg/"));
        assert!(EDGE_UA.ends_with("Edg/148.0.0.0"));
        assert!(FIREFOX_UA.contains("rv:158.0") && FIREFOX_UA.ends_with("Firefox/158.0"));
        assert!(SAFARI_UA.contains("Version/26.6"));
    }

    #[test]
    fn headers_are_coherent_with_the_user_agent() {
        for b in ALL {
            let h = b.default_headers();
            assert_eq!(h.get("user-agent").unwrap(), b.user_agent());
            // Only Chromium sends client hints, and only its brand.
            let ch = h.get("sec-ch-ua").map(|v| v.to_str().unwrap().to_owned());
            match b {
                Browser::Chrome => {
                    let ch = ch.unwrap();
                    assert!(ch.contains("\"Google Chrome\";v=\"148\""));
                    assert!(!ch.contains("Edge"));
                }
                Browser::Edge => {
                    let ch = ch.unwrap();
                    assert!(ch.contains("\"Microsoft Edge\";v=\"148\""));
                    assert!(!ch.contains("Google"));
                }
                Browser::Firefox | Browser::Safari => assert_eq!(ch, None, "{b:?}"),
            }
            // Every header a profile sends has a place in its order.
            for name in h.keys() {
                assert!(
                    b.header_order().contains(name),
                    "{b:?} sends {name} without a place for it"
                );
            }
        }
        // Safari does not advertise zstd; the others do.
        assert_eq!(
            Browser::Safari.default_headers()["accept-encoding"],
            "gzip, deflate, br"
        );
        assert_eq!(
            Browser::Firefox.default_headers()["accept-encoding"],
            "gzip, deflate, br, zstd"
        );
    }

    #[test]
    fn chromium_brand_list_is_the_greased_one_for_148() {
        // GenerateBrandVersionList with seed 148: greasy characters
        // [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"] at 148 % 11 = 5
        // and 149 % 11 = 6, version ["8", "99", "24"][148 % 3], and permutation
        // {2, 0, 1} (148 % 6 = 4), which puts the greased brand last.
        let chars = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
        let seed = 148usize;
        let brand = format!(
            "Not{}A{}Brand",
            chars[seed % chars.len()],
            chars[(seed + 1) % chars.len()]
        );
        let version = ["8", "99", "24"][seed % 3];
        assert_eq!(brand, "Not/A)Brand");
        assert_eq!(version, "99");
        let header = Browser::Chrome.default_headers()["sec-ch-ua"]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(header.ends_with(&format!("\"{brand}\";v=\"{version}\"")));
    }

    #[test]
    fn tls_settings_follow_each_browser() {
        let chrome = Browser::Chrome.tls();
        assert_eq!(chrome.grease_enabled, Some(true));
        assert_eq!(chrome.permute_extensions, Some(true));
        assert!(chrome.extension_permutation_indices.is_none());
        assert_eq!(
            chrome.cipher_list.as_deref(),
            Some(CHROMIUM_CIPHERS.join(":").as_str())
        );
        assert_eq!(chrome.curves.as_deref(), Some(CHROMIUM_GROUPS));
        assert_eq!(chrome.alps_protos, Some(AlpsProtos::HTTP2));
        assert!(chrome.alps_use_new_codepoint && chrome.enable_ech_grease);
        assert!(chrome.delegated_credentials.is_none() && chrome.record_size_limit.is_none());
        assert_eq!(
            chrome.cert_compression_algorithm.as_deref(),
            Some(&[CertCompressionAlgorithm::Brotli][..])
        );

        let firefox = Browser::Firefox.tls();
        assert_eq!(firefox.grease_enabled, Some(false));
        assert_eq!(firefox.permute_extensions, Some(false));
        assert_eq!(
            firefox.extension_permutation_indices.as_deref(),
            Some(&FIREFOX_EXTENSIONS[..])
        );
        assert_eq!(firefox.key_shares_limit, Some(3));
        assert_eq!(firefox.record_size_limit, Some(16_385));
        assert_eq!(
            firefox.delegated_credentials.as_deref(),
            Some(FIREFOX_DELEGATED_CREDENTIALS.join(":").as_str())
        );
        assert!(firefox.alps_protos.is_none() && firefox.enable_ech_grease);
        assert_eq!(
            firefox.cert_compression_algorithm.as_deref(),
            Some(FIREFOX_CERT_COMPRESSION)
        );

        let safari = Browser::Safari.tls();
        assert_eq!(safari.grease_enabled, Some(true));
        assert_eq!(
            safari.extension_permutation_indices.as_deref(),
            Some(&SAFARI_EXTENSIONS[..])
        );
        assert!(safari.alps_protos.is_none() && !safari.enable_ech_grease);
        assert!(safari.key_shares_limit.is_none());
        assert_eq!(
            safari.cert_compression_algorithm.as_deref(),
            Some(&[CertCompressionAlgorithm::Zlib][..])
        );

        for b in ALL {
            let t = b.tls();
            assert!(t.session_ticket, "{b:?}");
            assert!(t.pre_shared_key, "{b:?}");
        }
    }

    #[test]
    fn fixed_extension_orders_leave_out_what_the_browser_does_not_send() {
        let at = |e: ExtensionType| ExtensionType::index_of(e).unwrap() as u8;
        // Safari sends no session_ticket, ECH or ALPS; Firefox no ALPS.
        for e in [
            ExtensionType::SESSION_TICKET,
            ExtensionType::ENCRYPTED_CLIENT_HELLO,
            ExtensionType::APPLICATION_SETTINGS,
            ExtensionType::APPLICATION_SETTINGS_NEW,
        ] {
            assert!(!SAFARI_EXTENSIONS.contains(&at(e)));
        }
        assert!(!FIREFOX_EXTENSIONS.contains(&at(ExtensionType::APPLICATION_SETTINGS_NEW)));
        // Firefox ends on ECH GREASE.
        assert_eq!(
            FIREFOX_EXTENSIONS.last(),
            Some(&at(ExtensionType::ENCRYPTED_CLIENT_HELLO))
        );
    }

    #[test]
    fn http2_settings_follow_each_browser() {
        let c = Browser::Chrome.http2();
        assert_eq!(c.header_table_size, Some(65_536));
        assert_eq!(c.enable_push, Some(false));
        assert_eq!(c.initial_stream_window_size, Some(6_291_456));
        assert_eq!(c.max_header_list_size, Some(262_144));
        assert_eq!(c.max_concurrent_streams, None);
        assert_eq!(c.max_frame_size, None);
        assert_eq!(
            c.initial_connection_window_size
                .map(|w| w - H2_DEFAULT_WINDOW),
            Some(15_663_105)
        );
        assert_eq!(
            c.headers_priority,
            Some(StreamDependency::new(StreamId::zero(), 255, true))
        );
        assert_eq!(c.initial_stream_id, None);

        let f = Browser::Firefox.http2();
        assert_eq!(f.initial_stream_id, Some(3));
        assert_eq!(f.header_table_size, Some(65_536));
        assert_eq!(f.initial_stream_window_size, Some(131_072));
        assert_eq!(f.max_frame_size, Some(16_384));
        assert_eq!(f.max_header_list_size, None);
        assert_eq!(
            f.initial_connection_window_size
                .map(|w| w - H2_DEFAULT_WINDOW),
            Some(12_517_377)
        );
        assert_eq!(
            f.headers_priority,
            Some(StreamDependency::new(StreamId::zero(), 41, false))
        );

        let s = Browser::Safari.http2();
        assert_eq!(s.enable_push, Some(false));
        assert_eq!(s.max_concurrent_streams, Some(100));
        assert_eq!(s.initial_stream_window_size, Some(2_097_152));
        assert_eq!(s.unknown_setting9, Some(true));
        assert_eq!(s.header_table_size, None);
        assert_eq!(
            s.initial_connection_window_size
                .map(|w| w - H2_DEFAULT_WINDOW),
            Some(10_420_225)
        );
        assert_eq!(s.headers_priority, None);

        for b in ALL {
            assert!(b.http2().priority.is_none(), "{b:?} sends PRIORITY frames");
        }
    }
}
