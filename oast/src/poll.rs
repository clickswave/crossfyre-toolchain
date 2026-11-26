//! Control-plane-facing API: register a correlation id (+ public key + secret),
//! poll for sealed interactions, deregister. Reached by the Crossfyre control
//! plane / node. Register + poll are gated by the per-correlation secret
//! (anti-drain); the interactions themselves are already sealed to the client's
//! key, so this service holds no plaintext and can be internet-reachable. The
//! secret always travels in a JSON body, never in a URL, which proxies and access
//! logs keep.

use crate::Config;
use crate::store::Store;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;

/// Shared state for the control-plane API and the callback-capture fallback. Both
/// live on the same HTTPS listener in production (one wildcard cert, standard 443),
/// so they must share a state type. `scheme` labels captured interactions.
#[derive(Clone)]
pub struct Ctx {
    pub cfg: Config,
    pub store: Arc<Store>,
    pub scheme: &'static str,
}

/// Build the control-plane API routes (register/poll/deregister/config/health).
/// The caller adds a capture fallback and picks the listener (plaintext or TLS).
pub fn api_router() -> Router<Ctx> {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/config", get(config))
        .route("/register", post(register))
        .route("/poll", post(poll))
        .route("/deregister", post(deregister))
}

pub async fn serve(
    cfg: Config,
    store: Arc<Store>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = cfg.poll_addr.parse()?;
    let ctx = Ctx {
        cfg,
        store,
        scheme: "http",
    };
    let app = api_router().with_state(ctx);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("oast api on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn config(State(ctx): State<Ctx>) -> Json<Value> {
    Json(json!({ "domain": ctx.cfg.domain, "corr_len": crate::store::CORR_LEN }))
}

#[derive(Deserialize)]
struct RegisterInput {
    corr_id: String,
    /// base64 PKCS#1 DER RSA public key.
    pubkey: String,
    secret: String,
}

async fn register(State(ctx): State<Ctx>, Json(p): Json<RegisterInput>) -> Json<Value> {
    let ok = ctx.store.register(&p.corr_id, &p.pubkey, &p.secret);
    Json(json!({ "ok": ok, "domain": ctx.cfg.domain }))
}

#[derive(Deserialize)]
struct PollInput {
    corr_id: String,
    secret: String,
}

async fn poll(State(ctx): State<Ctx>, Json(p): Json<PollInput>) -> Json<Value> {
    match ctx.store.poll(&p.corr_id, &p.secret) {
        Some(items) => Json(json!({ "ok": true, "count": items.len(), "interactions": items })),
        None => Json(json!({ "ok": false, "error": "unknown correlation id or bad secret" })),
    }
}

#[derive(Deserialize)]
struct DeregInput {
    corr_id: String,
    secret: String,
}

async fn deregister(State(ctx): State<Ctx>, Json(p): Json<DeregInput>) -> Json<Value> {
    Json(json!({ "ok": ctx.store.deregister(&p.corr_id, &p.secret) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// The API on a loopback port of its own, with a correlation registered under
    /// `secret` and one interaction captured for it.
    async fn api_with_one_interaction(corr: &str, secret: &str) -> u16 {
        use base64::Engine as _;
        use rsa::pkcs1::EncodeRsaPublicKey;
        let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("a key");
        let der = key.to_public_key().to_pkcs1_der().expect("der");
        let pubkey = base64::engine::general_purpose::STANDARD.encode(der.as_bytes());
        let store = Arc::new(Store::new(600));
        assert!(store.register(corr, &pubkey, secret));
        store.capture(
            corr,
            &crate::store::Interaction {
                protocol: "dns".into(),
                full_host: format!("{corr}x.oast.example"),
                remote_addr: "192.0.2.1".into(),
                at_unix: crate::store::now_unix(),
                detail: String::new(),
                raw: String::new(),
            },
        );
        let ctx = Ctx {
            cfg: Config::new(vec!["oast.example".into()], [127, 0, 0, 1]),
            store,
            scheme: "http",
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, api_router().with_state(ctx)).await;
        });
        port
    }

    /// One HTTP/1.1 exchange, returning the response's status line and body.
    async fn exchange(port: u16, request: String) -> (String, String) {
        tokio::task::spawn_blocking(move || {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
            s.write_all(request.as_bytes()).expect("send");
            let mut out = String::new();
            s.read_to_string(&mut out).expect("read");
            let status = out.lines().next().unwrap_or("").to_string();
            let body = out.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            (status, body)
        })
        .await
        .expect("join")
    }

    const CORR: &str = "abcdefghij0123456789";

    /// The secret goes in the body of a POST, where a request line written to an access
    /// log does not carry it. The query string no longer authorises a poll.
    #[tokio::test]
    async fn a_poll_takes_its_secret_in_the_body_and_not_the_url() {
        let port = api_with_one_interaction(CORR, "s3cret").await;

        let body = format!(r#"{{"corr_id":"{CORR}","secret":"s3cret"}}"#);
        let (status, answer) = exchange(
            port,
            format!(
                "POST /poll HTTP/1.1\r\nHost: api\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
        .await;
        assert!(status.contains(" 200 "), "{status}");
        let v: Value = serde_json::from_str(&answer).expect("json");
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["count"], 1, "{v}");

        let (status, answer) = exchange(
            port,
            format!(
                "GET /poll?corr_id={CORR}&secret=s3cret HTTP/1.1\r\nHost: api\r\n\
                 Connection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(
            !answer.contains("interactions"),
            "a poll was answered from the query string: {status} {answer}"
        );
    }
}
