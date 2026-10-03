//! Control-plane-facing API: register a correlation id (+ public key + secret),
//! poll for sealed interactions, deregister. Reached by the Crossfyre control
//! plane / node. Register + poll are gated by the per-correlation secret
//! (anti-drain); the interactions themselves are already sealed to the client's
//! key, so this service holds no plaintext and can be internet-reachable.

use crate::Config;
use crate::store::Store;
use axum::{
    Json, Router,
    extract::{Query, State},
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
        .route("/poll", get(poll))
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
struct PollQuery {
    corr_id: String,
    secret: String,
}

async fn poll(State(ctx): State<Ctx>, Query(q): Query<PollQuery>) -> Json<Value> {
    match ctx.store.poll(&q.corr_id, &q.secret) {
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
