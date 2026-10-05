//! HTTP(S) callback capture. A catch-all fallback logs every inbound request that
//! targets our OAST domain, keyed by the Host header (which carries the token).

use crate::Config;
use crate::poll::{Ctx, api_router};
use crate::store::{Interaction, Store, now_unix};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::Request,
    response::IntoResponse,
};
use std::net::SocketAddr;
use std::sync::Arc;

pub async fn serve(
    cfg: Config,
    store: Arc<Store>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr: SocketAddr = cfg.http_addr.parse()?;
    let ctx = Ctx {
        cfg,
        store,
        scheme: "http",
    };
    let app = Router::new().fallback(capture).with_state(ctx);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("oast http capture on {addr}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// HTTPS listener on 443 using the wildcard cert. Serves both the control-plane
/// API (register/poll/deregister at `https://api.<domain>/...`) and the callback
/// capture fallback (blind SSRF/RCE payloads increasingly target `https://`, and a
/// valid cert avoids TLS errors that would abort the client before it is logged).
pub async fn serve_https(
    cfg: Config,
    store: Arc<Store>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(server_config) = crate::tls::build_server_config(
        cfg.tls_cert.as_deref(),
        cfg.tls_key.as_deref(),
        cfg.tls_certs.as_deref(),
    ) else {
        return Ok(()); // No usable cert; nothing to serve.
    };
    let addr: SocketAddr = cfg.https_addr.parse()?;
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(server_config);
    let ctx = Ctx {
        cfg,
        store,
        scheme: "https",
    };
    let app = api_router().fallback(capture).with_state(ctx);
    tracing::info!("oast https api+capture on {addr}");
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

async fn capture(
    State(ctx): State<Ctx>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> impl IntoResponse {
    let (parts, body) = req.into_parts();
    let method = parts.method.to_string();
    let uri = parts.uri.to_string();
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let full_host = host
        .split(':')
        .next()
        .unwrap_or(&host)
        .trim()
        .to_ascii_lowercase();

    let mut raw = format!("{method} {uri}\n");
    for (k, v) in parts.headers.iter() {
        raw.push_str(k.as_str());
        raw.push_str(": ");
        raw.push_str(v.to_str().unwrap_or(""));
        raw.push('\n');
    }
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .unwrap_or_else(|_| Bytes::new());
    if !bytes.is_empty() {
        raw.push('\n');
        raw.push_str(&String::from_utf8_lossy(&bytes));
    }

    // Match the callback to a registered correlation id; unregistered / off-domain
    // hosts are dropped by capture().
    if let Some(corr) = crate::store::corr_from_any(&full_host, &ctx.cfg.domains) {
        ctx.store.capture(
            &corr,
            &Interaction {
                protocol: ctx.scheme.to_string(),
                full_host,
                remote_addr: peer.ip().to_string(),
                at_unix: now_unix(),
                detail: format!("{method} {uri}"),
                raw,
            },
        );
    }

    ([("content-type", "text/plain")], "ok")
}
