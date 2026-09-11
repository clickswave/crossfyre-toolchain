use crate::engine::{self, ScanParams};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::mpsc;

#[derive(Debug, Deserialize)]
struct DaemonRequest {
    operation: String,
    #[serde(default = "default_response")]
    #[allow(dead_code)]
    response: String,
    #[serde(flatten)]
    params: Value,
}
fn default_response() -> String {
    "stream".to_string()
}

pub async fn run(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    // Loopback unless an operator opts out: this channel has no per-request
    // credential of its own, so the bind address is the boundary.
    let addr = dguard::bind_addr(port);
    let gate = dguard::Gate::from_env();
    let listener = TcpListener::bind(addr).await?;
    gate.announce("Cortex", addr);

    loop {
        let (stream, addr) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let gate_clone = gate.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, gate_clone).await {
                eprintln!("Connection error from {addr}: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    gate: dguard::Gate,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        // The bind address is the primary boundary. This is the second one, for
        // deployments that used CFX_DAEMON_BIND to move the listener off loopback;
        // with no token configured it is a no-op.
        if !gate.allows(
            serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .as_ref()
                .and_then(|v| v.get("token"))
                .and_then(|t| t.as_str()),
        ) {
            let _ = writer
                .write_all(b"{\"status\":\"error\",\"error\":\"unauthorized\"}\n")
                .await;
            continue;
        }

        let req: DaemonRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_line(
                    &mut writer,
                    &serde_json::json!({
                        "type": "error",
                        "message": format!("Invalid JSON: {}", e),
                    }),
                )
                .await?;
                continue;
            }
        };

        match req.operation.as_str() {
            "scan" => {
                handle_scan(req.params, &mut writer).await?;
                return Ok(());
            }
            "authz" => {
                handle_authz(req.params, &mut writer).await?;
                return Ok(());
            }
            "inject" => {
                handle_inject(req.params, &mut writer).await?;
                return Ok(());
            }
            "discover" => {
                handle_discover(req.params, &mut writer).await?;
                return Ok(());
            }
            "fuzz" => {
                handle_fuzz(req.params, &mut writer).await?;
                return Ok(());
            }
            "graphql" => {
                handle_graphql(req.params, &mut writer).await?;
                return Ok(());
            }
            "flow" => {
                handle_flow(req.params, &mut writer).await?;
                return Ok(());
            }
            other => {
                write_line(
                    &mut writer,
                    &serde_json::json!({
                        "type": "error",
                        "message": format!("Unknown operation: {}", other),
                    }),
                )
                .await?;
            }
        }
    }

    Ok(())
}

async fn handle_scan(
    params: Value,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let sp: ScanParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            write_line(
                writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid scan params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        engine::run(sp, tx).await;
    });

    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

async fn handle_authz(
    params: Value,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ap: crate::authz::AuthzParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            write_line(
                writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid authz params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        crate::authz::run(ap, tx).await;
    });

    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

async fn handle_graphql(
    params: Value,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let gp: crate::graphql::GraphqlParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            write_line(
                writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid graphql params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        crate::graphql::run(gp, tx).await;
    });
    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

async fn handle_inject(
    params: Value,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ip: crate::inject::InjectParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            write_line(
                writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid inject params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        crate::inject::run(ip, tx).await;
    });

    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

async fn handle_discover(
    params: Value,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dp: crate::discover::DiscoverParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            write_line(
                writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid discover params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        crate::discover::run(dp, tx).await;
    });

    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

async fn handle_fuzz(
    params: Value,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fp: crate::fuzz::FuzzParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            write_line(
                writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid fuzz params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        crate::fuzz::run(fp, tx).await;
    });

    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

/// Replay a recorded multi-step flow and test its order. See `flow`.
async fn handle_flow(
    params: Value,
    writer: &mut OwnedWriteHalf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let fp: crate::flow::FlowParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            write_line(
                writer,
                &serde_json::json!({
                    "type": "error",
                    "message": format!("Invalid flow params: {}", e),
                }),
            )
            .await?;
            return Ok(());
        }
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    tokio::spawn(async move {
        crate::flow::run(fp, tx).await;
    });

    while let Some(ev) = rx.recv().await {
        write_line(writer, &ev).await?;
    }
    Ok(())
}

async fn write_line(
    writer: &mut OwnedWriteHalf,
    v: &Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut s = serde_json::to_string(v)?;
    s.push('\n');
    writer.write_all(s.as_bytes()).await?;
    Ok(())
}
