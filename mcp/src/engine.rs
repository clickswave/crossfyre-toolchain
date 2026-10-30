//! The engines' own daemon protocol, spoken from here the way the CLIs and the node
//! speak it: one JSON request line to `127.0.0.1:<port>`, then a stream of JSON event
//! lines back. Before the request, the daemon is asked which options it honours, so
//! an operation is never sent to one that would ignore the options that fence it.
//! The token, when the daemons require one, is stamped by `dguard::encode` from the
//! same variable the daemons read.

use crate::core::Clearance;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a daemon has to answer the capabilities question.
const CAPABILITIES_WAIT: Duration = Duration::from_secs(5);
/// An engine event longer than this is skipped, not buffered.
pub(crate) const LINE_MAX: usize = 4 * 1024 * 1024;

/// A connection to an engine daemon with no operation sent on it yet.
pub(crate) struct EngineConn {
    reader: LineReader,
    writer: OwnedWriteHalf,
}

/// Connect without sending, so a stopped daemon is found before a person is asked
/// to confirm anything.
pub(crate) async fn connect(port: u16) -> std::io::Result<EngineConn> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
    let _ = stream.set_nodelay(true);
    let (r, writer) = stream.into_split();
    Ok(EngineConn {
        reader: LineReader {
            inner: BufReader::new(r),
        },
        writer,
    })
}

/// Whether a daemon honours the options an operation is about to be sent with.
pub(crate) enum Support {
    Yes,
    /// It does not know the question, or knows it and lacks an option: a daemon from
    /// before these options, which would run the operation and ignore them.
    Old,
    /// No usable answer: the connection closed, the token was refused, or nothing
    /// came in time.
    Failed(String),
}

impl EngineConn {
    /// Ask whether the daemon honours every one of `options` for `operation`. Nothing
    /// is run by asking, on a daemon of any age, and the connection stays usable for
    /// the operation.
    pub(crate) async fn supports(&mut self, operation: &str, options: &[&str]) -> Support {
        let mut line = dguard::encode(&json!({"operation": "capabilities"}));
        line.push('\n');
        if let Err(e) = self.writer.write_all(line.as_bytes()).await {
            return Support::Failed(e.to_string());
        }
        let answer = tokio::time::timeout(CAPABILITIES_WAIT, async {
            loop {
                match self.reader.next().await {
                    Ok(Some(Line::Event(v))) => return Ok(v),
                    Ok(Some(_)) => continue,
                    Ok(None) => return Err("the connection closed".to_string()),
                    Err(e) => return Err(e.to_string()),
                }
            }
        })
        .await
        .unwrap_or_else(|_| Err("no answer in time".into()));
        let v = match answer {
            Ok(v) => v,
            Err(why) => return Support::Failed(why),
        };
        let message = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
        match event_type(&v) {
            "capabilities" => {
                let listed = v.get(operation).and_then(|o| o.as_array());
                let has = |o: &&str| listed.is_some_and(|l| l.iter().any(|x| x == *o));
                if options.iter().all(has) {
                    Support::Yes
                } else {
                    Support::Old
                }
            }
            "error" if message.starts_with("Unknown operation") => Support::Old,
            _ => Support::Failed(message.to_string()),
        }
    }

    /// Send the operation. Taking a [`Clearance`] is the point: the only way to put a
    /// request in front of an engine is to have been through the guard first.
    pub(crate) async fn start(
        mut self,
        _cleared: &Clearance,
        op: &Value,
    ) -> std::io::Result<(LineReader, EngineWriter)> {
        let mut line = dguard::encode(op);
        line.push('\n');
        self.writer.write_all(line.as_bytes()).await?;
        Ok((self.reader, EngineWriter { inner: self.writer }))
    }
}

/// The half of the connection that can still ask the engine to stop.
pub(crate) struct EngineWriter {
    inner: OwnedWriteHalf,
}

impl EngineWriter {
    pub(crate) async fn send_cancel(&mut self) -> std::io::Result<()> {
        let mut line = dguard::encode(&json!({"operation": "cancel"}));
        line.push('\n');
        self.inner.write_all(line.as_bytes()).await
    }
}

pub(crate) enum Line {
    Event(Value),
    /// Longer than [`LINE_MAX`]; skipped.
    TooLong,
    /// Not JSON; skipped.
    NotJson,
}

pub(crate) struct LineReader {
    inner: BufReader<OwnedReadHalf>,
}

impl LineReader {
    /// The next line, or `None` at the end of the stream. Never holds more than
    /// [`LINE_MAX`] bytes of one line, however long the engine's line is.
    pub(crate) async fn next(&mut self) -> std::io::Result<Option<Line>> {
        let mut acc: Vec<u8> = Vec::new();
        let mut too_long = false;
        loop {
            let buf = self.inner.fill_buf().await?;
            if buf.is_empty() {
                if acc.is_empty() && !too_long {
                    return Ok(None);
                }
                break;
            }
            let (take, found) = match buf.iter().position(|b| *b == b'\n') {
                Some(i) => (i, true),
                None => (buf.len(), false),
            };
            if !too_long {
                if acc.len() + take > LINE_MAX {
                    too_long = true;
                    acc.clear();
                } else {
                    acc.extend_from_slice(&buf[..take]);
                }
            }
            self.inner.consume(if found { take + 1 } else { take });
            if found {
                break;
            }
        }
        if too_long {
            return Ok(Some(Line::TooLong));
        }
        let text = String::from_utf8_lossy(&acc);
        let t = text.trim();
        if t.is_empty() {
            return Ok(Some(Line::NotJson));
        }
        Ok(Some(match serde_json::from_str::<Value>(t) {
            Ok(v) => Line::Event(v),
            Err(_) => Line::NotJson,
        }))
    }
}

pub(crate) fn event_type(v: &Value) -> &str {
    v.get("type").and_then(|t| t.as_str()).unwrap_or("")
}
