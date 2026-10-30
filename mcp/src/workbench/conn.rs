//! One connection to one Workbench: the handshake, requests matched to their answers by
//! id, and the events the Workbench sends unasked.

use super::Registry;
use cfx_bridge::{
    Call, CancelParams, ClientInfo, Endpoint, Event, Handshake, Hello, ProjectInfo, Response,
    ServerLine, Welcome,
};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::oneshot;

/// How long the socket has to accept and the Workbench to answer `hello`.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(2);

/// Why a request did not get a result.
#[derive(Debug)]
pub(crate) enum BridgeErr {
    /// The connection closed first.
    Closed,
    /// No answer in time. A `cancel` was sent.
    Timeout,
    /// The Workbench answered with an error.
    Remote(cfx_bridge::ErrorBody),
    /// The answer was not the shape the method has.
    Bad(String),
}

impl BridgeErr {
    /// A short sentence for `status`. The Workbench's own words are cleaned, since they
    /// can quote a target.
    pub(crate) fn describe(&self) -> String {
        match self {
            BridgeErr::Closed => "the connection closed".into(),
            BridgeErr::Timeout => "it did not answer in time".into(),
            BridgeErr::Remote(e) => format!(
                "it answered {}: {}",
                crate::untrusted::clean(e.code.as_str(), 40),
                crate::untrusted::clean(&e.message, 200)
            ),
            BridgeErr::Bad(why) => format!(
                "its answer could not be read ({})",
                crate::untrusted::clean(why, 200)
            ),
        }
    }
}

type Writer = Box<dyn AsyncWrite + Send + Unpin>;

pub(crate) struct Instance {
    pub pid: u32,
    pub welcome: Welcome,
    project: Mutex<Option<ProjectInfo>>,
    writer: tokio::sync::Mutex<Writer>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Response>>>,
    next_id: AtomicU64,
    closed: AtomicBool,
}

impl Instance {
    /// The open project, as the Workbench last said.
    pub(crate) fn project(&self) -> Option<ProjectInfo> {
        self.project.lock().ok().and_then(|p| p.clone())
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    async fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut w = self.writer.lock().await;
        w.write_all(line.as_bytes()).await?;
        w.flush().await
    }

    /// Send one request and wait for its answer. Dropping the future before the answer
    /// comes, as a cancelled tool call does, sends `cancel` for it.
    pub(crate) async fn request<T: DeserializeOwned>(
        self: &Arc<Self>,
        call: &Call,
        wait: Duration,
    ) -> Result<T, BridgeErr> {
        if self.is_closed() {
            return Err(BridgeErr::Closed);
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(id, tx);
        }
        let mut waiting = Unanswered {
            inst: Arc::clone(self),
            id,
            armed: true,
        };
        if self.write_line(&call.to_line(id)).await.is_err() {
            waiting.disarm();
            return Err(BridgeErr::Closed);
        }
        match tokio::time::timeout(wait, rx).await {
            Ok(Ok(resp)) => {
                waiting.disarm();
                resp.into_result::<T>().map_err(|e| {
                    if e.code == cfx_bridge::ErrorCode::Internal
                        && e.message.starts_with("unexpected result")
                    {
                        BridgeErr::Bad(e.message)
                    } else {
                        BridgeErr::Remote(e)
                    }
                })
            }
            Ok(Err(_)) => {
                waiting.disarm();
                Err(BridgeErr::Closed)
            }
            // `waiting` sends the cancel on its way out.
            Err(_) => Err(BridgeErr::Timeout),
        }
    }

    fn apply(&self, ev: &Event) {
        if let Event::Project { project } = ev
            && let Ok(mut p) = self.project.lock()
        {
            *p = project.clone();
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Dropping the senders wakes every waiting request with `Closed`.
        if let Ok(mut p) = self.pending.lock() {
            p.clear();
        }
    }
}

/// A request still waiting. When it is dropped while armed, the Workbench is told to
/// stop working on it.
struct Unanswered {
    inst: Arc<Instance>,
    id: u64,
    armed: bool,
}

impl Unanswered {
    fn disarm(&mut self) {
        self.armed = false;
        if let Ok(mut p) = self.inst.pending.lock() {
            p.remove(&self.id);
        }
    }
}

impl Drop for Unanswered {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut p) = self.inst.pending.lock() {
            p.remove(&self.id);
        }
        if self.inst.is_closed() {
            return;
        }
        // The cancel is a request of its own, with an id nothing waits on.
        let own = self.inst.next_id.fetch_add(1, Ordering::SeqCst);
        let line = Call::Cancel(CancelParams { id: self.id }).to_line(own);
        let inst = Arc::clone(&self.inst);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                let _ = inst.write_line(&line).await;
            });
        }
    }
}

/// A line from the Workbench, cut off rather than buffered past `max`.
enum Line {
    Text(String),
    TooLong,
}

async fn read_line<R: AsyncBufRead + Unpin>(
    r: &mut R,
    max: usize,
) -> std::io::Result<Option<Line>> {
    let mut acc: Vec<u8> = Vec::new();
    let mut too_long = false;
    loop {
        let buf = r.fill_buf().await?;
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
            if acc.len() + take > max {
                too_long = true;
                acc.clear();
            } else {
                acc.extend_from_slice(&buf[..take]);
            }
        }
        r.consume(if found { take + 1 } else { take });
        if found {
            break;
        }
    }
    if too_long {
        return Ok(Some(Line::TooLong));
    }
    Ok(Some(Line::Text(String::from_utf8_lossy(&acc).into_owned())))
}

/// Connect to the endpoint's socket, check that its other end is this user, and shake
/// hands. Every failure is a sentence for `status`.
#[cfg(unix)]
pub(crate) async fn connect(
    e: &Endpoint,
    client: ClientInfo,
    registry: Weak<Registry>,
) -> Result<Arc<Instance>, String> {
    let Some((socket, token)) = e.connectable() else {
        return Err("Agent access is off".into());
    };
    let stream = tokio::time::timeout(HANDSHAKE_WAIT, tokio::net::UnixStream::connect(socket))
        .await
        .map_err(|_| "the socket did not accept in time".to_string())?
        .map_err(|e| format!("the socket refused: {e}"))?;
    let peer = stream.peer_cred().ok().map(|c| c.uid());
    if !super::peer_allowed(peer, super::euid()) {
        return Err("the process on the socket is not this user's".into());
    }
    let (r, w) = stream.into_split();
    handshake(
        e.pid,
        token,
        client,
        BufReader::new(r),
        Box::new(w),
        registry,
    )
    .await
}

#[cfg(not(unix))]
pub(crate) async fn connect(
    _: &Endpoint,
    _: ClientInfo,
    _: Weak<Registry>,
) -> Result<Arc<Instance>, String> {
    Err("the Workbench bridge is not available on this platform".into())
}

#[cfg_attr(not(unix), allow(dead_code))]
async fn handshake<R>(
    pid: u32,
    token: &str,
    client: ClientInfo,
    mut r: R,
    mut w: Writer,
    registry: Weak<Registry>,
) -> Result<Arc<Instance>, String>
where
    R: AsyncBufRead + Unpin + Send + 'static,
{
    let hello = Handshake::Hello(Hello {
        protocol: cfx_bridge::PROTOCOL,
        token: token.to_string(),
        client,
    });
    w.write_all(cfx_bridge::to_line(&hello).as_bytes())
        .await
        .map_err(|e| format!("could not send hello: {e}"))?;
    w.flush().await.map_err(|e| e.to_string())?;
    let first = tokio::time::timeout(
        HANDSHAKE_WAIT,
        read_line(&mut r, cfx_bridge::MAX_RESPONSE_LINE),
    )
    .await
    .map_err(|_| "the Workbench did not answer hello in time".to_string())?
    .map_err(|e| e.to_string())?;
    let line = match first {
        Some(Line::Text(l)) => l,
        Some(Line::TooLong) => return Err("the Workbench's first line was too long".into()),
        None => {
            return Err(
                "the Workbench closed the connection without a welcome; the token in its \
                 endpoint file may be stale"
                    .into(),
            );
        }
    };
    let welcome = match serde_json::from_str::<Handshake>(&line) {
        Ok(Handshake::Welcome(w)) => w,
        Ok(Handshake::Refused(f)) => {
            return Err(format!(
                "the Workbench refused the connection ({})",
                f.code.as_str()
            ));
        }
        _ => return Err("the Workbench's first line was not a welcome".into()),
    };
    if welcome.protocol != cfx_bridge::PROTOCOL {
        return Err(format!(
            "the Workbench welcomed protocol {}, not {}",
            welcome.protocol,
            cfx_bridge::PROTOCOL
        ));
    }
    if welcome.pid != pid {
        return Err("the Workbench on the socket is not the process the file names".into());
    }
    let inst = Arc::new(Instance {
        pid,
        project: Mutex::new(welcome.project.clone()),
        welcome,
        writer: tokio::sync::Mutex::new(w),
        pending: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        closed: AtomicBool::new(false),
    });
    tokio::spawn(read_loop(Arc::clone(&inst), r, registry));
    Ok(inst)
}

#[cfg_attr(not(unix), allow(dead_code))]
async fn read_loop<R: AsyncBufRead + Unpin>(
    inst: Arc<Instance>,
    mut r: R,
    registry: Weak<Registry>,
) {
    loop {
        match read_line(&mut r, cfx_bridge::MAX_RESPONSE_LINE).await {
            Ok(Some(Line::Text(l))) => match ServerLine::parse(&l) {
                Ok(ServerLine::Response(resp)) => {
                    let tx = inst
                        .pending
                        .lock()
                        .ok()
                        .and_then(|mut p| p.remove(&resp.id));
                    if let Some(tx) = tx {
                        let _ = tx.send(resp);
                    }
                }
                Ok(ServerLine::Event(ev)) => inst.apply(&ev),
                // A newer Workbench's event, or a line this version cannot read.
                Ok(ServerLine::UnknownEvent(_)) | Err(_) => {}
            },
            // Its request waits out its time and is reported as unanswered.
            Ok(Some(Line::TooLong)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    inst.close();
    if let Some(reg) = registry.upgrade() {
        reg.forget(inst.pid);
    }
}
