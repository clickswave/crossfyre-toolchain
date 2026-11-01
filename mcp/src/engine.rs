//! The engines' own daemon protocol, spoken from here the way the CLIs and the node
//! speak it: one JSON request line to `127.0.0.1:<port>`, then a stream of JSON event
//! lines back. Before the request, the daemon is asked which options it honours, so
//! an operation is never sent to one that would ignore the options that fence it.
//! The token, when the daemons require one, is stamped by `dguard::encode` from the
//! same variable the daemons read.

use crate::core::Clearance;
use serde_json::{Value, json};
use std::net::SocketAddr;
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
    /// This end and the daemon's, for finding who owns the daemon's.
    ends: Option<(SocketAddr, SocketAddr)>,
}

/// Connect without sending, so a stopped daemon is found before a person is asked
/// to confirm anything.
pub(crate) async fn connect(port: u16) -> std::io::Result<EngineConn> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(("127.0.0.1", port)))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
    let _ = stream.set_nodelay(true);
    let ends = stream.local_addr().ok().zip(stream.peer_addr().ok());
    let (r, writer) = stream.into_split();
    Ok(EngineConn {
        reader: LineReader {
            inner: BufReader::new(r),
        },
        writer,
        ends,
    })
}

/// A test's word for who owns the listener on a port, in place of the kernel's: a port
/// another user holds cannot be made in a test that runs as one user.
#[cfg(all(test, unix))]
pub(crate) static OWNERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u16, u32>>,
> = std::sync::LazyLock::new(Default::default);

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
    /// Whether the daemon on the other end runs as this user.
    ///
    /// A loopback port is open to every account on the machine, and while the daemon is
    /// stopped anyone can listen on its port. What is about to be sent can carry a
    /// captured session, which must reach only this user's daemon. On Linux the kernel
    /// says which user owns the daemon's end of this connection; elsewhere there is no
    /// way to ask it, and the answer is no.
    pub(crate) async fn runs_as_this_user(&self) -> Result<(), String> {
        let Some((local, peer)) = self.ends else {
            return Err("the connection's addresses could not be read".into());
        };
        #[cfg(all(test, unix))]
        if let Some(uid) = OWNERS
            .lock()
            .ok()
            .and_then(|o| o.get(&peer.port()).copied())
        {
            return owned_by_me(&[uid]);
        }
        #[cfg(target_os = "linux")]
        {
            // The daemon's end is in the table as soon as the connect returns, but a
            // busy machine is given a moment.
            let mut owners = Vec::new();
            for _ in 0..5 {
                owners = owners_on_linux(peer, local);
                if !owners.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            owned_by_me(&owners)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (local, peer);
            Err("the owner of a loopback port can be checked only on Linux".into())
        }
    }

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

/// Every uid found has to be this process's, and at least one has to be found.
#[cfg(any(all(test, unix), target_os = "linux"))]
fn owned_by_me(owners: &[u32]) -> Result<(), String> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    match owners.iter().find(|u| **u != me) {
        _ if owners.is_empty() => Err("the kernel lists no socket for it".into()),
        Some(u) => Err(format!("it belongs to uid {u}, not to uid {me}")),
        None => Ok(()),
    }
}

/// The owners the kernel lists for the socket whose own address is `at` and whose
/// remote address is `from`: the daemon's end of a connection this process made.
#[cfg(target_os = "linux")]
fn owners_on_linux(at: SocketAddr, from: SocketAddr) -> Vec<u32> {
    ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|t| owners_in(&t, at, from))
        .collect()
}

/// [`owners_on_linux`] for one table's text.
#[cfg(any(test, target_os = "linux"))]
fn owners_in(table: &str, at: SocketAddr, from: SocketAddr) -> Vec<u32> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (local, remote, uid) = (f.get(1)?, f.get(2)?, f.get(7)?);
            (table_addr(local)? == at && table_addr(remote)? == from)
                .then(|| uid.parse().ok())
                .flatten()
        })
        .collect()
}

/// An address as the kernel's tcp tables print it: the address in hex as the host
/// stores it, 32 bits at a time, then the port. An IPv4 address mapped into IPv6, as a
/// dual-stack listener's end shows, is read as the IPv4 address.
#[cfg(any(test, target_os = "linux"))]
fn table_addr(field: &str) -> Option<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let (ip, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        Some(
            u32::from_str_radix(ip.get(i * 8..i * 8 + 8)?, 16)
                .ok()?
                .to_ne_bytes(),
        )
    };
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            let v6 = Ipv6Addr::from(b);
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod unit {
    use super::*;

    /// Lines as a little-endian Linux machine prints them: a daemon on 127.0.0.1:4442
    /// (0x115A), one connection to it from port 41000 (0xA028), and the client's end.
    #[cfg(target_endian = "little")]
    #[test]
    fn the_daemons_end_is_found_by_both_addresses() {
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 0100007F:115A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 1 1 0\n\
             1: 0100007F:115A 0100007F:A028 01 00000000:00000000 00:00000000 00000000  1001        0 2 1 0\n\
             2: 0100007F:A028 0100007F:115A 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0\n";
        let daemon: SocketAddr = "127.0.0.1:4442".parse().unwrap();
        let client: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        assert_eq!(owners_in(v4, daemon, client), vec![1001]);
        assert_eq!(owners_in(v4, client, daemon), vec![1000]);
        // A dual-stack listener's end, with both addresses mapped into IPv6.
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 0000000000000000FFFF00000100007F:115A 0000000000000000FFFF00000100007F:A028 01 00000000:00000000 00:00000000 00000000  1002        0 4 1 0\n";
        assert_eq!(owners_in(v6, daemon, client), vec![1002]);
        assert!(owners_in("header\nnot a line\n", daemon, client).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn only_this_users_daemon_is_trusted() {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        assert!(owned_by_me(&[me]).is_ok());
        assert!(owned_by_me(&[me, me.wrapping_add(1)]).is_err());
        assert!(owned_by_me(&[]).is_err());
    }
}
