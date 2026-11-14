//! Who is listening on an engine's port.
//!
//! An engine listens on a loopback port. Every account on the machine can open that
//! port, and while the engine is stopped, restarting or not yet started, any of them
//! can listen on it. What the node sends an engine can carry the target's credentials,
//! and what comes back is published as the scan's results, so the node sends only to a
//! listener that runs as the account the engines run as, or as root. On Linux the
//! kernel says who owns the engine's end of a connection. Elsewhere it cannot be asked
//! this way, nor on a Linux whose tables list no sockets, and the connection is used as
//! it always was.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// Connect to the engine at `addr`. A listener another account owns is refused before
/// anything is written to it.
pub(crate) async fn connect(addr: &str) -> io::Result<tokio::net::TcpStream> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let ends = (stream.local_addr()?, stream.peer_addr()?);
    let trusted = trusted();
    // Reading the kernel's tables takes a few milliseconds on a host with many
    // connections, so it is done off the runtime's workers.
    tokio::task::spawn_blocking(move || check(ends, &trusted))
        .await
        .map_err(io::Error::other)?
        .map_err(|e| e.into_io(ends.1))?;
    Ok(stream)
}

/// [`connect`] without a runtime, waiting at most `timeout` for the connection.
pub fn connect_blocking(addr: SocketAddr, timeout: Duration) -> io::Result<std::net::TcpStream> {
    connect_blocking_trusting(addr, timeout, &trusted())
}

/// [`connect_blocking`], taking only listeners of the accounts in `trusted` for an
/// engine.
pub fn connect_blocking_trusting(
    addr: SocketAddr,
    timeout: Duration,
    trusted: &[u32],
) -> io::Result<std::net::TcpStream> {
    let stream = std::net::TcpStream::connect_timeout(&addr, timeout)?;
    let ends = (stream.local_addr()?, stream.peer_addr()?);
    check(ends, trusted).map_err(|e| e.into_io(ends.1))?;
    Ok(stream)
}

/// Whether the engine's end of the connection `ends` belongs to a trusted account.
fn check(ends: (SocketAddr, SocketAddr), trusted: &[u32]) -> Result<(), NotOurs> {
    let mut verdict = owned_by(owners(ends), trusted);
    // The engine's end is listed as soon as the connect returns, but a busy machine is
    // given a moment.
    for _ in 0..4 {
        if !matches!(verdict, Err(Unlisted)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
        verdict = owned_by(owners(ends), trusted);
    }
    verdict
}

/// Why a listener is not taken for an engine.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NotOurs {
    /// The kernel lists no socket for it.
    Unlisted,
    /// It belongs to an account the engines do not run as.
    Other(u32),
}
use NotOurs::{Other, Unlisted};

impl NotOurs {
    fn into_io(self, peer: SocketAddr) -> io::Error {
        let why = match self {
            Unlisted => format!("no owner could be found for the listener on {peer}"),
            Other(uid) => format!(
                "the listener on {peer} belongs to uid {uid}, which the engines do not run as"
            ),
        };
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{why}; nothing was sent to it"),
        )
    }
}

/// `None` where the kernel cannot be asked, and every listener is taken as before.
type Owners = Option<Vec<u32>>;

/// Every owner listed has to be trusted, and at least one has to be listed.
pub(crate) fn owned_by(owners: Owners, trusted: &[u32]) -> Result<(), NotOurs> {
    let Some(owners) = owners else {
        return Ok(());
    };
    if owners.is_empty() {
        return Err(Unlisted);
    }
    match owners.into_iter().find(|u| !trusted.contains(u)) {
        Some(u) => Err(Other(u)),
        None => Ok(()),
    }
}

/// The accounts whose listeners are the engines: root, this process's own and, when it
/// acts for an operator under sudo (as the node service does), the operator's, whose
/// own services the engines are.
pub fn trusted() -> Vec<u32> {
    #[cfg(test)]
    if let Ok(uids) = TRUSTED.try_with(Clone::clone) {
        return uids;
    }
    production_trusted()
}

#[cfg(unix)]
fn production_trusted() -> Vec<u32> {
    static KNOWN: std::sync::OnceLock<Vec<u32>> = std::sync::OnceLock::new();
    if let Some(uids) = KNOWN.get() {
        return uids.clone();
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let mut uids = vec![0, euid];
    let operator = crate::toolchain::sudo_user::sudo_user_info();
    if let Some((uid, ..)) = operator {
        uids.push(uid);
    }
    // A name SUDO_USER gives that could not be looked up, as when a directory service
    // does not answer for a moment, is looked up again next time rather than left out
    // for good.
    let named = euid == 0 && std::env::var("SUDO_USER").is_ok_and(|u| !u.is_empty() && u != "root");
    if operator.is_some() || !named {
        let _ = KNOWN.set(uids.clone());
    }
    uids
}

#[cfg(not(unix))]
fn production_trusted() -> Vec<u32> {
    Vec::new()
}

#[cfg(test)]
tokio::task_local! {
    /// A test's word for which accounts the engines run as: a listener another account
    /// owns cannot be made in a test that runs as one account, so the test says its own
    /// account is not one of them instead.
    pub(crate) static TRUSTED: Vec<u32>;
}

/// The owners the kernel lists for the engine's end of the connection whose own end is
/// `ends.0` and whose engine end is `ends.1`.
#[cfg(target_os = "linux")]
fn owners(ends: (SocketAddr, SocketAddr)) -> Owners {
    let tables: Vec<String> = ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect();
    listed(&tables, ends)
}

/// [`owners`] from the kernel's tcp `tables`.
#[cfg(any(test, target_os = "linux"))]
fn listed(tables: &[String], (local, peer): (SocketAddr, SocketAddr)) -> Owners {
    // This end is listed before the connect returns. A kernel that lists not even this
    // one lists no sockets at all, as on WSL 1 and in some sandboxes, and cannot be
    // asked who listens: the listener is taken as on the systems without these tables.
    if tables.iter().all(|t| owners_in(t, local, peer).is_empty()) {
        return None;
    }
    Some(
        tables
            .iter()
            .flat_map(|t| owners_in(t, peer, local))
            .collect(),
    )
}

#[cfg(not(target_os = "linux"))]
fn owners(_ends: (SocketAddr, SocketAddr)) -> Owners {
    None
}

/// The owners in one of the kernel's tcp tables of the socket whose own address is `at`
/// and whose remote address is `from`.
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
mod tests {
    use super::*;

    #[cfg(target_endian = "little")]
    #[test]
    fn the_engines_end_is_found_by_both_addresses() {
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 0100007F:115D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 1 1 0\n\
             1: 0100007F:115D 0100007F:A028 01 00000000:00000000 00:00000000 00000000  1001        0 2 1 0\n\
             2: 0100007F:A028 0100007F:115D 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0\n";
        let engine: SocketAddr = "127.0.0.1:4445".parse().unwrap();
        let node: SocketAddr = "127.0.0.1:41000".parse().unwrap();
        assert_eq!(owners_in(v4, engine, node), vec![1001]);
        assert_eq!(owners_in(v4, node, engine), vec![0]);
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             0: 0000000000000000FFFF00000100007F:115D 0000000000000000FFFF00000100007F:A028 01 00000000:00000000 00:00000000 00000000  1002        0 4 1 0\n";
        assert_eq!(owners_in(v6, engine, node), vec![1002]);
        assert!(owners_in("header\nnot a line\n", engine, node).is_empty());
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn a_kernel_that_lists_no_sockets_is_not_asked() {
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let ends: (SocketAddr, SocketAddr) = (
            "127.0.0.1:41000".parse().unwrap(),
            "127.0.0.1:4445".parse().unwrap(),
        );
        // WSL 1 and some sandboxes list no sockets at all, not even this end.
        assert_eq!(listed(&[header.into(), header.into()], ends), None);
        assert_eq!(listed(&[], ends), None);
        // This end is listed and the engine's is not: that is a listener with no owner.
        let ours = format!(
            "{header}   0: 0100007F:A028 0100007F:115D 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0\n"
        );
        assert_eq!(listed(&[ours.clone()], ends), Some(vec![]));
        let both = format!(
            "{ours}   1: 0100007F:115D 0100007F:A028 01 00000000:00000000 00:00000000 00000000  1001        0 2 1 0\n"
        );
        assert_eq!(listed(&[header.into(), both], ends), Some(vec![1001]));
    }

    #[test]
    fn only_a_listener_of_a_trusted_account_is_an_engine() {
        assert_eq!(owned_by(Some(vec![1000]), &[0, 1000]), Ok(()));
        assert_eq!(owned_by(Some(vec![0]), &[0, 1000]), Ok(()));
        assert_eq!(
            owned_by(Some(vec![1000, 1001]), &[0, 1000]),
            Err(Other(1001))
        );
        assert_eq!(owned_by(Some(vec![]), &[0, 1000]), Err(Unlisted));
        assert_eq!(owned_by(None, &[0]), Ok(()));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_listener_of_another_account_is_refused_and_this_ones_is_not() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        assert!(connect(&addr.to_string()).await.is_ok());
        assert!(connect_blocking(addr, Duration::from_secs(1)).is_ok());
        let refused = TRUSTED
            .scope(vec![me.wrapping_add(1)], connect(&addr.to_string()))
            .await
            .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            refused.to_string().contains(&format!("uid {me}")),
            "{refused}"
        );
        let blocking = TRUSTED.sync_scope(vec![me.wrapping_add(1)], || {
            connect_blocking(addr, Duration::from_secs(1))
        });
        assert_eq!(
            blocking.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }
}
