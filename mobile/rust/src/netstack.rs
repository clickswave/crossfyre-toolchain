//! The mobile netstack: the VpnService hands us a TUN file descriptor carrying the captured apps'
//! raw IP packets. We run a userspace TCP/IP stack (`ipstack`) over it, and for every TCP flow we
//! reassemble, hand the stream to the SHARED `cfx_capture::serve_mitm_flow` - the exact same
//! MITM-inspect-and-forward core the desktop Web Tracer uses. Each flow's original destination
//! (`peer_addr`) is the forwarding target; the app's own SNI/Host drives the leaf + upstream cert.
//!
//! Compile-verified + cross-compiled to Android here; run-verification needs a device (a TUN fd only
//! exists inside a live VpnService).

use std::os::fd::{FromRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use cfx_capture::{CaptureCfg, Egress, SessionCa, TraceEvent};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackUdpStream};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc::UnboundedSender;

/// An async wrapper over the VpnService TUN fd. Each read yields exactly one raw IP packet; each write
/// sends one. No packet-information header (Android VpnService TUN is bare IP).
struct TunDevice {
    inner: AsyncFd<OwnedFd>,
}

impl TunDevice {
    /// SAFETY: `fd` must be a valid TUN file descriptor from the VpnService. We `dup` it so native
    /// owns its own copy (closed on stop) while Kotlin keeps the original ParcelFileDescriptor.
    unsafe fn from_raw(fd: i32) -> std::io::Result<Self> {
        let dup_fd = unsafe { dup(fd) };
        if dup_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Put the dup in non-blocking mode so AsyncFd can drive it.
        let flags = unsafe { libc_fcntl_getfl(dup_fd) };
        unsafe { libc_fcntl_setfl(dup_fd, flags | O_NONBLOCK) };
        let owned = unsafe { OwnedFd::from_raw_fd(dup_fd) };
        Ok(Self {
            inner: AsyncFd::new(owned)?,
        })
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|fd| {
                let n = unsafe {
                    read(
                        as_raw(fd.get_ref()),
                        unfilled.as_mut_ptr() as *mut _,
                        unfilled.len(),
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            match guard.try_io(|fd| {
                let n =
                    unsafe { write(as_raw(fd.get_ref()), data.as_ptr() as *const _, data.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => return Poll::Ready(res),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Drive the stack: accept flows off the TUN and MITM each TCP flow through the shared capture core.
/// Runs until the TUN closes (VpnService stopped). UDP/QUIC flows are dropped for now (h3 is not
/// MITM'd; they surface as metadata in a later pass).
pub async fn run(
    tun_fd: i32,
    ca: Arc<SessionCa>,
    egress: Egress,
    tx: UnboundedSender<TraceEvent>,
    capture_cfg: CaptureCfg,
) -> std::io::Result<()> {
    let device = unsafe { TunDevice::from_raw(tun_fd)? };
    let mut cfg = IpStackConfig::default();
    cfg.mtu = 1500;
    cfg.packet_information = false; // Android VpnService TUN is bare IP, no packet-info header.
    let mut stack = IpStack::new(cfg, device);

    loop {
        match stack.accept().await {
            Ok(IpStackStream::Tcp(tcp)) => {
                let dst = tcp.peer_addr();
                log::info!("tcp flow -> {dst}");
                crate::stats::inc(&crate::stats::FLOWS);
                if dst.port() == 443 {
                    crate::stats::inc(&crate::stats::TLS_FLOWS);
                }
                let ca = ca.clone();
                let egress = egress.clone();
                let tx = tx.clone();
                let flow_cfg = capture_cfg.clone();
                tokio::spawn(async move {
                    match cfx_capture::serve_mitm_flow(
                        tcp,
                        dst.ip().to_string(),
                        dst.port(),
                        ca,
                        egress,
                        tx,
                        flow_cfg,
                    )
                    .await
                    {
                        // A TLS flow that completed the handshake and then carried
                        // no request at all is the fingerprint of pinning done in
                        // app code: the app trusts our CA (that is what patching
                        // arranges, and why other hosts decrypt), then its own
                        // pinner refuses this certificate and closes without
                        // sending anything. Counting it as a refusal is the
                        // difference between the panel saying "no traffic yet" and
                        // saying which host would not accept us.
                        Ok(outcome) if outcome.tls && outcome.requests == 0 => {
                            crate::stats::inc(&crate::stats::CA_REJECTED);
                            crate::stats::set_last_error(format!(
                                "{dst} accepted the handshake then sent nothing (pinned?)"
                            ));
                            log::info!("flow -> {dst} refused our certificate after the handshake (likely pinned)");
                        }
                        Ok(_) => log::info!("flow -> {dst} closed cleanly"),
                        Err(e) => {
                            log::info!("flow -> {dst} error: {e}");
                            crate::stats::record_flow_error(&e.to_string());
                        }
                    }
                });
            }
            Ok(IpStackStream::Udp(udp)) => {
                let dst = udp.peer_addr();
                if dst.port() == 443 {
                    // Drop QUIC (HTTP/3 over UDP :443). We cannot MITM QUIC, so relaying it would
                    // let the app use it and its HTTPS traffic would never be captured at all.
                    // Dropping it is meant to make the app fall back to TCP + TLS, which we DO MITM.
                    //
                    // The fallback is NOT always quick. Blackholing gives the client no signal, so
                    // it retries the handshake until its own timer expires: measured at ~60s against
                    // an app whose API is fronted by a CDN speaking h3, during which its TCP
                    // connection sits open without ever sending a ClientHello. The visible result is
                    // a capture holding nothing but analytics, because the SDKs that do not try h3
                    // are the only ones getting through.
                    //
                    // Count it and say so at INFO. This used to be a debug line, which is off in
                    // release, so the traffic vanished and so did any hint that it had: the one
                    // thing worse than dropping traffic is dropping it silently.
                    crate::stats::inc(&crate::stats::QUIC_DROPPED);
                    log::info!("dropped QUIC/h3 -> {dst} (forcing TCP+TLS fallback; app may stall briefly)");
                } else {
                    // Relay other UDP (crucially DNS on :53) transparently, or the phone can't resolve
                    // anything and nothing browses. The app is excluded from the VPN, so this socket
                    // egresses directly.
                    tokio::spawn(relay_udp(udp));
                }
            }
            Ok(IpStackStream::UnknownTransport(_)) | Ok(IpStackStream::UnknownNetwork(_)) => {}
            Err(e) => {
                log::warn!("ipstack accept ended: {e}");
                return Ok(());
            }
        }
    }
}

/// Transparently proxy one UDP flow (e.g. DNS) between the app and its real destination. We do not
/// MITM UDP; we relay datagrams so name resolution and other UDP keep working while the VPN is up.
/// Times out after idle so relays do not leak.
async fn relay_udp(mut udp: IpStackUdpStream) {
    let dst = udp.peer_addr();
    let bind = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = match tokio::net::UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(_) => return,
    };
    if sock.connect(dst).await.is_err() {
        return;
    }
    let mut from_app = vec![0u8; 65535];
    let mut from_net = vec![0u8; 65535];
    let idle = std::time::Duration::from_secs(30);
    loop {
        let alive = tokio::time::timeout(idle, async {
            tokio::select! {
                r = udp.read(&mut from_app) => match r {
                    Ok(0) | Err(_) => false,
                    Ok(n) => sock.send(&from_app[..n]).await.is_ok(),
                },
                r = sock.recv(&mut from_net) => match r {
                    Ok(n) => udp.write_all(&from_net[..n]).await.is_ok(),
                    Err(_) => false,
                },
            }
        })
        .await;
        if !matches!(alive, Ok(true)) {
            break;
        }
    }
}

// --- minimal libc shims (avoid a libc dep for a few syscalls) ---------------------------------
const O_NONBLOCK: i32 = 0x800;
unsafe extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn read(fd: i32, buf: *mut core::ffi::c_void, count: usize) -> isize;
    fn write(fd: i32, buf: *const core::ffi::c_void, count: usize) -> isize;
    fn dup(fd: i32) -> i32;
}
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
unsafe fn libc_fcntl_getfl(fd: i32) -> i32 {
    unsafe { fcntl(fd, F_GETFL) }
}
unsafe fn libc_fcntl_setfl(fd: i32, flags: i32) {
    unsafe {
        fcntl(fd, F_SETFL, flags);
    }
}
fn as_raw(fd: &OwnedFd) -> i32 {
    use std::os::fd::AsRawFd;
    fd.as_raw_fd()
}
