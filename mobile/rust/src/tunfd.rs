//! The native side's hold on the VpnService tunnel.
//!
//! The netstack reads and writes its own `dup` of the tunnel fd, and Android keeps
//! the VPN up, and stays bound to the service, for as long as any copy of that fd
//! is open. Closing ours used to depend on the runtime dropping the task that owns
//! it, and a task can outlive a shutdown: a connection whose `Drop` blocks its
//! worker thread keeps every other task on that runtime alive with it. Then Stop
//! left the tunnel up with nothing reading it.
//!
//! So the hold is recorded here, and [`release`] lets go of the tunnel at once,
//! whatever the tasks are doing. It does not close the fd, which is still owned
//! by the device wrapper and will be closed by it; it points the fd at
//! `/dev/null` instead. The tunnel loses its last native reference, the fd number
//! stays valid, so nothing else can be handed the same number and then closed by
//! mistake, and the wrapper's eventual close closes `/dev/null`.

use std::sync::Mutex;

static HELD: Mutex<Option<i32>> = Mutex::new(None);

fn held() -> std::sync::MutexGuard<'static, Option<i32>> {
    HELD.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record that `fd` is the native copy of the tunnel.
pub fn hold(fd: i32) {
    *held() = Some(fd);
}

/// The owner is about to close `fd`. Runs `close` with the hold forgotten, under
/// the same lock [`release`] takes, so a release can never act on a number that
/// has just been closed and handed out again.
pub fn forget(fd: i32, close: impl FnOnce()) {
    let mut h = held();
    if *h == Some(fd) {
        *h = None;
    }
    close();
}

unsafe extern "C" {
    fn open(path: *const core::ffi::c_char, flags: i32, ...) -> i32;
    fn dup2(old: i32, new: i32) -> i32;
    #[link_name = "close"]
    fn close_fd(fd: i32) -> i32;
}

const O_RDWR: i32 = 2;

/// Let go of the tunnel now. Returns whether there was a hold to let go of.
pub fn release() -> bool {
    let mut h = held();
    let Some(fd) = h.take() else {
        return false;
    };
    let null = unsafe { open(c"/dev/null".as_ptr(), O_RDWR) };
    if null < 0 {
        // Nothing to swap in: keep the hold, so the owner's close still ends it.
        *h = Some(fd);
        return false;
    }
    let swapped = unsafe { dup2(null, fd) } >= 0;
    unsafe { close_fd(null) };
    swapped
}

// Linux and Android only, the systems this crate is the tunnel core for. The test
// speaks to libc through its own declarations, with Linux's value for O_NONBLOCK
// (0x800). On macOS that bit is another flag, so the pipe stays blocking and the
// first read waits forever instead of failing.
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn pipe(fds: *mut i32) -> i32;
        fn dup(fd: i32) -> i32;
        fn close(fd: i32) -> i32;
        fn read(fd: i32, buf: *mut core::ffi::c_void, count: usize) -> isize;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }

    /// 0 at end of file, -1 when the other end is still open.
    fn read_now(fd: i32) -> isize {
        let mut b = [0u8; 1];
        unsafe { read(fd, b.as_mut_ptr() as *mut _, 1) }
    }

    // One test: the hold is process-global and tests run on several threads.
    #[test]
    fn a_release_lets_go_of_the_tunnel_while_the_fd_stays_valid() {
        // A pipe stands in for the tunnel: its read end sees end of file only once
        // every copy of the write end has gone, as the VPN goes down only once
        // every copy of the tunnel fd has.
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
        let (rd, wr) = (fds[0], fds[1]);
        unsafe {
            fcntl(rd, 4 /* F_SETFL */, 0x800 /* O_NONBLOCK */)
        };
        let native = unsafe { dup(wr) };
        unsafe { close(wr) };
        hold(native);
        assert_eq!(
            read_now(rd),
            -1,
            "the native copy should still be holding the tunnel"
        );

        assert!(release());
        assert_eq!(
            read_now(rd),
            0,
            "after a release nothing should hold the tunnel"
        );
        // The number is still open (now /dev/null), so the owner's close is safe.
        assert_eq!(unsafe { close(native) }, 0);
        // Nothing left to release.
        assert!(!release());

        // An owner that closes first is forgotten, and a later release leaves the
        // number alone even if it has been reused.
        let other = unsafe { dup(rd) };
        hold(other);
        forget(other, || unsafe {
            close(other);
        });
        assert!(!release());
        unsafe { close(rd) };
    }
}
