//! Ending a daemon that nothing uses.
//!
//! A daemon its client started (see [`crate::Daemon`]) is given [`IDLE_EXIT_ENV`], and
//! exits once no client has been connected and no scan has run for that many seconds.
//! A daemon started by its unit, or by hand, is not given it and runs until stopped.
//! What keeps a daemon in use is each task it starts with [`spawn_busy`]: a client's
//! connection, and a scan, which can outlive the connection that asked for it.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// The seconds a daemon may go unused before it exits. A client sets it on the daemon
/// it starts, to [`IDLE_EXIT_DEFAULT`] unless the client's own environment gives it.
pub const IDLE_EXIT_ENV: &str = "CFX_DAEMON_IDLE_EXIT";

/// How long a daemon its client started may go unused: half an hour.
pub(crate) const IDLE_EXIT_DEFAULT: Duration = Duration::from_secs(30 * 60);

/// The connections and scans this daemon has in hand.
static BUSY: AtomicUsize = AtomicUsize::new(0);

/// When a task last ended, in milliseconds since [`epoch`]: with none in hand, how long
/// the daemon has gone unused is counted from it.
static IDLE_SINCE: AtomicU64 = AtomicU64::new(0);

/// The instant [`IDLE_SINCE`] counts from.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn now() -> u64 {
    u64::try_from(epoch().elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Held for as long as a task started with [`spawn_busy`] runs.
struct Busy;

impl Busy {
    fn take() -> Self {
        BUSY.fetch_add(1, Ordering::SeqCst);
        Busy
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        // Marked before the count falls, so a check that finds nothing in hand also
        // finds when the last task ended, never a time from before it.
        IDLE_SINCE.store(now(), Ordering::SeqCst);
        BUSY.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Spawn `task`, a client's connection or a scan, and count the daemon in use until it
/// ends.
pub fn spawn_busy<F>(task: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    let busy = Busy::take();
    tokio::spawn(async move {
        let _busy = busy;
        task.await
    })
}

/// The limit `value`, what [`IDLE_EXIT_ENV`] holds, gives: whole seconds above nothing.
fn idle_limit(value: Option<&str>) -> Option<Duration> {
    let secs: u64 = value?.trim().parse().ok()?;
    (secs > 0).then(|| Duration::from_secs(secs))
}

/// Whether a daemon with `busy` tasks in hand, which last had none at `since`, has gone
/// unused for `limit` at `at`, all in milliseconds since [`epoch`].
fn unused_for(busy: usize, since: u64, at: u64, limit: Duration) -> bool {
    busy == 0 && u128::from(at.saturating_sub(since)) >= limit.as_millis()
}

/// Have this daemon, engine `engine`'s, exit once it has gone unused for as long as
/// [`IDLE_EXIT_ENV`] says, when it says. Called once, when the daemon listens.
pub fn exit_when_idle(engine: &str) {
    let Some(limit) = idle_limit(std::env::var(IDLE_EXIT_ENV).ok().as_deref()) else {
        return;
    };
    IDLE_SINCE.store(now(), Ordering::SeqCst);
    eprintln!(
        "{engine} daemon: started by its client, so it exits after {} seconds with no client \
         and no scan ({IDLE_EXIT_ENV})",
        limit.as_secs()
    );
    let engine = engine.to_string();
    let every = (limit / 10).clamp(Duration::from_secs(1), Duration::from_secs(30));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            let busy = BUSY.load(Ordering::SeqCst);
            let since = IDLE_SINCE.load(Ordering::SeqCst);
            if unused_for(busy, since, now(), limit) {
                eprintln!(
                    "{engine} daemon: no client and no scan for {} seconds, so it exits",
                    limit.as_secs()
                );
                std::process::exit(0);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_limit_is_whole_seconds_above_nothing() {
        assert_eq!(idle_limit(Some("1800")), Some(Duration::from_secs(1800)));
        assert_eq!(idle_limit(Some(" 20 ")), Some(Duration::from_secs(20)));
        assert_eq!(idle_limit(Some("0")), None);
        assert_eq!(idle_limit(Some("soon")), None);
        assert_eq!(idle_limit(Some("-5")), None);
        assert_eq!(idle_limit(None), None);
    }

    #[test]
    fn a_daemon_is_unused_only_with_nothing_in_hand_for_the_whole_limit() {
        let minute = Duration::from_secs(60);
        assert!(unused_for(0, 1_000, 61_000, minute));
        assert!(
            !unused_for(0, 1_000, 60_999, minute),
            "not yet the whole minute"
        );
        assert!(
            !unused_for(1, 0, 600_000, minute),
            "a client or a scan in hand"
        );
    }

    #[tokio::test]
    async fn a_task_spawned_busy_holds_the_daemon_until_it_ends() {
        let before = BUSY.load(Ordering::SeqCst);
        let (go, wait) = tokio::sync::oneshot::channel::<()>();
        let task = spawn_busy(async move {
            let _ = wait.await;
        });
        assert_eq!(BUSY.load(Ordering::SeqCst), before + 1);
        let at = now();
        go.send(()).unwrap();
        task.await.unwrap();
        assert_eq!(BUSY.load(Ordering::SeqCst), before);
        assert!(
            IDLE_SINCE.load(Ordering::SeqCst) >= at,
            "the idle time did not restart"
        );
    }
}
