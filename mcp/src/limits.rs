//! How fast a model may drive the server.
//!
//! A model in a loop does not get tired. These are the brakes that do not depend on
//! it noticing: a bucket over all calls, and a pace per destination for the tools
//! that send requests themselves. The scan caps live in the job store, because they
//! have to count scans started by earlier runs of the server too.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The longest a request waits for its destination's next slot before it is refused.
const PACE_WAIT_MAX: Duration = Duration::from_secs(2);

/// A token bucket over every tool call.
pub(crate) struct CallBucket {
    burst: f64,
    per_sec: f64,
    state: Mutex<(f64, Instant)>,
}

impl CallBucket {
    pub(crate) fn new(burst: u32, per_minute: u32) -> Self {
        CallBucket {
            burst: burst as f64,
            per_sec: per_minute as f64 / 60.0,
            state: Mutex::new((burst as f64, Instant::now())),
        }
    }

    /// Take one call, or say how many seconds until one is free.
    pub(crate) fn take(&self) -> Result<(), u64> {
        let Ok(mut s) = self.state.lock() else {
            return Err(1);
        };
        let now = Instant::now();
        let refill = now.duration_since(s.1).as_secs_f64() * self.per_sec;
        s.0 = (s.0 + refill).min(self.burst);
        s.1 = now;
        if s.0 >= 1.0 {
            s.0 -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - s.0) / self.per_sec).ceil().max(1.0) as u64)
        }
    }
}

/// Spacing between requests to one host and port.
pub(crate) struct HostPacer {
    interval: Duration,
    next: Mutex<HashMap<String, Instant>>,
}

impl HostPacer {
    pub(crate) fn new(per_second: u32) -> Self {
        HostPacer {
            interval: Duration::from_secs_f64(1.0 / per_second.max(1) as f64),
            next: Mutex::new(HashMap::new()),
        }
    }

    /// Wait for this destination's next slot. A slot more than two seconds away is a
    /// refusal, with the seconds to wait, rather than a call that hangs.
    pub(crate) async fn wait(&self, key: &str) -> Result<(), u64> {
        let slot = {
            let Ok(mut m) = self.next.lock() else {
                return Err(1);
            };
            let now = Instant::now();
            let free = m.get(key).copied().unwrap_or(now).max(now);
            if free.duration_since(now) > PACE_WAIT_MAX {
                return Err(free.duration_since(now).as_secs().max(1));
            }
            m.insert(key.to_string(), free + self.interval);
            free
        };
        tokio::time::sleep_until(slot.into()).await;
        Ok(())
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn the_bucket_allows_a_burst_then_refuses() {
        let b = CallBucket::new(10, 60);
        for _ in 0..10 {
            assert!(b.take().is_ok());
        }
        let retry = b.take().unwrap_err();
        assert!((1..=2).contains(&retry), "{retry}");
    }

    #[tokio::test]
    async fn the_pacer_spaces_and_then_refuses() {
        let p = HostPacer::new(2);
        let t = Instant::now();
        for _ in 0..4 {
            p.wait("h:80").await.unwrap();
        }
        // Four slots half a second apart: the fourth is 1.5 s after the first.
        assert!(
            t.elapsed() >= Duration::from_millis(1400),
            "{:?}",
            t.elapsed()
        );
        // Another destination is not held up by this one.
        let t2 = Instant::now();
        p.wait("other:80").await.unwrap();
        assert!(t2.elapsed() < Duration::from_millis(100));
        // A destination whose next slot is past the two-second horizon is refused.
        let fast = HostPacer::new(1);
        fast.next
            .lock()
            .unwrap()
            .insert("x".into(), Instant::now() + Duration::from_secs(5));
        assert!(fast.wait("x").await.is_err());
    }
}
