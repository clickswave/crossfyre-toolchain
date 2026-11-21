//! Isolated egress as a node runs it, through the egress helper (see [`super::helper`]).
//!
//! A node whose network config is not direct asks the helper to bring egress up, and
//! holds it up for the daemon's life. Without a helper that answers, the node goes on
//! directly and says why, unless the config's kill switch is on: a kill switch says
//! traffic must never leave from the node's own address, so then the node sends nothing
//! at all until a helper answers. It keeps asking, so a helper installed or repaired
//! later is taken up without a restart, and one that stops is noticed.

use super::helper::{self, Limits, Up};
use super::state::{EgressState, Isolated};
use crate::NetworkConfig;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How a node finds and asks its helper.
#[derive(Clone)]
pub struct Setup {
    /// The executable the helper sits beside.
    pub exe: PathBuf,
    pub limits: Limits,
    /// How often the helper is asked again while egress is not up.
    pub retry: Duration,
}

impl Setup {
    pub fn for_this_process() -> Setup {
        Setup {
            exe: std::env::current_exe()
                .and_then(std::fs::canonicalize)
                .unwrap_or_default(),
            limits: Limits::default(),
            retry: Duration::from_secs(30),
        }
    }
}

/// Isolated egress for one daemon. Dropping it takes egress down.
pub struct Isolation {
    up: Arc<Mutex<Option<Up>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Isolation {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut up) = self.up.lock() {
            drop(up.take());
        }
    }
}

/// What one try gave.
enum Tried {
    Up(Up),
    No(String),
}

/// Where a node's egress comes from: its config as the platform last sent it (`raw`),
/// the config it keeps (`net`), and the rest of what the helper is handed.
#[derive(Clone)]
pub struct Asked {
    pub raw: Option<serde_json::Value>,
    pub net: NetworkConfig,
    pub net_dir: PathBuf,
    pub node_id: String,
    pub tunnel_hooks: bool,
}

fn try_up(setup: &Setup, asked: &Asked) -> Tried {
    let found = match helper::find(&setup.exe) {
        Ok(h) => h,
        Err(why) => return Tried::No(why),
    };
    // The helper is given the config as the platform sent it first: one taken while no
    // helper answered was never written where egress reads it.
    let net = match &asked.raw {
        Some(raw) => {
            match helper::config(
                &found,
                raw,
                &asked.net_dir,
                asked.tunnel_hooks,
                setup.limits,
            ) {
                Ok((_, Some(n))) => n,
                Ok((_, None)) => asked.net.clone(),
                Err(why) => return Tried::No(why),
            }
        }
        None => asked.net.clone(),
    };
    match helper::up(
        &found,
        &net,
        &asked.net_dir,
        &asked.node_id,
        asked.tunnel_hooks,
        setup.limits,
    ) {
        Ok(up) => Tried::Up(up),
        Err(why) => Tried::No(why),
    }
}

/// What the node says and refuses, for egress up by `up`, or not up for `why`.
fn isolated(net: &NetworkConfig, outcome: Result<&str, &str>) -> Isolated {
    match outcome {
        Ok(version) => Isolated {
            label: format!("helper {version}"),
            refusal: None,
        },
        Err(why) if net.kill_switch => {
            let label = format!("refused (kill switch on, helper {why})");
            Isolated {
                refusal: Some(format!("egress: {label}")),
                label,
            }
        }
        Err(why) => Isolated {
            label: format!("baseline (helper {why})"),
            refusal: None,
        },
    }
}

fn say(state: &EgressState, now: Isolated) {
    if state.isolation() != now {
        println!("[network] egress: {}", now.label);
        if now.refusal.is_some() {
            println!(
                "[network] Nothing is sent until the egress helper answers: the kill switch is on."
            );
        } else if now.label.starts_with("baseline") {
            println!("[network] This node sends directly.");
        }
        state.set_isolation(now);
    }
}

/// Bring isolated egress up as `asked`, and keep it up.
pub fn start(asked: Asked, setup: Setup, state: Arc<EgressState>) -> Isolation {
    let up: Arc<Mutex<Option<Up>>> = Arc::new(Mutex::new(None));
    let stop = Arc::new(AtomicBool::new(false));
    let net = &asked.net;
    if net.kind.is_empty() || net.kind == "direct" {
        state.set_isolation(Isolated {
            label: "direct".into(),
            refusal: None,
        });
        return Isolation { up, stop };
    }
    match try_up(&setup, &asked) {
        Tried::Up(u) => {
            say(&state, isolated(net, Ok(&u.version)));
            *up.lock().unwrap_or_else(|e| e.into_inner()) = Some(u);
        }
        Tried::No(why) => say(&state, isolated(net, Err(&why))),
    }
    let (held, stopped) = (Arc::clone(&up), Arc::clone(&stop));
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(setup.retry);
            if stopped.load(Ordering::SeqCst) {
                return;
            }
            {
                let mut cur = held.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(u) = cur.as_mut() {
                    if u.running() {
                        continue;
                    }
                    drop(cur.take());
                    say(&state, isolated(&asked.net, Err("stopped")));
                }
            }
            match try_up(&setup, &asked) {
                Tried::Up(u) => {
                    let mut cur = held.lock().unwrap_or_else(|e| e.into_inner());
                    if stopped.load(Ordering::SeqCst) {
                        return;
                    }
                    say(&state, isolated(&asked.net, Ok(&u.version)));
                    *cur = Some(u);
                }
                Tried::No(why) => say(&state, isolated(&asked.net, Err(&why))),
            }
        }
    });
    Isolation { up, stop }
}

#[cfg(all(test, unix))]
mod tests;
