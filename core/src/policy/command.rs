//! `crossfyre policy list` and `crossfyre policy set`.
//!
//! Logged in, `connected` and `private` are the account's and are written to Crossfyre
//! first. When it cannot be reached, a tightening holds on this machine at once and is
//! sent at the next contact, and a loosening changes nothing. Logged out, they change
//! this machine alone, and the next login replaces them with the account's. `offline`
//! is this machine's alone, recorded with why, and a node here stops for it. A session
//! Crossfyre no longer takes puts the machine offline too, and `crossfyre login` leaves
//! it.

use super::cloud::{Cloud, Failed, Session};
use super::{ALL, Machine, Offline, Policy, Reason, utc_now};
use std::path::Path;

/// A node on this machine, which a machine taken offline does not run.
pub trait NodeHere {
    fn runs(&self) -> bool;
}

/// The nodes registered in a data directory, which its supervisor runs.
pub struct Registered<'a>(pub &'a Path);

impl NodeHere for Registered<'_> {
    fn runs(&self) -> bool {
        std::fs::read_dir(crate::nodes_dir(self.0)).is_ok_and(|entries| {
            entries.filter_map(Result::ok).any(|e| {
                let p = e.path();
                p.extension().is_some_and(|x| x == "toml")
                    && p.file_stem()
                        .and_then(|s| s.to_str())
                        .is_some_and(crate::toolchain::node_config::is_plain_node_id)
            })
        })
    }
}

/// What `set` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Crossfyre took it, and this machine follows.
    Saved(Policy),
    /// Crossfyre could not be reached: it holds here now, and goes there at the next
    /// contact.
    HeldHere(Policy),
    /// Set on this machine alone, which is logged out.
    ThisMachine(Policy),
    /// This machine is offline now. `node` says a node here stops for it.
    Offline { node: bool },
    /// It was already so; with `left_offline`, the machine has left offline for it.
    Unchanged { policy: Policy, left_offline: bool },
}

/// Where a policy set on this machine alone says it was set.
pub const HERE: &str = "this machine";

/// Set `want` as this machine's policy, through Crossfyre when `session` is one.
/// `node_stops` is asked, when a node here would stop for offline, whether to go on.
pub async fn set(
    data_dir: &Path,
    session: Option<&Session>,
    want: Policy,
    cloud: &impl Cloud,
    node: &impl NodeHere,
    node_stops: impl FnOnce() -> bool,
) -> Result<Outcome, String> {
    let mut machine = super::load(data_dir);
    if want == Policy::Offline {
        if machine
            .offline
            .as_ref()
            .is_some_and(|o| o.reason == Reason::Chosen)
        {
            return Ok(Outcome::Unchanged {
                policy: want,
                left_offline: false,
            });
        }
        let runs = node.runs();
        if runs && !node_stops() {
            return Err("Nothing changed: the node on this machine keeps running.".into());
        }
        machine.offline = Some(Offline {
            reason: Reason::Chosen,
            since: utc_now(),
        });
        super::save(data_dir, &machine)?;
        return Ok(Outcome::Offline { node: runs });
    }
    let was_offline = machine.offline.is_some();
    let Some(session) = session else {
        machine.account = Some(want);
        machine.changed_at = Some(utc_now());
        machine.changed_via = Some(HERE.into());
        machine.unsent = false;
        machine.offline = None;
        super::save(data_dir, &machine)?;
        return Ok(Outcome::ThisMachine(want));
    };
    let current = machine.account.unwrap_or(Policy::Connected);
    match cloud.set(session, want).await {
        Ok(remote) => {
            super::cloud::take(&mut machine, &remote);
            machine.offline = None;
            super::save(data_dir, &machine)?;
            Ok(Outcome::Saved(want))
        }
        Err(Failed::Unreachable(_)) if want == current && machine.account.is_some() => {
            // Nothing of the account's changes, so this machine needs nobody's word to
            // leave offline for it.
            machine.offline = None;
            super::save(data_dir, &machine)?;
            Ok(Outcome::Unchanged {
                policy: want,
                left_offline: was_offline,
            })
        }
        Err(Failed::Unreachable(_)) if want > current => {
            machine.account = Some(want);
            machine.changed_at = Some(utc_now());
            machine.changed_via = Some(HERE.into());
            machine.unsent = true;
            machine.offline = None;
            super::save(data_dir, &machine)?;
            Ok(Outcome::HeldHere(want))
        }
        Err(Failed::Unreachable(why)) => Err(format!(
            "Nothing changed: Crossfyre could not be reached ({why}), and a looser policy is \
             set there first."
        )),
        Err(Failed::NotLoggedIn(why)) => {
            let line = super::session_ended(data_dir, &session.key)
                .unwrap_or_else(|| "Run crossfyre login.".into());
            Err(format!(
                "Crossfyre does not take this machine's session: {why}\n{line}"
            ))
        }
        Err(Failed::Refused(why)) => Err(format!("Nothing changed: {why}")),
    }
}

/// Bring this machine's copy of the account's policy up to date, as each contact with
/// Crossfyre does: a tightening held here is sent first, then the account's is fetched.
/// An offline machine makes no contact and keeps what it has.
pub async fn refresh(
    data_dir: &Path,
    session: &Session,
    cloud: &impl Cloud,
) -> Result<Machine, Failed> {
    let mut machine = super::load(data_dir);
    if machine.offline.is_some() {
        return Ok(machine);
    }
    if let Err(e) = sync(&mut machine, session, cloud).await {
        if matches!(e, Failed::NotLoggedIn(_)) {
            super::session_ended(data_dir, &session.key);
        }
        return Err(e);
    }
    super::save(data_dir, &machine).map_err(Failed::Refused)?;
    Ok(machine)
}

/// Take the account's policy into `machine`, sending a tightening held here first.
async fn sync(machine: &mut Machine, session: &Session, cloud: &impl Cloud) -> Result<(), Failed> {
    if machine.unsent
        && let Some(held) = machine.account
    {
        let remote = cloud.set(session, held).await?;
        super::cloud::take(machine, &remote);
    }
    let remote = cloud.fetch(session).await?;
    super::cloud::take(machine, &remote);
    Ok(())
}

/// What `crossfyre login` did to this machine's policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtLogin {
    pub machine: Machine,
    /// The one line login prints: which policy is active, and why.
    pub line: String,
    /// What did not go as it should have, when something did not.
    pub note: Option<String>,
}

/// After `crossfyre login` saved `session`: leave offline, asking first when the user
/// chose it, and take the account's policy in place of whatever this machine had.
/// `same_account` says the session is the account's this machine had before, so a
/// tightening held for it is sent; another account's never is.
pub async fn at_login(
    data_dir: &Path,
    session: &Session,
    same_account: bool,
    cloud: &impl Cloud,
    leave_offline: impl FnOnce() -> bool,
) -> AtLogin {
    let mut machine = super::load(data_dir);
    let stays = machine
        .offline
        .as_ref()
        .is_some_and(|o| o.reason == Reason::Chosen)
        && !leave_offline();
    if !stays {
        machine.offline = None;
    }
    if !same_account {
        machine.unsent = false;
    }
    let mut note = None;
    match sync(&mut machine, session, cloud).await {
        Ok(()) => {}
        Err(Failed::NotLoggedIn(why)) => {
            machine.offline = Some(Offline {
                reason: Reason::SessionEnded,
                since: utc_now(),
            });
            note = Some(format!("Crossfyre did not take the new session: {why}"));
        }
        Err(e) => {
            note = Some(format!(
                "Crossfyre did not give the account's policy ({e}), so this machine keeps what \
                 it had until its next contact."
            ))
        }
    }
    if let Err(e) = super::save(data_dir, &machine) {
        note = Some(format!("The policy could not be recorded here: {e}"));
    }
    let line = login_line(&machine);
    AtLogin {
        machine,
        line,
        note,
    }
}

fn login_line(machine: &Machine) -> String {
    match (&machine.offline, machine.account) {
        (Some(o), _) if o.reason == Reason::Chosen => format!(
            "policy: offline (you chose it), and the account's is {}. Leave offline with \
             crossfyre policy set connected or private.",
            machine.account.unwrap_or(Policy::Connected).key()
        ),
        (Some(o), _) => format!("policy: offline ({})", o.reason.says()),
        (None, _) => format!("policy: {}", why(machine, true)),
    }
}

/// `crossfyre policy list`.
pub async fn run_list(data_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use crate::toolchain::ui::*;
    title(
        "Crossfyre policy",
        "what this machine may send to Crossfyre",
    );
    let session = crate::auth::load_account(data_dir).map(|a| Session::of(&a));
    let mut note = None;
    let machine = match &session {
        Some(s) => match refresh(data_dir, s, &super::cloud::Crossfyre).await {
            Ok(m) => m,
            Err(Failed::NotLoggedIn(e)) => {
                note = Some(format!(
                    "Crossfyre does not take this machine's session: {e}"
                ));
                super::load(data_dir)
            }
            Err(e) => {
                note = Some(format!(
                    "Crossfyre did not answer ({e}), so this is what this machine last had."
                ));
                super::load(data_dir)
            }
        },
        None => super::load(data_dir),
    };
    let run = super::in_force(&machine, std::env::var(super::ENV).ok().as_deref());
    section("Policies");
    for p in ALL {
        let mark = if p == run.policy {
            arrow()
        } else {
            " ".to_string()
        };
        println!("  {mark} {:<10} {}", bold(p.key()), dim(p.sends()));
    }
    section("Active");
    field("policy", run.policy.key());
    field("why", &why(&machine, session.is_some()));
    if let Some(n) = &run.note {
        warn(n);
    }
    if let Some(n) = note {
        hint(&n);
    }
    end();
    Ok(())
}

/// Why this machine runs under what it does, with when that last changed.
pub fn why(machine: &Machine, logged_in: bool) -> String {
    if let Some(o) = &machine.offline {
        return format!("offline since {} ({})", o.since, o.reason.says());
    }
    let changed = match (&machine.changed_at, &machine.changed_via) {
        (Some(at), Some(via)) => format!(", changed {at} from {via}"),
        (Some(at), None) => format!(", changed {at}"),
        _ => String::new(),
    };
    match (machine.account, logged_in) {
        (None, _) => "connected, as every account starts".to_string(),
        (Some(p), true) if machine.unsent => {
            format!(
                "{} set here{changed}, sent to Crossfyre at its next contact",
                p.key()
            )
        }
        (Some(p), true) => format!("the account's {}{changed}", p.key()),
        (Some(p), false) => {
            format!(
                "{} on this machine{changed}; the next login takes the account's",
                p.key()
            )
        }
    }
}

/// What stops working when `machine` goes to `want`, when that is private and the
/// machine is not private already. Nothing stops for any other change.
pub fn going_private(machine: &Machine, want: Policy) -> Option<[&'static str; 4]> {
    (want == Policy::Private && machine.account != Some(Policy::Private))
        .then_some(super::PRIVATE_STOPS)
}

/// `crossfyre policy set [name]`. With no name, a picker at a terminal; without one,
/// the names to choose from. Private says what stops working before it is set.
pub async fn run_set(
    data_dir: &Path,
    name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::toolchain::ui::*;
    use std::io::IsTerminal;
    let terminal = std::io::stdin().is_terminal();
    let want = match name {
        Some(n) => Policy::parse(n).ok_or_else(|| {
            format!("{n} is not a policy. The policies are connected, private and offline.")
        })?,
        None if terminal => {
            let current = super::load(data_dir).active();
            let items: Vec<String> = ALL
                .iter()
                .map(|p| format!("{:<10} {}", p.key(), p.sends()))
                .collect();
            let pick = dialoguer::Select::new()
                .with_prompt("Which policy should this machine run under?")
                .items(&items)
                .default(ALL.iter().position(|p| *p == current).unwrap_or(0))
                .interact()
                .map_err(|e| e.to_string())?;
            ALL[pick]
        }
        None => {
            return Err(
                "No policy named and no terminal to pick one at. Run crossfyre policy set \
                        connected, private or offline."
                    .into(),
            );
        }
    };
    title("Crossfyre policy", want.key());
    if let Some(stops) = going_private(&super::load(data_dir), want) {
        warn("Private stops these for the account:");
        for line in stops {
            step(line);
        }
    }
    let session = crate::auth::load_account(data_dir).map(|a| Session::of(&a));
    let ask = || {
        warn(
            "This machine has a node, and a machine taken offline runs none: it stops until \
             you leave offline.",
        );
        !terminal
            || dialoguer::Confirm::new()
                .with_prompt("Go offline and stop the node?")
                .default(false)
                .interact()
                .unwrap_or(false)
    };
    let outcome = set(
        data_dir,
        session.as_ref(),
        want,
        &super::cloud::Crossfyre,
        &Registered(data_dir),
        ask,
    )
    .await?;
    match outcome {
        Outcome::Saved(p) => done(&format!(
            "policy: {} for the account, from this machine",
            p.key()
        )),
        Outcome::HeldHere(p) => {
            done(&format!("policy: {} on this machine now", p.key()));
            hint("Crossfyre could not be reached, so it goes there at the next contact.");
        }
        Outcome::ThisMachine(p) => {
            done(&format!("policy: {} on this machine", p.key()));
            hint("Logged out, so this machine alone. The next login takes the account's policy.");
        }
        Outcome::Offline { node } => {
            done("policy: offline on this machine");
            hint("It contacts Crossfyre only when you run crossfyre login or crossfyre update.");
            if node {
                hint("The node here stops, and does not start while this machine is offline.");
            }
        }
        Outcome::Unchanged {
            policy,
            left_offline: true,
        } => done(&format!(
            "policy: {}, and this machine is no longer offline",
            policy.key()
        )),
        Outcome::Unchanged { policy, .. } => ok(&format!("policy: already {}", policy.key())),
    }
    end();
    Ok(())
}
