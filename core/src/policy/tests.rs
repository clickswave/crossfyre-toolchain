use super::cloud::{Cloud, Failed, Remote, Session};
use super::command::{self, NodeHere, Outcome};
use super::*;
use std::sync::Mutex;

#[test]
fn a_time_is_written_as_crossfyre_writes_one() {
    assert_eq!(utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc(1_795_325_407), "2026-11-22T05:30:07Z");
    assert_eq!(utc(951_868_799), "2000-02-29T23:59:59Z");
}

/// The state beside auth.toml, read back as written; none reads as the default.
#[test]
fn the_machines_policy_is_kept_beside_the_session() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(load(dir.path()), Machine::default());
    let m = Machine {
        account: Some(Policy::Private),
        changed_at: Some("2026-11-22T05:30:07Z".into()),
        changed_via: Some("web".into()),
        unsent: false,
        offline: Some(Offline {
            reason: Reason::SessionEnded,
            since: "t".into(),
        }),
    };
    save(dir.path(), &m).unwrap();
    assert_eq!(path(dir.path()), dir.path().join("policy.toml"));
    assert_eq!(
        path(dir.path()).parent(),
        crate::auth::account_path(dir.path()).parent()
    );
    assert_eq!(load(dir.path()), m);
}

/// Crossfyre as a test answers it.
struct Fake {
    /// What `set` and `fetch` answer: the account's policy, or why they cannot.
    account: Mutex<Result<Policy, Failed>>,
    calls: Mutex<Vec<String>>,
}

impl Fake {
    fn answering(p: Policy) -> Fake {
        Fake {
            account: Mutex::new(Ok(p)),
            calls: Mutex::default(),
        }
    }
    fn failing(f: Failed) -> Fake {
        Fake {
            account: Mutex::new(Err(f)),
            calls: Mutex::default(),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn answer(&self) -> Result<Remote, Failed> {
        self.account.lock().unwrap().clone().map(|policy| Remote {
            policy,
            chosen: true,
            changed_at: Some("2026-11-22T05:30:07Z".into()),
            changed_via: Some("web".into()),
        })
    }
}

impl Cloud for Fake {
    async fn fetch(&self, _: &Session) -> Result<Remote, Failed> {
        self.calls.lock().unwrap().push("fetch".into());
        self.answer()
    }
    async fn set(&self, _: &Session, policy: Policy) -> Result<Remote, Failed> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("set {}", policy.key()));
        if let Ok(p) = self.account.lock().unwrap().as_mut() {
            *p = policy;
        }
        self.answer()
    }
}

struct Node(bool);
impl NodeHere for Node {
    fn runs(&self) -> bool {
        self.0
    }
}

fn session() -> Session {
    Session {
        api_url: "http://127.0.0.1:9".into(),
        key: "cfk_test".into(),
    }
}

#[tokio::test]
async fn logged_in_the_policy_is_written_to_crossfyre_first() {
    let dir = tempfile::tempdir().unwrap();
    let cloud = Fake::answering(Policy::Connected);
    let got = command::set(
        dir.path(),
        Some(&session()),
        Policy::Private,
        &cloud,
        &Node(false),
        || true,
    )
    .await
    .unwrap();
    assert_eq!(got, Outcome::Saved(Policy::Private));
    assert_eq!(cloud.calls(), ["set private"]);
    let m = load(dir.path());
    assert_eq!(m.account, Some(Policy::Private));
    assert_eq!(m.changed_via.as_deref(), Some("web"));
    assert!(!m.unsent);
}

/// Unreachable, a tightening holds here at once and goes at the next contact; a
/// loosening changes nothing.
#[tokio::test]
async fn unreachable_a_tightening_holds_here_and_a_loosening_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let down = Fake::failing(Failed::Unreachable("connection refused".into()));
    let got = command::set(
        dir.path(),
        Some(&session()),
        Policy::Private,
        &down,
        &Node(false),
        || true,
    )
    .await
    .unwrap();
    assert_eq!(got, Outcome::HeldHere(Policy::Private));
    let held = load(dir.path());
    assert_eq!((held.account, held.unsent), (Some(Policy::Private), true));
    assert_eq!(held.changed_via.as_deref(), Some(command::HERE));

    let err = command::set(
        dir.path(),
        Some(&session()),
        Policy::Connected,
        &down,
        &Node(false),
        || true,
    )
    .await
    .unwrap_err();
    assert!(
        err.starts_with("Nothing changed: Crossfyre could not be reached"),
        "{err}"
    );
    assert_eq!(load(dir.path()), held);

    // The next contact sends the tightening, then reads the account's back.
    let up = Fake::answering(Policy::Connected);
    let m = command::refresh(dir.path(), &session(), &up).await.unwrap();
    assert_eq!(up.calls(), ["set private", "fetch"]);
    assert_eq!((m.account, m.unsent), (Some(Policy::Private), false));
    assert_eq!(load(dir.path()), m);
}

#[tokio::test]
async fn logged_out_the_policy_is_this_machines_alone() {
    let dir = tempfile::tempdir().unwrap();
    let cloud = Fake::answering(Policy::Connected);
    let got = command::set(
        dir.path(),
        None,
        Policy::Private,
        &cloud,
        &Node(false),
        || true,
    )
    .await
    .unwrap();
    assert_eq!(got, Outcome::ThisMachine(Policy::Private));
    assert!(cloud.calls().is_empty());
    let m = load(dir.path());
    assert_eq!(m.account, Some(Policy::Private));
    assert_eq!(m.changed_via.as_deref(), Some(command::HERE));
    assert!(command::why(&m, false).contains("the next login takes the account's"));
}

/// Offline is this machine's, recorded with why; a node here stops for it, and only
/// once the user says so.
#[tokio::test]
async fn offline_is_recorded_with_why_and_a_node_here_stops_only_when_told() {
    let dir = tempfile::tempdir().unwrap();
    let cloud = Fake::answering(Policy::Connected);
    let err = command::set(
        dir.path(),
        Some(&session()),
        Policy::Offline,
        &cloud,
        &Node(true),
        || false,
    )
    .await
    .unwrap_err();
    assert!(
        err.contains("the node on this machine keeps running"),
        "{err}"
    );
    assert_eq!(load(dir.path()).offline, None);

    let asked = std::cell::Cell::new(false);
    let got = command::set(
        dir.path(),
        Some(&session()),
        Policy::Offline,
        &cloud,
        &Node(true),
        || {
            asked.set(true);
            true
        },
    )
    .await
    .unwrap();
    assert!(asked.get());
    assert_eq!(got, Outcome::Offline { node: true });
    assert!(
        cloud.calls().is_empty(),
        "offline asked Crossfyre: {:?}",
        cloud.calls()
    );
    let m = load(dir.path());
    assert_eq!(m.offline.as_ref().map(|o| o.reason), Some(Reason::Chosen));
    assert!(command::why(&m, true).starts_with("offline since "));

    // Offline, a contact asks Crossfyre nothing.
    let m = command::refresh(dir.path(), &session(), &cloud)
        .await
        .unwrap();
    assert!(cloud.calls().is_empty());
    assert_eq!(m.active(), Policy::Offline);

    // Setting the account's policy again leaves offline, through Crossfyre.
    let got = command::set(
        dir.path(),
        Some(&session()),
        Policy::Connected,
        &cloud,
        &Node(true),
        || true,
    )
    .await
    .unwrap();
    assert_eq!(got, Outcome::Saved(Policy::Connected));
    assert_eq!(load(dir.path()).offline, None);
}

fn logged_in(dir: &std::path::Path, user: &str) {
    crate::auth::save_account(
        dir,
        &crate::auth::Account {
            api_url: session().api_url,
            api_key: session().key,
            user_id: user.into(),
            username: user.into(),
            email: format!("{user}@example.test"),
        },
    )
    .unwrap();
}

/// A session Crossfyre no longer takes puts the machine offline, saying why, and the
/// contacts after it ask Crossfyre nothing.
#[tokio::test]
async fn a_session_crossfyre_does_not_take_puts_the_machine_offline() {
    let dir = tempfile::tempdir().unwrap();
    logged_in(dir.path(), "u1");
    let cloud = Fake::failing(Failed::NotLoggedIn("The key is invalid or revoked.".into()));
    let err = command::set(
        dir.path(),
        Some(&session()),
        Policy::Private,
        &cloud,
        &Node(false),
        || true,
    )
    .await
    .unwrap_err();
    assert!(
        err.ends_with("policy: offline (your session ended; run crossfyre login)"),
        "{err}"
    );
    let m = load(dir.path());
    assert_eq!(m.account, None);
    assert_eq!(m.offline.map(|o| o.reason), Some(Reason::SessionEnded));
    command::refresh(dir.path(), &session(), &cloud)
        .await
        .unwrap();
    assert_eq!(cloud.calls(), ["set private"]);
}

/// Noticed at the next contact: a refresh Crossfyre refuses the session for.
#[tokio::test]
async fn a_revoked_session_is_noticed_at_the_next_contact() {
    let dir = tempfile::tempdir().unwrap();
    logged_in(dir.path(), "u1");
    let cloud = Fake::failing(Failed::NotLoggedIn("The key is invalid or revoked.".into()));
    assert!(matches!(
        command::refresh(dir.path(), &session(), &cloud).await,
        Err(Failed::NotLoggedIn(_))
    ));
    assert_eq!(
        load(dir.path()).offline.map(|o| o.reason),
        Some(Reason::SessionEnded)
    );
    // A key that is not the session's, a node's, records nothing.
    let other = tempfile::tempdir().unwrap();
    logged_in(other.path(), "u1");
    assert_eq!(session_ended(other.path(), "cfn_a_node"), None);
    assert_eq!(load(other.path()), Machine::default());
}

async fn login(
    dir: &std::path::Path,
    same: bool,
    cloud: &Fake,
    leave: Option<bool>,
    choose: Option<Policy>,
) -> command::AtLogin {
    command::at_login(
        dir,
        &session(),
        same,
        cloud,
        || leave.expect("login asked to leave offline"),
        || choose,
    )
    .await
}

/// Login takes the account's policy in place of the machine's, and says which and why.
#[tokio::test]
async fn login_takes_the_accounts_policy_and_says_which() {
    let dir = tempfile::tempdir().unwrap();
    // Set here while logged out: the account's replaces it.
    save(
        dir.path(),
        &Machine {
            account: Some(Policy::Private),
            changed_via: Some(command::HERE.into()),
            ..Machine::default()
        },
    )
    .unwrap();
    let cloud = Fake::answering(Policy::Connected);
    let got = login(dir.path(), false, &cloud, None, None).await;
    assert_eq!(cloud.calls(), ["fetch"]);
    assert_eq!(got.machine.account, Some(Policy::Connected));
    assert_eq!(
        got.line,
        "policy: the account's connected, changed 2026-11-22T05:30:07Z from web"
    );
    assert_eq!(got.note, None);
    assert_eq!(load(dir.path()), got.machine);
}

/// A tightening held for this account is sent at its login; another account's never is.
#[tokio::test]
async fn a_held_tightening_goes_to_its_own_account_alone() {
    let held = Machine {
        account: Some(Policy::Private),
        changed_via: Some(command::HERE.into()),
        unsent: true,
        ..Machine::default()
    };
    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &held).unwrap();
    let cloud = Fake::answering(Policy::Connected);
    let got = login(dir.path(), true, &cloud, None, None).await;
    assert_eq!(cloud.calls(), ["set private", "fetch"]);
    assert_eq!(
        (got.machine.account, got.machine.unsent),
        (Some(Policy::Private), false)
    );

    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &held).unwrap();
    let cloud = Fake::answering(Policy::Connected);
    let got = login(dir.path(), false, &cloud, None, None).await;
    assert_eq!(cloud.calls(), ["fetch"]);
    assert_eq!(
        (got.machine.account, got.machine.unsent),
        (Some(Policy::Connected), false)
    );

    // Crossfyre out of reach: the other account's tightening stays here, unsent.
    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &held).unwrap();
    let down = Fake::failing(Failed::Unreachable("connection refused".into()));
    let got = login(dir.path(), false, &down, None, None).await;
    assert_eq!(
        (got.machine.account, got.machine.unsent),
        (Some(Policy::Private), false)
    );
    assert!(got.note.unwrap().contains("keeps what it had"));
}

/// Offline the user chose is left only when they say so at login; one a session's end
/// caused is left without asking.
#[tokio::test]
async fn login_asks_before_leaving_an_offline_the_user_chose() {
    let chosen = |reason| Machine {
        offline: Some(Offline {
            reason,
            since: "2026-11-22T05:30:07Z".into(),
        }),
        ..Machine::default()
    };
    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &chosen(Reason::Chosen)).unwrap();
    let cloud = Fake::answering(Policy::Private);
    let got = login(dir.path(), true, &cloud, Some(false), None).await;
    assert_eq!(got.machine.active(), Policy::Offline);
    assert_eq!(got.machine.account, Some(Policy::Private));
    assert!(
        got.line
            .starts_with("policy: offline (you chose it), and the account's is private."),
        "{}",
        got.line
    );
    assert_eq!(cloud.calls(), ["fetch"]);

    let got = login(dir.path(), true, &cloud, Some(true), None).await;
    assert_eq!(got.machine.offline, None);
    assert_eq!(got.machine.active(), Policy::Private);

    let dir = tempfile::tempdir().unwrap();
    save(dir.path(), &chosen(Reason::SessionEnded)).unwrap();
    let got = login(dir.path(), true, &cloud, None, None).await;
    assert_eq!(got.machine.offline, None);
}

/// An account with no policy yet is asked for one, connected selected, when someone is
/// here; with nobody here, it is left unchosen, which runs as connected, and says so.
#[tokio::test]
async fn a_first_login_asks_for_a_policy_or_leaves_it_unchosen() {
    /// Crossfyre for an account that has chosen none.
    struct Unchosen(Fake);
    impl Cloud for Unchosen {
        async fn fetch(&self, s: &Session) -> Result<Remote, Failed> {
            self.0.fetch(s).await.map(|r| Remote {
                chosen: false,
                changed_at: None,
                changed_via: None,
                ..r
            })
        }
        async fn set(&self, s: &Session, policy: Policy) -> Result<Remote, Failed> {
            self.0.set(s, policy).await
        }
    }
    let cloud = Unchosen(Fake::answering(Policy::Connected));
    let dir = tempfile::tempdir().unwrap();
    let got = command::at_login(dir.path(), &session(), false, &cloud, || false, || None).await;
    assert_eq!(cloud.0.calls(), ["fetch"]);
    assert_eq!(got.machine.account, None);
    assert_eq!(got.machine.active(), Policy::Connected);
    assert_eq!(
        got.line,
        "policy: connected, as none is chosen yet; choose one with crossfyre policy set"
    );

    let got = command::at_login(
        dir.path(),
        &session(),
        true,
        &cloud,
        || false,
        || Some(Policy::Private),
    )
    .await;
    assert_eq!(cloud.0.calls(), ["fetch", "fetch", "set private"]);
    assert_eq!(got.machine.account, Some(Policy::Private));
    assert!(
        got.line.starts_with("policy: the account's private"),
        "{}",
        got.line
    );
}

/// Logout leaves the machine's policy as it is.
#[test]
fn logout_leaves_the_policy_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    logged_in(dir.path(), "u1");
    let m = Machine {
        account: Some(Policy::Private),
        ..Machine::default()
    };
    save(dir.path(), &m).unwrap();
    assert!(crate::auth::clear_account(dir.path()));
    assert_eq!(load(dir.path()), m);
}

#[test]
fn why_says_when_the_policy_last_changed() {
    let m = Machine {
        account: Some(Policy::Private),
        changed_at: Some("2026-11-22T05:30:07Z".into()),
        changed_via: Some("web".into()),
        ..Machine::default()
    };
    assert_eq!(
        command::why(&m, true),
        "the account's private, changed 2026-11-22T05:30:07Z from web"
    );
    assert_eq!(
        command::why(&Machine::default(), true),
        "connected until a policy is chosen"
    );
}

/// Crossfyre's answer, read as /cli/policy gives it; offline is never an account's.
#[test]
fn the_accounts_policy_reads_from_crossfyres_answer() {
    let got = super::cloud::remote(&serde_json::json!({
        "policy": "private",
        "chosen": true,
        "changed_at": "2026-11-22T05:30:07Z",
        "changed_via": "cli: laptop",
    }))
    .unwrap();
    assert_eq!(
        got,
        Remote {
            policy: Policy::Private,
            chosen: true,
            changed_at: Some("2026-11-22T05:30:07Z".into()),
            changed_via: Some("cli: laptop".into()),
        }
    );
    let unchosen = super::cloud::remote(&serde_json::json!({ "policy": "connected" })).unwrap();
    let mut m = Machine {
        account: Some(Policy::Private),
        unsent: true,
        ..Machine::default()
    };
    super::cloud::take(&mut m, &unchosen);
    assert_eq!(m, Machine::default());
    assert_eq!(
        super::cloud::remote(&serde_json::json!({ "policy": "offline", "chosen": true })),
        None
    );
}

/// A node here is one registered in this data directory, which its supervisor runs.
#[test]
fn a_node_here_is_one_registered_in_this_data_directory() {
    let dir = tempfile::tempdir().unwrap();
    let here = command::Registered(dir.path());
    assert!(!here.runs());
    std::fs::create_dir(crate::nodes_dir(dir.path())).unwrap();
    std::fs::write(crate::nodes_dir(dir.path()).join("notes.txt"), "").unwrap();
    std::fs::write(crate::nodes_dir(dir.path()).join("-x.toml"), "").unwrap();
    assert!(!here.runs());
    std::fs::write(crate::nodes_dir(dir.path()).join("n1.toml"), "").unwrap();
    assert!(here.runs());
}

/// What an offline machine says, and only an offline one.
#[test]
fn an_offline_machine_says_why_and_a_connected_one_says_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(offline_line(dir.path()), None);
    assert_eq!(offline_refuses(dir.path(), "crossfyre node list"), None);
    save(
        dir.path(),
        &Machine {
            offline: Some(Offline {
                reason: Reason::SessionEnded,
                since: "2026-11-22T05:30:07Z".into(),
            }),
            ..Machine::default()
        },
    )
    .unwrap();
    assert_eq!(
        offline_line(dir.path()).as_deref(),
        Some("policy: offline (your session ended; run crossfyre login)")
    );
    let why = offline_refuses(dir.path(), "crossfyre node list").unwrap();
    assert!(why.contains("so crossfyre node list does not run"), "{why}");
}
