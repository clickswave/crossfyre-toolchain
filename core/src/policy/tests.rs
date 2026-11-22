use super::cloud::{Cloud, Failed, Remote, Session};
use super::command::{self, NodeHere, Outcome};
use super::*;
use std::sync::Mutex;

#[test]
fn the_policies_go_from_most_sent_to_least() {
    assert!(Policy::Connected < Policy::Private && Policy::Private < Policy::Offline);
    assert_eq!(Policy::parse(" private "), Some(Policy::Private));
    assert_eq!(Policy::parse("open"), None);
    assert!(!Policy::Offline.is_account());
}

#[test]
fn offline_comes_before_the_accounts_policy_and_none_is_connected() {
    let mut m = Machine::default();
    assert_eq!(m.active(), Policy::Connected);
    m.account = Some(Policy::Private);
    assert_eq!(m.active(), Policy::Private);
    m.offline = Some(Offline {
        reason: Reason::Chosen,
        since: "x".into(),
    });
    assert_eq!(m.active(), Policy::Offline);
}

/// CROSSFYRE_POLICY tightens a run and never loosens it, and says when it is ignored.
#[test]
fn the_variable_tightens_a_run_and_never_loosens_it() {
    let private = Machine {
        account: Some(Policy::Private),
        ..Machine::default()
    };
    let run = in_force(&private, Some("offline"));
    assert_eq!(run.policy, Policy::Offline);
    assert!(run.note.unwrap().contains("tightens this run from private"));
    let run = in_force(&private, Some("connected"));
    assert_eq!(run.policy, Policy::Private);
    assert!(
        run.note
            .unwrap()
            .contains("looser than this machine's private, so it is ignored")
    );
    let run = in_force(&private, Some("loose"));
    assert_eq!(run.policy, Policy::Private);
    assert!(run.note.unwrap().contains("names no policy"));
    assert_eq!(
        in_force(&private, Some("private")),
        InForce {
            policy: Policy::Private,
            note: None
        }
    );
    assert_eq!(
        in_force(&private, None),
        InForce {
            policy: Policy::Private,
            note: None
        }
    );
    assert_eq!(in_force(&private, Some("  ")).note, None);
}

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
            reason: Reason::SessionRevoked,
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

#[tokio::test]
async fn a_session_crossfyre_does_not_take_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
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
    assert!(err.contains("Run crossfyre login"), "{err}");
    assert_eq!(load(dir.path()), Machine::default());
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
    m.take(&unchosen);
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
