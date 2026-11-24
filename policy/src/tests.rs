use super::*;

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

/// The state as the CLI writes it, read back by any program; what does not read is the
/// default, connected.
#[test]
fn the_state_reads_as_it_was_written_and_garbage_as_the_default() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read(dir.path()), Machine::default());
    let m = Machine {
        account: Some(Policy::Private),
        changed_at: Some("2026-11-22T05:30:07Z".into()),
        changed_via: Some("web".into()),
        unsent: true,
        offline: Some(Offline {
            reason: Reason::SessionEnded,
            since: "2026-11-22T05:30:07Z".into(),
        }),
    };
    std::fs::write(path(dir.path()), m.to_toml().unwrap()).unwrap();
    assert_eq!(read(dir.path()), m);
    assert_eq!(Machine::from_toml("account = 7"), Machine::default());
    assert_eq!(path(dir.path()), dir.path().join("policy.toml"));
}

/// A local tool that sends data about a target says why it does not run, and how to
/// change that; under connected it runs.
#[test]
fn a_tool_that_sends_targets_says_why_it_does_not_run() {
    let tool = "crossfyre trace";
    let connected = Machine::default();
    assert_eq!(
        turned_off(&connected, &in_force(&connected, None), tool),
        None
    );
    assert!(Policy::Connected.sends_targets());
    assert!(!Policy::Private.sends_targets() && !Policy::Offline.sends_targets());

    let private = Machine {
        account: Some(Policy::Private),
        ..Machine::default()
    };
    let why = turned_off(&private, &in_force(&private, None), tool).unwrap();
    assert!(
        why.starts_with("policy: private (the account's). This machine's tools send nothing"),
        "{why}"
    );
    assert!(why.contains("so crossfyre trace does not run"), "{why}");

    let offline = Machine {
        offline: Some(Offline {
            reason: Reason::Chosen,
            since: "t".into(),
        }),
        ..Machine::default()
    };
    let why = turned_off(&offline, &in_force(&offline, None), tool).unwrap();
    assert!(why.starts_with("policy: offline (you chose it)."), "{why}");
    assert!(
        why.ends_with("Leave offline with crossfyre policy set connected."),
        "{why}"
    );

    // Tightened for this run, it says the variable did it.
    let why = turned_off(&connected, &in_force(&connected, Some("private")), tool).unwrap();
    assert!(
        why.starts_with(
            "policy: private (CROSSFYRE_POLICY=private tightens this run from connected)."
        ),
        "{why}"
    );
}
