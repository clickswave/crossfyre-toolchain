//! Helpers here are shell scripts in a folder of their own, beside a stand-in for the
//! node's executable, so each test says what its helper does.

use super::*;
use crate::egress::testkit::resolver;
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::time::Instant;

/// A folder holding a stand-in node executable, where a helper can be put.
struct Beside {
    dir: tempfile::TempDir,
}

impl Beside {
    fn new() -> Beside {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(dir.path().join("node"), "").unwrap();
        Beside { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Put a helper whose `up` and `config` are `up` and `config`, shell run with the
    /// request on stdin, in a folder `$D`.
    fn helper(&self, up: &str, config: &str, mode: u32) {
        let script = format!(
            "#!/bin/sh\nD='{}'\ncase \"$1\" in\nconfig)\n{config}\n;;\nup)\n{up}\n;;\nesac\n",
            self.dir.path().display()
        );
        let path = self.path(helper::HELPER);
        let new = self.path("helper.new");
        std::fs::write(&new, script).unwrap();
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(mode)).unwrap();
        std::fs::rename(new, path).unwrap();
    }

    fn setup(&self) -> Setup {
        Setup {
            exe: self.path("node"),
            limits: Limits {
                config: Duration::from_secs(5),
                up: Duration::from_millis(800),
                down: Duration::from_secs(5),
            },
            retry: Duration::from_millis(100),
        }
    }
}

/// Answers `config` and `up` and holds egress up until its stdin closes.
const GOOD_UP: &str = r#"IFS= read -r line; printf '%s\n' "$line" > "$D/up.req"
printf '%s\n' '{"version": "fake 1", "up": true, "handle": {"n": 1}}'
cat > /dev/null; echo down > "$D/down""#;
const GOOD_CONFIG: &str = r#"cat > "$D/config.req"
printf '%s\n' '{"version": "fake 1", "network": {"kind": "openvpn", "kill_switch": true, "config_path": "/n/x.ovpn"}}'"#;

fn net(kill_switch: bool) -> NetworkConfig {
    serde_json::from_value(json!({"kind": "openvpn", "kill_switch": kill_switch})).unwrap()
}

fn asked(beside: &Beside, kill_switch: bool) -> Asked {
    Asked {
        raw: Some(
            json!({"kind": "openvpn", "kill_switch": kill_switch, "config_text": "client\n"}),
        ),
        net: net(kill_switch),
        net_dir: beside.path("n.network"),
        node_id: "node-1".into(),
        tunnel_hooks: false,
    }
}

fn state() -> Arc<EgressState> {
    EgressState::new(resolver(&[]))
}

/// Wait up to five seconds for `what` to hold.
fn soon(what: impl Fn() -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if what() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    what()
}

#[test]
fn a_helper_holds_egress_up_and_takes_it_down_when_dropped() {
    let beside = Beside::new();
    beside.helper(GOOD_UP, GOOD_CONFIG, 0o755);
    let st = state();
    let isolation = start(asked(&beside, true), beside.setup(), Arc::clone(&st));
    assert_eq!(
        st.isolation(),
        Isolated {
            label: "helper fake 1".into(),
            refusal: None
        }
    );
    assert_eq!(st.heartbeat()["isolation"], "helper fake 1");
    // It was handed the config as sent before it was asked to bring egress up.
    let config: Value =
        serde_json::from_str(&std::fs::read_to_string(beside.path("config.req")).unwrap()).unwrap();
    assert_eq!(config["interface"], 1);
    assert_eq!(config["raw"]["config_text"], "client\n");
    let up: Value =
        serde_json::from_str(&std::fs::read_to_string(beside.path("up.req")).unwrap()).unwrap();
    assert_eq!(up["node_id"], "node-1");
    assert_eq!(
        up["net"]["config_path"], "/n/x.ovpn",
        "the config the helper kept"
    );
    assert!(!beside.path("down").exists());
    drop(isolation);
    assert!(beside.path("down").exists(), "egress was not taken down");
}

#[tokio::test]
async fn without_a_helper_a_kill_switch_refuses_every_op_and_without_one_the_node_goes_direct() {
    let beside = Beside::new();
    let st = state();
    let _held = start(asked(&beside, true), beside.setup(), Arc::clone(&st));
    let why = "egress: refused (kill switch on, helper not installed)";
    assert_eq!(st.isolation().refusal.as_deref(), Some(why));
    assert_eq!(
        st.heartbeat()["isolation"],
        "refused (kill switch on, helper not installed)"
    );
    let h = reqwest::Client::new();
    let f = crate::egress::state::Fetch {
        http: &h,
        api_url: "http://127.0.0.1:9",
        api_key: "k",
    };
    assert_eq!(
        st.for_op("op", "node-1", &json!({}), &f).await.unwrap_err(),
        why
    );
    assert_eq!(st.for_bench(&json!({}), &f).await.unwrap_err(), why);

    let st = state();
    let _held = start(asked(&beside, false), beside.setup(), Arc::clone(&st));
    assert_eq!(
        st.isolation(),
        Isolated {
            label: "baseline (helper not installed)".into(),
            refusal: None
        }
    );
    assert!(
        st.for_op("op", "node-1", &json!({}), &f)
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_kill_switch_lets_ops_run_once_a_helper_answers() {
    let beside = Beside::new();
    let st = state();
    let _held = start(asked(&beside, true), beside.setup(), Arc::clone(&st));
    assert!(st.isolation().refusal.is_some());
    beside.helper(GOOD_UP, GOOD_CONFIG, 0o755);
    assert!(
        soon(|| st.isolation().refusal.is_none()),
        "{:?}",
        st.isolation()
    );
    assert_eq!(st.isolation().label, "helper fake 1");
}

#[test]
fn a_helper_that_stops_is_noticed_and_the_kill_switch_holds() {
    let beside = Beside::new();
    // Up once, then gone; every later try ends without an answer.
    let once = r#"if [ -e "$D/once" ]; then exit 1; fi; touch "$D/once"
IFS= read -r line; printf '%s\n' '{"version": "fake 1", "up": true}'; exit 0"#;
    beside.helper(once, GOOD_CONFIG, 0o755);
    let st = state();
    let _held = start(asked(&beside, true), beside.setup(), Arc::clone(&st));
    assert!(
        soon(|| st.isolation().refusal.as_deref()
            == Some("egress: refused (kill switch on, helper stopped)")
            || st
                .isolation()
                .refusal
                .as_deref()
                .is_some_and(|r| r.contains("ended without an answer"))),
        "{:?}",
        st.isolation()
    );
}

#[test]
fn a_helper_others_can_write_is_not_run() {
    let beside = Beside::new();
    let marks = r#"touch "$D/ran"; IFS= read -r line; printf '%s\n' '{"version": "x", "up": true}'; cat >/dev/null"#;
    beside.helper(marks, r#"touch "$D/ran""#, 0o775);
    let st = state();
    let _held = start(asked(&beside, true), beside.setup(), Arc::clone(&st));
    let refusal = st.isolation().refusal.unwrap();
    assert!(
        refusal.contains("helper not run:") && refusal.contains("writable by group or others"),
        "{refusal}"
    );
    assert!(!beside.path("ran").exists());
}

#[test]
fn a_helper_that_does_not_answer_or_answers_badly_is_not_taken() {
    let beside = Beside::new();
    for (up, why) in [
        ("sleep 30", "helper did not answer within 800 ms"),
        ("printf 'nope\\n'", "helper answered something unreadable"),
        (
            r#"printf '%s\n' '{"error": "interface 1 is not\none this helper speaks"}'"#,
            "helper said: interface 1 is not?one this helper speaks",
        ),
        (
            r#"printf '%s\n' '{"up": true}'"#,
            "helper answered without a version",
        ),
        (
            r#"printf '%s\n' '{"version": "v", "up": false}'"#,
            "helper answered without bringing egress up",
        ),
    ] {
        beside.helper(
            up,
            r#"printf '%s\n' '{"version": "v", "network": null}'"#,
            0o755,
        );
        let st = state();
        let _held = start(asked(&beside, false), beside.setup(), Arc::clone(&st));
        assert_eq!(st.isolation().label, format!("baseline ({why})"), "{up}");
    }
}

#[test]
fn a_direct_config_runs_no_helper() {
    let beside = Beside::new();
    beside.helper(r#"touch "$D/ran""#, r#"touch "$D/ran""#, 0o755);
    let st = state();
    let mut direct = asked(&beside, true);
    direct.net = NetworkConfig::default();
    let _held = start(direct, beside.setup(), Arc::clone(&st));
    assert_eq!(st.isolation().label, "direct");
    std::thread::sleep(Duration::from_millis(300));
    assert!(!beside.path("ran").exists());
}

#[test]
fn config_is_the_helpers_answer() {
    let beside = Beside::new();
    beside.helper(GOOD_UP, GOOD_CONFIG, 0o755);
    let found = helper::find(&beside.path("node")).unwrap();
    let raw = json!({"kind": "openvpn", "config_text": "client\n"});
    let (version, net) =
        helper::config(&found, &raw, &beside.path("n"), true, Limits::default()).unwrap();
    assert_eq!(version, "fake 1");
    assert_eq!(net.unwrap().config_path.as_deref(), Some("/n/x.ovpn"));
    let asked: Value =
        serde_json::from_str(&std::fs::read_to_string(beside.path("config.req")).unwrap()).unwrap();
    assert_eq!(asked["tunnel_hooks"], true);
    assert_eq!(
        helper::find(&beside.path("elsewhere/node")).unwrap_err(),
        "not installed"
    );
}
