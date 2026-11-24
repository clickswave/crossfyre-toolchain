//! The policy, as the installed program applies it.

use std::process::Command;

/// A listener on a free loopback port, standing in for Crossfyre, and whether anything
/// connected to it.
fn crossfyre_stand_in() -> (String, std::net::TcpListener) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    (format!("http://{}", l.local_addr().unwrap()), l)
}

/// `crossfyre` with `args` on the data directory `data`, stopped if it is still running
/// after 20 s, as one that started would be, waiting on a stand-in that never answers:
/// its status when it ended on its own, and its stderr.
fn crossfyre(
    data: &std::path::Path,
    args: &[&str],
    env: Option<&str>,
) -> (Option<std::process::ExitStatus>, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_crossfyre"));
    c.arg("--data-dir")
        .arg(data)
        .args(args)
        .env_remove("CROSSFYRE_POLICY")
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    if let Some(v) = env {
        c.env("CROSSFYRE_POLICY", v);
    }
    let mut child = c.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break Some(s);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let mut err = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
    (status, err)
}

/// Under private or offline, `crossfyre trace` says why and does not run: nothing is
/// opened and Crossfyre is not contacted. CROSSFYRE_POLICY tightens it the same way.
#[test]
fn trace_does_not_run_where_the_policy_sends_nothing_about_targets() {
    let (api_url, listener) = crossfyre_stand_in();
    for (state, env, says) in [
        (
            "account = \"private\"\n",
            None,
            "policy: private (the account's).",
        ),
        (
            "[offline]\nreason = \"chosen\"\nsince = \"2026-11-22T05:30:07Z\"\n",
            None,
            "policy: offline (you chose it).",
        ),
        (
            "",
            Some("offline"),
            "policy: offline (CROSSFYRE_POLICY=offline tightens this run from connected).",
        ),
    ] {
        let data = tempfile::tempdir().unwrap();
        std::fs::write(data.path().join("policy.toml"), state).unwrap();
        let trace = [
            "trace",
            "--workflow-id",
            "w1",
            "--token",
            "cfxt_test",
            "--api-url",
            &api_url,
        ];
        let (status, err) = crossfyre(data.path(), &trace, env);
        assert!(status.is_some_and(|s| !s.success()), "{state:?} ran: {err}");
        assert!(err.contains(says), "{state:?}: {err}");
        assert!(err.contains("so crossfyre trace does not run"), "{err}");
    }
    assert!(
        listener.accept().is_err(),
        "a trace the policy turned off contacted Crossfyre"
    );
}

/// On a machine taken offline, a command that would reach Crossfyre says why it does not
/// run, and nothing is contacted.
#[test]
fn an_offline_machine_lists_no_nodes_and_contacts_nothing() {
    let (api_url, listener) = crossfyre_stand_in();
    let data = tempfile::tempdir().unwrap();
    std::fs::write(
        data.path().join("auth.toml"),
        format!(
            "api_url = \"{api_url}\"\napi_key = \"cfk_test\"\nuser_id = \"u1\"\nusername = \"op\"\nemail = \"op@example.test\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        data.path().join("policy.toml"),
        "[offline]\nreason = \"chosen\"\nsince = \"2026-11-22T05:30:07Z\"\n",
    )
    .unwrap();
    let (status, err) = crossfyre(data.path(), &["node", "list"], None);
    assert!(
        status.is_some_and(|s| !s.success()),
        "node list ran offline: {err}"
    );
    assert!(
        err.contains("policy: offline (you chose it).")
            && err.contains("so crossfyre node list does not run"),
        "{err}"
    );
    assert!(
        listener.accept().is_err(),
        "an offline machine contacted Crossfyre"
    );
}

/// `policy set private` says what stops working before it sets the policy, and setting
/// connected, which stops nothing, says none of it.
#[test]
fn setting_private_says_what_stops_working_first() {
    let data = tempfile::tempdir().unwrap();
    let set = |name: &str| {
        let out = Command::new(env!("CARGO_BIN_EXE_crossfyre"))
            .arg("--data-dir")
            .arg(data.path())
            .args(["policy", "set", name])
            .env_remove("CROSSFYRE_POLICY")
            .env("NO_COLOR", "1")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "policy set {name} failed");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let connected = set("connected");
    let private = set("private");
    let saved = private
        .find("policy: private on this machine")
        .expect("the policy was not set");
    for line in cfx_core::policy::PRIVATE_STOPS {
        assert!(!connected.contains(line), "connected warned: {connected}");
        let said = private
            .find(line)
            .unwrap_or_else(|| panic!("not said: {line}\n{private}"));
        assert!(said < saved, "said after the policy was set: {line}");
    }
    // Already private, there is nothing new to stop.
    let again = set("private");
    assert!(
        !again.contains(cfx_core::policy::PRIVATE_STOPS[0]),
        "{again}"
    );
}
