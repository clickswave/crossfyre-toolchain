//! The policy, as the installed program applies it.

use std::process::Command;

/// A listener on a free loopback port, standing in for Crossfyre, and whether anything
/// connected to it.
fn crossfyre_stand_in() -> (String, std::net::TcpListener) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    (format!("http://{}", l.local_addr().unwrap()), l)
}

/// `crossfyre trace` against `api_url`, stopped if it is still running after 20 s, as a
/// trace that started would be: its status when it ended on its own, and its stderr.
fn trace(
    data: &std::path::Path,
    api_url: &str,
    env: Option<&str>,
) -> (Option<std::process::ExitStatus>, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_crossfyre"));
    c.arg("--data-dir")
        .arg(data)
        .args(["trace", "--workflow-id", "w1", "--token", "cfxt_test"])
        .args(["--api-url", api_url])
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
        let (status, err) = trace(data.path(), &api_url, env);
        assert!(status.is_some_and(|s| !s.success()), "{state:?} ran: {err}");
        assert!(err.contains(says), "{state:?}: {err}");
        assert!(err.contains("so crossfyre trace does not run"), "{err}");
    }
    assert!(
        listener.accept().is_err(),
        "a trace the policy turned off contacted Crossfyre"
    );
}
