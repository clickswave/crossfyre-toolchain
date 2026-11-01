//! The Cloud key: checked with the platform before it is saved, saved where only its
//! owner can read it, and sent nowhere but the `Authorization` header of a request to
//! the origin it was saved with.

use super::fake_cloud::{self, FakeCloud, KEY, Resp};
use super::support::*;
use crate::cloud::file::{self, Loaded};
use crate::cloud::login::{self, CloudCommand};
use cfx_cloud_wire as wire;
use std::sync::Arc;

/// The key's 32 hex characters, which must never be printed, whatever surrounds them.
const SECRET: &str = "0123456789abcdef0123456789abcdef";

fn cmd(d: &TempDir) -> CloudCommand {
    CloudCommand {
        default_dir: d.path().join("mcp"),
        cloud_file: None,
        version: "0.0.0-test".into(),
    }
}

fn saved(d: &TempDir) -> std::path::PathBuf {
    d.path().join("mcp").join(file::FILE_NAME)
}

#[tokio::test]
async fn login_checks_the_key_then_saves_it_for_its_owner_alone() {
    let cloud = FakeCloud::start(fake_cloud::account("launch")).await;
    let d = TempDir::new();
    let out = login::login(&cmd(&d), &cloud.url(), KEY)
        .await
        .unwrap()
        .join("\n");
    assert!(out.contains("Acme staging"), "{out}");
    assert!(out.contains("launch"), "{out}");
    assert!(out.contains("2 entries a launch may target"), "{out}");
    assert!(!out.contains(SECRET), "{out}");

    let p = saved(&d);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode();
        assert_eq!(mode(&p) & 0o777, 0o600);
        assert_eq!(mode(p.parent().unwrap()) & 0o777, 0o700);
    }
    match file::load_with(&p, None, |_| None) {
        Loaded::Ready(c) => {
            assert_eq!(c.key.expose(), KEY);
            assert_eq!(c.api_url, cloud.url());
            assert_eq!(c.cached.workspace_name.as_deref(), Some("Acme staging"));
            assert_eq!(c.cached.permission.as_deref(), Some("launch"));
            assert_eq!(c.cached.key_prefix.as_deref(), Some("cfm_01234567"));
        }
        other => panic!("{other:?}"),
    }

    let reqs = cloud.requests();
    assert_eq!(reqs.len(), 1);
    let r = &reqs[0];
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, "/api/v1/mcp/whoami");
    assert_eq!(r.header("authorization"), Some(&*format!("Bearer {KEY}")));
    assert_eq!(r.header(wire::header::TOOL), Some("cloud_login"));
    assert_eq!(r.header(wire::header::CLIENT), Some("crossfyre-cli"));
    assert_eq!(r.body, serde_json::json!({}));
    assert!(
        r.header("user-agent")
            .is_some_and(|u| u.starts_with("crossfyre-mcp/")),
        "{r:?}"
    );
    // The key is in the one header and nowhere else in the request.
    assert_eq!(r.raw.matches(SECRET).count(), 1, "{}", r.raw);
}

#[tokio::test]
async fn a_refused_key_is_not_saved_and_never_echoed() {
    let cloud = FakeCloud::start(Arc::new(|_: &fake_cloud::Req| {
        Resp::refusal(401, wire::Reason::KeyExpired)
    }))
    .await;
    let d = TempDir::new();
    let e = login::login(&cmd(&d), &cloud.url(), KEY).await.unwrap_err();
    assert!(e.contains("key_expired"), "{e}");
    assert!(!e.contains(SECRET), "{e}");
    assert!(!saved(&d).exists());

    // Not a key at all: refused before anything is sent, and not repeated back.
    let before = cloud.conns();
    let wrong = "cfk_0123456789abcdef0123456789abcdef";
    let e = login::login(&cmd(&d), &cloud.url(), wrong)
        .await
        .unwrap_err();
    assert!(!e.contains(SECRET), "{e}");
    assert_eq!(cloud.conns(), before);
    assert!(!saved(&d).exists());
}

#[tokio::test]
async fn the_key_goes_only_to_the_origin_it_was_given() {
    // A redirect to another listener on this machine is not followed.
    let elsewhere = listener(Reply::ok("{}")).await;
    let to = format!("http://127.0.0.1:{}/api/v1/mcp/whoami", elsewhere.port);
    let cloud = FakeCloud::start(Arc::new(move |_: &fake_cloud::Req| {
        Resp::raw(307, "").header("location", &to)
    }))
    .await;
    let d = TempDir::new();
    let e = login::login(&cmd(&d), &cloud.url(), KEY).await;
    assert_eq!(elsewhere.conns(), 0, "the redirect was followed");
    let e = e.unwrap_err();
    assert!(e.contains("307"), "{e}");
    assert_eq!(cloud.conns(), 1);
    assert!(!saved(&d).exists());

    // Plain http to another machine would send the key in the clear: refused before
    // any connection is made.
    for bad in [
        "http://crossfyre.example",
        "http://10.0.0.5:12004",
        "ftp://x.example",
    ] {
        let e = login::login(&cmd(&d), bad, KEY).await.unwrap_err();
        assert!(!e.contains(SECRET), "{e}");
    }
    assert!(!saved(&d).exists());
}

#[tokio::test]
async fn status_reads_the_key_and_logout_revokes_then_removes_it() {
    let cloud = FakeCloud::start(fake_cloud::account("read")).await;
    let d = TempDir::new();
    login::login(&cmd(&d), &cloud.url(), KEY).await.unwrap();

    let out = login::status(&cmd(&d)).await.unwrap().join("\n");
    assert!(out.contains("cfm_01234567 from the file"), "{out}");
    assert!(out.contains("read"), "{out}");
    assert!(out.contains("call-"), "{out}");
    assert!(!out.contains(SECRET), "{out}");

    let out = login::logout(&cmd(&d), true).await.unwrap().join("\n");
    assert!(out.contains("Revoked cfm_01234567"), "{out}");
    assert_eq!(
        cloud.routes().last().map(String::as_str),
        Some("key/revoke")
    );
    assert!(!saved(&d).exists());

    let e = login::status(&cmd(&d)).await.unwrap_err();
    assert!(e.contains("crossfyre mcp cloud login"), "{e}");
}

#[tokio::test]
async fn logout_removes_a_key_the_platform_already_refuses() {
    let cloud = FakeCloud::start(Arc::new(|r: &fake_cloud::Req| match r.route.as_str() {
        wire::route::KEY_REVOKE => Resp::refusal(401, wire::Reason::KeyRevoked),
        _ => Resp::ok(fake_cloud::whoami("launch")),
    }))
    .await;
    let d = TempDir::new();
    login::login(&cmd(&d), &cloud.url(), KEY).await.unwrap();
    let out = login::logout(&cmd(&d), true).await.unwrap().join("\n");
    assert!(out.contains("already refused"), "{out}");
    assert!(!saved(&d).exists());

    // A platform that answers with something else leaves the file in place, so the
    // person can try again.
    let failing = FakeCloud::start(Arc::new(|r: &fake_cloud::Req| match r.route.as_str() {
        wire::route::KEY_REVOKE => Resp::raw(500, "<html>oops</html>"),
        _ => Resp::ok(fake_cloud::whoami("launch")),
    }))
    .await;
    login::login(&cmd(&d), &failing.url(), KEY).await.unwrap();
    assert!(login::logout(&cmd(&d), true).await.is_err());
    assert!(saved(&d).exists());
    // Without --revoke it is only removed.
    login::logout(&cmd(&d), false).await.unwrap();
    assert!(!saved(&d).exists());
}

#[tokio::test]
async fn a_rate_limited_check_says_when_to_try_again() {
    let cloud = FakeCloud::start(Arc::new(|_: &fake_cloud::Req| {
        Resp::refusal(429, wire::Reason::RateLimited).header("retry-after", "42")
    }))
    .await;
    let d = TempDir::new();
    let e = login::login(&cmd(&d), &cloud.url(), KEY).await.unwrap_err();
    assert!(e.contains("rate_limited") && e.contains("42 s"), "{e}");
    assert!(!saved(&d).exists());
}
