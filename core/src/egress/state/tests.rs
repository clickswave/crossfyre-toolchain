use super::*;
use crate::egress::testkit::{
    FakeEngine, FakePlatform, direct_settings, http, ok, proxy_settings, refusing_port, resolver,
};
use cfx_tunnel::recorder::{Fixture, Recorder, to_loopback};

const NODE: &str = "node-1";
const ROUTE: &str = "/api/v1/node-egress";

fn fetch<'a>(h: &'a reqwest::Client, p: &'a FakePlatform) -> Fetch<'a> {
    Fetch {
        http: h,
        api_url: &p.url,
        api_key: "cfk_node",
    }
}

fn state() -> Arc<EgressState> {
    EgressState::new(resolver(&[]))
}

fn expect(mode: &str, proxy_id: Option<&str>, rev: i64) -> Value {
    json!({"egress_expect": {NODE: {"mode": mode, "proxy_id": proxy_id, "rev": rev}}})
}

#[test]
fn the_settings_read_as_the_platform_sends_them() {
    let d = NodeEgress::from_wire(&direct_settings(4)).unwrap();
    assert!(matches!(d.setting, Setting::Direct));
    assert_eq!((d.rev, d.mode(), d.proxy_id()), (4, "direct", None));

    let p = NodeEgress::from_wire(&json!({"v": 1, "rev": 7, "mode": "proxy", "proxy": {
        "id": "p1", "type": "http", "host": "2001:db8::7", "port": 3128,
        "username": "u", "password": ""}}))
    .unwrap();
    let Setting::Proxy { id, upstream } = &p.setting else {
        panic!("{p:?}")
    };
    assert_eq!(id, "p1");
    assert_eq!(upstream.label(), "http://[2001:db8::7]:3128");
    assert_eq!(upstream.auth, Some(("u".into(), "".into())));
    assert_eq!((p.mode(), p.proxy_id()), ("proxy", Some("p1")));

    // No user name: no credentials at all.
    let p = NodeEgress::from_wire(&json!({"v": 1, "rev": 1, "mode": "proxy", "proxy": {
        "id": "p1", "type": "socks5", "host": "gw.example.net", "port": 1080}}))
    .unwrap();
    let Setting::Proxy { upstream, .. } = &p.setting else {
        panic!()
    };
    assert_eq!(upstream.auth, None);
}

/// Proxy mode that names no usable proxy is refused, never read as direct.
#[test]
fn proxy_mode_without_a_usable_proxy_refuses_everything() {
    for proxy in [
        Value::Null,
        json!({"id": "p1", "type": "gopher", "host": "h", "port": 1}),
        json!({"id": "p1", "type": "socks4", "host": "h", "port": 1, "username": "u", "password": "p"}),
        json!({"id": "p1", "type": "http", "host": "h", "port": 0}),
        json!({"id": "p1", "type": "http", "host": "bad host", "port": 80}),
        json!({"id": "p1", "type": "http", "host": "h", "port": 80, "password": "only"}),
        json!({"type": "http", "host": "h", "port": 80}),
    ] {
        let n = NodeEgress::from_wire(&json!({"v": 1, "rev": 3, "mode": "proxy", "proxy": proxy}))
            .unwrap();
        assert!(
            matches!(n.setting, Setting::Unusable(_)),
            "{proxy} gave {n:?}"
        );
        assert_eq!(n.mode(), "proxy");
    }
}

#[test]
fn settings_this_node_cannot_read_are_an_error() {
    for v in [
        json!({"v": 2, "rev": 1, "mode": "direct"}),
        json!({"rev": 1, "mode": "direct"}),
        json!({"v": 1, "mode": "direct"}),
        json!({"v": 1, "rev": 1}),
        json!({"v": 1, "rev": 1, "mode": "tor"}),
        json!("direct"),
    ] {
        assert!(NodeEgress::from_wire(&v).is_err(), "{v} was read");
    }
}

/// An error about a proxy never quotes its password.
#[test]
fn a_proxy_error_does_not_quote_the_password() {
    let e = read_proxy(
        &json!({"id": "p1", "type": "socks5", "host": "h", "port": 1,
        "username": "u", "password": "s3cret".repeat(50)}),
    )
    .unwrap_err();
    assert!(!e.contains("s3cret"), "{e}");
}

#[test]
fn an_expectation_reads_or_refuses() {
    assert_eq!(Expect::read(&Value::Null), Ok(None));
    assert_eq!(
        Expect::read(&json!({"mode": "proxy", "proxy_id": "p1", "rev": 3})),
        Ok(Some(Expect {
            proxy_id: Some("p1".into()),
            rev: 3
        }))
    );
    assert_eq!(
        Expect::read(&json!({"mode": "direct", "proxy_id": null, "rev": 2})),
        Ok(Some(Expect {
            proxy_id: None,
            rev: 2
        }))
    );
    for bad in [
        json!({"mode": "proxy", "rev": 3}),
        json!({"mode": "proxy", "proxy_id": "p1"}),
        json!({"mode": "sideways", "rev": 3}),
        json!("proxy"),
    ] {
        assert!(Expect::read(&bad).is_err(), "{bad}");
    }
}

/// A direct node with current settings runs its ops as before, without asking the
/// platform anything.
#[tokio::test]
async fn a_direct_node_runs_ops_without_a_lease_or_a_fetch() {
    let p = FakePlatform::start(|_, _| ok(direct_settings(9))).await;
    let h = http();
    let st = state();
    st.apply_authorize(&direct_settings(5));
    for data in [
        json!({}),
        expect("direct", None, 5),
        expect("direct", None, 4),
    ] {
        assert!(
            st.for_op("op", NODE, &data, &fetch(&h, &p))
                .await
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(p.count(ROUTE), 0);
    assert!(!st.sends_through_proxy());
}

/// An authorize answer without `egress` is from a controller older than proxies.
#[tokio::test]
async fn no_egress_from_the_controller_means_direct() {
    let st = state();
    st.apply_authorize(&Value::Null);
    assert!(matches!(st.current().setting, Setting::Direct));
    assert!(!st.sends_through_proxy());
}

/// The op expects revision 8 through a proxy,
/// the node has revision 7 direct, and the fetch fails. The op is refused.
#[tokio::test]
async fn stale_settings_are_refreshed_or_refused() {
    let p = FakePlatform::start(|_, _| (500, json!({"status": 500, "message": "down"}))).await;
    let h = http();
    let st = state();
    st.apply_authorize(&direct_settings(7));
    let got = st
        .for_op("op", NODE, &expect("proxy", Some("p1"), 8), &fetch(&h, &p))
        .await;
    let why = got.unwrap_err();
    assert!(
        why.starts_with("could not fetch this node's proxy settings"),
        "{why}"
    );
    assert!(why.contains("500"), "{why}");
    assert_eq!(p.count(ROUTE), 1);
    // The node now knows it is behind: an op that expects nothing is refused too, and
    // within the retry window without asking again.
    let why = st
        .for_op("op2", NODE, &json!({}), &fetch(&h, &p))
        .await
        .unwrap_err();
    assert!(why.contains("could not fetch"), "{why}");
    assert_eq!(p.count(ROUTE), 1);
    assert!(st.sends_through_proxy());
    assert_eq!(st.heartbeat()["stale"], true);
}

/// The same op, with a platform that answers: the node takes the new settings and the
/// op gets a lease on them.
#[tokio::test]
async fn newer_settings_are_fetched_before_the_op_runs() {
    let rec = Recorder::start(to_loopback).await;
    let settings = proxy_settings(8, "p1", &rec);
    let p = FakePlatform::start(move |_, _| ok(settings.clone())).await;
    let h = http();
    let st = state();
    st.apply_authorize(&direct_settings(7));
    let lease = st
        .for_op("op", NODE, &expect("proxy", Some("p1"), 8), &fetch(&h, &p))
        .await
        .unwrap()
        .expect("a lease");
    assert_eq!(lease.proxy_id(), "p1");
    let reqs = p.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].0, ROUTE);
    assert_eq!(
        reqs[0].1,
        json!({"api_key": "cfk_node", "proxy_id": null, "test_id": null})
    );
    assert_eq!(st.current().rev, 8);
    let hb = st.heartbeat();
    assert_eq!(
        hb,
        json!({"gateway": GATEWAY_VERSION, "rev": 8, "mode": "proxy", "proxy_id": "p1"})
    );
}

/// The platform answered with an older revision than the op was dispatched with. The
/// op is refused rather than run on settings the platform has moved past.
#[tokio::test]
async fn settings_older_than_the_op_expects_refuse_it() {
    let p = FakePlatform::start(|_, _| ok(direct_settings(7))).await;
    let h = http();
    let st = state();
    st.apply_authorize(&direct_settings(7));
    let why = st
        .for_op("op", NODE, &expect("direct", None, 8), &fetch(&h, &p))
        .await
        .unwrap_err();
    assert!(
        why.contains("older than the ones this operation was sent with"),
        "{why}"
    );
}

#[tokio::test]
async fn an_op_for_another_proxy_is_refused() {
    let rec = Recorder::start(to_loopback).await;
    let p = FakePlatform::start(|_, _| (500, json!({}))).await;
    let h = http();
    let st = state();
    st.apply_authorize(&proxy_settings(5, "p2", &rec));
    let why = st
        .for_op("op", NODE, &expect("proxy", Some("p1"), 5), &fetch(&h, &p))
        .await
        .unwrap_err();
    assert_eq!(why, NOT_THAT_PROXY);

    // A direct node with an op that expects a proxy: refused, not run directly.
    st.apply_authorize(&direct_settings(6));
    let why = st
        .for_op("op", NODE, &expect("proxy", Some("p1"), 5), &fetch(&h, &p))
        .await
        .unwrap_err();
    assert_eq!(why, NOT_THAT_PROXY);
    assert_eq!(p.count(ROUTE), 0);
}

/// Settings newer than an op that expected direct win: the op goes through the proxy.
#[tokio::test]
async fn a_proxy_set_since_dispatch_carries_an_op_that_expected_direct() {
    let rec = Recorder::start(to_loopback).await;
    let p = FakePlatform::start(|_, _| (500, json!({}))).await;
    let h = http();
    let st = state();
    st.apply_authorize(&proxy_settings(6, "p1", &rec));
    let lease = st
        .for_op("op", NODE, &expect("direct", None, 5), &fetch(&h, &p))
        .await
        .unwrap();
    assert!(lease.is_some());
    // An op from a dispatch path that sets no expectation gets the lease too.
    assert!(
        st.for_op("op", NODE, &json!({}), &fetch(&h, &p))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn an_unusable_proxy_refuses_ops_and_bench_sends() {
    let p = FakePlatform::start(|_, _| (500, json!({}))).await;
    let h = http();
    let st = state();
    st.apply_authorize(&json!({"v": 1, "rev": 3, "mode": "proxy", "proxy": null}));
    let why = st
        .for_op("op", NODE, &json!({}), &fetch(&h, &p))
        .await
        .unwrap_err();
    assert!(why.contains("could not hand over"), "{why}");
    let why = st.for_bench(&json!({}), &fetch(&h, &p)).await.unwrap_err();
    assert!(why.contains("could not hand over"), "{why}");
    assert!(st.sends_through_proxy());
    assert!(st.heartbeat()["error"].is_string());
}

/// Settings the node cannot read at start leave it refusing ops until a fetch works.
#[tokio::test]
async fn unreadable_settings_at_start_are_fetched_again() {
    let rec = Recorder::start(to_loopback).await;
    let settings = proxy_settings(2, "p1", &rec);
    let p = FakePlatform::start(move |_, _| ok(settings.clone())).await;
    let h = http();
    let st = state();
    st.apply_authorize(&json!({"v": 99}));
    assert!(st.sends_through_proxy());
    let lease = st
        .for_op("op", NODE, &json!({}), &fetch(&h, &p))
        .await
        .unwrap();
    assert!(lease.is_some());
    assert_eq!(p.count(ROUTE), 1);
    assert!(st.heartbeat().get("stale").is_none());
}

/// `egress_changed` names a revision; until it is fetched, nothing runs on the old one.
#[tokio::test]
async fn an_announced_change_is_fetched_before_the_next_op() {
    let rec = Recorder::start(to_loopback).await;
    let settings = proxy_settings(4, "p1", &rec);
    let p = FakePlatform::start(move |_, _| ok(settings.clone())).await;
    let h = http();
    let st = state();
    st.apply_authorize(&direct_settings(3));
    st.announce(Some(3));
    assert!(!st.sends_through_proxy(), "an old revision changed nothing");
    st.announce(Some(4));
    assert!(st.sends_through_proxy());
    let lease = st
        .for_op("op", NODE, &json!({}), &fetch(&h, &p))
        .await
        .unwrap();
    assert_eq!(lease.unwrap().proxy_id(), "p1");
    assert_eq!(p.count(ROUTE), 1);
}

#[tokio::test]
async fn the_engine_request_is_wrapped_only_with_a_lease() {
    let rec = Recorder::start(to_loopback).await;
    let p = FakePlatform::start(|_, _| (500, json!({}))).await;
    let h = http();
    let st = state();
    st.apply_authorize(&proxy_settings(1, "p1", &rec));
    let lease = st
        .for_op("op", NODE, &json!({}), &fetch(&h, &p))
        .await
        .unwrap()
        .unwrap();
    let req = json!({"operation": "inject", "target": "http://a.example.test/"});
    let plain: Value = serde_json::from_str(&encode_for_engine(&req, None)).unwrap();
    assert_eq!(plain["operation"], "inject");
    let wrapped: Value = serde_json::from_str(&encode_for_engine(&req, Some(&lease))).unwrap();
    assert_eq!(wrapped["operation"], "egress");
    assert_eq!(wrapped["inner"], req);
    assert_eq!(wrapped["egress"], lease.wire());
    let url = wrapped["egress"]["proxy"].as_str().unwrap();
    assert!(
        url.starts_with("socks5h://") && url.contains("@127.0.0.1:"),
        "{url}"
    );
    // The engine is told the gateway, never the team proxy or its credentials.
    let up = Upstream::parse(url).unwrap();
    assert_ne!(up.port, rec.port);
    assert_ne!(up.auth.unwrap().0, cfx_tunnel::recorder::USER);
    assert!(!wrapped.to_string().contains(cfx_tunnel::recorder::PASS));
}

#[test]
fn an_old_engine_is_told_apart_from_an_ordinary_error() {
    let note = wrapper_refusal(
        "plessor",
        r#"{"type":"error","message":"Unknown operation: egress"}"#,
    );
    assert_eq!(
        note.as_deref(),
        Some(
            "plessor on this node cannot send through a proxy. Run `crossfyre update`, then retry"
        )
    );
    // ambulo and voyage before this release answer with `status`.
    assert!(
        wrapper_refusal(
            "ambulo",
            r#"{"operation_id":"","status":"error","message":"Unknown operation: egress"}"#
        )
        .is_some()
    );
    assert!(wrapper_refusal(
        "voyage",
        r#"{"type":"error","message":"egress version 1 is not one this engine reads (it reads 2)"}"#
    )
    .is_some());
    assert!(wrapper_refusal("plessor", r#"{"type":"error","message":"bad target"}"#).is_none());
    assert!(wrapper_refusal("plessor", r#"{"type":"ack","total":3}"#).is_none());
}

/// The heartbeat says, per engine, whether it sends a wrapped op through a proxy.
#[tokio::test]
async fn each_engine_is_asked_whether_it_reads_the_wrapper() {
    let current =
        FakeEngine::start(|_| async { vec![json!({"type": "capabilities", "egress": 1})] }).await;
    let old = FakeEngine::old().await;
    let doorward = FakeEngine::start(|_| async {
        vec![json!({"operation_id": "", "status": "error",
                    "message": "Unknown operation: capabilities"})]
    })
    .await;
    let newer =
        FakeEngine::start(|_| async { vec![json!({"type": "capabilities", "egress": 2})] }).await;
    let at = |p: u16| format!("127.0.0.1:{p}");
    assert_eq!(engine_reads_egress(&at(current.port)).await, Some(true));
    assert_eq!(engine_reads_egress(&at(old.port)).await, Some(false));
    assert_eq!(engine_reads_egress(&at(doorward.port)).await, Some(false));
    assert_eq!(engine_reads_egress(&at(newer.port)).await, Some(false));
    assert_eq!(engine_reads_egress("127.0.0.1:0").await, None);
    // The probe is wrapped, with a direct egress: it sends nothing anywhere.
    let probe = &current.seen()[0];
    assert_eq!(probe["operation"], "egress");
    assert_eq!(probe["egress"], json!({"v": 1, "proxy": null}));
    assert_eq!(probe["inner"], json!({"operation": "capabilities"}));
}

/// `egress_test`: the node fetches the proxy the platform names, against its test id,
/// and reports the exit address the check page saw through it.
#[tokio::test]
async fn a_proxy_check_reports_the_exit_address() {
    let rec = Recorder::start(to_loopback).await;
    let trace = Fixture::http("text/plain", "fl=1\nh=x\nip=198.51.100.7\nts=1\n".into()).await;
    let candidate = proxy_settings(0, "p9", &rec)["proxy"].clone();
    let p = FakePlatform::start(move |_, body| {
        if body["test_id"] == "t1" && body["proxy_id"] == "p9" {
            ok(json!({"v": 1, "proxy": candidate.clone()}))
        } else {
            (403, json!({"status": 403, "message": "no such test"}))
        }
    })
    .await;
    let h = http();
    let st = state();
    st.apply_authorize(&direct_settings(1));
    let url = format!("http://check.example.test:{}/cdn-cgi/trace", trace.port);
    let cmd = json!({"type": "egress_test", "command_id": "c1", "proxy_id": "p9", "test_id": "t1"});
    let r = st.check(&cmd, &url, &fetch(&h, &p)).await;
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["exit_ip"], "198.51.100.7");
    assert_eq!(r["proxy_id"], "p9");
    assert!(r["latency_ms"].is_u64(), "{r}");
    assert!(r["error"].is_null());
    // Through the proxy, by name: the node did not look the check host up.
    assert_eq!(
        cfx_tunnel::recorder::name_of(&rec.seen()[0]),
        Some("check.example.test")
    );
    assert_eq!(trace.connections(), rec.joined());

    let bad = json!({"type": "egress_test", "command_id": "c2", "proxy_id": "p9", "test_id": "t0"});
    let r = st.check(&bad, &url, &fetch(&h, &p)).await;
    assert_eq!(r["ok"], false);
    assert!(r["error"].as_str().unwrap().contains("403"), "{r}");
    let none = json!({"type": "egress_test", "command_id": "c3", "proxy_id": null});
    assert_eq!(st.check(&none, &url, &fetch(&h, &p)).await["ok"], false);
    assert_eq!(trace.connections(), 1);
}

#[tokio::test]
async fn a_failed_check_says_why_the_proxy_failed() {
    let (_held, dead) = refusing_port();
    let p = FakePlatform::start(move |_, _| {
        ok(json!({"v": 1, "proxy": {"id": "p9", "type": "socks5", "host": "127.0.0.1", "port": dead}}))
    })
    .await;
    let h = http();
    let st = state();
    let cmd = json!({"command_id": "c1", "proxy_id": "p9", "test_id": "t1"});
    let r = st
        .check(&cmd, "http://check.example.test/", &fetch(&h, &p))
        .await;
    assert_eq!(r["ok"], false);
    let e = r["error"].as_str().unwrap();
    assert!(
        e.starts_with("the proxy failed: could not connect to the proxy"),
        "{e}"
    );
}

/// Polls with a short interval, as the daemon does every minute.
fn keep(st: &Arc<EgressState>, p: &FakePlatform) -> Arc<tokio::sync::Notify> {
    let reconnected = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(Arc::clone(st).keep_current(
        http(),
        p.url.clone(),
        "cfk_node".into(),
        Arc::clone(&reconnected),
        Duration::from_millis(50),
    ));
    reconnected
}

/// The platform announces a change over NATS, and an announcement sent while the node
/// is reconnecting is lost. An op dispatched before the change, still queued or sent
/// again on resume, expects the old settings, so it would never make the node ask. The
/// node asks on its own, and sends nothing directly once it has the answer.
#[tokio::test]
async fn a_change_whose_announcement_was_lost_is_found_by_asking() {
    let rec = Recorder::start(to_loopback).await;
    let now = proxy_settings(6, "p1", &rec);
    let p = FakePlatform::start(move |_, _| ok(now.clone())).await;
    let h = http();
    let st = state();
    st.apply_authorize(&direct_settings(5));
    keep(&st, &p);
    for _ in 0..100 {
        if st.current().rev == 6 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(st.current().rev, 6, "the node never asked");
    assert!(st.sends_through_proxy());
    let lease = st
        .for_op(
            "op-queued",
            NODE,
            &expect("direct", None, 5),
            &fetch(&h, &p),
        )
        .await
        .unwrap();
    assert_eq!(
        lease.map(|l| l.proxy_id().to_string()).as_deref(),
        Some("p1")
    );
}

/// While the node's NATS connection is down it cannot hear of a change, so from the
/// moment it drops, an op asks for the settings before it runs, and a .cfx job, which
/// cannot go through a proxy, is refused until they are confirmed.
#[tokio::test]
async fn after_the_connection_drops_the_settings_are_confirmed_before_an_op() {
    let rec = Recorder::start(to_loopback).await;
    let now = proxy_settings(6, "p1", &rec);
    let p = FakePlatform::start(move |_, _| ok(now.clone())).await;
    let h = http();
    let st = state();
    st.apply_authorize(&direct_settings(5));
    st.connection_lost();
    assert!(
        st.sends_through_proxy(),
        "unconfirmed settings let a .cfx job run"
    );
    let lease = st
        .for_op("op-after", NODE, &expect("direct", None, 5), &fetch(&h, &p))
        .await
        .unwrap();
    assert_eq!(p.count(ROUTE), 1);
    assert_eq!(
        lease.map(|l| l.proxy_id().to_string()).as_deref(),
        Some("p1")
    );
}

/// Settings confirmed after a reconnect clear the doubt: a direct node runs direct again
/// without asking once per op.
#[tokio::test]
async fn a_reconnect_asks_at_once_and_clears_the_doubt() {
    let p = FakePlatform::start(|_, _| ok(direct_settings(5))).await;
    let h = http();
    let st = state();
    st.apply_authorize(&direct_settings(5));
    let reconnected = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(Arc::clone(&st).keep_current(
        http(),
        p.url.clone(),
        "cfk_node".into(),
        Arc::clone(&reconnected),
        Duration::from_secs(3600),
    ));
    st.connection_lost();
    reconnected.notify_one();
    for _ in 0..100 {
        if !st.sends_through_proxy() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !st.sends_through_proxy(),
        "the reconnect did not confirm the settings"
    );
    assert_eq!(p.count(ROUTE), 1);
    let lease = st
        .for_op("op", NODE, &expect("direct", None, 5), &fetch(&h, &p))
        .await
        .unwrap();
    assert!(lease.is_none());
    assert_eq!(p.count(ROUTE), 1);
}

/// A controller older than proxies has no settings route. Its nodes never ask, so a
/// dropped connection or the poll cannot leave them refusing every op.
#[tokio::test]
async fn a_controller_without_egress_settings_is_never_asked() {
    let p = FakePlatform::start(|_, _| (404, json!({"status": 404, "message": "no route"}))).await;
    let h = http();
    let st = state();
    st.apply_authorize(&Value::Null);
    let reconnected = keep(&st, &p);
    st.connection_lost();
    reconnected.notify_one();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(p.count(ROUTE), 0);
    assert!(!st.sends_through_proxy());
    let lease = st
        .for_op("op", NODE, &json!({}), &fetch(&h, &p))
        .await
        .unwrap();
    assert!(lease.is_none());
}
