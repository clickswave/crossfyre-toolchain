//! Against a Crossfyre of the tests' own, which answers `/cli/components` and serves the
//! files, into a binaries' folder of each test's own and never this host's.

use super::*;
use base64::Engine as _;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncWriteExt;

const KEY: &str = "cfk_test_account_key";

/// What the fake Crossfyre answers.
#[derive(Clone)]
struct Answers {
    /// The status `/cli/components` answers with, and its message when it is not 200.
    status: u16,
    message: String,
    included: Vec<&'static str>,
    manifest: String,
    files: HashMap<String, Vec<u8>>,
}

struct Crossfyre {
    url: String,
    asked: Arc<Mutex<Vec<(String, Value)>>>,
}

impl Crossfyre {
    async fn start(answers: Answers) -> Crossfyre {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let asked: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
        let keep = Arc::clone(&asked);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let (keep, answers) = (Arc::clone(&keep), answers.clone());
                tokio::spawn(async move {
                    let Some((path, body)) =
                        crate::egress::testkit::read_http_request(&mut s).await
                    else {
                        return;
                    };
                    keep.lock().unwrap().push((path.clone(), body.clone()));
                    let (code, kind, bytes) = match path.as_str() {
                        "/api/v1/cli/components" if answers.status != 200 => (
                            answers.status,
                            "application/json",
                            json!({"message": answers.message, "errors": [answers.message]})
                                .to_string()
                                .into_bytes(),
                        ),
                        "/api/v1/cli/components" => (
                            200,
                            "application/json",
                            json!({"data": {"plan": "pro", "included": answers.included,
                                            "manifest": answers.manifest, "signature": null}})
                            .to_string()
                            .into_bytes(),
                        ),
                        "/api/v1/cli/components/download" => {
                            let component = body["component"].as_str().unwrap_or("");
                            let file = body["file"].as_str().unwrap_or("");
                            match answers.files.get(file) {
                                Some(b) if answers.included.contains(&component) => {
                                    (200, "application/octet-stream", b.clone())
                                }
                                _ => (
                                    403,
                                    "application/json",
                                    json!({"message": "not included"}).to_string().into_bytes(),
                                ),
                            }
                        }
                        _ => (404, "application/json", b"{}".to_vec()),
                    };
                    let head = format!(
                        "HTTP/1.1 {code} X\r\nContent-Type: {kind}\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n",
                        bytes.len()
                    );
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(&bytes).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        Crossfyre { url, asked }
    }

    fn creds(&self) -> Credentials {
        Credentials {
            api_url: self.url.clone(),
            key: KEY.into(),
        }
    }

    fn downloads(&self) -> Vec<String> {
        self.asked
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == "/api/v1/cli/components/download")
            .map(|(_, b)| b["file"].as_str().unwrap_or("").to_string())
            .collect()
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}

const HELPER_BYTES: &[u8] = b"#!/bin/sh\necho the helper\n";
const LICENCE: &[u8] = b"CROSSFYRE BINARY LICENCE\n\nThe terms of a test.\n";
const NOTICES: &[u8] = b"THIRD-PARTY NOTICES: Crossfyre components\n\nBinaries: egress pacing\n";

/// The release key the tests' module is signed with, and the data key it must not be.
fn release_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
}
fn data_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
}
fn public(k: &ed25519_dalek::SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(k.verifying_key().as_bytes())
}
fn sign(k: &ed25519_dalek::SigningKey, bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(k.sign(bytes).to_bytes())
}

/// A pacing module of the interface, as small as one can be.
fn module() -> Vec<u8> {
    wat::parse_str(
        r#"(module
          (memory (export "memory") 1)
          (data (i32.const 16) "test 1")
          (func (export "cfx_interface") (result i32) (i32.const 1))
          (func (export "cfx_version") (result i64)
            (i64.or (i64.shl (i64.const 16) (i64.const 32)) (i64.const 6)))
          (func (export "cfx_alloc") (param i32) (result i32) (i32.const 1024))
          (func (export "cfx_call") (param i32 i32 i32 i32) (result i64) (i64.const -1)))"#,
    )
    .unwrap()
}

/// Crossfyre with egress and pacing, egress at `egress_version`, the module signed by
/// `signer`, and `included` in the plan.
fn answers(
    included: Vec<&'static str>,
    egress_version: &str,
    signer: &ed25519_dalek::SigningKey,
) -> Answers {
    let platform = super::super::install::platform_key();
    let m = module();
    let manifest = json!({"components": {
        "egress": {"version": egress_version, "artifacts": {
            platform.clone(): {"file": "cfx-egress-test", "sha256": sha(HELPER_BYTES)}}},
        "pacing": {"version": "0.3.0", "artifacts": {
            "any": {"file": "pacing.wasm", "sha256": sha(&m), "sig": "pacing.wasm.sig"}}},
    }, "texts": {
        "BINARY-LICENCE.txt": {"file": "BINARY-LICENCE-0.3.txt", "sha256": sha(LICENCE)},
        "THIRD-PARTY-NOTICES-COMPONENTS": {"file": "notices-0.3.txt", "sha256": sha(NOTICES)},
    }})
    .to_string();
    Answers {
        status: 200,
        message: String::new(),
        included,
        manifest,
        files: HashMap::from([
            ("cfx-egress-test".to_string(), HELPER_BYTES.to_vec()),
            ("pacing.wasm".to_string(), m.clone()),
            ("pacing.wasm.sig".to_string(), sign(signer, &m).into_bytes()),
            ("BINARY-LICENCE-0.3.txt".to_string(), LICENCE.to_vec()),
            ("notices-0.3.txt".to_string(), NOTICES.to_vec()),
        ]),
    }
}

/// `answers` with the manifest's texts as `edit` leaves them.
fn with_texts(mut a: Answers, edit: impl FnOnce(&mut Value)) -> Answers {
    let mut m: Value = serde_json::from_str(&a.manifest).unwrap();
    edit(&mut m["texts"]);
    a.manifest = m.to_string();
    a
}

/// A binaries' folder of the test's own, writable by its owner only.
fn here() -> (tempfile::TempDir, Here) {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let here = Here {
        bin: dir.path().to_path_buf(),
        services: false,
    };
    (dir, here)
}

#[tokio::test]
async fn what_the_plan_includes_is_installed_checked_and_versioned() {
    let cf = Crossfyre::start(answers(vec!["egress", "pacing"], "0.2.0", &release_key())).await;
    let (_dir, here) = here();
    let client = reqwest::Client::new();
    let offer = offer(&client, &cf.creds()).await.unwrap();
    assert_eq!(offer.plan.as_deref(), Some("pro"));
    let keys = [public(&release_key())];
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    let got = bring_current(
        &client,
        &cf.creds(),
        &offer,
        &COMPONENTS,
        true,
        &keys,
        &here,
    )
    .await;
    assert_eq!(
        got,
        [
            ("pacing", Kept::Installed("0.3.0".into())),
            ("egress", Kept::Installed("0.2.0".into())),
        ]
    );
    let (helper, sidecar) = here.placed("egress");
    assert_eq!(std::fs::read(&helper).unwrap(), HELPER_BYTES);
    assert_eq!(std::fs::read_to_string(sidecar).unwrap(), "0.2.0");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&helper).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }
    // The module and its signature, where engines load them.
    assert_eq!(
        std::fs::read(here.bin.join("pacing.wasm")).unwrap(),
        module()
    );
    assert!(here.bin.join("pacing.wasm.sig").exists());
    assert_eq!(installed_version(&here, "pacing").as_deref(), Some("0.3.0"));
    // plessor-authz is not in the plan here, so nothing was asked for it.
    assert!(!cf.downloads().iter().any(|f| f.contains("authz")));
    assert!(
        cf.asked
            .lock()
            .unwrap()
            .iter()
            .all(|(_, b)| b["api_key"] == KEY)
    );

    // Asked again: current, and nothing downloaded.
    let before = cf.downloads().len();
    let again = bring_current(
        &client,
        &cf.creds(),
        &offer,
        &COMPONENTS,
        false,
        &keys,
        &here,
    )
    .await;
    assert_eq!(
        again,
        [
            ("pacing", Kept::Current("0.3.0".into())),
            ("egress", Kept::Current("0.2.0".into())),
        ]
    );
    assert_eq!(cf.downloads().len(), before);
}

#[tokio::test]
async fn a_newer_version_is_taken_and_a_dropped_plan_keeps_what_is_here() {
    let (_dir, here) = here();
    let client = reqwest::Client::new();
    let keys: Vec<&str> = Vec::new();
    let old = Crossfyre::start(answers(vec!["egress"], "0.1.0", &release_key())).await;
    let o = offer(&client, &old.creds()).await.unwrap();
    bring_current(&client, &old.creds(), &o, &["egress"], true, &keys, &here).await;
    assert_eq!(installed_version(&here, "egress").as_deref(), Some("0.1.0"));

    let newer = Crossfyre::start(answers(vec!["egress"], "0.2.0", &release_key())).await;
    let o = offer(&client, &newer.creds()).await.unwrap();
    let got = bring_current(
        &client,
        &newer.creds(),
        &o,
        &["egress"],
        false,
        &keys,
        &here,
    )
    .await;
    assert_eq!(got, [("egress", Kept::Installed("0.2.0".into()))]);

    // The plan no longer includes it: kept as it is, not updated, nothing fetched.
    let dropped = Crossfyre::start(answers(vec![], "0.9.0", &release_key())).await;
    let o = offer(&client, &dropped.creds()).await.unwrap();
    let got = bring_current(
        &client,
        &dropped.creds(),
        &o,
        &COMPONENTS,
        true,
        &keys,
        &here,
    )
    .await;
    assert_eq!(got, [("egress", Kept::NoLongerIncluded("0.2.0".into()))]);
    assert_eq!(installed_version(&here, "egress").as_deref(), Some("0.2.0"));
    assert!(dropped.downloads().is_empty());
}

#[tokio::test]
async fn a_file_that_does_not_check_out_is_not_placed() {
    let (_dir, here) = here();
    let client = reqwest::Client::new();
    // The helper's bytes are not what the manifest's SHA-256 says.
    let mut a = answers(vec!["egress", "pacing"], "0.2.0", &data_key());
    a.files.insert(
        "cfx-egress-test".into(),
        b"#!/bin/sh\necho another\n".to_vec(),
    );
    let cf = Crossfyre::start(a).await;
    let o = offer(&client, &cf.creds()).await.unwrap();
    // The module is signed by the data key, which never vouches for code.
    let keys = [public(&release_key())];
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    let got = bring_current(&client, &cf.creds(), &o, &COMPONENTS, true, &keys, &here).await;
    for (component, kept) in &got {
        assert!(matches!(kept, Kept::Failed(_)), "{component}: {kept:?}");
    }
    let Kept::Failed(why) = &got[0].1 else {
        unreachable!()
    };
    assert!(why.contains("not signed by a release key"), "{why}");
    let Kept::Failed(why) = &got[1].1 else {
        unreachable!()
    };
    assert!(why.starts_with("checksum mismatch"), "{why}");
    assert_eq!(
        std::fs::read_dir(&here.bin).unwrap().count(),
        0,
        "something was placed"
    );
}

#[tokio::test]
async fn out_of_reach_waits_and_a_refusal_says_why() {
    let client = reqwest::Client::new();
    // Nothing listens on port 9.
    let gone = Credentials {
        api_url: "http://127.0.0.1:9".into(),
        key: KEY.into(),
    };
    assert!(matches!(
        offer(&client, &gone).await,
        Err(Unavailable::Unreachable(_))
    ));
    let mut down = answers(vec![], "0.1.0", &release_key());
    down.status = 503;
    down.message = "Service temporarily unavailable.".into();
    let cf = Crossfyre::start(down).await;
    assert!(matches!(
        offer(&client, &cf.creds()).await,
        Err(Unavailable::Unreachable(_))
    ));
    let mut refused = answers(vec![], "0.1.0", &release_key());
    refused.status = 401;
    refused.message = "The key is invalid or revoked.".into();
    let cf = Crossfyre::start(refused).await;
    assert_eq!(
        offer(&client, &cf.creds()).await.err(),
        Some(Unavailable::Refused(
            "The key is invalid or revoked.".into()
        ))
    );
}

#[tokio::test]
async fn a_component_the_plan_does_not_include_is_not_installed() {
    let (_dir, here) = here();
    let client = reqwest::Client::new();
    let cf = Crossfyre::start(answers(vec!["egress"], "0.2.0", &release_key())).await;
    let o = offer(&client, &cf.creds()).await.unwrap();
    let err = install(&client, &cf.creds(), &o, "pacing", &[], &here)
        .await
        .unwrap_err();
    assert!(
        err.starts_with("pacing comes with a Crossfyre plan that includes it"),
        "{err}"
    );
    assert!(cf.downloads().is_empty());
}

#[test]
fn the_account_key_is_asked_with_before_a_nodes() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(credentials(dir.path()), None);
    let nodes = crate::nodes_dir(dir.path());
    std::fs::create_dir_all(&nodes).unwrap();
    std::fs::write(
        nodes.join("n1.toml"),
        "api_key = \"cfxn_node_key\"\nnode_id = \"n1\"\napi_url = \"http://cf.test\"\n",
    )
    .unwrap();
    assert_eq!(
        credentials(dir.path()),
        Some(Credentials {
            api_url: "http://cf.test".into(),
            key: "cfxn_node_key".into(),
        })
    );
    crate::auth::save_account(
        dir.path(),
        &crate::auth::Account {
            api_url: "http://account.test".into(),
            api_key: "cfk_account".into(),
            user_id: "u".into(),
            username: "u".into(),
            email: "u@example.com".into(),
        },
    )
    .unwrap();
    assert_eq!(
        credentials(dir.path()),
        Some(Credentials {
            api_url: "http://account.test".into(),
            key: "cfk_account".into(),
        })
    );
}

#[test]
fn an_update_target_names_the_components_or_one_of_them() {
    assert_eq!(asked_for("components"), Some(COMPONENTS.to_vec()));
    assert_eq!(asked_for("plessor-authz"), Some(vec!["plessor-authz"]));
    assert_eq!(asked_for("pacing"), Some(vec!["pacing"]));
    assert_eq!(asked_for("plessor"), None);
    assert_eq!(asked_for("all"), None);
}

/// The licence and the notices come with the first component, into licences/ beside the
/// binaries, once: the next component finds them there.
#[tokio::test]
async fn the_licence_and_the_notices_are_installed_beside_the_components() {
    let cf = Crossfyre::start(answers(vec!["egress", "pacing"], "0.2.0", &release_key())).await;
    let (_dir, here) = here();
    let client = reqwest::Client::new();
    let offer = offer(&client, &cf.creds()).await.unwrap();
    let keys = [public(&release_key())];
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    let got = bring_current(
        &client,
        &cf.creds(),
        &offer,
        &COMPONENTS,
        true,
        &keys,
        &here,
    )
    .await;
    assert!(
        got.iter().all(|(_, k)| matches!(k, Kept::Installed(_))),
        "{got:?}"
    );
    assert_eq!(
        std::fs::read(here.licences().join("BINARY-LICENCE.txt")).unwrap(),
        LICENCE
    );
    assert_eq!(
        std::fs::read(here.licences().join("THIRD-PARTY-NOTICES-COMPONENTS")).unwrap(),
        NOTICES
    );
    let fetched: Vec<String> = cf
        .downloads()
        .into_iter()
        .filter(|f| f.ends_with(".txt"))
        .collect();
    assert_eq!(fetched, ["BINARY-LICENCE-0.3.txt", "notices-0.3.txt"]);
    let mut left: Vec<String> = std::fs::read_dir(here.licences())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        ["BINARY-LICENCE.txt", "THIRD-PARTY-NOTICES-COMPONENTS"]
    );
}

/// A component does not go in without its licence: a manifest that names none, one that
/// names a text by a path, and a text with other bytes than the manifest's are refused.
#[tokio::test]
async fn a_component_without_its_licence_is_not_installed() {
    let cases: Vec<(Answers, &str)> = vec![
        (
            with_texts(answers(vec!["egress"], "0.2.0", &release_key()), |t| {
                *t = json!({})
            }),
            "names no licence",
        ),
        (
            with_texts(answers(vec!["egress"], "0.2.0", &release_key()), |t| {
                t["../BINARY-LICENCE.txt"] = t["BINARY-LICENCE.txt"].clone();
            }),
            "names a text as ../BINARY-LICENCE.txt",
        ),
        (
            with_texts(answers(vec!["egress"], "0.2.0", &release_key()), |t| {
                t["BINARY-LICENCE.txt"]["sha256"] = json!(sha(b"other terms"));
            }),
            "checksum mismatch",
        ),
    ];
    for (a, why) in cases {
        let cf = Crossfyre::start(a).await;
        let (_dir, here) = here();
        let client = reqwest::Client::new();
        let offer = offer(&client, &cf.creds()).await.unwrap();
        let err = install(&client, &cf.creds(), &offer, "egress", &[], &here)
            .await
            .unwrap_err();
        assert!(err.contains(why), "{why}: {err}");
        assert!(!here.licences().join("../BINARY-LICENCE.txt").exists());
        assert_eq!(installed_version(&here, "egress"), None, "{why}");
    }
}

/// What uninstall takes away for the components besides an engine's.
#[test]
fn the_component_files_are_the_module_its_signature_the_helper_and_their_versions() {
    let (_dir, here) = here();
    let mut got: Vec<String> = here
        .component_files()
        .into_iter()
        .map(|p| p.strip_prefix(&here.bin).unwrap().display().to_string())
        .collect();
    got.sort();
    let helper = format!("cfx-egress{}", std::env::consts::EXE_SUFFIX);
    let mut want = vec![
        "egress.version".to_string(),
        helper,
        "pacing.version".to_string(),
        "pacing.wasm".to_string(),
        "pacing.wasm.sig".to_string(),
    ];
    want.sort();
    assert_eq!(got, want);
}
