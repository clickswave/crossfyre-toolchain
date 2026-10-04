//! What the project store has to survive.
//!
//! The test plan's second layer: write exchanges, reopen, assert nothing is lost and
//! search still finds them, then the same across a process that was killed mid-write.
//! A pentester closing a laptop lid is the normal case, and a project file that does not
//! reopen costs a day of engagement evidence rather than a restart.

use std::path::{Path, PathBuf};

use cfx_project::{Cap, Exchange, INLINE_MAX, Project, searchable_text};

/// A project directory under the system temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "cfx-project-test-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&p);
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn exchange(n: usize) -> Exchange {
    Exchange {
        at_ms: 1_700_000_000_000 + n as i64,
        method: "POST".into(),
        url: format!("https://api.example.test/v1/orders/{n}?include=lines"),
        host: "api.example.test".into(),
        status: Some(200),
        duration_ms: Some(12),
        req_headers: vec![
            ["content-type".into(), "application/json".into()],
            ["x-request-id".into(), format!("req-{n}")],
        ],
        resp_headers: vec![["content-type".into(), "application/json".into()]],
        req_body: format!(r#"{{"sku":"WIDGET-{n}","qty":2}}"#).into_bytes(),
        resp_body: format!(r#"{{"order":{n},"state":"confirmed"}}"#).into_bytes(),
        resp_len: None,
    }
}

/// How many bytes count as "over the inline threshold" without being slow to build.
fn big_body(seed: u8) -> Vec<u8> {
    let mut v = vec![seed; INLINE_MAX + 1];
    // A distinguishable head, so a truncation shows up as wrong content rather than as a
    // length that happens to match.
    v[..8].copy_from_slice(b"BIGBODY!");
    v
}

// ---------------------------------------------------------------------------
// Durability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_hundred_exchanges_survive_a_reopen_and_are_still_searchable() {
    let s = Scratch::new("reopen");
    let n = 200usize;

    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    for i in 0..n {
        p.insert(&exchange(i)).await.expect("insert");
    }
    p.close().await;

    // A different Project over the same directory, which is what reopening is.
    let p = Project::open(s.path(), Cap::default())
        .await
        .expect("reopen");
    assert_eq!(p.count().await.expect("count"), n as i64);

    // Every row readable, not just countable. A count proves rows exist; this proves the
    // bodies came back.
    for i in 1..=n as i64 {
        let got = p.get(i).await.expect("get").expect("row present");
        assert_eq!(got.exchange.host, "api.example.test");
        assert!(
            got.exchange.resp_body.starts_with(br#"{"order":"#),
            "row {i} body: {:?}",
            String::from_utf8_lossy(&got.exchange.resp_body)
        );
    }

    // Search survives too, which it would not if the index were built in memory.
    let hits = p.search("WIDGET-7", 50).await.expect("search");
    assert_eq!(
        hits.len(),
        1,
        "a term from a request body finds its exchange"
    );
    let hits = p.search("confirmed", 500).await.expect("search");
    assert_eq!(
        hits.len(),
        n,
        "a term every response carries finds all of them"
    );
}

#[tokio::test]
async fn search_covers_the_url_the_headers_and_the_body() {
    let s = Scratch::new("search");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    p.insert(&exchange(42)).await.expect("insert");

    for (term, what) in [
        ("orders", "a path segment"),
        ("req-42", "a header value"),
        ("WIDGET-42", "a request body field"),
        ("confirmed", "a response body value"),
    ] {
        let hits = p.search(term, 10).await.expect("search");
        assert_eq!(hits.len(), 1, "{what} ({term}) should match");
    }
    assert!(
        p.search("nothinglikethis", 10)
            .await
            .expect("search")
            .is_empty(),
        "and a term that is not there matches nothing"
    );
}

#[tokio::test]
async fn wal_is_on_so_a_reader_does_not_block_the_proxy() {
    let s = Scratch::new("wal");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    p.insert(&exchange(1)).await.expect("insert");
    // The sidecar files WAL creates. Asserting the mode through a pragma would only
    // restate what the connection options asked for; these exist on disk or they do not.
    assert!(
        s.path().join("project.db-wal").exists(),
        "no -wal file, so the journal mode did not take"
    );
}

// ---------------------------------------------------------------------------
// Out-of-line bodies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_body_over_the_threshold_goes_to_a_file_and_comes_back_whole() {
    let s = Scratch::new("blob");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");

    let mut ex = exchange(1);
    ex.resp_body = big_body(0xAB);
    let id = p.insert(&ex).await.expect("insert");

    let blobs = count_files(&s.path().join("blobs"));
    assert_eq!(blobs, 1, "one body went out of line");

    let got = p.get(id).await.expect("get").expect("row");
    assert_eq!(got.exchange.resp_body.len(), INLINE_MAX + 1);
    assert_eq!(got.exchange.resp_body, ex.resp_body, "byte for byte");

    // And a small body stays in the row, or the threshold is doing nothing.
    let small = p.insert(&exchange(2)).await.expect("insert");
    assert_eq!(
        count_files(&s.path().join("blobs")),
        1,
        "a small body did not create a second blob"
    );
    let got = p.get(small).await.expect("get").expect("row");
    assert!(got.exchange.resp_body.starts_with(br#"{"order":2"#));
}

#[tokio::test]
async fn the_same_body_twice_is_stored_once() {
    let s = Scratch::new("dedup");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");

    // The common case on a real capture: the same bundle, sprite sheet or empty object
    // answered over and over.
    for i in 0..5 {
        let mut ex = exchange(i);
        ex.resp_body = big_body(0x11);
        p.insert(&ex).await.expect("insert");
    }
    assert_eq!(
        count_files(&s.path().join("blobs")),
        1,
        "five exchanges carrying one body occupy one file"
    );
}

#[tokio::test]
async fn deleting_one_holder_leaves_a_shared_body_intact_for_the_others() {
    // The reference-counting trap. Unlinking by hash would empty the surviving exchange,
    // and the symptom would be a response body that is there until an unrelated row ages
    // out, which is close to undiagnosable from a bug report.
    let s = Scratch::new("refcount");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");

    let body = big_body(0x22);
    let mut a = exchange(1);
    a.resp_body = body.clone();
    let mut b = exchange(2);
    b.resp_body = body.clone();
    let id_a = p.insert(&a).await.expect("insert a");
    let id_b = p.insert(&b).await.expect("insert b");
    assert_eq!(count_files(&s.path().join("blobs")), 1);

    assert!(p.delete(id_a).await.expect("delete a"));
    assert_eq!(
        count_files(&s.path().join("blobs")),
        1,
        "the file is still referenced and must stay"
    );
    let surviving = p.get(id_b).await.expect("get b").expect("b is still there");
    assert_eq!(surviving.exchange.resp_body, body, "and still has its body");

    // Now the last holder goes, and so should the file.
    assert!(p.delete(id_b).await.expect("delete b"));
    assert_eq!(
        count_files(&s.path().join("blobs")),
        0,
        "the last reference released the file"
    );
}

#[tokio::test]
async fn a_body_whose_file_vanished_is_an_error_and_not_an_empty_body() {
    let s = Scratch::new("missing");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    let mut ex = exchange(1);
    ex.resp_body = big_body(0x33);
    let id = p.insert(&ex).await.expect("insert");

    // Somebody pruned the directory, or a sync dropped a file.
    remove_all_files(&s.path().join("blobs"));

    let err = p.get(id).await.expect_err("a missing blob is an error");
    let msg = err.to_string();
    assert!(
        msg.contains("missing from the project directory"),
        "got: {msg}"
    );
    // The distinction that matters: an empty body would read as "the server sent nothing",
    // which is a finding-shaped claim about the target rather than about our storage.
    assert!(
        msg.contains("different thing from the server having sent nothing"),
        "got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// The cap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_cap_evicts_the_oldest_and_never_a_pinned_exchange() {
    let s = Scratch::new("cap");
    let cap = Cap {
        max_exchanges: Some(5),
        max_bytes: None,
    };
    let p = Project::open(s.path(), cap).await.expect("open");

    for i in 0..10 {
        p.insert(&exchange(i)).await.expect("insert");
    }
    // The oldest two are deliberately kept.
    p.set_pinned(1, true).await.expect("pin");
    p.set_pinned(2, true).await.expect("pin");

    let ev = p.enforce_cap().await.expect("enforce");
    assert_eq!(p.count().await.expect("count"), 5, "back under the cap");
    assert_eq!(ev.exchanges, 5, "five were evicted");

    assert!(
        p.get(1).await.expect("get").is_some(),
        "pinned id 1 survived"
    );
    assert!(
        p.get(2).await.expect("get").is_some(),
        "pinned id 2 survived"
    );
    // Eviction is oldest-first among the unpinned, so the survivors are the pins plus the
    // newest three.
    let left: Vec<i64> = p
        .recent(100)
        .await
        .expect("recent")
        .into_iter()
        .map(|r| r.id)
        .collect();
    let mut sorted = left.clone();
    sorted.sort();
    assert_eq!(sorted, vec![1, 2, 8, 9, 10], "got {left:?}");
}

#[tokio::test]
async fn a_project_held_over_its_cap_by_pins_stops_rather_than_spinning() {
    // If eviction could take a pinned row, pinning would be worthless. So the honest
    // outcome is to stay over the cap and say so, not to loop looking for a victim.
    let s = Scratch::new("allpinned");
    let cap = Cap {
        max_exchanges: Some(2),
        max_bytes: None,
    };
    let p = Project::open(s.path(), cap).await.expect("open");
    for i in 0..6 {
        p.insert(&exchange(i)).await.expect("insert");
    }
    for id in 1..=6 {
        p.set_pinned(id, true).await.expect("pin");
    }

    let ev = p.enforce_cap().await.expect("enforce");
    assert_eq!(ev.exchanges, 0, "nothing could be evicted");
    assert_eq!(
        ev.kept_pinned, 6,
        "and it reports why rather than silently failing"
    );
    assert_eq!(p.count().await.expect("count"), 6);
}

#[tokio::test]
async fn no_cap_means_no_eviction() {
    let s = Scratch::new("nocap");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    for i in 0..20 {
        p.insert(&exchange(i)).await.expect("insert");
    }
    let ev = p.enforce_cap().await.expect("enforce");
    assert_eq!(ev, cfx_project::Evicted::default());
    assert_eq!(p.count().await.expect("count"), 20);
}

#[tokio::test]
async fn a_byte_cap_counts_the_blobs_too() {
    let s = Scratch::new("bytecap");
    // Low enough that one out-of-line body is already over it, so the blob side of the
    // accounting is what decides. A cap that only measured the database would never fire
    // on a capture of large responses, which is the capture that fills a disk.
    let cap = Cap {
        max_bytes: Some(96 * 1024),
        max_exchanges: None,
    };
    let p = Project::open(s.path(), cap).await.expect("open");

    for i in 0..4 {
        let mut ex = exchange(i);
        ex.resp_body = big_body(i as u8);
        p.insert(&ex).await.expect("insert");
    }
    assert!(p.size_bytes().await.expect("size") > 96 * 1024);

    let ev = p.enforce_cap().await.expect("enforce");
    assert!(ev.exchanges > 0, "the byte cap evicted something");
    assert!(
        p.size_bytes().await.expect("size") <= 96 * 1024 || p.count().await.expect("c") == 0,
        "and kept going until it was under, or until nothing was left"
    );
}

// ---------------------------------------------------------------------------
// Schema versioning
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_project_from_a_newer_build_is_refused_rather_than_opened() {
    let s = Scratch::new("newer");
    {
        let p = Project::open(s.path(), Cap::default()).await.expect("open");
        p.insert(&exchange(1)).await.expect("insert");
        p.close().await;
    }
    // Stamp it as written by something newer, the way a future build would.
    stamp_user_version(&s.path().join("project.db"), 999).await;

    let err = Project::open(s.path(), Cap::default())
        .await
        .expect_err("a newer file must not open");
    let msg = err.to_string();
    assert!(msg.contains("newer version"), "got: {msg}");
    assert!(
        msg.contains("could lose what the newer version recorded"),
        "the message has to say why refusing is the safe move: {msg}"
    );
}

#[tokio::test]
async fn a_later_version_actually_changes_an_existing_file() {
    // The bug this was written for: `migrate` used to run the whole DDL array
    // unconditionally and then stamp `user_version`. Every statement in that array is
    // `CREATE ... IF NOT EXISTS`, so against a file that already had the tables it did
    // nothing at all, and then stamped the file as the new version. The file claimed a
    // shape it did not have, and the first query touching a new column would fail at
    // runtime against a file that looked migrated.
    //
    // Driven through `apply` with a synthetic second step, because the crate is still on
    // version 1 and the defect is in the runner rather than in any particular step.
    use sqlx::Row;
    use sqlx::sqlite::SqliteConnectOptions;

    let s = Scratch::new("upgrade");
    {
        let p = Project::open(s.path(), Cap::default()).await.expect("open");
        p.insert(&exchange(1)).await.expect("insert");
        p.close().await;
    }

    let opts = SqliteConnectOptions::new().filename(s.path().join("project.db"));
    let pool = sqlx::SqlitePool::connect_with(opts).await.expect("connect");

    // Relative to whatever the crate is on, so shipping a real new version does not
    // break this test, and a column name a real step will never use.
    let here = cfx_project::schema::SCHEMA_VERSION;
    let steps = vec![
        cfx_project::schema::Step {
            version: here,
            statements: &[],
        },
        cfx_project::schema::Step {
            version: here + 1,
            statements: &["ALTER TABLE exchange ADD COLUMN probe_marker INTEGER"],
        },
    ];
    cfx_project::schema::apply(&pool, &steps)
        .await
        .expect("the upgrade applies");

    let cols: Vec<String> = sqlx::query("PRAGMA table_info(exchange)")
        .fetch_all(&pool)
        .await
        .expect("table_info")
        .iter()
        .map(|r| r.get::<String, _>(1))
        .collect();
    assert!(
        cols.iter().any(|c| c == "probe_marker"),
        "the later step did not reach the file: {cols:?}"
    );

    let stamped: i64 = sqlx::query("PRAGMA user_version")
        .fetch_one(&pool)
        .await
        .expect("read")
        .try_get(0)
        .expect("int");
    assert_eq!(stamped, here + 1, "and the file says so");

    // Running it again is a no-op rather than an error, because opening a project twice
    // is the normal case and ALTER TABLE is not idempotent.
    cfx_project::schema::apply(&pool, &steps)
        .await
        .expect("applying an already-current file does nothing");

    // The row written at version 1 is still there. A migration that loses the user's
    // captures is worse than one that refuses to run.
    let n: i64 = sqlx::query("SELECT COUNT(*) FROM exchange")
        .fetch_one(&pool)
        .await
        .expect("count")
        .try_get(0)
        .expect("int");
    assert_eq!(n, 1);
    pool.close().await;
}

#[tokio::test]
async fn a_failing_step_leaves_the_file_on_its_old_version() {
    // Half-migrated is the state nobody can reason about, and this is a document the
    // user owns: there is no operator to go and repair it.
    use sqlx::Row;
    use sqlx::sqlite::SqliteConnectOptions;

    let s = Scratch::new("halfway");
    {
        let p = Project::open(s.path(), Cap::default()).await.expect("open");
        p.close().await;
    }
    let opts = SqliteConnectOptions::new().filename(s.path().join("project.db"));
    let pool = sqlx::SqlitePool::connect_with(opts).await.expect("connect");

    let here = cfx_project::schema::SCHEMA_VERSION;
    let steps = vec![
        cfx_project::schema::Step {
            version: here,
            statements: &[],
        },
        cfx_project::schema::Step {
            version: here + 1,
            statements: &[
                "ALTER TABLE exchange ADD COLUMN good INTEGER",
                "ALTER TABLE exchange ADD COLUMN good INTEGER",
            ],
        },
    ];
    cfx_project::schema::apply(&pool, &steps)
        .await
        .expect_err("the duplicate column must fail");

    let stamped: i64 = sqlx::query("PRAGMA user_version")
        .fetch_one(&pool)
        .await
        .expect("read")
        .try_get(0)
        .expect("int");
    assert_eq!(
        stamped, here,
        "the version must not advance past a failed step"
    );

    let cols: Vec<String> = sqlx::query("PRAGMA table_info(exchange)")
        .fetch_all(&pool)
        .await
        .expect("table_info")
        .iter()
        .map(|r| r.get::<String, _>(1))
        .collect();
    assert!(
        !cols.iter().any(|c| c == "good"),
        "the partial change was not rolled back: {cols:?}"
    );
    pool.close().await;
}

#[tokio::test]
async fn exchanges_are_attributed_to_the_capture_session_that_produced_them() {
    // The cheapest row in the schema and the one three later features need. Without it
    // an exchange has a timestamp and nothing else to say which sitting it came from, so
    // coverage cannot say which run tested what and a retest has nothing to diff
    // against.
    use sqlx::Row;

    let s = Scratch::new("runs");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");

    // Before any session, an exchange belongs to no run and says so rather than being
    // invented into one.
    assert_eq!(p.current_run(), None);
    let orphan = p.insert(&exchange(1)).await.expect("insert");

    let run = p
        .begin_run(1_700_000_000_000, Some("acme, day one"))
        .await
        .expect("begin");
    assert_eq!(p.current_run(), Some(run));
    let during = p.insert(&exchange(2)).await.expect("insert");

    p.end_run(1_700_000_060_000).await.expect("end");
    assert_eq!(p.current_run(), None, "the session closed");
    let after = p.insert(&exchange(3)).await.expect("insert");

    let run_of = |id: i64| {
        let pool = p.pool_for_test();
        async move {
            sqlx::query("SELECT run_id FROM exchange WHERE id = ?1")
                .bind(id)
                .fetch_one(pool)
                .await
                .expect("row")
                .try_get::<Option<i64>, _>(0)
                .expect("col")
        }
    };
    assert_eq!(run_of(orphan).await, None, "written before the session");
    assert_eq!(run_of(during).await, Some(run), "written during it");
    assert_eq!(run_of(after).await, None, "written after it closed");

    // And the session records when it ran, which is what a retest compares.
    let (started, ended): (i64, Option<i64>) =
        sqlx::query("SELECT started_ms, ended_ms FROM run WHERE id = ?1")
            .bind(run)
            .fetch_one(p.pool_for_test())
            .await
            .map(|r| (r.get(0), r.get(1)))
            .expect("the run row");
    assert_eq!(started, 1_700_000_000_000);
    assert_eq!(ended, Some(1_700_000_060_000));
}

#[tokio::test]
async fn a_version_one_project_upgrades_without_losing_anything() {
    // The first real exercise of the step runner, against the shape that actually exists
    // in the wild: a file written before runs existed. Its exchanges keep their bodies
    // and their searchability, and they belong to no run, which is the truth about them.
    let s = Scratch::new("v1-upgrade");
    {
        let p = Project::open(s.path(), Cap::default()).await.expect("open");
        for i in 1..=3 {
            p.insert(&exchange(i)).await.expect("insert");
        }
        p.close().await;
    }
    // Put the file back to version 1 by undoing every step above it, which is what a file
    // from an older build looks like. Each new version adds its undo here: that is the
    // cost of testing the upgrade path against a real old file rather than a simulated
    // one, and it is cheaper than the alternative, which is finding out from somebody
    // else's project that the upgrade never worked.
    {
        use sqlx::sqlite::SqliteConnectOptions;
        let opts = SqliteConnectOptions::new().filename(s.path().join("project.db"));
        let pool = sqlx::SqlitePool::connect_with(opts).await.expect("connect");
        // Version 3.
        for stmt in [
            "DROP INDEX refusal_at",
            "DROP TABLE refusal",
            "DROP TABLE setting",
        ] {
            sqlx::query(stmt).execute(&pool).await.expect(stmt);
        }
        // Version 2.
        sqlx::query("DROP INDEX IF EXISTS exchange_run")
            .execute(&pool)
            .await
            .expect("drop index");
        sqlx::query("ALTER TABLE exchange DROP COLUMN run_id")
            .execute(&pool)
            .await
            .expect("drop column");
        sqlx::query("DROP TABLE run")
            .execute(&pool)
            .await
            .expect("drop run");
        sqlx::query("PRAGMA user_version = 1")
            .execute(&pool)
            .await
            .expect("stamp");
        pool.close().await;
    }

    let p = Project::open(s.path(), Cap::default())
        .await
        .expect("a version 1 file opens and upgrades");
    assert_eq!(p.count().await.expect("count"), 3, "nothing was lost");
    let got = p.get(1).await.expect("get").expect("still there");
    assert!(!got.exchange.resp_body.is_empty(), "bodies survived");
    assert_eq!(
        p.search("WIDGET-1", 10).await.expect("search").len(),
        1,
        "and the index still answers"
    );
    // And the file really has the shape it now claims. A step that silently no-ops stamps
    // a version the file does not have, and every query against the new table then fails
    // at runtime against a file that looks migrated.
    p.set_setting("probe", "value")
        .await
        .expect("v3 setting table exists");
    assert_eq!(
        p.setting("probe").await.expect("read back"),
        Some("value".to_string())
    );

    // The new session machinery works on the upgraded file.
    let run = p
        .begin_run(42, None)
        .await
        .expect("begin on an upgraded file");
    let fresh = p.insert(&exchange(9)).await.expect("insert");
    assert!(run > 0 && fresh > 0);
}

// ---------------------------------------------------------------------------
// Indexed text
// ---------------------------------------------------------------------------

#[test]
fn what_reaches_the_text_index() {
    assert_eq!(searchable_text(b""), "");
    assert_eq!(searchable_text(br#"{"a":1}"#), r#"{"a":1}"#);

    // A NUL means binary. This is the byte that has already broken this family of code
    // once, when captured bodies containing NULs were rejected outright and the Requests
    // tab stayed empty with nothing logged anywhere.
    assert_eq!(searchable_text(b"PNG\x00\x01\x02"), "");

    // Truncated at a character boundary, so a body cut mid-sequence does not land a
    // replacement character where a term used to be.
    let mut body = "e".repeat(cfx_project::FTS_BODY_MAX - 1);
    body.push('é'); // two bytes, straddling the limit
    let out = searchable_text(body.as_bytes());
    assert!(!out.contains('\u{fffd}'), "no replacement character");
    assert_eq!(out.len(), cfx_project::FTS_BODY_MAX - 1);

    // Invalid UTF-8 with no NUL keeps whatever prefix was valid.
    assert_eq!(searchable_text(b"ok-\xff\xfe"), "ok-");
}

// ---------------------------------------------------------------------------
// A process killed mid-write
// ---------------------------------------------------------------------------

/// Not a test. It is the child half of the kill test below, which re-executes this binary
/// and runs this one case by name. Returns immediately in an ordinary run.
#[tokio::test]
async fn writer_child() {
    let Ok(dir) = std::env::var("CFX_PROJECT_KILL_DIR") else {
        return;
    };
    let p = Project::open(&dir, Cap::default())
        .await
        .expect("child open");
    let mut i = 0usize;
    loop {
        // Alternating big and small bodies, so the kill can land during a blob write, a
        // transaction commit or an index update rather than always in the same place.
        let mut ex = exchange(i);
        if i % 3 == 0 {
            ex.resp_body = big_body((i % 251) as u8);
        }
        if p.insert(&ex).await.is_err() {
            return;
        }
        i += 1;
    }
}

#[tokio::test]
async fn a_project_whose_writer_was_killed_still_opens_and_reads() {
    let s = Scratch::new("kill");
    std::fs::create_dir_all(s.path()).expect("mkdir");

    let exe = std::env::current_exe().expect("own path");
    let mut child = std::process::Command::new(exe)
        .args(["--exact", "writer_child", "--nocapture"])
        .env("CFX_PROJECT_KILL_DIR", s.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the writer");

    // Wait until it has actually written something, so the kill lands mid-capture rather
    // than before the file exists. Polling the file is enough; opening the database from
    // here while the child holds it is the thing being tested, not the setup.
    let db = s.path().join("project.db");
    let mut waited = 0u64;
    while !(db.exists()
        && std::fs::metadata(&db)
            .map(|m| m.len() > 16_384)
            .unwrap_or(false))
    {
        if waited > 10_000 {
            let _ = child.kill();
            panic!("the writer never got going");
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        waited += 25;
    }
    // A moment more, so the kill is not racing the very first commit.
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    // SIGKILL: no unwinding, no flush, no chance to close the database. The laptop lid,
    // the OOM killer, the power cut.
    child.kill().expect("kill");
    let _ = child.wait();

    // The whole claim: this reopens.
    let p = Project::open(s.path(), Cap::default())
        .await
        .expect("a killed writer must leave a project that opens");

    let n = p.count().await.expect("count");
    assert!(n > 0, "the capture before the kill survived, got {n} rows");

    assert_eq!(
        p.integrity_check().await.expect("integrity_check"),
        "ok",
        "SQLite reports the file as intact"
    );

    // Every row that exists is whole. A torn write would show up as a row whose blob was
    // never finished, and that is the case worth being sure about, because a half-written
    // body is indistinguishable from a short response unless the read fails.
    let all = p.recent(100_000).await.expect("recent");
    assert_eq!(all.len() as i64, n);
    for r in &all {
        let got = p.get(r.id).await.unwrap_or_else(|e| {
            panic!("row {} survived the kill but will not read back: {e}", r.id)
        });
        let got = got.unwrap_or_else(|| panic!("row {} listed but absent", r.id));
        assert_eq!(
            got.exchange.resp_body.len() as i64,
            r.resp_len,
            "row {} came back a different length than it was stored with",
            r.id
        );
    }

    // And it is still writable, which is what makes it a recovered project rather than a
    // readable corpse.
    let id = p.insert(&exchange(999_999)).await.expect("still writable");
    assert!(p.get(id).await.expect("get").is_some());
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn count_files(dir: &Path) -> usize {
    let mut n = 0;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            n += count_files(&p);
        } else {
            n += 1;
        }
    }
    n
}

fn remove_all_files(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            remove_all_files(&p);
        } else {
            let _ = std::fs::remove_file(&p);
        }
    }
}

async fn stamp_user_version(db: &Path, v: i64) {
    use sqlx::sqlite::SqliteConnectOptions;
    let opts = SqliteConnectOptions::new().filename(db);
    let pool = sqlx::SqlitePool::connect_with(opts).await.expect("connect");
    sqlx::query(&format!("PRAGMA user_version = {v}"))
        .execute(&pool)
        .await
        .expect("stamp");
    pool.close().await;
}

#[test]
fn what_a_search_box_becomes() {
    use cfx_project::fts_query;

    assert_eq!(fts_query("confirmed").as_deref(), Some(r#""confirmed""#));
    // Every term has to appear, which is what a search box is taken to mean.
    assert_eq!(
        fts_query("widget confirmed").as_deref(),
        Some(r#""widget" AND "confirmed""#)
    );
    // Nothing typed, nothing matched. Not every row, and not a syntax error.
    assert_eq!(fts_query(""), None);
    assert_eq!(fts_query("   \t "), None);

    // The punctuation that makes an unquoted term a parser error rather than a search.
    for term in ["WIDGET-7", "a:b", "NEAR", "AND", "^x", "*", "(a)"] {
        let q = fts_query(term).expect("a term");
        assert!(
            q.starts_with('"') && q.ends_with('"'),
            "{term} must be quoted, got {q}"
        );
    }
    // An embedded quote is doubled, so it cannot end the phrase early.
    assert_eq!(fts_query(r#"say"hi"#).as_deref(), Some(r#""say""hi""#));
}

#[tokio::test]
async fn a_quote_in_the_search_box_is_a_search_and_not_an_error() {
    // The reason the quoting above matters: these all reach SQLite as a MATCH expression,
    // and before the terms were quoted an ordinary SKU came back as `no such column`.
    let s = Scratch::new("fts-safe");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    p.insert(&exchange(7)).await.expect("insert");

    for term in [
        "WIDGET-7",
        r#"say"hi"#,
        "a:b",
        "NEAR",
        "AND",
        "*",
        "(unclosed",
        "x OR y",
    ] {
        p.search(term, 10)
            .await
            .unwrap_or_else(|e| panic!("searching for {term:?} must not error: {e}"));
    }
    // And the one that should match still does.
    assert_eq!(p.search("WIDGET-7", 10).await.expect("search").len(), 1);
}

/// The scope, and the refusals it produced, survive closing the project.
///
/// Both halves matter and they fail differently. A scope that did not persist means an
/// operator who closes the window at the end of a day reopens it with no fence at all,
/// which is the worst possible default because it looks exactly like the fence they set.
/// A refusal that did not persist means the audit answer is only ever "since this window
/// opened", which is not an answer.
#[tokio::test]
async fn the_scope_and_what_it_refused_survive_a_reopen() {
    let s = Scratch::new("scope-persist");
    let written = vec![
        "api.example.com".to_string(),
        "*.staging.example.com".to_string(),
        "10.0.0.0/8".to_string(),
    ];
    {
        let p = Project::open(s.path(), Cap::default()).await.expect("open");
        p.set_scope_entries(&written).await.expect("save the scope");
        p.begin_run(1_700_000_000_000, Some("a sitting"))
            .await
            .expect("run");
        p.record_refusal(&cfx_scope::Refusal {
            at_ms: 1_700_000_000_123,
            host: "out.example".into(),
            port: 8443,
            point: cfx_scope::Point::Connect,
            detail: None,
        })
        .await
        .expect("record");
        p.record_refusal(&cfx_scope::Refusal {
            at_ms: 1_700_000_000_456,
            host: "other.example".into(),
            port: 80,
            point: cfx_scope::Point::Request,
            detail: Some("GET /admin".into()),
        })
        .await
        .expect("record");
        p.close().await;
    }

    let p = Project::open(s.path(), Cap::default())
        .await
        .expect("reopen");
    assert_eq!(
        p.scope_entries().await.expect("read back"),
        written,
        "the entries round trip exactly, in order, as text"
    );
    // And they still mean the same thing, which is the claim text alone does not make.
    let (policy, rejected) = cfx_scope::Policy::from_entries(&p.scope_entries().await.unwrap());
    assert!(rejected.is_empty());
    assert!(policy.admits("api.example.com", 443));
    assert!(policy.admits("a.staging.example.com", 443));
    assert!(policy.admits("10.1.2.3", 22));
    assert!(!policy.admits("example.com", 443));

    let back = p.refusals(10).await.expect("refusals");
    assert_eq!(back.len(), 2);
    assert_eq!(back[0].host, "other.example", "newest first");
    assert_eq!(back[0].point, cfx_scope::Point::Request);
    assert_eq!(back[0].detail.as_deref(), Some("GET /admin"));
    assert_eq!(back[1].point, cfx_scope::Point::Connect);
    assert_eq!(back[1].port, 8443);
    assert_eq!(p.refusal_count().await.expect("count"), 2);
}

/// An empty list clears the fence rather than leaving the old one in force.
#[tokio::test]
async fn clearing_the_scope_is_saved_as_clearing_it() {
    let s = Scratch::new("scope-clear");
    let p = Project::open(s.path(), Cap::default()).await.expect("open");
    p.set_scope_entries(&["api.example.com".to_string()])
        .await
        .expect("set");
    p.set_scope_entries(&[]).await.expect("clear");
    assert!(
        p.scope_entries().await.expect("read").is_empty(),
        "an operator who deletes every line means it, and the stored value has to agree \
         or the window and the proxy disagree about what is fenced"
    );
}
