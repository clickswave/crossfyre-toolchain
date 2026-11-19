use super::*;
use std::collections::BTreeSet;

/// The files in toolmark/signatures are the ones files.rs includes, both ways, so a file
/// added to the folder and not to the list fails here rather than never being compiled
/// in. Each entry is named after the file it includes, and every file loads.
#[test]
fn the_compiled_set_is_the_signatures_folder() {
    let root = env!("CARGO_MANIFEST_DIR");
    let on_disk: BTreeSet<String> = std::fs::read_dir(format!("{root}/signatures"))
        .expect("toolmark/signatures")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    let source = std::fs::read_to_string(format!("{root}/src/signatures/files.rs"))
        .expect("src/signatures/files.rs");
    let included: Vec<String> =
        Regex::new(r#"include_str!\(\s*"\.\./\.\./signatures/([^"]+)"\s*\)"#)
            .expect("pattern")
            .captures_iter(&source)
            .map(|c| c[1].to_string())
            .collect();
    let listed: BTreeSet<String> = included.iter().cloned().collect();
    assert_eq!(listed.len(), included.len(), "a file is included twice");
    let unlisted: Vec<&String> = on_disk.difference(&listed).collect();
    let gone: Vec<&String> = listed.difference(&on_disk).collect();
    assert!(
        unlisted.is_empty() && gone.is_empty(),
        "in toolmark/signatures and not in files.rs: {unlisted:?}; \
         in files.rs and not in toolmark/signatures: {gone:?}"
    );
    let names: Vec<&str> = files::FILES.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        names, included,
        "each entry is named after the file it includes"
    );
    let (signatures, skipped) = load::load(files::FILES);
    assert!(skipped.is_empty(), "{skipped:#?}");
    assert_eq!(signatures.list.len(), files::FILES.len());
}

#[test]
fn a_cpe_escapes_what_its_formatted_string_escapes() {
    assert_eq!(cpe_value("joomla!"), "joomla\\!");
    assert_eq!(cpe_value("node.js"), "node.js");
    assert_eq!(cpe_value("http_server"), "http_server");
    assert_eq!(cpe_value("1.2+b3:4"), "1.2\\+b3\\:4");
}

/// Signatures from `files`, which must all load.
fn set(files: &[(&str, &str)]) -> Signatures {
    let (signatures, skipped) = load::load(files);
    assert!(skipped.is_empty(), "{skipped:#?}");
    signatures
}

/// A signature `id` whose detect is `detect`, written as YAML.
fn file(id: &str, detect: &str) -> (String, String) {
    (
        format!("{id}.yaml"),
        format!("id: {id}\ninfo: {{ name: {id}, category: Test }}\ndetect: {detect}\n"),
    )
}

/// How each signature in `files` answers on a landing page whose Server header is
/// `server`, at `tier`, with `asked` answered as given and a host that 404s honestly.
fn answers(
    files: &[(String, String)],
    server: &str,
    tier: u8,
    asked: &[(&str, Answered)],
) -> Vec<(String, Answer)> {
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(f, t)| (f.as_str(), t.as_str()))
        .collect();
    let signatures = set(&files);
    let headers = [("server".to_string(), server.to_string())];
    let mut host = Host::new(&signatures, "http://host.test/", &headers, &[], "", tier);
    host.not_found = NotFound::Honest;
    for (path, answered) in asked {
        host.asked.insert(path.to_string(), answered.clone());
    }
    host.outcomes()
        .into_iter()
        .map(|(s, o)| (s.id.clone(), o.answer))
        .collect()
}

fn status(code: u16, body: &str) -> Answered {
    Answered::new(code, false, body.as_bytes())
}

/// `all`, `any` and `none` over present, absent and unknown, as the plan states them:
/// `all` is absent if a child is, else unknown if one is, else present; `any` present if
/// a child is, else unknown if one is, else absent; `none` present only when every child
/// is absent, absent when one is present, else unknown.
#[test]
fn groups_combine_present_absent_and_unknown() {
    // On this page `yes` is present and `no` absent; the path is never asked, so unknown.
    let yes = "{ header: { name: server, regex: 'yes' } }";
    let no = "{ header: { name: server, regex: 'no' } }";
    let unknown = "{ path: { path: /never-asked } }";
    let cases = [
        (
            "all-present",
            format!("{{ all: [ {yes}, {yes} ] }}"),
            Answer::Present,
        ),
        (
            "all-absent",
            format!("{{ all: [ {yes}, {no}, {unknown} ] }}"),
            Answer::Absent,
        ),
        (
            "all-unknown",
            format!("{{ all: [ {yes}, {unknown} ] }}"),
            Answer::Unknown,
        ),
        (
            "any-present",
            format!("{{ any: [ {no}, {unknown}, {yes} ] }}"),
            Answer::Present,
        ),
        (
            "any-unknown",
            format!("{{ any: [ {no}, {unknown} ] }}"),
            Answer::Unknown,
        ),
        (
            "any-absent",
            format!("{{ any: [ {no}, {no} ] }}"),
            Answer::Absent,
        ),
        (
            "none-present",
            format!("{{ all: [ {yes}, {{ none: [ {no}, {no} ] }} ] }}"),
            Answer::Present,
        ),
        (
            "none-absent",
            format!("{{ all: [ {yes}, {{ none: [ {no}, {yes}, {unknown} ] }} ] }}"),
            Answer::Absent,
        ),
        (
            "none-unknown",
            format!("{{ all: [ {yes}, {{ none: [ {no}, {unknown} ] }} ] }}"),
            Answer::Unknown,
        ),
        (
            "nested",
            format!(
                "{{ any: [ {{ all: [ {yes}, {no} ] }}, {{ all: [ {yes}, {{ none: [ {no} ] }} ] }} ] }}"
            ),
            Answer::Present,
        ),
    ];
    let files: Vec<(String, String)> = cases.iter().map(|(id, d, _)| file(id, d)).collect();
    let got = answers(&files, "yes", STANDARD, &[]);
    let want: Vec<(String, Answer)> = cases
        .iter()
        .map(|(id, _, a)| (id.to_string(), *a))
        .collect();
    assert_eq!(got, want);
}

/// What a present detection carries: the confidence and evidence of the leaves that hold
/// it up, not of one under a branch that failed or under a `none`.
#[test]
fn only_the_leaves_that_hold_a_detection_count_for_it() {
    let files = [file(
        "framework",
        "{ any: [ { all: [ { header: { name: server, regex: 'nginx' } }, \
                          { header: { name: server, regex: 'never' } } ] }, \
                  { all: [ { header: { name: server, regex: 'nginx/' }, confidence: 40 } ] } ] }",
    )];
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(f, t)| (f.as_str(), t.as_str()))
        .collect();
    let (_, skipped) = load::load(&files);
    // A confidence goes inside the leaf's own map.
    assert!(skipped[0].contains("map with one key"), "{skipped:?}");

    let files = [file(
        "framework",
        "{ any: [ { all: [ { header: { name: server, regex: 'nginx' } }, \
                          { header: { name: server, regex: 'never' } } ] }, \
                  { all: [ { header: { name: server, regex: 'nginx/', confidence: 40 } }, \
                           { none: [ { header: { name: server, regex: 'apache' } } ] } ] } ] }",
    )];
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(f, t)| (f.as_str(), t.as_str()))
        .collect();
    let signatures = set(&files);
    let headers = [("server".to_string(), "nginx/1.24.0".to_string())];
    let host = Host::new(
        &signatures,
        "http://host.test/",
        &headers,
        &[],
        "",
        STANDARD,
    );
    let found = host.detections();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].confidence, 40);
    assert_eq!(found[0].evidence, ["header server: nginx/1.24.0"]);
}

/// A path leaf is absent only on a 404 or a 410, or on the host's own not-found page.
/// Anything else that is not the evidence is unknown: a 401, a 403, a 429, a 5xx, a
/// redirect, no answer, and a 200 whose body does not match.
#[test]
fn a_path_is_absent_only_on_a_404_a_410_or_the_not_found_page() {
    let leaf = |id: &str, path: &str| {
        file(
            id,
            &format!("{{ path: {{ path: {path}, regex: 'marker' }} }}"),
        )
    };
    let paths = [
        ("ok", "/ok", status(200, "the marker")),
        ("gone-404", "/gone-404", status(404, "")),
        ("gone-410", "/gone-410", status(410, "")),
        ("other", "/other", status(200, "something else")),
        ("auth", "/auth", status(401, "the marker")),
        ("forbidden", "/forbidden", status(403, "the marker")),
        ("slow", "/slow", status(429, "")),
        ("broken", "/broken", status(500, "the marker")),
        ("moved", "/moved", Answered::new(200, true, b"the marker")),
        ("silent", "/silent", Answered::none()),
    ];
    let files: Vec<(String, String)> = paths.iter().map(|(id, path, _)| leaf(id, path)).collect();
    let asked: Vec<(&str, Answered)> = paths
        .iter()
        .map(|(_, path, a)| (*path, a.clone()))
        .collect();
    let got = answers(&files, "", STANDARD, &asked);
    use Answer::*;
    let want = [
        ("ok", Present),
        ("gone-404", Absent),
        ("gone-410", Absent),
        ("other", Unknown),
        ("auth", Unknown),
        ("forbidden", Unknown),
        ("slow", Unknown),
        ("broken", Unknown),
        ("moved", Unknown),
        ("silent", Unknown),
    ];
    let want: Vec<(String, Answer)> = want.iter().map(|(id, a)| (id.to_string(), *a)).collect();
    assert_eq!(got, want);

    // Below the standard tier a path is never looked at, whatever it answered.
    let got = answers(&files[..1], "", 1, &asked[..1]);
    assert_eq!(got, [("ok".to_string(), Unknown)]);
}

/// The not-found page, learned from two random paths, decides a path with no pattern of
/// its own: the same page is absent, another page is the path being there. Where the two
/// random answers differ nothing can be compared, so another page is unknown.
#[test]
fn the_not_found_page_decides_a_path_that_has_no_pattern() {
    let files = [file("exists", "{ path: { path: /admin/ } }")];
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(f, t)| (f.as_str(), t.as_str()))
        .collect();
    let signatures = set(&files);
    let answer = |not_found: NotFound, body: &str| {
        let mut host = Host::new(&signatures, "http://host.test/", &[], &[], "", STANDARD);
        host.not_found = not_found;
        host.asked.insert("/admin/".into(), status(200, body));
        host.outcomes()[0].1.answer
    };
    let catch_all = || {
        NotFound::learn(
            (
                "/0123456789abcdef",
                &status(200, "<p>No page at /0123456789abcdef</p>"),
            ),
            (
                "/fedcba9876543210",
                &status(200, "<p>No page at /fedcba9876543210</p>"),
            ),
        )
    };
    assert!(matches!(catch_all(), NotFound::Page { status: 200, .. }));
    assert_eq!(
        answer(catch_all(), "<p>No page at /admin/</p>"),
        Answer::Absent
    );
    assert_eq!(answer(catch_all(), "<h1>Admin</h1>"), Answer::Present);
    assert_eq!(answer(NotFound::Honest, "<h1>Admin</h1>"), Answer::Present);
    let shifting = NotFound::learn(
        ("/0123456789abcdef", &status(200, "<p>request 1</p>")),
        ("/fedcba9876543210", &status(200, "<p>request 2</p>")),
    );
    assert!(matches!(shifting, NotFound::Unusable));
    assert_eq!(answer(shifting, "<h1>Admin</h1>"), Answer::Unknown);
    let honest = NotFound::learn(("/a1", &status(404, "x")), ("/b2", &status(410, "y")));
    assert!(matches!(honest, NotFound::Honest));
}

/// Framework B refines framework A. Both present: only B is reported. B unknown: A is
/// reported with B as a candidate. B absent: A alone. Through a chain, C refining B
/// refining A, everything unknown above what is present is a candidate.
#[test]
fn a_refining_signature_replaces_its_base_or_is_named_as_a_candidate() {
    let a = "{ header: { name: server, regex: 'frame' } }";
    let files = [
        file("a", a),
        (
            "b.yaml".to_string(),
            "id: b\ninfo: { name: b, category: Test }\nrefines: a\n\
             detect: { all: [ { header: { name: server, regex: 'frame' } }, { path: { path: /b } } ] }\n"
                .to_string(),
        ),
        (
            "c.yaml".to_string(),
            "id: c\ninfo: { name: c, category: Test }\nrefines: b\n\
             detect: { all: [ { header: { name: server, regex: 'frame' } }, { path: { path: /c } } ] }\n"
                .to_string(),
        ),
    ];
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(f, t)| (f.as_str(), t.as_str()))
        .collect();
    let signatures = set(&files);
    let headers = [("server".to_string(), "frame".to_string())];
    let reported = |asked: &[(&str, u16)]| {
        let mut host = Host::new(
            &signatures,
            "http://host.test/",
            &headers,
            &[],
            "",
            STANDARD,
        );
        host.not_found = NotFound::Honest;
        for (path, code) in asked {
            host.asked.insert(path.to_string(), status(*code, "page"));
        }
        host.detections()
            .into_iter()
            .map(|d| (d.name, d.candidates))
            .collect::<Vec<_>>()
    };
    let named = |name: &str, candidates: &[&str]| {
        (
            name.to_string(),
            candidates.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
        )
    };
    assert_eq!(reported(&[("/b", 200), ("/c", 404)]), [named("b", &[])]);
    assert_eq!(reported(&[("/b", 200), ("/c", 200)]), [named("c", &[])]);
    assert_eq!(reported(&[("/b", 404), ("/c", 404)]), [named("a", &[])]);
    assert_eq!(reported(&[("/b", 403)]), [named("a", &["b", "c"])]);
    assert_eq!(reported(&[("/b", 200), ("/c", 403)]), [named("b", &["c"])]);
}

/// Only paths that can still change an answer are asked: none for a signature whose
/// passive evidence decided it, the deciding one for a signature that is unknown, and a
/// version path for one reported without a version. Version paths first, then those of
/// signatures with some evidence present, then the rest.
#[test]
fn only_a_path_that_could_change_an_answer_is_worth_asking() {
    let files = [
        file(
            "decided",
            "{ all: [ { header: { name: server, regex: 'nothing' } }, { path: { path: /decided } } ] }",
        ),
        file("blind", "{ path: { path: /blind } }"),
        file(
            "supported",
            "{ all: [ { header: { name: server, regex: 'frame' } }, { path: { path: /supported } } ] }",
        ),
        (
            "versioned.yaml".to_string(),
            "id: versioned\ninfo: { name: versioned, category: Test }\n\
             detect: { header: { name: server, regex: 'frame' } }\n\
             version: [ { header: { name: server, regex: 'frame/([0-9.]+)' } }, \
                        { path: { path: /version.txt, regex: 'v([0-9.]+)' } } ]\n"
                .to_string(),
        ),
    ];
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(f, t)| (f.as_str(), t.as_str()))
        .collect();
    let signatures = set(&files);
    let headers = [("server".to_string(), "frame".to_string())];
    let mut host = Host::new(
        &signatures,
        "http://host.test/",
        &headers,
        &[],
        "",
        STANDARD,
    );
    host.not_found = NotFound::Honest;
    let mut order = Vec::new();
    while let Some(Next::Path(path)) = host.next() {
        order.push(path.clone());
        host.asked.insert(path, status(200, "v2.1"));
    }
    assert_eq!(order, ["/version.txt", "/supported", "/blind"]);
    let versioned = host
        .detections()
        .into_iter()
        .find(|d| d.name == "versioned")
        .expect("versioned");
    assert_eq!(versioned.version.as_deref(), Some("2.1"));

    // With the version in the Server header, the version path is not worth asking.
    let headers = [("server".to_string(), "frame/3.0".to_string())];
    let host = Host::new(
        &signatures,
        "http://host.test/",
        &headers,
        &[],
        "",
        STANDARD,
    );
    assert_eq!(host.next(), Some(Next::NotFound));
    let mut host = host;
    host.not_found = NotFound::Honest;
    assert_eq!(host.next(), Some(Next::Path("/supported".into())));

    // Below the standard tier nothing is asked.
    let host = Host::new(&signatures, "http://host.test/", &headers, &[], "", 1);
    assert_eq!(host.next(), None);
}

/// [`ask`] learns the not-found page first, asks each path once, and stops at the cap,
/// on a 429, or after three failures in a row.
#[tokio::test]
async fn asking_learns_the_not_found_page_first_and_stops_where_it_should() {
    let many: Vec<(String, String)> = (0..40)
        .map(|n| file(&format!("p{n}"), &format!("{{ path: {{ path: /p{n} }} }}")))
        .collect();
    let files: Vec<(&str, &str)> = many.iter().map(|(f, t)| (f.as_str(), t.as_str())).collect();
    let signatures = set(&files);
    let run = |answer: fn(&str) -> Answered| {
        let signatures = &signatures;
        async move {
            let mut host = Host::new(signatures, "http://host.test/", &[], &[], "", STANDARD);
            let mut seen = Vec::new();
            let sent = ask(&mut host, |path| {
                seen.push(path.clone());
                std::future::ready(answer(&path))
            })
            .await;
            (sent, seen)
        }
    };

    // A host that 404s anything it does not have: the two random paths, then paths up to
    // the cap, each once.
    let (sent, seen) = run(|path| {
        if path == "/p3" {
            status(200, "")
        } else {
            status(404, "")
        }
    })
    .await;
    assert_eq!(sent, MAX_PATHS);
    assert_eq!(seen.len(), MAX_PATHS);
    assert!(
        seen[..2]
            .iter()
            .all(|p| p.len() == 17 && !p.starts_with("/p")),
        "{seen:?}"
    );
    assert_eq!(seen[2..5], ["/p0", "/p1", "/p2"]);
    let unique: BTreeSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), seen.len(), "a path asked twice: {seen:?}");

    // A host that says to slow down is left alone.
    let (sent, _) = run(|path| {
        if path.starts_with("/p") {
            status(429, "")
        } else {
            status(404, "")
        }
    })
    .await;
    assert_eq!(sent, 3);

    // A host that keeps failing is left alone after three failures in a row.
    let (sent, _) = run(|path| {
        if path.starts_with("/p") {
            Answered::none()
        } else {
            status(404, "")
        }
    })
    .await;
    assert_eq!(sent, 5);
    let (sent, _) = run(|_| status(503, "")).await;
    assert_eq!(sent, 3);
}

/// `script_src` reads the `src` of each script the landing page loads: present when one
/// matches, absent when none does, and a version from the first that captures one.
#[test]
fn a_script_src_is_read_from_the_landing_page() {
    let files = [(
        "lib.yaml".to_string(),
        "id: lib\ninfo: { name: Lib, category: Test }\n\
         detect: { script_src: { regex: '/lib(?:\\.min)?\\.js' } }\n\
         version: [ { script_src: { regex: '/lib(?:\\.min)?\\.js\\?ver=([0-9.]+)' } } ]\n"
            .to_string(),
    )];
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(f, t)| (f.as_str(), t.as_str()))
        .collect();
    let signatures = set(&files);
    let found = |body: &str| {
        Host::new(&signatures, "http://host.test/", &[], &[], body, 0)
            .detections()
            .into_iter()
            .map(|d| (d.name, d.version, d.evidence))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        found(
            "<script src='/a.js'></script><SCRIPT defer SRC=\"/static/lib.min.js?ver=2.1\"></SCRIPT>"
        ),
        [(
            "Lib".to_string(),
            Some("2.1".to_string()),
            vec!["script src /static/lib.min.js?ver=2.1".to_string()]
        )]
    );
    assert!(found("<script src='/a.js'></script><p>/lib.js</p>").is_empty());
}

/// `script` reads the content of the first script the landing page loads from its own
/// host whose `src` matches: asked for like a path, absent with no request when the page
/// loads no such script, and unknown with no request when it comes from another host.
#[test]
fn a_script_is_asked_for_only_when_the_page_loads_it_from_its_own_host() {
    let files = [(
        "lib.yaml".to_string(),
        "id: lib\ninfo: { name: Lib, category: Test }\n\
         detect: { script: { src: 'lib\\.js', regex: 'lib-marker' } }\n\
         version: [ { script: { src: 'lib\\.js', regex: 'Lib v([0-9.]+)' } } ]\n"
            .to_string(),
    )];
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(f, t)| (f.as_str(), t.as_str()))
        .collect();
    let signatures = set(&files);
    let host = |body: &'static str| {
        let mut host = Host::new(
            &signatures,
            "http://host.test/app/",
            &[],
            &[],
            body,
            STANDARD,
        );
        host.not_found = NotFound::Honest;
        host
    };

    // From its own host, by a relative src: the path is asked, query and all.
    let mut own = host("<script src='js/lib.js?v=7'></script>");
    assert_eq!(own.next(), Some(Next::Path("/app/js/lib.js?v=7".into())));
    own.asked.insert(
        "/app/js/lib.js?v=7".into(),
        status(200, "/* lib-marker Lib v1.4.2 */"),
    );
    let found = own.detections();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].version.as_deref(), Some("1.4.2"));
    assert_eq!(found[0].evidence, ["script /app/js/lib.js?v=7: 200"]);
    assert_eq!(own.next(), None);

    // A 404 for it is the script not being there.
    let mut gone = host("<script src='/js/lib.js'></script>");
    gone.asked.insert("/js/lib.js".into(), status(404, ""));
    assert_eq!(gone.outcomes()[0].1.answer, Answer::Absent);

    // From another host: nothing is asked, and it stays unknown.
    let elsewhere = host("<script src='https://cdn.test/lib.js'></script>");
    assert_eq!(elsewhere.next(), None);
    assert_eq!(elsewhere.outcomes()[0].1.answer, Answer::Unknown);

    // Not loaded at all: absent, and nothing is asked.
    let none = host("<script src='/other.js'></script>");
    assert_eq!(none.next(), None);
    assert_eq!(none.outcomes()[0].1.answer, Answer::Absent);
}

/// `not_found` reads what the host answered for the first random path. Nothing else asks
/// for it, yet the two random paths are asked for it alone, and only when its answer
/// could change one. A 403 or a 5xx for a random path is the host refusing or failing,
/// and proves nothing.
#[tokio::test]
async fn an_error_page_leaf_reads_the_not_found_page() {
    let files = [(
        "server.yaml".to_string(),
        "id: server\ninfo: { name: Server, category: Test }\n\
         detect: { any: [ { header: { name: server, regex: 'server' } }, \
                          { not_found: { regex: 'Server/[0-9]' } } ] }\n\
         version: [ { not_found: { regex: 'Server/([0-9.]+)' } } ]\n"
            .to_string(),
    )];
    let files: Vec<(&str, &str)> = files
        .iter()
        .map(|(f, t)| (f.as_str(), t.as_str()))
        .collect();
    let signatures = set(&files);
    let scan = |server: &'static str, answer: fn() -> Answered| {
        let signatures = &signatures;
        async move {
            let headers = [("server".to_string(), server.to_string())];
            let mut host = Host::new(signatures, "http://host.test/", &headers, &[], "", STANDARD);
            let sent = ask(&mut host, |_| std::future::ready(answer())).await;
            let found: Vec<(String, Option<String>, Vec<String>)> = host
                .detections()
                .into_iter()
                .map(|d| (d.name, d.version, d.evidence))
                .collect();
            (sent, found)
        }
    };
    let page = || status(404, "<hr><address>Server/2.4 at host.test</address>");

    // Nothing on the landing page: the not-found page decides, and gives the version.
    assert_eq!(
        scan("other", page).await,
        (
            2,
            vec![(
                "Server".into(),
                Some("2.4".into()),
                vec!["not-found page: 404".into()]
            )]
        )
    );
    // Found from its header without a version: asked for the version, and once asked the
    // not-found page is evidence too.
    assert_eq!(
        scan("server", page).await,
        (
            2,
            vec![(
                "Server".into(),
                Some("2.4".into()),
                vec!["header server: server".into(), "not-found page: 404".into()]
            )]
        )
    );
    // Another server's not-found page: absent.
    assert_eq!(
        scan("other", || status(404, "<h1>Not Found</h1>")).await,
        (2, vec![])
    );
    // Refused: nothing is proved either way.
    let (_, found) = scan("other", || status(403, "Server/2.4")).await;
    assert!(found.is_empty(), "{found:?}");
    let mut host = Host::new(&signatures, "http://host.test/", &[], &[], "", STANDARD);
    host.not_found = NotFound::Unusable;
    host.not_found_page = Some(status(403, "Server/2.4"));
    assert_eq!(host.outcomes()[0].1.answer, Answer::Unknown);
}

/// A `path` or `script` leaf can name its file by checksum: present on exactly those
/// bytes, binary or not, unknown on any other file there, and absent on a 404.
#[test]
fn a_checksum_names_one_exact_file() {
    use sha2::Digest;
    let file_bytes: &[u8] = b"\x89PNG\r\n\x1a\n\xff\xfe exact bytes";
    let hex: String = sha2::Sha256::digest(file_bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let files = [file(
        "exact",
        &format!(
            "{{ path: {{ path: /logo.png, sha256: '{}' }} }}",
            hex.to_uppercase()
        ),
    )];
    let answer =
        |answered: Answered| answers(&files, "", STANDARD, &[("/logo.png", answered)])[0].1;
    assert_eq!(
        answer(Answered::new(200, false, file_bytes)),
        Answer::Present
    );
    assert_eq!(
        answer(Answered::new(200, false, b"another file")),
        Answer::Unknown
    );
    assert_eq!(answer(status(404, "")), Answer::Absent);
}
