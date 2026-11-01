//! Every message, as the exact line that goes over the socket.
//!
//! Both ends build against this crate, but they are released apart: a Workbench and a
//! `crossfyre mcp` from different months have to understand each other. A change that
//! moves one of these lines is a protocol change, and this is where it shows up.

use std::fmt::Debug;

use cfx_bridge::*;
use serde::Serialize;
use serde::de::DeserializeOwned;

const UID: &str = "3f9a0c21be7d44c1a0e5b6f1c2d3e4f5";
const TOKEN: &str = "9f2c4e1a9f2c4e1a9f2c4e1a9f2c4e1a9f2c4e1a9f2c4e1a9f2c4e1a9f2c4e1a";
const LABEL: &str = "example-client 1.2.0";

/// Serialises to exactly `json`, and `json` reads back as the same value.
fn golden<T>(value: &T, json: &str)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    assert_eq!(to_line(value), format!("{json}\n"), "the line written");
    let back: T = serde_json::from_str(json).expect("the line reads back");
    assert_eq!(&back, value, "and is the same value");
}

/// A request line, and the call a server types it as.
fn golden_call(call: Call, id: u64, json: &str) {
    assert_eq!(call.to_line(id), format!("{json}\n"), "the request line");
    let req = Request::parse(json).expect("a request");
    assert_eq!(req.id, id);
    assert_eq!(Call::from_request(&req), Ok(call), "typed as sent");
}

/// A result line, as the server writes it and as a client reads it.
fn golden_ok<T>(id: u64, result: T, json: &str)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug + Clone,
{
    let resp = Response::ok(id, result.clone());
    golden(&resp, json);
    match ServerLine::parse(json).expect("a server line") {
        ServerLine::Response(r) => {
            assert_eq!(r.id, id);
            assert_eq!(r.into_result::<T>(), Ok(result), "the client's reading");
        }
        other => panic!("read as {other:?}"),
    }
}

fn project(exchanges: u64) -> ProjectInfo {
    ProjectInfo {
        uid: UID.into(),
        name: "acme-q4".into(),
        exchanges,
    }
}

// ----- the endpoint file -----

#[test]
fn endpoint_files() {
    let on = Endpoint {
        v: 1,
        app: ENDPOINT_APP.into(),
        app_version: "0.1.2".into(),
        pid: 4242,
        started_ms: 1_798_619_564_512,
        protocol: PROTOCOL,
        agent_access: true,
        socket: Some("/home/u/.local/share/io.crossfyre.workbench/control/4242.sock".into()),
        token: Some(TOKEN.into()),
        why: None,
    };
    let json = format!(
        r#"{{"v":1,"app":"crossfyre-workbench","app_version":"0.1.2","pid":4242,"started_ms":1798619564512,"protocol":1,"agent_access":true,"socket":"/home/u/.local/share/io.crossfyre.workbench/control/4242.sock","token":"{TOKEN}"}}"#
    );
    golden(&on, &json);
    assert_eq!(Endpoint::parse(json.as_bytes()), Ok(on.clone()));
    assert!(on.connectable().is_some());
    assert!(
        !format!("{on:?}").contains(TOKEN),
        "a token never reaches a log line through Debug"
    );

    let off = Endpoint {
        agent_access: false,
        socket: None,
        token: None,
        ..on.clone()
    };
    let json = r#"{"v":1,"app":"crossfyre-workbench","app_version":"0.1.2","pid":4242,"started_ms":1798619564512,"protocol":1,"agent_access":false}"#;
    golden(&off, json);
    assert_eq!(Endpoint::parse(json.as_bytes()), Ok(off.clone()));
    assert!(off.connectable().is_none());

    let failed = Endpoint {
        socket: None,
        token: None,
        why: Some("no socket path short enough".into()),
        ..on.clone()
    };
    let json = r#"{"v":1,"app":"crossfyre-workbench","app_version":"0.1.2","pid":4242,"started_ms":1798619564512,"protocol":1,"agent_access":true,"why":"no socket path short enough"}"#;
    golden(&failed, json);
    assert_eq!(Endpoint::parse(json.as_bytes()), Ok(failed.clone()));
    assert!(failed.connectable().is_none());
}

#[test]
fn an_endpoint_file_a_client_must_not_act_on_is_refused() {
    let base = r#""v":1,"app":"crossfyre-workbench","app_version":"0.1.2","pid":4242,"started_ms":1,"protocol":1"#;
    let upper = TOKEN.to_uppercase();
    for bad in [
        format!(r#"{{{base},"agent_access":true,"socket":"/s","token":"{upper}"}}"#),
        format!(r#"{{{base},"agent_access":true,"socket":"/s","token":"9f2c"}}"#),
        format!(r#"{{{base},"agent_access":true,"socket":"","token":"{TOKEN}"}}"#),
        format!(r#"{{{base},"agent_access":true,"socket":"/s"}}"#),
        format!(r#"{{{base},"agent_access":true}}"#),
        format!(r#"{{{base},"agent_access":false,"socket":"/s"}}"#),
        format!(r#"{{{base},"agent_access":false,"token":"{TOKEN}"}}"#),
        format!(
            r#"{{{},"agent_access":false}}"#,
            base.replace(r#""v":1"#, r#""v":2"#)
        ),
        "not json".to_string(),
    ] {
        assert!(Endpoint::parse(bad.as_bytes()).is_err(), "accepted: {bad}");
    }
    let padded = format!(
        r#"{{{base},"agent_access":false,"why":"{}"}}"#,
        "x".repeat(MAX_ENDPOINT_FILE)
    );
    assert!(Endpoint::parse(padded.as_bytes()).is_err(), "over 4 KB");
}

// ----- the handshake -----

#[test]
fn handshake_lines() {
    let hello = Handshake::Hello(Hello {
        protocol: 1,
        token: TOKEN.into(),
        client: ClientInfo {
            name: "crossfyre mcp".into(),
            version: "0.1.39".into(),
            pid: 5150,
            label: Some(LABEL.into()),
        },
    });
    golden(
        &hello,
        &format!(
            r#"{{"type":"hello","protocol":1,"token":"{TOKEN}","client":{{"name":"crossfyre mcp","version":"0.1.39","pid":5150,"label":"example-client 1.2.0"}}}}"#
        ),
    );
    assert!(!format!("{hello:?}").contains(TOKEN));

    let welcome = Welcome {
        protocol: 1,
        app_version: "0.1.2".into(),
        pid: 4242,
        capabilities: Method::ALL.iter().map(|m| m.as_str().to_string()).collect(),
        project: Some(project(1834)),
    };
    golden(
        &Handshake::Welcome(welcome.clone()),
        &format!(
            r#"{{"type":"welcome","protocol":1,"app_version":"0.1.2","pid":4242,"capabilities":["status","history","exchange","selection","site_map","scope","check","replay","scan_source","cancel"],"project":{{"uid":"{UID}","name":"acme-q4","exchanges":1834}}}}"#
        ),
    );
    assert!(Method::ALL.iter().all(|m| welcome.supports(*m)));

    let older = Welcome {
        capabilities: vec!["status".into(), "history".into()],
        project: None,
        ..welcome
    };
    golden(
        &Handshake::Welcome(older.clone()),
        r#"{"type":"welcome","protocol":1,"app_version":"0.1.2","pid":4242,"capabilities":["status","history"],"project":null}"#,
    );
    assert!(older.supports(Method::History));
    assert!(!older.supports(Method::Replay));

    golden(
        &Handshake::Refused(Refused {
            code: RefusedCode::Protocol,
            supported: vec![1],
        }),
        r#"{"type":"refused","code":"protocol","supported":[1]}"#,
    );
    golden(
        &Handshake::Refused(Refused {
            code: RefusedCode::Token,
            supported: vec![],
        }),
        r#"{"type":"refused","code":"token"}"#,
    );
}

// ----- requests -----

#[test]
fn request_lines() {
    golden_call(Call::Status, 1, r#"{"id":1,"method":"status"}"#);
    golden_call(Call::Selection, 4, r#"{"id":4,"method":"selection"}"#);

    golden_call(
        Call::History(HistoryParams {
            project_uid: UID.into(),
            filter: HistoryFilter {
                host: Some("api.example.com".into()),
                status_min: Some(200),
                status_max: Some(299),
                origins: vec![Origin::Proxy, Origin::Agent],
                url_contains: Some("/items".into()),
                ..HistoryFilter::default()
            },
            cursor: Some(HistoryCursor {
                at_ms: 1_798_619_564_512,
                id: 1042,
            }),
            limit: 50,
        }),
        12,
        &format!(
            r#"{{"id":12,"method":"history","params":{{"project_uid":"{UID}","filter":{{"host":"api.example.com","status_min":200,"status_max":299,"origins":["proxy","agent"],"url_contains":"/items"}},"cursor":{{"at_ms":1798619564512,"id":1042}},"limit":50}}}}"#
        ),
    );
    golden_call(
        Call::History(HistoryParams {
            project_uid: UID.into(),
            filter: HistoryFilter::default(),
            cursor: None,
            limit: 100,
        }),
        2,
        &format!(
            r#"{{"id":2,"method":"history","params":{{"project_uid":"{UID}","filter":{{}},"limit":100}}}}"#
        ),
    );

    golden_call(
        Call::Exchange(ExchangeParams {
            project_uid: UID.into(),
            id: 1042,
            parts: vec![Part::Request, Part::Response],
            max_body_bytes: 4096,
        }),
        13,
        &format!(
            r#"{{"id":13,"method":"exchange","params":{{"project_uid":"{UID}","id":1042,"parts":["request","response"],"max_body_bytes":4096}}}}"#
        ),
    );

    golden_call(
        Call::SiteMap(SiteMapParams {
            project_uid: UID.into(),
            host: Some("api.example.com".into()),
            cursor: Some(SiteMapCursor {
                host: "api.example.com".into(),
                path: "/items".into(),
                method: "GET".into(),
            }),
            limit: 100,
        }),
        14,
        &format!(
            r#"{{"id":14,"method":"site_map","params":{{"project_uid":"{UID}","host":"api.example.com","cursor":{{"host":"api.example.com","path":"/items","method":"GET"}},"limit":100}}}}"#
        ),
    );

    golden_call(
        Call::Scope(ScopeParams {
            project_uid: UID.into(),
        }),
        15,
        &format!(r#"{{"id":15,"method":"scope","params":{{"project_uid":"{UID}"}}}}"#),
    );

    golden_call(
        Call::Check(CheckParams {
            project_uid: UID.into(),
            dests: vec![Dest {
                host: "api.example.com".into(),
                port: 443,
            }],
            record: true,
            detail: Some("agent injection test".into()),
        }),
        16,
        &format!(
            r#"{{"id":16,"method":"check","params":{{"project_uid":"{UID}","dests":[{{"host":"api.example.com","port":443}}],"record":true,"detail":"agent injection test"}}}}"#
        ),
    );

    golden_call(
        Call::Replay(ReplayParams {
            project_uid: UID.into(),
            id: 1042,
            edits: Edits {
                query: Pairs(vec![
                    ("id".into(), Some("2".into())),
                    ("debug".into(), None),
                ]),
                headers: Pairs(vec![
                    ("accept-encoding".into(), Some("identity".into())),
                    ("cookie".into(), None),
                ]),
                ..Edits::default()
            },
            pins: vec![
                "93.184.216.34:443".parse().unwrap(),
                "[2606:2800:220:1:248:1893:25c8:1946]:443".parse().unwrap(),
            ],
            label: LABEL.into(),
            mcp: McpRef {
                session: "m_5e1f".into(),
                seq: 7,
            },
            max_body_bytes: 8192,
        }),
        17,
        &format!(
            r#"{{"id":17,"method":"replay","params":{{"project_uid":"{UID}","id":1042,"edits":{{"query":{{"id":"2","debug":null}},"headers":{{"accept-encoding":"identity","cookie":null}}}},"pins":["93.184.216.34:443","[2606:2800:220:1:248:1893:25c8:1946]:443"],"label":"example-client 1.2.0","mcp":{{"session":"m_5e1f","seq":7}},"max_body_bytes":8192}}}}"#
        ),
    );

    golden_call(
        Call::ScanSource(ScanSourceParams {
            project_uid: UID.into(),
            id: 1042,
        }),
        18,
        &format!(
            r#"{{"id":18,"method":"scan_source","params":{{"project_uid":"{UID}","id":1042}}}}"#
        ),
    );

    golden_call(
        Call::Cancel(CancelParams { id: 17 }),
        19,
        r#"{"id":19,"method":"cancel","params":{"id":17}}"#,
    );
}

#[test]
fn a_request_the_server_cannot_take_is_answered_with_why() {
    let code = |line: &str| {
        Call::from_request(&Request::parse(line).expect("a request"))
            .expect_err("refused")
            .code
    };
    assert_eq!(
        code(r#"{"id":5,"method":"export_project"}"#),
        ErrorCode::UnsupportedMethod,
        "no method that is not in the list, whatever a client asks for"
    );
    let bad_params = [
        format!(r#"{{"id":1,"method":"history","params":{{"project_uid":"{UID}","limit":0}}}}"#),
        format!(r#"{{"id":1,"method":"history","params":{{"project_uid":"{UID}","limit":101}}}}"#),
        r#"{"id":1,"method":"history","params":{"project_uid":"ACME","limit":10}}"#.into(),
        format!(
            r#"{{"id":1,"method":"history","params":{{"project_uid":"{UID}","filter":{{"status_min":500,"status_max":200}},"limit":10}}}}"#
        ),
        r#"{"id":1,"method":"history"}"#.into(),
        format!(
            r#"{{"id":1,"method":"exchange","params":{{"project_uid":"{UID}","id":1,"parts":[],"max_body_bytes":32769}}}}"#
        ),
        format!(
            r#"{{"id":1,"method":"exchange","params":{{"project_uid":"{UID}","id":1,"parts":["cookies"],"max_body_bytes":0}}}}"#
        ),
        format!(r#"{{"id":1,"method":"site_map","params":{{"project_uid":"{UID}","limit":201}}}}"#),
        format!(
            r#"{{"id":1,"method":"check","params":{{"project_uid":"{UID}","dests":[{}],"record":false}}}}"#,
            [r#"{"host":"a","port":1}"#; CHECK_DESTS_MAX + 1].join(",")
        ),
        replay(r#""pins":[]"#, "{}"),
        replay(
            &format!(
                r#""pins":[{}]"#,
                [r#""10.0.0.1:443""#; PINS_MAX + 1].join(",")
            ),
            "{}",
        ),
        replay(r#""pins":["api.example.com:443"]"#, "{}"),
        replay(
            r#""pins":["10.0.0.1:443"]"#,
            r#"{"headers":{"content-length":"0"}}"#,
        ),
        replay(r#""pins":["10.0.0.1:443"]"#, r#"{"path":"no-slash"}"#),
        // Typed from the line itself, so a name written twice is still seen as two.
        replay(
            r#""pins":["10.0.0.1:443"]"#,
            r#"{"query":{"role":"user","role":"admin"}}"#,
        ),
    ];
    for line in &bad_params {
        assert_eq!(code(line), ErrorCode::InvalidParams, "{line}");
    }
    assert_eq!(
        Call::from_request(&Request::parse(r#"{"id":1,"method":"status","params":{}}"#).unwrap()),
        Ok(Call::Status),
        "params a method does not take are ignored"
    );
    let long = format!(
        r#"{{"id":1,"method":"status","params":{{"pad":"{}"}}}}"#,
        "x".repeat(MAX_REQUEST_LINE)
    );
    assert!(Request::parse(&long).is_err(), "a request line over 64 KB");
}

fn replay(pins: &str, edits: &str) -> String {
    format!(
        r#"{{"id":1,"method":"replay","params":{{"project_uid":"{UID}","id":1,"edits":{edits},{pins},"label":"a","mcp":{{"session":"s","seq":1}},"max_body_bytes":0}}}}"#
    )
}

// ----- results -----

#[test]
fn result_lines() {
    golden_ok(
        1,
        StatusResult {
            project: Some(project(1834)),
            proxy_port: Some(8080),
            intercepting: false,
            scope: ScopeSummary {
                restricted: true,
                rules: 4,
            },
        },
        &format!(
            r#"{{"id":1,"ok":{{"project":{{"uid":"{UID}","name":"acme-q4","exchanges":1834}},"proxy_port":8080,"intercepting":false,"scope":{{"restricted":true,"rules":4}}}}}}"#
        ),
    );

    golden_ok(
        12,
        HistoryResult {
            rows: vec![
                HistoryRow {
                    id: 1041,
                    at_ms: 1_798_619_564_000,
                    method: "GET".into(),
                    url: "https://api.example.com/items/1".into(),
                    host: "api.example.com".into(),
                    status: Some(200),
                    req_len: 312,
                    resp_len: 5120,
                    pinned: false,
                    origin: Origin::Proxy,
                    actor: None,
                },
                HistoryRow {
                    id: 1040,
                    at_ms: 1_798_619_563_000,
                    method: "POST".into(),
                    url: "https://api.example.com/items".into(),
                    host: "api.example.com".into(),
                    status: None,
                    req_len: 420,
                    resp_len: 0,
                    pinned: true,
                    origin: Origin::Agent,
                    actor: Some(LABEL.into()),
                },
            ],
            next: Some(HistoryCursor {
                at_ms: 1_798_619_563_000,
                id: 1040,
            }),
        },
        r#"{"id":12,"ok":{"rows":[{"id":1041,"at_ms":1798619564000,"method":"GET","url":"https://api.example.com/items/1","host":"api.example.com","status":200,"req_len":312,"resp_len":5120,"pinned":false,"origin":"proxy","actor":null},{"id":1040,"at_ms":1798619563000,"method":"POST","url":"https://api.example.com/items","host":"api.example.com","status":null,"req_len":420,"resp_len":0,"pinned":true,"origin":"agent","actor":"example-client 1.2.0"}],"next":{"at_ms":1798619563000,"id":1040}}}"#,
    );

    golden_ok(
        13,
        ExchangeResult {
            id: 1042,
            at_ms: 1_798_619_564_512,
            method: "POST".into(),
            url: "https://api.example.com/items/2".into(),
            host: "api.example.com".into(),
            status: Some(200),
            duration_ms: Some(84),
            origin: Origin::Repeater,
            actor: None,
            pinned: false,
            req_headers: Some(vec![
                ("host".into(), "api.example.com".into()),
                ("content-type".into(), "application/json".into()),
            ]),
            resp_headers: Some(vec![("content-type".into(), "image/png".into())]),
            req_body: Some(Body::text(r#"{"qty":1}"#.into(), 9, false)),
            resp_body: Some(Body::binary(
                &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
                20480,
            )),
        },
        r#"{"id":13,"ok":{"id":1042,"at_ms":1798619564512,"method":"POST","url":"https://api.example.com/items/2","host":"api.example.com","status":200,"duration_ms":84,"origin":"repeater","actor":null,"pinned":false,"req_headers":[["host","api.example.com"],["content-type","application/json"]],"resp_headers":[["content-type","image/png"]],"req_body":{"encoding":"text","text":"{\"qty\":1}","len":9,"truncated":false},"resp_body":{"encoding":"binary","magic_hex":"89504e470d0a1a0a","len":20480,"truncated":true}}}"#,
    );

    golden_ok(
        4,
        SelectionResult {
            project_uid: UID.into(),
            changed_ms: 1_798_619_570_000,
            tool: "repeater".into(),
            exchange_id: Some(1042),
            repeater: Some(RepeaterDraft {
                target: Target {
                    host: "api.example.com".into(),
                    port: 443,
                    tls: true,
                },
                text: "GET /items/2 HTTP/1.1\r\nHost: api.example.com\r\n\r\n".into(),
                truncated: false,
            }),
        },
        &format!(
            r#"{{"id":4,"ok":{{"project_uid":"{UID}","changed_ms":1798619570000,"tool":"repeater","exchange_id":1042,"repeater":{{"target":{{"host":"api.example.com","port":443,"tls":true}},"text":"GET /items/2 HTTP/1.1\r\nHost: api.example.com\r\n\r\n","truncated":false}}}}}}"#
        ),
    );

    golden_ok(
        14,
        SiteMapResult {
            endpoints: vec![SiteMapRow {
                host: "api.example.com".into(),
                path: "/items".into(),
                method: "GET".into(),
                status: Some(200),
                count: 31,
                last_ms: 1_798_619_564_000,
                bytes: 158_720,
                has_query: true,
            }],
            next: None,
            incomplete: false,
        },
        r#"{"id":14,"ok":{"endpoints":[{"host":"api.example.com","path":"/items","method":"GET","status":200,"count":31,"last_ms":1798619564000,"bytes":158720,"has_query":true}],"next":null,"incomplete":false}}"#,
    );

    golden_ok(
        15,
        ScopeResult {
            restricted: true,
            entries: vec!["api.example.com".into(), "*.example.com".into()],
            rejected: vec!["*.com".into()],
            refused_total: 3,
            refusals_dropped: 0,
            recent: vec![RefusalRow {
                at_ms: 1_798_619_569_000,
                host: "evil.example.net".into(),
                port: 443,
                point: "agent".into(),
                detail: Some(LABEL.into()),
            }],
        },
        r#"{"id":15,"ok":{"restricted":true,"entries":["api.example.com","*.example.com"],"rejected":["*.com"],"refused_total":3,"refusals_dropped":0,"recent":[{"at_ms":1798619569000,"host":"evil.example.net","port":443,"point":"agent","detail":"example-client 1.2.0"}]}}"#,
    );

    golden_ok(
        16,
        CheckResult {
            results: vec![CheckRow {
                host: "api.example.com".into(),
                port: 443,
                admitted: true,
            }],
        },
        r#"{"id":16,"ok":{"results":[{"host":"api.example.com","port":443,"admitted":true}]}}"#,
    );

    golden_ok(
        17,
        ReplayResult {
            new_id: 1843,
            status: Some(200),
            duration_ms: 91,
            bytes: 734,
            request_line: "GET /items/2?id=2 HTTP/1.1".into(),
            applied: vec![
                "query id set to 2".into(),
                "query debug removed".into(),
                "header cookie removed".into(),
            ],
            resp_headers: vec![("content-type".into(), "application/json".into())],
            resp_body: Some(Body::text(r#"{"id":2}"#.into(), 8, false)),
        },
        r#"{"id":17,"ok":{"new_id":1843,"status":200,"duration_ms":91,"bytes":734,"request_line":"GET /items/2?id=2 HTTP/1.1","applied":["query id set to 2","query debug removed","header cookie removed"],"resp_headers":[["content-type","application/json"]],"resp_body":{"encoding":"text","text":"{\"id\":2}","len":8,"truncated":false}}}"#,
    );

    golden_ok(
        18,
        ScanSourceResult {
            method: "POST".into(),
            url: "https://api.example.com/items".into(),
            req_headers: vec![(
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            body: Some("qty=1&note=x".into()),
            content_type: Some("application/x-www-form-urlencoded".into()),
        },
        r#"{"id":18,"ok":{"method":"POST","url":"https://api.example.com/items","req_headers":[["content-type","application/x-www-form-urlencoded"]],"body":"qty=1&note=x","content_type":"application/x-www-form-urlencoded"}}"#,
    );

    golden_ok(19, CancelResult {}, r#"{"id":19,"ok":{}}"#);
}

#[test]
fn error_lines() {
    let changed: Response = Response::err(
        17,
        ErrorBody {
            code: ErrorCode::ProjectChanged,
            message: "The open project is not the one this handle came from.".into(),
            current: Some(ProjectRef {
                uid: "0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e".into(),
                name: "other".into(),
            }),
        },
    );
    golden(
        &changed,
        r#"{"id":17,"err":{"code":"project_changed","message":"The open project is not the one this handle came from.","current":{"uid":"0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e","name":"other"}}}"#,
    );
    assert_eq!(
        changed.into_result::<ReplayResult>().map_err(|e| e.code),
        Err(ErrorCode::ProjectChanged)
    );

    let codes = [
        (ErrorCode::NoProject, "no_project"),
        (ErrorCode::ProjectChanged, "project_changed"),
        (ErrorCode::NotFound, "not_found"),
        (ErrorCode::OutOfScope, "out_of_scope"),
        (ErrorCode::PinMismatch, "pin_mismatch"),
        (ErrorCode::BinaryBody, "binary_body"),
        (ErrorCode::TooLarge, "too_large"),
        (ErrorCode::InvalidParams, "invalid_params"),
        (ErrorCode::Busy, "busy"),
        (ErrorCode::UnsupportedMethod, "unsupported_method"),
        (ErrorCode::SendFailed, "send_failed"),
        (ErrorCode::AccessOff, "access_off"),
        (ErrorCode::Internal, "internal"),
    ];
    for (code, text) in codes {
        golden(
            &Response::<serde_json::Value>::err(3, ErrorBody::new(code, "m")),
            &format!(r#"{{"id":3,"err":{{"code":"{text}","message":"m"}}}}"#),
        );
    }

    // A code from a newer server is kept as it was sent, not a failed line.
    let line = r#"{"id":3,"err":{"code":"quota_spent","message":"m"}}"#;
    let Ok(ServerLine::Response(r)) = ServerLine::parse(line) else {
        panic!("unreadable");
    };
    let e = r.into_result::<StatusResult>().unwrap_err();
    assert_eq!(e.code, ErrorCode::Other("quota_spent".into()));
    assert_eq!(e.code.as_str(), "quota_spent");
}

// ----- events -----

#[test]
fn event_lines() {
    let lines = [
        (
            Event::Project {
                project: Some(project(1900)),
            },
            format!(
                r#"{{"event":"project","project":{{"uid":"{UID}","name":"acme-q4","exchanges":1900}}}}"#
            ),
        ),
        (
            Event::Project { project: None },
            r#"{"event":"project","project":null}"#.into(),
        ),
        (
            Event::Selection {
                changed_ms: 1_798_619_570_000,
            },
            r#"{"event":"selection","changed_ms":1798619570000}"#.into(),
        ),
        (
            Event::Scope {
                restricted: true,
                rules: 4,
            },
            r#"{"event":"scope","restricted":true,"rules":4}"#.into(),
        ),
        (
            Event::AgentAccess { enabled: false },
            r#"{"event":"agent_access","enabled":false}"#.into(),
        ),
    ];
    for (event, json) in lines {
        golden(&event, &json);
        assert_eq!(ServerLine::parse(&json), Ok(ServerLine::Event(event)));
    }
}

// ----- reading a server line -----

#[test]
fn what_a_newer_server_adds_does_not_break_an_older_client() {
    // An event this version has never heard of is named and can be ignored.
    assert_eq!(
        ServerLine::parse(r#"{"event":"window_closed","at_ms":1}"#),
        Ok(ServerLine::UnknownEvent("window_closed".into()))
    );
    // A field it has never heard of is ignored, at any depth.
    let line = format!(
        r#"{{"id":1,"took_ms":3,"ok":{{"project":{{"uid":"{UID}","name":"acme-q4","exchanges":1,"colour":"red"}},"proxy_port":null,"intercepting":true,"theme":"dark","scope":{{"restricted":false,"rules":0}}}}}}"#
    );
    let Ok(ServerLine::Response(r)) = ServerLine::parse(&line) else {
        panic!("unreadable");
    };
    let status = r.into_result::<StatusResult>().expect("still a status");
    assert!(status.intercepting);
    assert_eq!(status.proxy_port, None);
    // An origin it has never heard of is kept.
    let row: HistoryRow = serde_json::from_str(
        r#"{"id":1,"at_ms":1,"method":"GET","url":"u","host":"h","status":200,"req_len":0,"resp_len":0,"pinned":false,"origin":"import","actor":null}"#,
    )
    .unwrap();
    assert_eq!(row.origin, Origin::Other("import".into()));
}

#[test]
fn a_server_line_that_is_wrong_is_an_error_not_a_guess() {
    for bad in [
        r#"{"event":"scope","restricted":"yes","rules":4}"#,
        r#"{"event":"project"}"#,
        r#"{"ok":{}}"#,
        r#"{"id":1}"#,
        r#"{"id":"1","ok":{}}"#,
        "[]",
        "",
    ] {
        assert!(ServerLine::parse(bad).is_err(), "accepted: {bad}");
    }
    let long = format!(r#"{{"id":1,"ok":"{}"}}"#, "x".repeat(MAX_RESPONSE_LINE));
    assert!(ServerLine::parse(&long).is_err(), "a line over 1 MiB");

    // A status that leaves out the project says nothing about it, which is not the same
    // as saying none is open.
    let Ok(ServerLine::Response(r)) = ServerLine::parse(
        r#"{"id":1,"ok":{"proxy_port":1,"intercepting":false,"scope":{"restricted":false,"rules":0}}}"#,
    ) else {
        panic!("unreadable");
    };
    assert_eq!(
        r.into_result::<StatusResult>().map_err(|e| e.code),
        Err(ErrorCode::Internal)
    );
}

#[test]
fn every_method_has_one_name() {
    for m in Method::ALL {
        assert_eq!(Method::parse(m.as_str()), Some(m));
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            format!("\"{}\"", m.as_str())
        );
    }
    assert_eq!(Method::parse("Status"), None);
}
