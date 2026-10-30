//! `crossfyre mcp` spoken to over its real stdin and stdout, the way a client runs it.
//!
//! A stand-in toolmark daemon on loopback plays the engine and makes one request to
//! whatever target it is given, so the out-of-scope listener counting zero means the
//! server refused before the engine was ever asked.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "crossfyre-mcp-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("mcp")).unwrap();
    // The server refuses a scope file others could change, whatever the umask made.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.join("mcp"), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    d
}

fn write_scope(data: &std::path::Path, text: &str) {
    let p = data.join("mcp/scope.toml");
    std::fs::write(&p, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn write_config(data: &std::path::Path, toolmark: u16, plessor: u16) {
    std::fs::write(
        data.join("config.toml"),
        format!(
            "[postgres]\nhost = \"127.0.0.1\"\nport = {}\nuser = \"crossfyre\"\n\
             db_name = \"crossfyre\"\n\n[container]\n\n[extensions]\ntoolmark = {toolmark}\n\
             plessor = {plessor}\n",
            closed_port()
        ),
    )
    .unwrap();
}

/// Read request lines from an engine client, answering the capabilities question,
/// until the operation arrives.
fn read_op(r: &mut impl BufRead, w: &mut TcpStream, caps: &Value) -> Option<Value> {
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        if v["operation"] != "capabilities" {
            return Some(v);
        }
        writeln!(w, "{caps}").ok()?;
    }
}

fn closed_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An HTTP listener that counts connections.
fn target() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let n = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&n);
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            c.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    (port, n)
}

/// A toolmark daemon stand-in: records each op, requests the target once, and answers
/// with one technology and the service record.
fn toolmark() -> (u16, Arc<Mutex<Vec<Value>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let ops = Arc::new(Mutex::new(Vec::new()));
    let o = Arc::clone(&ops);
    let caps = json!({"type": "capabilities", "fingerprint": ["resolve", "block_internal"]});
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            let mut w = s.try_clone().unwrap();
            let Some(op) = read_op(&mut BufReader::new(s), &mut w, &caps) else {
                continue;
            };
            o.lock().unwrap().push(op.clone());
            let t = op["target"].as_str().unwrap_or("");
            if let Some(hp) = t.strip_prefix("http://").and_then(|r| r.split('/').next())
                && let Ok(mut c) = TcpStream::connect(hp)
            {
                let _ = c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
                let _ = c.read(&mut [0u8; 256]);
            }
            for ev in [
                json!({"type": "ack", "target": t}),
                json!({"type": "finding", "data": {"type": "technology", "source": "scout",
                    "severity": "info", "name": "nginx", "category": "web-server",
                    "version": "1.25.3", "cpe": "", "confidence": 100, "evidence": "server"}}),
                json!({"type": "finding", "data": {"type": "service", "source": "scout",
                    "severity": "info", "status_code": 200, "title": "t", "server": "nginx"}}),
                json!({"type": "done"}),
            ] {
                let _ = writeln!(w, "{ev}");
            }
        }
    });
    (port, ops)
}

/// A plessor daemon stand-in that acknowledges a scan, sends nothing more, and
/// counts the cancel lines it is sent.
fn plessor() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let cancels = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&cancels);
    let caps = json!({"type": "capabilities", "cancel": true,
                      "inject": ["follow_redirects", "resolve"]});
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            let (c, caps) = (Arc::clone(&c), caps.clone());
            std::thread::spawn(move || {
                let mut w = s.try_clone().unwrap();
                let mut r = BufReader::new(s);
                let Some(op) = read_op(&mut r, &mut w, &caps) else {
                    return;
                };
                let _ = writeln!(
                    w,
                    "{}",
                    json!({"type": "ack", "target": op["target"], "cancellable": true})
                );
                let mut line = String::new();
                while r.read_line(&mut line).unwrap_or(0) > 0 {
                    if line.contains("\"cancel\"") {
                        c.fetch_add(1, Ordering::SeqCst);
                        let _ = writeln!(w, "{}", json!({"type": "done", "cancelled": true}));
                        return;
                    }
                    line.clear();
                }
            });
        }
    });
    (port, cancels)
}

fn spawn(data: &std::path::Path) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crossfyre"));
    cmd.arg("--data-dir")
        .arg(data)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for v in [
        "CFX_DAEMON_TOKEN",
        "CROSSFYRE_EGRESS_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        cmd.env_remove(v);
    }
    cmd.spawn().expect("crossfyre runs")
}

fn wait_exit(child: &mut Child, within: Duration) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s;
        }
        if start.elapsed() > within {
            let _ = child.kill();
            panic!("crossfyre mcp did not exit within {within:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

struct Client {
    stdin: ChildStdin,
    lines: Receiver<String>,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Client {
    /// Read the child's stdout on a thread, keeping every line it writes.
    fn attach(child: &mut Child) -> (Client, Arc<Mutex<Vec<String>>>) {
        let stdout = child.stdout.take().unwrap();
        let all_lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let (tx, rx) = channel();
        let keep = Arc::clone(&all_lines);
        std::thread::spawn(move || {
            for l in BufReader::new(stdout).lines() {
                let Ok(l) = l else { return };
                keep.lock().unwrap().push(l.clone());
                if tx.send(l).is_err() {
                    return;
                }
            }
        });
        let c = Client {
            stdin: child.stdin.take().unwrap(),
            lines: rx,
            seen: Arc::new(Mutex::new(Vec::new())),
        };
        (c, all_lines)
    }

    /// `initialize` and `notifications/initialized`, as a client with or without
    /// elicitation.
    fn initialize(&mut self, elicitation: bool) -> Value {
        let caps = if elicitation {
            json!({"elicitation": {}})
        } else {
            json!({})
        };
        self.send(
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": caps,
            "clientInfo": {"name": "stdio-test", "version": "1.0"}}}),
        );
        let init = self.reply(1)["result"].clone();
        self.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        init
    }

    fn send(&mut self, v: Value) {
        writeln!(self.stdin, "{v}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn next(&self) -> Value {
        let l = self
            .lines
            .recv_timeout(Duration::from_secs(20))
            .expect("a line from the server");
        serde_json::from_str(&l).expect("stdout carries JSON only")
    }

    /// The response to request `id`, answering any confirmation the server asks for
    /// with yes on the way.
    fn reply(&mut self, id: u64) -> Value {
        loop {
            let v = self.next();
            if v["method"] == "elicitation/create" {
                let field = v["params"]["requestedSchema"]["required"][0].clone();
                let mut content = json!({});
                content[field.as_str().unwrap()] = json!(true);
                self.send(json!({"jsonrpc": "2.0", "id": v["id"],
                                 "result": {"action": "accept", "content": content}}));
                self.seen.lock().unwrap().push("elicitation".into());
                continue;
            }
            if v["id"] == json!(id) {
                return v;
            }
        }
    }

    fn call(&mut self, id: u64, name: &str, args: Value) -> Value {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                         "params": {"name": name, "arguments": args}}));
        self.reply(id)["result"].clone()
    }
}

#[test]
fn a_client_session_over_stdio() {
    let (port_in, hits_in) = target();
    let (port_out, hits_out) = target();
    let (tm_port, ops) = toolmark();
    let data = temp_dir("session");
    write_config(&data, tm_port, closed_port());
    let scope_text = format!("entries = [\"127.0.0.1:{port_in}\"]\n");
    write_scope(&data, &scope_text);

    let mut child = spawn(&data);
    let mut stderr = child.stderr.take().unwrap();
    let (mut c, all_lines) = Client::attach(&mut child);

    let init = c.initialize(true);
    assert_eq!(init["protocolVersion"], "2025-11-25", "{init}");
    assert_eq!(init["serverInfo"]["name"], "crossfyre", "{init}");
    assert!(init["capabilities"]["tools"].is_object(), "{init}");
    // Declared whether or not a Workbench is running, since one can start later.
    assert_eq!(init["capabilities"]["tools"]["listChanged"], true, "{init}");

    c.send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let tools = c.reply(2)["result"]["tools"].clone();
    assert_eq!(tools.as_array().unwrap().len(), 11);

    let r = c.call(
        3,
        "check_scope",
        json!({"targets": [format!("127.0.0.1:{port_in}"), format!("127.0.0.1:{port_out}")]}),
    );
    let admitted: Vec<bool> = r["structuredContent"]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["admitted"].as_bool().unwrap())
        .collect();
    assert_eq!(admitted, [true, false]);

    let r = c.call(
        4,
        "fingerprint",
        json!({"url": format!("http://127.0.0.1:{port_out}/")}),
    );
    assert_eq!(r["isError"], true, "{r}");
    assert!(r.get("structuredContent").is_none());
    assert_eq!(hits_out.load(Ordering::SeqCst), 0);
    assert_eq!(ops.lock().unwrap().len(), 0);

    let r = c.call(
        5,
        "fingerprint",
        json!({"url": format!("http://127.0.0.1:{port_in}/")}),
    );
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(
        r["structuredContent"]["technologies"][0]["name"], "nginx",
        "{r}"
    );
    assert_eq!(
        *c.seen.lock().unwrap(),
        ["elicitation"],
        "asked once, before traffic"
    );
    assert_eq!(ops.lock().unwrap().len(), 1);
    assert_eq!(ops.lock().unwrap()[0]["follow_redirects"], false);
    assert!(hits_in.load(Ordering::SeqCst) >= 1);
    assert_eq!(hits_out.load(Ordering::SeqCst), 0);

    let r = c.call(6, "get_scope", json!({}));
    assert_eq!(r["structuredContent"]["state"], "loaded");
    let sha = r["structuredContent"]["sha256"]
        .as_str()
        .unwrap()
        .to_string();

    c.send(json!({"jsonrpc": "2.0", "id": 7, "method": "ping"}));
    assert_eq!(c.reply(7)["result"], json!({}));

    drop(c.stdin);
    let status = wait_exit(&mut child, Duration::from_secs(5));
    assert!(status.success(), "{status:?}");

    for l in all_lines.lock().unwrap().iter() {
        let v: Value = serde_json::from_str(l).expect("only JSON on stdout");
        assert_eq!(v["jsonrpc"], "2.0", "{l}");
    }
    let mut err = String::new();
    stderr.read_to_string(&mut err).unwrap();
    assert!(err.contains(&sha[..12]), "{err}");

    let audit = std::fs::read_to_string(data.join("mcp/audit.jsonl")).unwrap();
    let calls: Vec<Value> = audit
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|v| v["event"] == "call")
        .collect();
    assert_eq!(calls.len(), 4, "{audit}");
    let expected = sha256_hex(scope_text.as_bytes());
    assert_eq!(sha, expected);
    assert!(calls.iter().all(|v| v["scope_sha256"] == expected.as_str()));
    assert_eq!(calls[1]["reason"], "out_of_scope");
    assert_eq!(calls[2]["confirmation"], "elicited");
    assert!(audit.contains("\"event\":\"start\"") && audit.contains("\"event\":\"stop\""));
    let _ = std::fs::remove_dir_all(&data);
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn audit_calls(data: &std::path::Path) -> (String, Vec<Value>) {
    let audit = std::fs::read_to_string(data.join("mcp/audit.jsonl")).unwrap();
    let calls = audit
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .filter(|v| v["event"] == "call")
        .collect();
    (audit, calls)
}

#[test]
fn a_call_the_protocol_layer_cannot_read_is_still_logged() {
    let data = temp_dir("unreadable");
    write_config(&data, closed_port(), closed_port());
    write_scope(&data, "entries = [\"app.example.test\"]\n");
    let mut child = spawn(&data);
    let (mut c, _) = Client::attach(&mut child);
    c.initialize(false);

    let bad = [
        json!({"name": "get_scope", "arguments": "not an object"}),
        json!({"name": "get_scope", "arguments": [1, 2]}),
        json!({"arguments": {}}),
    ];
    for (i, params) in bad.iter().enumerate() {
        let id = 10 + i as u64;
        c.send(json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params}));
        let r = c.reply(id);
        assert_eq!(r["error"]["code"], -32602, "{r}");
    }
    drop(c.stdin);
    assert!(wait_exit(&mut child, Duration::from_secs(10)).success());

    let (audit, calls) = audit_calls(&data);
    assert_eq!(calls.len(), bad.len(), "{audit}");
    assert!(
        calls
            .iter()
            .all(|l| l["reason"] == "invalid_arguments" && l["decision"] == "error"),
        "{audit}"
    );
    assert_eq!(calls[0]["tool"], "get_scope");
    assert!(calls[2]["tool"].is_null());
    let _ = std::fs::remove_dir_all(&data);
}

#[cfg(unix)]
#[test]
fn sigterm_stops_the_scans_and_closes_the_log() {
    let (port_in, _) = target();
    let (pl_port, cancels) = plessor();
    let data = temp_dir("sigterm");
    write_config(&data, closed_port(), pl_port);
    write_scope(&data, &format!("entries = [\"127.0.0.1:{port_in}\"]\n"));
    let mut child = spawn(&data);
    let (mut c, _) = Client::attach(&mut child);
    c.initialize(false);

    let r = c.call(
        2,
        "test_injection",
        json!({"url": format!("http://127.0.0.1:{port_in}/?q=1")}),
    );
    assert_eq!(r["isError"], false, "{r}");
    let scan_id = r["structuredContent"]["scan_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(r["structuredContent"]["status"], "running", "{r}");

    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let status = wait_exit(&mut child, Duration::from_secs(10));
    assert!(status.success(), "{status:?}");

    let (audit, _) = audit_calls(&data);
    assert!(audit.contains("\"event\":\"stop\""), "{audit}");
    let job: Value = serde_json::from_str(
        &std::fs::read_to_string(data.join(format!("mcp/jobs/{scan_id}.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(job["status"], "interrupted", "{job}");
    assert_eq!(
        cancels.load(Ordering::SeqCst),
        1,
        "plessor was not told to stop"
    );
    let _ = std::fs::remove_dir_all(&data);
}

#[test]
fn an_entry_that_does_not_parse_stops_the_start() {
    let data = temp_dir("bad");
    write_scope(&data, "entries = [\"not a host\"]\n");
    let mut child = spawn(&data);
    // Stdin stays open: the server has to fail without waiting for a client.
    let _stdin = child.stdin.take();
    let status = wait_exit(&mut child, Duration::from_secs(10));
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert_eq!(status.code(), Some(2), "{err}");
    assert!(out.is_empty(), "stdout must stay empty: {out}");
    assert!(err.contains("\"not a host\""), "{err}");
    assert!(
        !data.join("mcp/audit.jsonl").exists(),
        "nothing ran, so nothing is logged"
    );
    let _ = std::fs::remove_dir_all(&data);
}
