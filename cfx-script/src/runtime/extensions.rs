use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use std::collections::HashMap;
use std::sync::Mutex;

// ── Registry ─────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
enum ExtensionKind {
    /// Shell out to a binary (subfinder, httpx, nuclei, etc.)
    Cli { binary: String },
    /// Talk to a Crossfyre extension daemon over TCP JSON protocol (ambulo, voyage)
    Daemon { port: u16 },
}

static REGISTRY: Mutex<Option<HashMap<String, ExtensionKind>>> = Mutex::new(None);

/// Populate the default extension registry.
pub fn inject_defaults() {
    let mut map = HashMap::new();

    // Crossfyre extension daemons (TCP JSON protocol). Ports come from the
    // host config.toml so a custom port applies to cfx scripts too.
    for name in ["ambulo", "voyage"] {
        let port = cfx_core::toolchain::config::engine_port(name);
        map.insert(name.to_string(), ExtensionKind::Daemon { port });
    }

    // Common CLI recon tools (shell out to binary)
    for name in [
        "subfinder",
        "httpx",
        "nuclei",
        "naabu",
        "amass",
        "ffuf",
        "dnsx",
        "katana",
        "gau",
        "waybackurls",
    ] {
        map.insert(
            name.to_string(),
            ExtensionKind::Cli {
                binary: name.to_string(),
            },
        );
    }

    *REGISTRY.lock().unwrap() = Some(map);
}

pub fn clear() {
    *REGISTRY.lock().unwrap() = None;
}

// ── Python types ─────────────────────────────────────────────────────

/// Wraps a CLI tool.  `ext.run(["-d", "example.com"])` shells out.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct Extension {
    name: String,
    binary: String,
}

#[pymethods]
impl Extension {
    fn run(&self, args: Vec<String>) -> PyResult<String> {
        let binary = self.binary.clone();
        let output = std::process::Command::new(&binary)
            .args(&args)
            .output()
            .map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to run '{binary}': {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "'{}' exited with {}: {}",
                binary,
                output.status,
                stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    fn __repr__(&self) -> String {
        format!("Extension(name='{}', binary='{}')", self.name, self.binary)
    }
}

/// Wraps a Crossfyre extension daemon (ambulo, voyage).
/// Communicates over TCP with newline-delimited JSON.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct DaemonExtension {
    name: String,
    port: u16,
}

/// How long a script waits for an engine to take its connection.
const CONNECT_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Connect to the engine on 127.0.0.1:`port`. What a script sends an engine can carry
/// the target's credentials, and what comes back becomes the job's results, so a
/// listener the engines' account does not own (another account can take the port
/// while the engine is stopped) is refused before anything is written to it.
fn connect(port: u16) -> std::io::Result<std::net::TcpStream> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    #[cfg(test)]
    if let Some(uids) = TRUSTED.with(|t| t.borrow().clone()) {
        return cfx_core::engine_link::connect_trusting(addr, CONNECT_WAIT, &uids);
    }
    cfx_core::engine_link::connect(addr, CONNECT_WAIT)
}

#[pymethods]
impl DaemonExtension {
    /// Send a raw JSON request to the daemon and return the response.
    ///
    ///   ambulo = extensions.get("ambulo")
    ///   ambulo.send({"operation": "probe", "url": "https://example.com", ...})
    fn send(&self, py: Python<'_>, request: Bound<'_, PyDict>) -> PyResult<Py<PyAny>> {
        let value: serde_json::Value = pythonize::depythonize(&request)?;
        let port = self.port;

        let response = connect(port)
            .and_then(|mut stream| {
                use std::io::{BufRead, Write};
                stream.set_nodelay(true)?;
                let mut req_str = serde_json::to_string(&value).unwrap();
                req_str.push('\n');
                stream.write_all(req_str.as_bytes())?;
                stream.flush()?;

                let mut reader = std::io::BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                Ok(line)
            })
            .map_err(|e| {
                pyo3::exceptions::PyConnectionError::new_err(format!(
                    "{} daemon not reachable on port {}: {}",
                    self.name, port, e
                ))
            })?;

        let parsed: serde_json::Value = serde_json::from_str(response.trim()).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!(
                "Invalid JSON from {} daemon: {}",
                self.name, e
            ))
        })?;

        pythonize::pythonize(py, &parsed)
            .map(|b| b.unbind())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Convenience: run a scan operation (stream mode).
    /// Returns a list of all result events.
    ///
    ///   results = ambulo.scan({
    ///       "endpoint": "https://example.com/::FUZZ::",
    ///       "wordlist": "/path/to/wordlist.txt",
    ///       "method": "GET",
    ///       "tasks": 10
    ///   })
    fn scan(&self, py: Python<'_>, params: Bound<'_, PyDict>) -> PyResult<Py<PyAny>> {
        self.stream_op(py, params, Some("scan"))
    }

    /// Run any stream-mode operation and return every event.
    ///
    ///   events = voyage.stream({"operation": "takeover", "domain": "example.com"})
    ///
    /// `scan()` is this with `operation` forced to "scan". Several daemons have
    /// stream-only operations that were unreachable from a script without it,
    /// because `send()` reads a single line and `scan()` overwrote the
    /// operation. Raises on an engine error or a stream that ends without
    /// `done`, exactly as `scan()` does.
    fn stream(&self, py: Python<'_>, params: Bound<'_, PyDict>) -> PyResult<Py<PyAny>> {
        self.stream_op(py, params, None)
    }

    fn stream_op(
        &self,
        py: Python<'_>,
        params: Bound<'_, PyDict>,
        force_operation: Option<&str>,
    ) -> PyResult<Py<PyAny>> {
        let mut value: serde_json::Value = pythonize::depythonize(&params)?;
        if let Some(op) = force_operation {
            value["operation"] = serde_json::json!(op);
        }
        value["response"] = serde_json::json!("stream");

        let port = self.port;
        let name = self.name.clone();

        let events = connect(port)
            .and_then(|mut stream| {
                use std::io::{BufRead, Write};
                stream.set_nodelay(true)?;
                let mut req_str = serde_json::to_string(&value).unwrap();
                req_str.push('\n');
                stream.write_all(req_str.as_bytes())?;
                stream.flush()?;

                let reader = std::io::BufReader::new(&stream);
                let mut results = Vec::new();
                let mut saw_done = false;
                let mut engine_error: Option<String> = None;

                for line in reader.lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                        match event["type"].as_str() {
                            Some("done") => {
                                saw_done = true;
                                results.push(event);
                                break;
                            }
                            Some("error") => {
                                // The daemons emit this and stop. Keep the first
                                // message: later ones are usually consequences.
                                if engine_error.is_none() {
                                    engine_error = Some(
                                        event["message"]
                                            .as_str()
                                            .unwrap_or("engine reported an error")
                                            .to_string(),
                                    );
                                }
                                results.push(event);
                            }
                            _ => results.push(event),
                        }
                    }
                }

                Ok((results, saw_done, engine_error))
            })
            .map_err(|e| {
                pyo3::exceptions::PyConnectionError::new_err(format!(
                    "{name} daemon not reachable on port {port}: {e}"
                ))
            })?;

        // A scan that did not run must not look like a scan that found nothing.
        // The daemon reports a fatal problem as an `error` event and then stops
        // without sending `done`; both of those used to be handed back as an
        // ordinary (usually empty) list, so a rejected scan returned no results
        // and the caller reported success. Raise instead, and say why.
        let (events, saw_done, engine_error) = events;
        if let Some(message) = engine_error {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "{name} scan failed: {message}"
            )));
        }
        if !saw_done {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "{name} scan ended after {} event(s) without completing; the daemon \
                 closed the connection early",
                events.len()
            )));
        }

        pythonize::pythonize(py, &events)
            .map(|b| b.unbind())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    /// Convenience: single-URL probe (instant mode).
    ///
    ///   result = ambulo.probe("https://example.com/admin", method="GET")
    #[pyo3(signature = (url, method="GET", success_codes=None, volatility=0))]
    fn probe(
        &self,
        py: Python<'_>,
        url: &str,
        method: &str,
        success_codes: Option<Vec<u16>>,
        volatility: u32,
    ) -> PyResult<Py<PyAny>> {
        let codes = success_codes.unwrap_or_else(|| vec![200, 201, 301, 302, 403]);
        let payload = serde_json::json!({
            "operation": "probe",
            "response": "instant",
            "url": url,
            "method": method,
            "success_codes": codes,
            "volatility": volatility,
        });

        let port = self.port;
        let name = self.name.clone();

        let response = connect(port)
            .and_then(|mut stream| {
                use std::io::{BufRead, Write};
                stream.set_nodelay(true)?;
                let mut req_str = dguard::encode(&payload);
                req_str.push('\n');
                stream.write_all(req_str.as_bytes())?;
                stream.flush()?;

                let mut reader = std::io::BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line)?;
                Ok(line)
            })
            .map_err(|e| {
                pyo3::exceptions::PyConnectionError::new_err(format!(
                    "{name} daemon not reachable on port {port}: {e}"
                ))
            })?;

        let parsed: serde_json::Value = serde_json::from_str(response.trim()).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid JSON from {name} daemon: {e}"))
        })?;

        pythonize::pythonize(py, &parsed)
            .map(|b| b.unbind())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    #[getter]
    fn name(&self) -> &str {
        &self.name
    }

    #[getter]
    fn port(&self) -> u16 {
        self.port
    }

    fn __repr__(&self) -> String {
        format!("DaemonExtension(name='{}', port={})", self.name, self.port)
    }
}

// ── Module‑level functions ───────────────────────────────────────────

/// Look up an extension by name. Returns Extension or DaemonExtension.
#[pyfunction]
fn get(py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
    let guard = REGISTRY.lock().unwrap();
    let map = guard.as_ref().ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err("Extension registry not initialized")
    })?;
    let kind = map.get(name).ok_or_else(|| {
        pyo3::exceptions::PyKeyError::new_err(format!("Unknown extension: '{name}'"))
    })?;
    match kind {
        ExtensionKind::Cli { binary } => Ok(Extension {
            name: name.to_string(),
            binary: binary.clone(),
        }
        .into_pyobject(py)?
        .into_any()
        .unbind()),
        ExtensionKind::Daemon { port } => Ok(DaemonExtension {
            name: name.to_string(),
            port: *port,
        }
        .into_pyobject(py)?
        .into_any()
        .unbind()),
    }
}

/// Register a custom CLI extension (name → binary path).
#[pyfunction]
fn register(name: &str, binary_path: &str) -> PyResult<()> {
    let mut guard = REGISTRY.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(
        name.to_string(),
        ExtensionKind::Cli {
            binary: binary_path.to_string(),
        },
    );
    Ok(())
}

/// Register a daemon extension (name → port).
#[pyfunction]
fn register_daemon(name: &str, port: u16) -> PyResult<()> {
    let mut guard = REGISTRY.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    map.insert(name.to_string(), ExtensionKind::Daemon { port });
    Ok(())
}

/// List all registered extension names.
#[pyfunction]
fn list_all() -> PyResult<Vec<String>> {
    let guard = REGISTRY.lock().unwrap();
    match guard.as_ref() {
        Some(map) => Ok(map.keys().cloned().collect()),
        None => Ok(vec![]),
    }
}

pub fn make_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let m = PyModule::new(py, "extensions")?;
    m.add_function(wrap_pyfunction!(get, &m)?)?;
    m.add_function(wrap_pyfunction!(register, &m)?)?;
    m.add_function(wrap_pyfunction!(register_daemon, &m)?)?;
    m.add_function(wrap_pyfunction!(list_all, &m)?)?;
    m.add_class::<Extension>()?;
    m.add_class::<DaemonExtension>()?;
    Ok(m)
}

#[cfg(test)]
std::thread_local! {
    /// A test's word for which accounts the engines run as: a listener another account
    /// owns cannot be made in a test that runs as one account, so the test says its own
    /// account is not one of them instead.
    static TRUSTED: std::cell::RefCell<Option<Vec<u32>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// A listener on an engine's port that is not the engine. It answers every request
    /// as an engine would and reports how many bytes it was sent.
    fn impostor() -> (u16, std::thread::JoinHandle<usize>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let seen = std::thread::spawn(move || {
            l.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            let mut total = 0;
            while std::time::Instant::now() < deadline {
                let Ok((mut s, _)) = l.accept() else {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                };
                s.set_nonblocking(false).unwrap();
                s.set_read_timeout(Some(std::time::Duration::from_millis(300)))
                    .unwrap();
                let mut buf = [0u8; 4096];
                if let Ok(n) = s.read(&mut buf) {
                    total += n;
                }
                let _ =
                    s.write_all(b"{\"type\":\"done\",\"found\":\"https://planted.example/\"}\n");
                break;
            }
            total
        });
        (port, seen)
    }

    /// Any account but this test's own: the impostor's listener is then another's.
    fn others() -> Vec<u32> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        vec![unsafe { libc::geteuid() }.wrapping_add(1)]
    }

    #[test]
    fn a_script_sends_nothing_to_a_listener_another_account_owns() {
        type Ask = fn(&DaemonExtension, Python<'_>) -> PyResult<Py<PyAny>>;
        let ask: [(&str, Ask); 3] = [
            ("send", |ext, py| {
                let d = PyDict::new(py);
                d.set_item("operation", "probe")?;
                d.set_item("headers", vec![("Authorization", "Bearer secret")])?;
                ext.send(py, d)
            }),
            ("stream", |ext, py| {
                let d = PyDict::new(py);
                d.set_item("operation", "takeover")?;
                d.set_item("cookie", "session=secret")?;
                ext.stream(py, d)
            }),
            ("probe", |ext, py| {
                ext.probe(py, "https://example.com/", "GET", None, 0)
            }),
        ];
        let mut wrong = Vec::new();
        for (how, call) in ask {
            let (port, seen) = impostor();
            let ext = DaemonExtension {
                name: "ambulo".into(),
                port,
            };
            TRUSTED.with(|t| *t.borrow_mut() = Some(others()));
            let answer = Python::attach(|py| call(&ext, py).map(|_| ()));
            TRUSTED.with(|t| *t.borrow_mut() = None);
            let sent = seen.join().unwrap();
            if sent != 0 {
                wrong.push(format!(
                    "{how} sent {sent} bytes to a listener the engines do not own"
                ));
            }
            if answer.is_ok() {
                wrong.push(format!("{how} took the impostor's answer"));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[test]
    fn a_script_reaches_an_engine_this_account_runs() {
        let (port, seen) = impostor();
        let ext = DaemonExtension {
            name: "ambulo".into(),
            port,
        };
        let answer = Python::attach(|py| {
            let d = PyDict::new(py);
            d.set_item("operation", "probe")?;
            ext.send(py, d).map(|_| ())
        });
        assert!(seen.join().unwrap() > 0);
        answer.unwrap();
    }
}
