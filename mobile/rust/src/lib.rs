//! Crossfyre mobile tracer - native core (JNI bridge).
//!
//! The heavy lifting (session CA, per-SNI MITM leaves, egress, per-flow inspect+forward, privacy-safe
//! reduction) is the SHARED `cfx_capture` crate - the same code the desktop Web Tracer proxy uses.
//! This crate is the thin Android boundary: JNI entry points the Kotlin `VpnService` calls, the TUN
//! netstack (`netstack`) that turns captured packets into flows for `cfx_capture`, and the ingest
//! shipper (`ingest`).
//!
//! JNI naming: symbols are `Java_io_crossfyre_tracer_Native_<method>` for a Kotlin
//! `object io.crossfyre.tracer.Native`.

mod ingest;
mod intercept;
mod netstack;
mod stats;

use std::sync::{Arc, Mutex, OnceLock};

use cfx_capture::{Egress, SessionCa, TraceEvent};
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::JNIEnv;

/// The session CA generated on-device by `generateCaPem` and reused by `startCapture`. The private
/// key never leaves native code.
fn session_ca() -> &'static Mutex<Option<Arc<SessionCa>>> {
    static CA: OnceLock<Mutex<Option<Arc<SessionCa>>>> = OnceLock::new();
    CA.get_or_init(|| Mutex::new(None))
}

/// App-private directory where the CA (cert + key) is PERSISTED so it survives app restarts. A stable
/// CA is what lets a repackaged, pinning-stripped target app (or an installed user cert) keep trusting
/// our leaves across sessions instead of breaking every time a fresh CA is minted.
fn storage_dir() -> &'static Mutex<Option<String>> {
    static D: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(None))
}

fn persist_ca(ca: &SessionCa) {
    if let Some(dir) = storage_dir().lock().unwrap().clone() {
        let _ = std::fs::write(format!("{dir}/ca.pem"), &ca.pem);
        let _ = std::fs::write(format!("{dir}/ca.key"), ca.key.serialize_pem());
    }
}

fn load_persisted_ca() -> Option<SessionCa> {
    let dir = storage_dir().lock().unwrap().clone()?;
    let cert = std::fs::read_to_string(format!("{dir}/ca.pem")).ok()?;
    let key = std::fs::read_to_string(format!("{dir}/ca.key")).ok()?;
    cfx_capture::load_ca(&cert, &key).ok()
}

/// The running capture: a tokio runtime driving the netstack + ingest tasks. Dropping it stops
/// everything (tasks aborted, TUN dup closed).
fn capture() -> &'static Mutex<Option<tokio::runtime::Runtime>> {
    static RT: OnceLock<Mutex<Option<tokio::runtime::Runtime>>> = OnceLock::new();
    RT.get_or_init(|| Mutex::new(None))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crossfyre_tracer_Native_initLogging(_env: JNIEnv, _class: JClass) {
    // Debug level logs full request URLs, query strings included, for every
    // flow under capture. That is fine on a developer's device and not fine in
    // a release build: access tokens, session ids and password-reset nonces end
    // up in logcat, which is readable over adb and swept into bug reports.
    let level = if cfg!(debug_assertions) {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(level)
            .with_tag("cfx-mobile"),
    );
    std::panic::set_hook(Box::new(|info| {
        log::error!("RUST PANIC: {info}");
    }));
    install_crypto_provider();
    log::info!("cfx_mobile native core initialised");
}

/// Generate a fresh session CA on-device, keep it for the capture session, and return its certificate
/// PEM to install. The private key stays in native memory.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crossfyre_tracer_Native_generateCaPem<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    // Reuse the stored CA if there is one, and only mint when there is not.
    //
    // This used to generate unconditionally, so every tap of "Generate + install
    // CA" produced a NEW certificate and overwrote the old one. Three things
    // broke at once: the user had to re-import into the OS trust store every
    // time, any app already patched to trust the previous CA silently stopped
    // being decryptable, and the certificate they had just been told to trust was
    // no longer the one capture would present.
    //
    // `startCapture` already preferred the persisted CA, so the two entry points
    // disagreed about which certificate was current. They now agree.
    //
    // Unpair is the deliberate reset: it deletes ca.pem and ca.key, so the next
    // call here mints a fresh one, which is what someone clearing their session
    // is asking for.
    let pem = match load_persisted_ca() {
        Some(ca) => {
            log::info!("generateCaPem: reusing persisted CA");
            let pem = ca.pem.clone();
            *session_ca().lock().unwrap() = Some(Arc::new(ca));
            pem
        }
        None => match cfx_capture::generate_ca() {
            Ok(ca) => {
                let pem = ca.pem.clone();
                persist_ca(&ca);
                *session_ca().lock().unwrap() = Some(Arc::new(ca));
                pem
            }
            Err(e) => format!("ERROR: {e}"),
        },
    };
    env.new_string(pem)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Start capturing: run the netstack over the VpnService TUN fd (MITM each flow via cfx_capture) and
/// ship events to `{api_url}/api/v1/web-trace/ingest` with the paired workflow_id + token. Routing is
/// Normal (Direct egress) in v1. Returns false if no CA was generated first or capture is already
/// running.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crossfyre_tracer_Native_startCapture<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
    api_url: JString<'local>,
    workflow_id: JString<'local>,
    token: JString<'local>,
    allow_full_capture: jboolean,
) -> jboolean {
    if tun_fd < 0 {
        log::warn!("startCapture: invalid tun fd");
        return 0;
    }
    // Belt and suspenders: ensure the crypto provider is installed even if initLogging did not run.
    install_crypto_provider();
    stats::reset();
    // Use the CA the user generated + installed; if none exists yet, mint one so capture still runs
    // (HTTPS to native apps won't validate until the CA is installed, but DNS/TCP/plaintext flow and
    // the pipeline is exercised).
    let ca = {
        let mut slot = session_ca().lock().unwrap();
        if slot.is_none() {
            // Prefer the persisted CA (stable across restarts) so an already-trusting app/cert keeps
            // working; only mint (and persist) a fresh one if none is stored yet.
            if let Some(ca) = load_persisted_ca() {
                log::info!("startCapture: reusing persisted CA");
                *slot = Some(Arc::new(ca));
            } else {
                match cfx_capture::generate_ca() {
                    Ok(ca) => {
                        persist_ca(&ca);
                        *slot = Some(Arc::new(ca));
                    }
                    Err(e) => {
                        log::error!("startCapture: CA generation failed: {e}");
                        return 0;
                    }
                }
            }
        }
        slot.clone().unwrap()
    };
    let api_url = jstr(&mut env, api_url);
    let workflow_id = jstr(&mut env, workflow_id);
    let token = jstr(&mut env, token);

    let mut slot = capture().lock().unwrap();
    if slot.is_some() {
        log::warn!("startCapture: already running");
        return 0;
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log::error!("startCapture: runtime build failed: {e}");
            return 0;
        }
    };

    // Events flow netstack -> channel -> ingest. Egress is Direct (node routing is locked in v1).
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<TraceEvent>();
    let egress = Egress::Direct;
    let cfg_api = api_url.clone();
    let cfg_wf = workflow_id.clone();
    let cfg_token = token.clone();
    // jboolean is a u8: JNI_TRUE is 1.
    let device_allows_full = allow_full_capture != 0;
    rt.spawn(async move {
        // Ask the control plane whether this session wants full capture / manual interception, then
        // build the capture config (a gate is installed only in manual mode).
        let http = reqwest::Client::new();
        let session_cfg = intercept::fetch_capture_config(
            &http,
            &cfg_api,
            &cfg_wf,
            &cfg_token,
            device_allows_full,
        )
        .await;
        let (server_full, mode) = (session_cfg.full_capture, session_cfg.intercept_mode.clone());
        // The server may REQUEST full capture; the device decides. Previously the
        // response alone flipped this on, so a control plane (including one
        // reached by scanning someone else's QR) could turn shape-only capture
        // into full headers and bodies, while the app's own screen told the user
        // that bodies and secrets never leave the device.
        let full = server_full && device_allows_full;
        if server_full && !device_allows_full {
            log::info!("capture config: server asked for full capture; device has not allowed it");
        }
        log::info!("capture config: full={full} intercept_mode={mode}");
        let gate: Option<Arc<dyn cfx_capture::InterceptGate>> = if mode == "manual" {
            Some(Arc::new(intercept::HttpGate {
                client: http,
                api_url: cfg_api,
                workflow_id: cfg_wf,
                token: cfg_token,
            }))
        } else {
            None
        };
        if !session_cfg.bypass_hosts.is_empty() {
            log::info!(
                "bypassing {} host(s) without interception: {}",
                session_cfg.bypass_hosts.len(),
                session_cfg.bypass_hosts.join(", ")
            );
        }
        let capture_cfg = cfx_capture::CaptureCfg {
            full,
            gate,
            bypass_hosts: session_cfg.bypass_hosts,
        };
        if let Err(e) = netstack::run(tun_fd, ca, egress, tx, capture_cfg).await {
            log::error!("netstack ended: {e}");
        }
    });
    rt.spawn(ingest::run(rx, api_url, workflow_id, token));

    *slot = Some(rt);
    log::info!("startCapture: capture running on tun fd {tun_fd}");
    1
}

/// Stop capturing: drop the runtime (aborts netstack + ingest, closes the TUN dup). Idempotent.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crossfyre_tracer_Native_stopCapture(_env: JNIEnv, _class: JClass) {
    if let Some(rt) = capture().lock().unwrap().take() {
        rt.shutdown_background();
        log::info!("stopCapture: capture stopped");
    }
}

/// Pin rustls to the aws-lc-rs crypto provider for this process. The dependency graph pulls in BOTH
/// aws-lc-rs (ours) and ring (via quinn-proto / rcgen), so rustls cannot auto-select one and every
/// `ClientConfig/ServerConfig::builder()` would panic ("make sure exactly one of 'aws-lc-rs' and
/// 'ring' features is enabled"). Installing the default explicitly ends the ambiguity. Idempotent:
/// a second call (or a race) just returns Err, which we ignore.
fn install_crypto_provider() {
    cfx_capture::install_default_crypto_provider();
}

/// Tell native where it may persist the CA (the app's private files dir). Call once at startup before
/// `generateCaPem` / `startCapture` so the CA is stable across app restarts.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crossfyre_tracer_Native_setStorageDir<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    dir: JString<'local>,
) {
    let dir = jstr(&mut env, dir);
    *storage_dir().lock().unwrap() = Some(dir);
}

/// Return a JSON snapshot of the live capture counters (flows, TLS flows, CA rejections, events,
/// ingest results, last event/error) for the UI to poll and render. See [`stats`].
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_crossfyre_tracer_Native_captureStats<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    env.new_string(stats::snapshot_json())
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn jstr(env: &mut JNIEnv, s: JString) -> String {
    env.get_string(&s).map(|s| s.into()).unwrap_or_default()
}
