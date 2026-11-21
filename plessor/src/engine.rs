//! The Plessor vulnerability engine (minimal, real detection).
//!
//! Every candidate flows through the correctness pipeline
//! (GENERATE -> DETECT -> CONFIRM -> REPORT): template matches are re-issued to
//! confirm (see template.rs), and passive checks are deterministic on the
//! observed response. Findings are relayed verbatim by the node into the shared
//! asset graph. OAST-backed blind detection, the full DSL, and the generative
//! API mode are the documented next milestones (docs/tier1-engines-plan.md).

use crate::template;
use cfx_finding::Finding;
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::mpsc;
use transport::Client;

#[derive(Debug, Deserialize)]
pub struct ScanParams {
    pub target: String,
    /// Evasiveness posture (set by the node's Evasiveness switch): blend in as a
    /// browser (true, default) vs a neutral honest client (false).
    #[serde(default = "d_true")]
    pub evasive: bool,
    /// Attribution token: when set, advertise it so an authorized program can
    /// allow-list the traffic.
    #[serde(default)]
    pub identify: Option<String>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "d_true")]
    pub follow_redirects: bool,
    /// Optional external nuclei-template directory (supported subset).
    #[serde(default)]
    pub templates_dir: Option<String>,
    /// Run the starter pack compiled from templates/ beside the built-in checks.
    ///
    /// Off unless a request asks: the node sends its own scans, and turning this
    /// on for it would change every platform scan at once. `plessor scan` asks,
    /// because without it an installed copy ran twelve checks and never the
    /// hundred templates it ships with.
    #[serde(default)]
    pub pack: bool,
    /// nuclei-style severity filter (lowercased); empty = all severities.
    #[serde(default)]
    pub severity: Vec<String>,
    /// Only run passive header checks (no template requests).
    #[serde(default)]
    pub passive_only: bool,
    /// Opt-in to templates whose method overwrites or destroys a resource
    /// (PUT, PATCH, DELETE). Off by default, the same rail the injection and
    /// authorization engines state.
    ///
    /// The built-in set is all GET, so a default `plessor scan` was already
    /// harmless: 12 templates, 23 requests, nothing state-changing. An external
    /// pack is a different matter, and pointing `templates_dir` at one is what
    /// the documentation tells people to do. Measured against a target that
    /// records what it is sent, with our own 112-template pack loaded: 194
    /// requests, 15 of them state-changing, and one of those is
    ///
    /// ```text
    /// PATCH /api/v1/account {"role":"admin","balance_cents":-99999}
    /// ```
    ///
    /// which does not test whether privilege escalation is possible, it performs
    /// it and then looks for the echo. That template's own description calls the
    /// oracle weak and says the engine's own mass-assignment probe is the sound
    /// one. The other fourteen are POST and are exploit confirmations of the
    /// ordinary kind: a login attempt with bad credentials, a command-injection
    /// marker, an SSRF callback, an XXE entity, a PHP eval. Those stay.
    #[serde(default)]
    pub test_writes: bool,
    /// Announce ourselves under this exact User-Agent instead of presenting as a
    /// browser.
    ///
    /// `evasive: false` is NOT enough for this. Both `Fast` and `Evasive` resolve
    /// to a real desktop-Chrome identity, because the flag chooses whether to
    /// BLEND (rotate profiles per target), not whether to be honest. Every mode
    /// therefore sends a Chrome User-Agent, which is the correct default for a
    /// scan a customer authorised on their own property and the wrong one for
    /// anything that reaches a host whose owner never asked.
    ///
    /// The public free tools set this. Presenting as a browser while probing a
    /// stranger is what turns a defensible service into an indefensible one, so
    /// there has to be a way to say plainly who is calling. Setting it also drops
    /// the browser hint headers, since a named scanner claiming Sec-Fetch-User
    /// and sec-ch-ua is not honest, just differently dressed.
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Refuse to connect to private / reserved addresses.
    ///
    /// Off by default: scanning a customer's own internal network from a node
    /// inside it is the product working. The public free tools turn it on,
    /// because there an anonymous stranger picks the destination and the hop is
    /// ours. Enforced in `transport` at the resolver, so it also covers redirect
    /// hops and DNS rebinding.
    #[serde(default)]
    pub block_internal: bool,
    /// Template-id allowlist. Empty = every template the severity filter admits.
    ///
    /// The severity filter alone cannot express "run the exposure pack and
    /// nothing else", because severity cuts across categories: a public tool
    /// that promises to look for exposed files must not also fire an SQLi
    /// probe at a stranger's host just because both are `high`. Naming the
    /// templates is the only selection that is precise enough to defend in an
    /// abuse ticket, so the free tools pass this and the caller decides the
    /// blast radius rather than the engine.
    #[serde(default)]
    pub only: Vec<String>,
    /// What toolmark saw on the target, by its names for them, part:vendor:product. With
    /// them, a template about one product runs only where toolmark saw it; with none,
    /// every template runs, as it always did. See [`template::Choice`].
    #[serde(default)]
    pub products: Option<Vec<String>>,
    /// Which inventory `products` came from and how old it was, said with the templates
    /// held back.
    #[serde(default)]
    pub products_from: Option<String>,
    /// Run every template, whatever `products` says.
    #[serde(default)]
    pub all_templates: bool,
    /// toolmark's CVE leads for what it saw on the target, from the same inventory as
    /// `products`, each answered once the templates that check it have run.
    #[serde(default)]
    pub leads: Vec<cfx_cve::inventory::HostLead>,
    /// Optional request auth (headers + cookie) resolved from a credential by the
    /// node, so scanning (and later authorization testing) runs authenticated.
    #[serde(default)]
    pub auth: Option<AuthSpec>,
    /// Optional OAST endpoint (domains + poll API) the node resolved from the
    /// workspace's selected endpoint. When present it overrides the env fallback,
    /// enabling per-scan choice of the managed pool or a BYO self-hosted OAST.
    #[serde(default)]
    pub oast: Option<OastSpec>,
    /// Where this op's connections go. Never read from the op's own fields: the
    /// daemon sets it from the egress wrapper the request came in, and a request
    /// without one gets `Inherit`.
    #[serde(skip)]
    pub egress: transport::Egress,
}
fn d_timeout() -> u64 {
    10_000
}
fn d_true() -> bool {
    true
}

/// An OAST endpoint resolved by the node for this scan.
#[derive(Debug, Deserialize)]
pub struct OastSpec {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub api_url: String,
}

/// Request auth resolved from a credential. Now shared across all engines via
/// `transport`; re-exported so `crate::engine::AuthSpec` keeps resolving.
pub use transport::AuthSpec;

pub(crate) struct BaseResp {
    pub(crate) is_https: bool,
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    /// First chunk of the body, for WAF/anti-bot challenge detection.
    pub(crate) body_prefix: String,
}

/// Replace a resolved identity with an honest, announced one.
///
/// No-op when `ua` is absent or blank, which is every existing workflow.
///
/// When set, this drops the browser-hint headers along with the User-Agent.
/// Keeping `sec-ch-ua` and the `Sec-Fetch-*` set alongside a scanner name would
/// be a client claiming to be two different things at once, which is worse than
/// either alone: it reads as evasion that forgot to change its User-Agent.
fn announce_as(ident: &mut adaptive::identity::Identity, ua: Option<&str>) {
    let Some(ua) = ua.map(str::trim).filter(|u| !u.is_empty()) else {
        return;
    };
    ident.user_agent = ua.to_string();
    ident.headers.retain(|(k, _)| {
        let k = k.to_ascii_lowercase();
        !(k.starts_with("sec-ch-ua")
            || k.starts_with("sec-fetch")
            || k == "upgrade-insecure-requests")
    });
}

/// Whether this scan should present a browser TLS/HTTP2 fingerprint.
///
/// An announced User-Agent forces emulation off regardless of posture, because
/// under the impersonate backend the emulation profile owns the fingerprint AND
/// replaces the header map. A browser signature shipping under a scanner's name
/// is the contradiction this exists to prevent.
fn should_emulate(ua: Option<&str>, mode: &adaptive::identity::Mode) -> bool {
    let announced = ua.map(str::trim).is_some_and(|u| !u.is_empty());
    !announced && !matches!(mode, adaptive::identity::Mode::Fast)
}

/// Scan `params.target`, sending what is found on `tx`, keeping the plan in `ledger`, and
/// with `pack`'s templates when the request asks for the pack.
pub async fn run<L: crate::ledger::Ledger>(
    params: ScanParams,
    tx: mpsc::UnboundedSender<Value>,
    ledger: std::sync::Arc<L>,
    pack: std::sync::Arc<template::Pack>,
) {
    let base = match normalize_base(&params.target) {
        Some(b) => b,
        None => {
            let _ = tx.send(
                json!({"type":"error","message":format!("invalid target: {}", params.target)}),
            );
            return;
        }
    };

    // Outbound identity, presented via the transport layer. The reqwest backend
    // sends UA + hint headers; the impersonate (wreq) backend presents a real
    // browser TLS/HTTP2 fingerprint, with the emulation profile owning the
    // fingerprint headers. Fast posture skips emulation. Stable-per-target; the
    // profile choice is the private `adaptive` drop-in.
    let mode = adaptive::identity::Mode::from_flags(params.evasive, params.identify.clone());

    // Builds an outbound client for a resolved identity. Closed over so a
    // challenge retry can rebuild it with a rotated identity.
    let build_client = |ident: &adaptive::identity::Identity,
                        clearance: Option<&crate::solver::Solved>| {
        let mut browser_headers = transport::HeaderMap::new();
        for (k, v) in &ident.headers {
            if let (Ok(name), Ok(val)) = (
                transport::HeaderName::from_bytes(k.as_bytes()),
                transport::HeaderValue::from_str(v),
            ) {
                browser_headers.insert(name, val);
            }
        }
        let mut extra_headers = transport::HeaderMap::new();
        if let Some(auth) = params.auth.as_ref().filter(|a| a.is_meaningful()) {
            for (k, v) in auth.to_header_map().iter() {
                extra_headers.insert(k.clone(), v.clone());
            }
        }
        // The attribution token (Identify posture) is an app header: it must
        // survive emulation, so it goes in extra_headers, not the fingerprint set.
        if let adaptive::identity::Mode::Identify(token) = &mode {
            if let Ok(val) = transport::HeaderValue::from_str(token) {
                extra_headers.insert(transport::HeaderName::from_static("x-bug-bounty"), val);
            }
        }
        // Challenge clearance (from the solver): the cf_clearance cookie must ride
        // on every request, and the UA must match the solver's browser or the
        // cookie is rejected - so adopt the solver's UA for the fingerprint too.
        let mut ua = ident.user_agent.clone();
        if let Some(sol) = clearance {
            if let Ok(val) = transport::HeaderValue::from_str(&sol.cookie_header) {
                extra_headers.insert(transport::header::COOKIE, val);
            }
            if let Some(sua) = &sol.user_agent {
                ua = sua.clone();
            }
        }
        transport::build_client(
            transport::ClientConfig {
                timeout: Some(Duration::from_millis(
                    params.timeout_ms.clamp(1000, 120_000),
                )),
                redirect: if params.follow_redirects {
                    transport::Redirect::Limited(5)
                } else {
                    transport::Redirect::None
                },
                accept_invalid_certs: true,
                cookie_store: true,
                user_agent: Some(ua),
                browser_headers,
                extra_headers,
                emulate: should_emulate(params.user_agent.as_deref(), &mode),
                resolve: Vec::new(),
                block_internal: params.block_internal,
                // A template request goes to the target. Off its origin a 307 or
                // 308 would carry the payload to a host nobody listed, and the
                // matchers would read that host's answer as the target's.
                same_origin_redirects: true,
            },
            &params.egress,
        )
    };

    let _ = tx.send(json!({"type":"ack","target": base}));

    // Which inventory chose the templates and gave the leads, said with both.
    let from = params
        .products_from
        .as_deref()
        .unwrap_or("the products the scan was given");
    let mut leads = crate::leads::Leads::new(&params.leads, from);
    if let Some(given) = leads.given() {
        let _ = tx.send(given);
    }

    // Fetch the base once and handle any WAF / anti-bot interference before
    // committing to the full scan: a challenge on the base means every
    // {{BaseURL}} template would just re-hit the WAF. Back off + rotate identity
    // per the challenge policy; if it persists, report it and skip the active
    // phase. (Broker escalation lands with the challenge-broker track; until then
    // an unclearable challenge ends the scan early.)
    let mut attempt: u32 = 0;
    let mut rotations: u32 = 0;
    let mut blocked = false;
    let mut block_label: &'static str = "blocked";
    // Set once the challenge solver returns a clearance cookie; every subsequent
    // client build then rides that cookie + the solver's UA.
    let mut clearance: Option<crate::solver::Solved> = None;
    let (client, base_resp) = loop {
        let seed = if rotations == 0 {
            params.target.clone()
        } else {
            format!("{}#{}", params.target, rotations)
        };
        let mut ident = adaptive::identity::resolve(&mode, Some(seed.as_str()));
        announce_as(&mut ident, params.user_agent.as_deref());
        let client = match build_client(&ident, clearance.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                let _ =
                    tx.send(json!({"type":"error","message":format!("client build failed: {e}")}));
                return;
            }
        };

        let base_resp = fetch_base(&client, &base).await;

        if let Some(ref br) = base_resp {
            let ch = adaptive::challenge::detect(
                br.status,
                |n| {
                    br.headers
                        .iter()
                        .find(|(k, _)| k == n)
                        .map(|(_, v)| v.clone())
                },
                &br.body_prefix,
            );
            if ch.is_challenge() {
                match adaptive::challenge::react(ch, attempt) {
                    adaptive::challenge::Reaction::Backoff {
                        delay_ms,
                        rotate_identity,
                    } => {
                        let _ = tx.send(json!({
                            "type":"log",
                            "message":format!(
                                "waf {} on base (HTTP {}), backing off {}ms{}",
                                ch.label(), br.status, delay_ms,
                                if rotate_identity { " + rotating identity" } else { "" }
                            )
                        }));
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                        attempt += 1;
                        if rotate_identity {
                            rotations += 1;
                        }
                        continue;
                    }
                    adaptive::challenge::Reaction::Broker => {
                        // Hand off to a node-side challenge solver (FlareSolverr-
                        // compatible), which mints a clearance cookie from the
                        // node's own egress. On success, retry the base carrying
                        // that cookie; if there is no solver, or it can't clear, or
                        // the challenge persists even with clearance, report + stop.
                        if let Some(note) = crate::solver::not_used(&params.egress)
                            .filter(|_| clearance.is_none() && crate::solver::configured())
                        {
                            let _ = tx.send(json!({
                                "type":"log",
                                "message":format!("waf {} on base; {note}; ending scan", ch.label())
                            }));
                        } else if clearance.is_none() && crate::solver::configured() {
                            let _ = tx.send(json!({
                                "type":"log",
                                "message":format!("waf {} on base; handing off to challenge solver", ch.label())
                            }));
                            match crate::solver::solve(
                                &base,
                                params.timeout_ms.clamp(1000, 120_000),
                                &params.egress,
                            )
                            .await
                            {
                                Some(sol) => {
                                    let _ = tx.send(json!({
                                        "type":"log",
                                        "message":"challenge solver returned clearance; retrying with cf_clearance"
                                    }));
                                    clearance = Some(sol);
                                    attempt += 1;
                                    continue;
                                }
                                None => {
                                    let _ = tx.send(json!({
                                        "type":"log",
                                        "message":"challenge solver could not clear the target; ending scan"
                                    }));
                                }
                            }
                        } else if clearance.is_some() {
                            let _ = tx.send(json!({
                                "type":"log",
                                "message":format!("waf {} persists even after solver clearance; ending scan", ch.label())
                            }));
                        } else {
                            let _ = tx.send(json!({
                                "type":"log",
                                "message":format!("waf {} on base persists; no challenge solver configured (set CROSSFYRE_CHALLENGE_SOLVER), ending scan", ch.label())
                            }));
                        }
                        blocked = true;
                        block_label = ch.label();
                        break (client, base_resp);
                    }
                    adaptive::challenge::Reaction::Abort => {
                        blocked = true;
                        block_label = ch.label();
                        break (client, base_resp);
                    }
                    adaptive::challenge::Reaction::Proceed => {}
                }
            }
        }
        break (client, base_resp);
    };

    // A persistent WAF challenge on the base is itself reportable and a reason to
    // skip the active phase.
    if blocked {
        let _ = tx.send(
            Finding::new(
                "plessor",
                "waf",
                format!("Target behind WAF/anti-bot ({block_label})"),
                "info",
                &base,
            )
            .kind("waf")
            .template("plessor:waf-challenge")
            .describe("The base URL returned a WAF/anti-bot challenge that could not be cleared, so active vulnerability templates were skipped. Consider origin discovery, an attribution/allowlist header, or a challenge-solving session.")
            .event(),
        );
    }

    let sev_filter: Vec<String> = params.severity.iter().map(|s| s.to_lowercase()).collect();
    let allow = |sev: &str| sev_filter.is_empty() || sev_filter.iter().any(|s| s == sev);

    // Template-id allowlist, applied on top of the severity filter. Both must
    // admit a template for it to run.
    let only: Vec<String> = params.only.iter().map(|s| s.to_lowercase()).collect();
    let allow_id = |id: &str| only.is_empty() || only.iter().any(|s| s == &id.to_lowercase());

    let mut found: i64 = 0;
    // Each finding is kept with its proof, which names the slots the scan's credential
    // fills and never what is in them.
    let proof_ctx = crate::proof::Ctx::new(params.auth.as_ref());

    // --- Passive header checks on the base response (deterministic) ---
    // fetch_base returns None only on a transport-level failure (connection
    // refused, timed out, TLS error): the target did not answer a simple GET.
    // Every {{BaseURL}} template dials the same host:port, so if the base is
    // unreachable the whole active phase would just re-dial a dead or tarpitting
    // target 100+ times, each attempt burning a full per-request timeout. Skip it.
    let base_reachable = if blocked {
        false
    } else if let Some(resp) = base_resp {
        for (name, template, severity, description) in header_checks(&resp) {
            if allow(severity) && allow_id(template) {
                found += 1;
                let mut event = Finding::new("plessor", "misconfig", name, severity, &base)
                    .template(template)
                    // These are read off the base response's headers, so the
                    // location is not a guess.
                    .location("header")
                    .describe(description)
                    .event();
                event["data"]["proof"] =
                    json!(header_proof(&proof_ctx, &base, template, name, &resp));
                let _ = tx.send(event);
            }
        }
        true
    } else {
        false
    };

    // --- Template mode (confirm-then-report) ---
    if !params.passive_only && base_reachable {
        let ext_dir = params
            .templates_dir
            .clone()
            .or_else(|| std::env::var("PLESSOR_TEMPLATES_DIR").ok());
        let external = ext_dir
            .as_deref()
            .map(template::load_dir)
            .unwrap_or_default();
        // Which pack it is, as the proofs of its templates name it.
        let pack_named = pack.named.as_str();
        // A directory template with a pack template's id replaces it, so a copy
        // of the pack pointed at with --templates runs each check once.
        let pack: Vec<&template::Template> = if params.pack {
            pack.templates
                .iter()
                .filter(|p| !external.iter().any(|e| e.id == p.id))
                .collect()
        } else {
            Vec::new()
        };
        // A template about one product runs where toolmark saw that product, and the
        // ones held back are said, never dropped in silence.
        let choice = template::Choice::new(params.products.as_deref(), params.all_templates);
        let (pack, held_pack): (Vec<&template::Template>, Vec<&template::Template>) =
            pack.into_iter().partition(|t| choice.runs(t));
        let (external, held_external): (Vec<template::Template>, Vec<template::Template>) =
            external.into_iter().partition(|t| choice.runs(t));
        let not_seen = format!("{from} names none of its products");
        for t in held_pack.iter().copied().chain(held_external.iter()) {
            leads.record(t, crate::leads::Outcome::NotRun(not_seen.clone()));
        }
        let held: Vec<&str> = held_pack
            .iter()
            .copied()
            .chain(held_external.iter())
            .map(|t| t.id.as_str())
            .filter(|id| allow_id(id))
            .collect();
        if !held.is_empty() {
            let _ = tx.send(json!({
                "type": "templates_held_back",
                "count": held.len(),
                "templates": held,
                "from": from,
                "reason": not_seen,
                "message": format!(
                    "{} product templates held back: {from} names none of their products. \
                     --all-templates runs them",
                    held.len()
                ),
            }));
        }
        // Count only what will actually run, or a filtered scan reports progress
        // against a denominator it can never reach and the UI sticks at 20%.
        let total = template::BUILTIN
            .iter()
            .chain(pack.iter().copied())
            .chain(external.iter())
            .filter(|t| allow_id(&t.id))
            .count();
        let mut done = 0usize;

        // The plan: every template, with where it starts. A scan taken up again leaves
        // out what it had run, unless the templates it started with are gone.
        use crate::ledger::{Planned, State};
        let planned: Vec<Planned> = template::BUILTIN
            .iter()
            .chain(pack.iter().copied())
            .chain(external.iter())
            .map(|t| {
                let sev = if t.info.severity.is_empty() {
                    "info".to_string()
                } else {
                    t.info.severity.to_lowercase()
                };
                let (state, reason) = if !allow_id(&t.id) {
                    (State::Skipped, Some("not one of the templates asked for"))
                } else if !params.test_writes && template_changes_target(t) {
                    (State::HeldBack, Some("what it sends changes the target"))
                } else if !allow(&sev) {
                    (State::Skipped, Some("below the severities asked for"))
                } else {
                    (State::Queued, None)
                };
                Planned {
                    id: t.id.clone(),
                    state,
                    reason,
                }
            })
            .collect();
        // The templates as they are written: one edited under the same id makes another
        // pack, and the order a folder happens to be read in does not.
        let pack_digest = {
            use sha2::Digest;
            let mut templates: Vec<(&str, &str)> = template::BUILTIN
                .iter()
                .chain(pack.iter().copied())
                .chain(external.iter())
                .map(|t| (t.id.as_str(), t.source.as_str()))
                .collect();
            templates.sort_unstable();
            let mut digest = sha2::Sha256::new();
            digest.update(env!("CARGO_PKG_VERSION"));
            for part in templates.into_iter().flat_map(|(id, source)| [id, source]) {
                digest.update((part.len() as u64).to_le_bytes());
                digest.update(part);
            }
            format!("{:x}", digest.finalize())
        };
        let planning = ledger.plan(&pack_digest, &planned).await;
        if planning.replanned {
            let _ = tx.send(json!({"type":"log","message":
                "the templates this scan started with are gone, so it was planned again and \
                 starts over"}));
        }
        for data in &planning.found {
            found += 1;
            let _ = tx.send(json!({"type":"finding","data": data}));
        }

        // OAST client for out-of-band (interactsh) templates; None disables OOB.
        // Per-scan endpoint (node-resolved) wins over the node env fallback.
        let oast = params
            .oast
            .as_ref()
            .and_then(|s| crate::oast::OastClient::from_spec(s.domains.clone(), &s.api_url))
            .or_else(crate::oast::OastClient::from_env);
        // The out-of-band API gets a client of its own, so the session the scan carries
        // for the target does not go there.
        let oast_http = oast.as_ref().and_then(|_| {
            crate::probe::oast_client_or_say(
                crate::probe::oast_client(
                    params.evasive,
                    params.identify.clone(),
                    &params.target,
                    params.timeout_ms,
                    params.block_internal,
                    &params.egress,
                    false,
                ),
                &tx,
            )
        });
        // One correlation for the scan's out-of-band templates, polled once at
        // the end rather than six seconds per template.
        let mut oob_reg = None;
        if let (Some(oc), Some(http)) = (oast.as_ref(), oast_http.as_ref()) {
            for attempt in 0..3 {
                if let Some(r) = oc.register(http).await {
                    oob_reg = Some(r);
                    break;
                }
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_millis(500 << attempt)).await;
                }
            }
            if oob_reg.is_none() {
                let _ = tx.send(json!({
                    "type": "log",
                    "message": "out-of-band callbacks are UNAVAILABLE (registration failed); \
                                out-of-band templates cannot be confirmed in this run."
                }));
            }
        }
        let oob_queue: crate::inject::OobQueue = Default::default();
        // `unsafe` templates go out over raw sockets, the same way as everything else.
        let raw = crate::rawhttp::Route {
            egress: params.egress.clone(),
            block_internal: params.block_internal,
        };
        // Templates held back because their method changes the target. Named
        // rather than dropped, so a shorter run is not mistaken for a clean one.
        let mut write_templates: Vec<String> = Vec::new();

        for tmpl in template::BUILTIN
            .iter()
            .chain(pack.iter().copied())
            .chain(external.iter())
        {
            // Skipped before the progress counter, because `total` above counts
            // only id-allowed templates. The severity filter stays inside the
            // loop, where it has always been counted as work done.
            if !allow_id(&tmpl.id) {
                leads.record(
                    tmpl,
                    crate::leads::Outcome::NotRun("not among the templates asked for".into()),
                );
                continue;
            }
            // Run before this scan was stopped, and taken up again.
            if planning.done.contains(&tmpl.id) {
                let found_then = planning
                    .found
                    .iter()
                    .any(|f| f["template"].as_str() == Some(tmpl.id.as_str()));
                leads.record(
                    tmpl,
                    if found_then {
                        crate::leads::Outcome::Found
                    } else {
                        crate::leads::Outcome::Ran
                    },
                );
                done += 1;
                let _ = tx.send(json!({"type":"progress","processed": done, "total": total}));
                continue;
            }
            // A template that overwrites or destroys is not a test of whether it
            // could. POST stays, for the reason the injection engine states.
            if !params.test_writes && template_changes_target(tmpl) {
                write_templates.push(tmpl.id.clone());
                leads.record(
                    tmpl,
                    crate::leads::Outcome::NotRun("what it sends changes the target".into()),
                );
                continue;
            }
            let sev = if tmpl.info.severity.is_empty() {
                "info".to_string()
            } else {
                tmpl.info.severity.to_lowercase()
            };
            if allow(&sev) {
                let pending_before = oob_queue.lock().map(|q| q.len()).unwrap_or_default();
                let mut confirmed = false;
                // Where the template came from, as its proofs name it.
                let origin = if template::BUILTIN.iter().any(|b| std::ptr::eq(b, tmpl)) {
                    "built in"
                } else if pack.iter().any(|p| std::ptr::eq(*p, tmpl)) {
                    pack_named
                } else {
                    "a templates folder"
                };
                for m in template::eval_template(
                    &client,
                    &base,
                    tmpl,
                    oast.as_ref(),
                    oob_reg.as_ref(),
                    Some(&oob_queue),
                    params.evasive,
                    &raw,
                    &proof_ctx,
                    origin,
                )
                .await
                {
                    found += 1;
                    confirmed = true;
                    let mut event =
                        Finding::new("plessor", &m.class, m.name, m.severity, m.matched_at)
                            .template(m.template_id)
                            .describe(m.description)
                            .event();
                    event["data"]["proof"] = json!(m.proof);
                    let _ = tx.send(event);
                }
                let pending = oob_queue.lock().map(|q| q.len()).unwrap_or_default();
                let state = if confirmed {
                    State::Confirmed
                } else if pending > pending_before {
                    State::Matched
                } else {
                    State::Sent
                };
                ledger.state(&tmpl.id, state).await;
                // One waiting on a callback ran; the callbacks say at the end if it found.
                leads.record(
                    tmpl,
                    if confirmed {
                        crate::leads::Outcome::Found
                    } else if tmpl.needs_oob() && oob_reg.is_none() {
                        crate::leads::Outcome::NotRun(
                            "out-of-band callbacks were unavailable".into(),
                        )
                    } else {
                        crate::leads::Outcome::Ran
                    },
                );
            } else {
                leads.record(
                    tmpl,
                    crate::leads::Outcome::NotRun("below the severities asked for".into()),
                );
            }
            done += 1;
            let _ = tx.send(json!({"type":"progress","processed": done, "total": total}));
        }
        if !write_templates.is_empty() {
            write_templates.sort();
            write_templates.dedup();
            let _ = tx.send(json!({
                "type": "templates_held_back",
                "count": write_templates.len(),
                "reason": "what it sends changes the target",
                "message": format!(
                    "{} template(s) were NOT run: {}. Each one uses a method that overwrites or \
                     destroys the resource, so sending it IS the change rather than a test of \
                     whether it is possible. Whatever they check is untested here, not clean. \
                     Re-run with writes enabled against a target you are willing to change.",
                    write_templates.len(),
                    write_templates.join(", ")
                ),
                "templates": write_templates,
            }));
        }

        // Out-of-band template callbacks, collected once for the whole scan.
        if let (Some(oc), Some(reg), Some(http)) =
            (oast.as_ref(), oob_reg.as_ref(), oast_http.as_ref())
        {
            let pending: Vec<crate::inject::PendingOob> = oob_queue
                .lock()
                .map(|mut v| std::mem::take(&mut *v))
                .unwrap_or_default();
            if !pending.is_empty() {
                let mut hosts: Vec<String> = Vec::new();
                for wait in [0u64, 2000, 4000] {
                    if wait > 0 {
                        tokio::time::sleep(Duration::from_millis(wait)).await;
                    }
                    hosts = oc.poll_hosts(http, reg).await;
                    if !hosts.is_empty() {
                        break;
                    }
                }
                // Each template waited on: confirmed when one of its callbacks came, and
                // only sent when none did.
                let mut waited: std::collections::BTreeMap<String, bool> = Default::default();
                for p in pending {
                    let called_back = hosts.iter().any(|h| h.contains(&p.marker));
                    if let Some(id) = p.finding["template"].as_str() {
                        *waited.entry(id.to_string()).or_default() |= called_back;
                    }
                    if called_back {
                        found += 1;
                        let _ = tx.send(json!({"type":"finding","data": p.finding}));
                    }
                }
                for (id, called_back) in waited {
                    let state = if called_back {
                        State::Confirmed
                    } else {
                        State::Sent
                    };
                    ledger.state(&id, state).await;
                    if called_back {
                        leads.update(&id, crate::leads::Outcome::Found);
                    }
                }
            }
            oc.deregister(http, reg).await;
        }
    }

    let unrun = if params.passive_only {
        Some("the scan ran passive checks only")
    } else if blocked {
        Some("a WAF challenge on the target stopped the templates")
    } else if !base_reachable {
        Some("the target did not answer")
    } else {
        None
    };
    if let Some(answers) = leads.answers(unrun) {
        let _ = tx.send(answers);
    }
    let _ = tx.send(json!({"type":"done","found": found}));
}

/// The proof of the header check `check`, `name`, on the base response `resp` of `base`:
/// a GET of the base, and the header it lacked.
fn header_proof(
    ctx: &crate::proof::Ctx,
    base: &str,
    check: &str,
    name: &str,
    resp: &BaseResp,
) -> crate::proof::Proof {
    crate::proof::Proof::new(
        ctx,
        "built in",
        crate::proof::Kind::Header,
        check,
        vec![crate::proof::Sent {
            method: "GET".into(),
            url: base.to_string(),
            fields: Vec::new(),
            body: None,
            raw: false,
        }],
        Vec::new(),
        "and",
        vec![crate::proof::Fired {
            matcher: "header".into(),
            part: "header".into(),
            evidence: name.to_string(),
        }],
        resp.status,
        &resp.body_prefix,
    )
}

/// Does running this template change the target rather than test it?
///
/// Any request in it whose method overwrites or destroys. POST is not counted,
/// for the reason the injection engine states: it is the main surface and what
/// it creates is usually recoverable. The one template this holds back in our
/// own pack is `mass-assignment-privilege-escalation`, which PATCHes
/// `{"role":"admin","balance_cents":-99999}` at an account endpoint and then
/// looks for the echo, and whose own description calls that oracle weak.
fn template_changes_target(tmpl: &template::Template) -> bool {
    tmpl.http
        .iter()
        .any(|r| crate::inject::destroys_a_resource(&r.method))
}

/// Passive security-header checks. Returns (name, template-id, severity, description).
fn header_checks(resp: &BaseResp) -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    let has = |n: &str| resp.headers.iter().any(|(k, _)| k == n);
    let mut out = Vec::new();
    if !has("x-frame-options") && !has("content-security-policy") {
        out.push((
            "Missing X-Frame-Options / frame-ancestors",
            "missing-x-frame-options",
            "info",
            "No X-Frame-Options or CSP frame-ancestors: the page may be framed for clickjacking.",
        ));
    }
    if !has("content-security-policy") {
        out.push((
            "Missing Content-Security-Policy header",
            "missing-csp",
            "low",
            "No Content-Security-Policy: reduced defense-in-depth against XSS and injection.",
        ));
    }
    if !has("x-content-type-options") {
        out.push((
            "Missing X-Content-Type-Options header",
            "missing-x-content-type-options",
            "info",
            "No X-Content-Type-Options: nosniff, so browsers may MIME-sniff responses.",
        ));
    }
    if resp.is_https && !has("strict-transport-security") {
        out.push((
            "Missing Strict-Transport-Security header",
            "missing-hsts",
            "low",
            "HTTPS site without HSTS: connections can be downgraded to plaintext.",
        ));
    }
    out
}

/// Cap on how much of a decoded response body we buffer. reqwest's gzip feature
/// auto-decompresses, so an unbounded read lets a scanned target serve a small
/// gzip "bomb" that inflates to gigabytes and OOMs the engine (a scanned target
/// is attacker-controlled). Reading in chunks with a ceiling keeps a hostile
/// response from exhausting memory; 8 MiB is far more than any real finding needs.
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Read a response body but stop after `MAX_BODY_BYTES` of decoded output.
pub async fn read_body_capped(mut resp: transport::Response) -> String {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < MAX_BODY_BYTES {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = MAX_BODY_BYTES - buf.len();
                let take = chunk.len().min(room);
                buf.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break;
                }
            }
            _ => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

pub(crate) async fn fetch_base(client: &Client, base: &str) -> Option<BaseResp> {
    match client.get(base).send().await {
        Ok(r) => {
            let status = r.status().as_u16();
            let is_https = base.starts_with("https://");
            let mut headers = Vec::new();
            for (k, v) in r.headers().iter() {
                headers.push((
                    k.as_str().to_lowercase(),
                    v.to_str().unwrap_or("").to_string(),
                ));
            }
            // A few KB of body is plenty to spot a challenge/block page.
            let body = read_body_capped(r).await;
            let body_prefix: String = body.chars().take(16_384).collect();
            Some(BaseResp {
                is_https,
                status,
                headers,
                body_prefix,
            })
        }
        Err(_) => None,
    }
}

fn normalize_base(t: &str) -> Option<String> {
    transport::url::normalize_target(t).map(|tgt| tgt.base())
}

#[cfg(test)]
mod tests {

    /// The node's scans do not name `pack`, and must keep running exactly the
    /// templates they ran before the pack was compiled in.
    #[test]
    fn a_scan_that_does_not_ask_for_the_pack_does_not_get_it() {
        let quiet: super::ScanParams =
            serde_json::from_value(serde_json::json!({ "target": "http://h" })).unwrap();
        assert!(!quiet.pack);
        let asked: super::ScanParams =
            serde_json::from_value(serde_json::json!({ "target": "http://h", "pack": true }))
                .unwrap();
        assert!(asked.pack);
    }

    /// The one template in our own pack that changes the target instead of
    /// testing it, and the shapes that must keep running.
    #[test]
    fn a_template_that_rewrites_an_account_is_held_back() {
        let parse = |y: &str| serde_yaml::from_str::<crate::template::Template>(y).expect("yaml");

        let privesc = parse(
            r#"
id: mass-assignment-privilege-escalation
http:
  - method: PATCH
    path: ["{{BaseURL}}/api/v1/account"]
    body: "{\"role\":\"admin\",\"balance_cents\":-99999}"
"#,
        );
        assert!(
            template_changes_target(&privesc),
            "a PATCH of role:admin is the change, not a test of it"
        );

        // Exploit confirmations of the ordinary kind. A login attempt with bad
        // credentials, a command-injection marker, an XXE entity: all POST, all
        // still run, because refusing them would leave the scanner unable to
        // confirm anything.
        for yaml in [
            r#"
id: sqli-error-based-login
http:
  - method: POST
    path: ["{{BaseURL}}/api/v1/auth/login"]
    body: "{\"email\":\"'\",\"password\":\"x\"}"
"#,
            r#"
id: os-command-injection
http:
  - method: POST
    path: ["{{BaseURL}}/api/v1/tools/ping"]
    body: "{\"host\":\"127.0.0.1;id\"}"
"#,
            r#"
id: git-config-exposed
http:
  - method: GET
    path: ["{{BaseURL}}/.git/config"]
"#,
        ] {
            let t = parse(yaml);
            assert!(!template_changes_target(&t), "{} must still run", t.id);
        }

        // And a DELETE anywhere in a multi-request template counts, not just
        // the first one.
        let mixed = parse(
            r#"
id: probe-then-delete
http:
  - method: GET
    path: ["{{BaseURL}}/a"]
  - method: DELETE
    path: ["{{BaseURL}}/a/1"]
"#,
        );
        assert!(template_changes_target(&mixed));
    }
    use super::*;
    use adaptive::identity::Mode;

    #[test]
    fn announced_ua_replaces_the_browser_identity() {
        let mut id = adaptive::identity::resolve(&Mode::Fast, None);
        // Baseline: EVERY posture resolves to a real browser, which is exactly
        // why an explicit announce is needed and `evasive: false` is not enough.
        assert!(
            id.user_agent.contains("Mozilla"),
            "expected a browser UA by default, got {}",
            id.user_agent
        );

        announce_as(
            &mut id,
            Some("Crossfyre-FreeTools/1.0 (+https://crossfyre.io/scanning)"),
        );
        assert_eq!(
            id.user_agent,
            "Crossfyre-FreeTools/1.0 (+https://crossfyre.io/scanning)"
        );
        // The browser-hint headers must go with it. A scanner claiming
        // sec-ch-ua is not honest, just differently dressed.
        for (k, _) in &id.headers {
            let lk = k.to_ascii_lowercase();
            assert!(
                !lk.starts_with("sec-ch-ua"),
                "left a browser hint header: {k}"
            );
            assert!(
                !lk.starts_with("sec-fetch"),
                "left a browser hint header: {k}"
            );
            assert_ne!(lk, "upgrade-insecure-requests");
        }
    }

    #[test]
    fn announce_is_a_noop_when_unset() {
        let before = adaptive::identity::resolve(&Mode::Evasive, None);
        for ua in [None, Some(""), Some("   ")] {
            let mut id = adaptive::identity::resolve(&Mode::Evasive, None);
            announce_as(&mut id, ua);
            assert_eq!(id.user_agent, before.user_agent);
            assert_eq!(id.headers.len(), before.headers.len());
        }
    }

    #[test]
    fn announcing_forces_emulation_off() {
        // An announced UA wins over every posture. Without this, a config that
        // set `identify` would resolve to Mode::Identify and silently turn a
        // browser TLS fingerprint back on underneath our own name.
        for mode in [Mode::Evasive, Mode::Fast, Mode::Identify("t".into())] {
            assert!(
                !should_emulate(Some("Crossfyre-FreeTools/1.0"), &mode),
                "announced UA must never emulate ({mode:?})"
            );
        }
        // Unannounced behaviour is unchanged: Fast never emulates, others do.
        assert!(!should_emulate(None, &Mode::Fast));
        assert!(should_emulate(None, &Mode::Evasive));
        assert!(should_emulate(Some("  "), &Mode::Identify("t".into())));
    }

    #[test]
    fn template_allowlist_matches_exactly_not_by_substring() {
        // `only` names templates. A substring match would let "git" pull in
        // every git-adjacent template and quietly widen a tool's blast radius,
        // which is the failure this allowlist exists to prevent.
        let only: Vec<String> = vec!["git-config-exposure".into()];
        let allow_id = |id: &str| only.is_empty() || only.iter().any(|s| s == &id.to_lowercase());
        assert!(allow_id("git-config-exposure"));
        assert!(allow_id("GIT-CONFIG-EXPOSURE"));
        assert!(!allow_id("git-head-exposure"));
        assert!(!allow_id("path-traversal-lfi"));

        // Empty means unrestricted, which is what every existing workflow sends.
        let none: Vec<String> = vec![];
        let allow_all = |id: &str| none.is_empty() || none.iter().any(|s| s == &id.to_lowercase());
        assert!(allow_all("anything"));
    }
}

#[cfg(test)]
mod ledger_tests {
    //! A template scan's plan and the state of each template go to its ledger, and a scan
    //! taken up again leaves out the templates it had run and reports what they found.
    use super::*;
    use crate::ledger::{Ledger, Planned, Planning, State};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Two of the built-in templates, which a target answering 404 gives nothing.
    const ASKED: [&str; 2] = ["git-config-exposure", "dotenv-exposure"];

    #[derive(Default)]
    struct Kept {
        /// The pack the scan was planned under.
        pack: Mutex<String>,
        planned: Mutex<Vec<(String, State, Option<&'static str>)>>,
        states: Mutex<Vec<(String, State)>>,
        /// What `plan` answers for a scan taken up again: the templates it had run, and
        /// what they found.
        done: Vec<String>,
        found: Vec<Value>,
    }

    impl Ledger for Kept {
        async fn plan(&self, pack: &str, templates: &[Planned]) -> Planning {
            *self.pack.lock().unwrap() = pack.to_string();
            *self.planned.lock().unwrap() = templates
                .iter()
                .map(|t| (t.id.clone(), t.state, t.reason))
                .collect();
            Planning {
                done: self.done.iter().cloned().collect(),
                found: self.found.clone(),
                replanned: false,
            }
        }
        async fn state(&self, id: &str, state: State) {
            self.states.lock().unwrap().push((id.to_string(), state));
        }
    }

    /// A target that answers 404 to everything and counts what it is sent.
    async fn target() -> (u16, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let counted = counted.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 {
                            return;
                        }
                        counted.fetch_add(1, Ordering::SeqCst);
                        let _ = s
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                            .await;
                    }
                });
            }
        });
        (port, hits)
    }

    /// A scan of the target on `port` for the templates [`ASKED`], and what it said.
    async fn scan(port: u16, ledger: Arc<Kept>) -> Vec<Value> {
        scan_with(port, json!({ "only": ASKED }), ledger).await
    }

    /// A scan of the target on `port` with `asked` among its settings, and what it said.
    async fn scan_with(port: u16, asked: Value, ledger: Arc<Kept>) -> Vec<Value> {
        let mut params = json!({
            "target": format!("http://127.0.0.1:{port}/"),
            "evasive": false,
            "timeout_ms": 2000,
        });
        if let (Some(params), Value::Object(asked)) = (params.as_object_mut(), asked) {
            params.extend(asked);
        }
        let params: ScanParams = serde_json::from_value(params).unwrap();
        let (tx, mut rx) = mpsc::unbounded_channel();
        run(
            params,
            tx,
            ledger,
            std::sync::Arc::new(template::Pack::compiled()),
        )
        .await;
        let mut said = Vec::new();
        while let Ok(event) = rx.try_recv() {
            said.push(event);
        }
        said
    }

    #[tokio::test]
    async fn the_plan_and_each_templates_state_are_kept_and_what_ran_is_left_out() {
        let (port, hits) = target().await;
        let first = Arc::new(Kept::default());
        scan(port, first.clone()).await;
        let planned = first.planned.lock().unwrap().clone();
        assert_eq!(planned.len(), template::BUILTIN.len());
        let queued: Vec<&str> = planned
            .iter()
            .filter(|(_, state, _)| *state == State::Queued)
            .map(|(id, _, _)| id.as_str())
            .collect();
        assert_eq!(queued, ASKED);
        for (id, state, reason) in &planned {
            if !ASKED.contains(&id.as_str()) {
                assert_eq!(
                    (*state, *reason),
                    (State::Skipped, Some("not one of the templates asked for")),
                    "{id}"
                );
            }
        }
        assert_eq!(
            *first.states.lock().unwrap(),
            ASKED.map(|id| (id.to_string(), State::Sent)),
            "each template's state is kept as it runs"
        );
        let all_of_it = hits.swap(0, Ordering::SeqCst);

        // Taken up again with the first template run, and what it had found.
        let earlier = json!({"name": "found before the scan stopped", "template": ASKED[0]});
        let again = Arc::new(Kept {
            done: vec![ASKED[0].to_string()],
            found: vec![earlier.clone()],
            ..Kept::default()
        });
        let said = scan(port, again.clone()).await;
        assert_eq!(
            *again.states.lock().unwrap(),
            [(ASKED[1].to_string(), State::Sent)],
            "only the template not yet run runs"
        );
        let resumed = hits.load(Ordering::SeqCst);
        assert!(
            resumed < all_of_it,
            "the template already run was sent again: {resumed} of {all_of_it}"
        );
        assert!(
            said.contains(&json!({"type": "finding", "data": earlier})),
            "what it had found is reported again: {said:?}"
        );
        assert_eq!(said.last(), Some(&json!({"type": "done", "found": 1})));
    }

    /// A template that looks for `WORD` at /p/t1.
    const T1: &str = r#"id: t1
info:
  name: lab t1
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/p/t1"
    matchers:
      - type: word
        words:
          - "WORD"
"#;

    #[tokio::test]
    async fn a_template_edited_under_the_same_id_makes_another_pack() {
        let (port, _) = target().await;
        let dir = std::env::temp_dir().join(format!("plessor-pack-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let asked = json!({ "templates_dir": dir.to_string_lossy(), "only": ["t1"] });
        std::fs::write(dir.join("t1.yaml"), T1.replace("WORD", "WRONG-t1")).unwrap();
        let first = Arc::new(Kept::default());
        scan_with(port, asked.clone(), first.clone()).await;
        let again = Arc::new(Kept::default());
        scan_with(port, asked.clone(), again.clone()).await;
        let pack = |kept: &Kept| kept.pack.lock().unwrap().clone();
        assert_eq!(pack(&again), pack(&first), "nothing changed");
        std::fs::write(dir.join("t1.yaml"), T1.replace("WORD", "FOUND-t1")).unwrap();
        let edited = Arc::new(Kept::default());
        scan_with(port, asked, edited.clone()).await;
        let _ = std::fs::remove_dir_all(&dir);
        assert_ne!(pack(&edited), pack(&first), "its matcher was edited");
    }
}
