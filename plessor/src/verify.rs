//! `verify`: one finding checked again by its proof, with nothing else of the scan run.
//!
//! The proof's requests are sent again through the client a scan of their origin would
//! use, with the credential the caller gives for the slots the proof names, and the
//! answer is judged by the proof's own matchers. The answer is one of four: reproduced,
//! changed (the matchers held, on other evidence), not reproduced, or unreachable. There
//! is no status here: what a finding becomes is Cloud's to say.

use crate::proof::{Fired, Kind, OAST_SLOT, Proof};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A `verify` request: the finding kept here, or a proof handed in, and how to send it.
#[derive(Debug, Deserialize)]
pub struct VerifyParams {
    #[serde(default)]
    pub finding: Option<i64>,
    #[serde(default)]
    pub proof: Option<Proof>,
    /// The credential for the slots the proof names, in the shape a scan takes it.
    #[serde(default)]
    pub auth: Option<transport::AuthSpec>,
    /// The out-of-band endpoint, for a proof confirmed by a callback.
    #[serde(default)]
    pub oast: Option<crate::engine::OastSpec>,
    /// Send what changes the target, as a scan with writes enabled does.
    #[serde(default)]
    pub test_writes: bool,
    #[serde(default = "yes")]
    pub evasive: bool,
    #[serde(default)]
    pub identify: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default = "ten_seconds")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub block_internal: bool,
    /// Follow same-origin redirects, as a scan does. A caller that checks each
    /// destination itself sets it false.
    #[serde(default = "yes")]
    pub follow_redirects: bool,
    /// Names pinned to addresses, `[["app.example.com", "203.0.113.7:443"], ...]`, as a
    /// scan takes them: the proof's origin is dialled at the address its caller checked.
    #[serde(default)]
    pub resolve: Vec<(String, std::net::SocketAddr)>,
    /// Set by the daemon from the egress wrapper, never from the request.
    #[serde(skip)]
    pub egress: transport::Egress,
}

fn yes() -> bool {
    true
}

fn ten_seconds() -> u64 {
    10_000
}

/// What a replay came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Verdict {
    #[serde(rename = "reproduced")]
    Reproduced,
    /// The matchers held, on evidence that is not the proof's.
    #[serde(rename = "changed")]
    Changed,
    #[serde(rename = "not reproduced")]
    NotReproduced,
    #[serde(rename = "unreachable")]
    Unreachable,
}

/// Why `proof` cannot be replayed with `params`, or None when it can: a proof of another
/// format, a slot nothing given fills, a value the proof did not keep, an out-of-band
/// check with no endpoint, a request off the proof's origin, or one that changes the
/// target without `test_writes`.
pub fn refusal(proof: &Proof, params: &VerifyParams) -> Option<String> {
    if proof.format != crate::proof::FORMAT {
        return Some(format!(
            "it is a proof of format {}, which this plessor does not replay",
            proof.format
        ));
    }
    let auth = params.auth.as_ref();
    let header =
        |name: &str| auth.is_some_and(|a| a.headers.keys().any(|k| k.eq_ignore_ascii_case(name)));
    for slot in &proof.slots {
        let filled = match slot.as_str() {
            "auth.cookie" => auth.is_some_and(|a| !a.cookies.trim().is_empty()),
            "url" | "body" => {
                return Some(format!(
                    "a value in its {slot} was not kept, so it cannot be sent as it was"
                ));
            }
            other => match other
                .strip_prefix("auth.header.")
                .or_else(|| other.strip_prefix("header."))
            {
                Some(name) => header(name),
                None => false,
            },
        };
        if !filled {
            return Some(format!("it needs {slot}, which was not given"));
        }
    }
    let oob = proof.requests.iter().any(|r| mentions(r, OAST_SLOT));
    if oob && params.oast.is_none() {
        return Some(
            "it is confirmed by an out-of-band callback, and no out-of-band endpoint was given"
                .to_string(),
        );
    }
    let origin = proof.requests.first().and_then(|r| origin_of(&r.url));
    if origin.is_none() || proof.requests.iter().any(|r| origin_of(&r.url) != origin) {
        return Some("its requests do not all go to one origin".to_string());
    }
    if !params.test_writes
        && proof
            .requests
            .iter()
            .any(|r| crate::inject::destroys_a_resource(&r.method))
    {
        return Some(
            "what it sends changes the target; give test_writes to send it again".to_string(),
        );
    }
    None
}

/// Whether `text` is anywhere in what `sent` sends.
fn mentions(sent: &crate::proof::Sent, text: &str) -> bool {
    sent.url.contains(text)
        || sent.fields.iter().any(|(_, v)| v.contains(text))
        || sent.body.as_deref().is_some_and(|b| b.contains(text))
}

/// The scheme, host and port `url` goes to.
fn origin_of(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    Some(url.origin().ascii_serialization())
}

/// `proof`'s requests with each slot filled from `params`: a credential header's value
/// from the headers given. The client carries the rest of the credential.
fn filled(proof: &Proof, params: &VerifyParams) -> Vec<crate::proof::Sent> {
    let given = |name: &str| {
        params.auth.as_ref().and_then(|a| {
            a.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        })
    };
    proof
        .requests
        .iter()
        .cloned()
        .map(|mut sent| {
            for (name, value) in &mut sent.fields {
                if value.starts_with("{{slot:")
                    && let Some(v) = given(name)
                {
                    *value = v;
                }
            }
            sent
        })
        .collect()
}

/// Replay `proof` with `params`, which [`refusal`] has passed: the verdict, the evidence
/// the matchers held on, and the answer's status and body hash.
pub async fn replay(proof: &Proof, params: &VerifyParams) -> Value {
    let requests = filled(proof, params);
    let origin = origin_of(&requests[0].url).unwrap_or_default();
    let scan: crate::engine::ScanParams = match serde_json::from_value(json!({
        "target": origin,
        "evasive": params.evasive,
        "identify": params.identify,
        "user_agent": params.user_agent,
        "timeout_ms": params.timeout_ms,
        "block_internal": params.block_internal,
        "follow_redirects": params.follow_redirects,
    })) {
        Ok(scan) => scan,
        Err(e) => return failed(format!("its settings do not read: {e}")),
    };
    let scan = crate::engine::ScanParams {
        egress: params.egress.clone(),
        auth: params.auth.clone(),
        resolve: params.resolve.clone(),
        ..scan
    };
    let mode = adaptive::identity::Mode::from_flags(scan.evasive, scan.identify.clone());
    let mut ident = adaptive::identity::resolve(&mode, Some(origin.as_str()));
    crate::engine::announce_as(&mut ident, scan.user_agent.as_deref());
    let client = match crate::engine::scan_client(&scan, &mode, &ident, None) {
        Ok(client) => client,
        Err(e) => return failed(format!("client build failed: {e}")),
    };
    let raw = crate::rawhttp::Route {
        egress: scan.egress.clone(),
        block_internal: scan.block_internal,
        resolve: scan.resolve.clone(),
    };
    match proof.kind {
        Kind::Header => {
            let Some(base) = crate::engine::fetch_base(&client, &requests[0].url).await else {
                return answer(Verdict::Unreachable, Vec::new(), None, "");
            };
            match crate::engine::header_checks(&base)
                .into_iter()
                .find(|(_, check, _, _)| *check == proof.check)
            {
                Some((name, ..)) => {
                    let fired = vec![Fired {
                        matcher: "header".into(),
                        part: "header".into(),
                        evidence: name.to_string(),
                    }];
                    let verdict = judged(proof, &fired);
                    answer(verdict, fired, Some(base.status), &base.body_prefix)
                }
                None => answer(
                    Verdict::NotReproduced,
                    Vec::new(),
                    Some(base.status),
                    &base.body_prefix,
                ),
            }
        }
        Kind::Template if requests.iter().any(|r| mentions(r, OAST_SLOT)) => {
            called_back(params, &scan, &client, &raw, &requests).await
        }
        Kind::Template => {
            match crate::template::send_again(
                &client,
                &raw,
                &requests,
                &proof.matchers,
                &proof.condition,
            )
            .await
            {
                crate::template::Again::Fired {
                    fired,
                    status,
                    body,
                } => {
                    let fired: Vec<Fired> = fired
                        .into_iter()
                        .map(|f| Fired {
                            evidence: crate::proof::evidence(&f.evidence),
                            ..f
                        })
                        .collect();
                    let verdict = judged(proof, &fired);
                    answer(verdict, fired, Some(status), &body)
                }
                crate::template::Again::Quiet { status, body } => {
                    answer(Verdict::NotReproduced, Vec::new(), Some(status), &body)
                }
                crate::template::Again::Unreachable => {
                    answer(Verdict::Unreachable, Vec::new(), None, "")
                }
            }
        }
    }
}

/// Reproduced when the evidence is the proof's, changed when it is other.
fn judged(proof: &Proof, fired: &[Fired]) -> Verdict {
    let said = |f: &[Fired]| f.iter().map(|f| f.evidence.clone()).collect::<Vec<_>>();
    if said(fired) == said(&proof.fired) {
        Verdict::Reproduced
    } else {
        Verdict::Changed
    }
}

/// An out-of-band check sent again under a marker of its own: reproduced when the target
/// calls back, not reproduced when it does not.
async fn called_back(
    params: &VerifyParams,
    scan: &crate::engine::ScanParams,
    client: &transport::Client,
    raw: &crate::rawhttp::Route,
    requests: &[crate::proof::Sent],
) -> Value {
    let Some(spec) = params.oast.as_ref() else {
        return failed("no out-of-band endpoint was given".to_string());
    };
    let Some(oc) = crate::oast::OastClient::from_spec(spec.domains.clone(), &spec.api_url) else {
        return failed("the out-of-band endpoint given cannot be used".to_string());
    };
    let http = match crate::probe::oast_client(
        scan.evasive,
        scan.identify.clone(),
        &scan.target,
        scan.timeout_ms,
        scan.block_internal,
        &scan.egress,
        false,
    ) {
        Ok(http) => http,
        Err(e) => return failed(format!("no client for the out-of-band API: {e}")),
    };
    let Some(reg) = oc.register(&http).await else {
        return failed("the out-of-band endpoint did not register this replay".to_string());
    };
    let (host, marker) = oc.host_marked(&reg);
    let marked: Vec<crate::proof::Sent> = requests
        .iter()
        .cloned()
        .map(|mut sent| {
            sent.url = sent.url.replace(OAST_SLOT, &host);
            for (_, value) in &mut sent.fields {
                *value = value.replace(OAST_SLOT, &host);
            }
            sent.body = sent.body.map(|b| b.replace(OAST_SLOT, &host));
            sent
        })
        .collect();
    let answered = crate::template::send_blind(client, raw, &marked).await;
    let mut came = false;
    if answered {
        for wait in [0u64, 2000, 4000] {
            if wait > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
            if oc
                .poll_hosts(&http, &reg)
                .await
                .iter()
                .any(|h| h.contains(&marker))
            {
                came = true;
                break;
            }
        }
    }
    oc.deregister(&http, &reg).await;
    if !answered {
        answer(Verdict::Unreachable, Vec::new(), None, "")
    } else if came {
        let fired = vec![Fired {
            matcher: "callback".into(),
            part: String::new(),
            evidence: "the target called back to the out-of-band host".into(),
        }];
        answer(Verdict::Reproduced, fired, None, "")
    } else {
        answer(Verdict::NotReproduced, Vec::new(), None, "")
    }
}

/// The answer to a replay.
fn answer(verdict: Verdict, fired: Vec<Fired>, status: Option<u16>, body: &str) -> Value {
    json!({
        "status": "completed",
        "answer": verdict,
        "fired": fired,
        "http_status": status,
        "response_sha256": if status.is_some() { crate::proof::sha256(body) } else { String::new() },
    })
}

/// A replay that could not be made, and why.
fn failed(message: String) -> Value {
    json!({"status": "error", "message": message})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::Sent;

    fn proof(requests: Vec<Sent>, slots: &[&str]) -> Proof {
        let mut p = Proof::new(
            &crate::proof::Ctx::new(None),
            "built in",
            Kind::Template,
            "t",
            requests,
            Vec::new(),
            "and",
            Vec::new(),
            200,
            "",
        );
        p.slots = slots.iter().map(|s| s.to_string()).collect();
        p
    }

    fn get(url: &str) -> Sent {
        Sent {
            method: "GET".into(),
            url: url.into(),
            fields: Vec::new(),
            body: None,
            raw: false,
        }
    }

    fn params(v: Value) -> VerifyParams {
        serde_json::from_value(v).unwrap()
    }

    /// A proof is replayed only with what it needs, on its own origin, and without
    /// changing the target unless told to; each refusal says why.
    #[test]
    fn a_proof_is_refused_what_it_cannot_be_sent_with() {
        let none = params(json!({}));
        assert_eq!(refusal(&proof(vec![get("http://h/a")], &[]), &none), None);
        let needs = proof(
            vec![get("http://h/a")],
            &[
                "auth.cookie",
                "auth.header.Authorization",
                "header.X-Api-Token",
            ],
        );
        assert_eq!(
            refusal(&needs, &none).as_deref(),
            Some("it needs auth.cookie, which was not given")
        );
        let given = params(json!({"auth": {"cookies": "s=1",
            "headers": {"authorization": "Bearer x", "X-Api-Token": "t"}}}));
        assert_eq!(refusal(&needs, &given), None);
        let partly = params(json!({"auth": {"cookies": "s=1", "headers": {"authorization": "x"}}}));
        assert_eq!(
            refusal(&needs, &partly).as_deref(),
            Some("it needs header.X-Api-Token, which was not given")
        );
        assert!(
            refusal(&proof(vec![get("http://h/a?token=")], &["url"]), &none)
                .unwrap()
                .contains("was not kept")
        );
        assert!(
            refusal(
                &proof(vec![get("http://h/a"), get("http://other/b")], &[]),
                &none
            )
            .unwrap()
            .contains("one origin")
        );
        let blind = proof(vec![get(&format!("http://h/?u=http://{OAST_SLOT}/"))], &[]);
        assert!(refusal(&blind, &none).unwrap().contains("out-of-band"));
        let mut write = get("http://h/account");
        write.method = "PATCH".into();
        let changes = proof(vec![write], &[]);
        assert!(refusal(&changes, &none).unwrap().contains("test_writes"));
        assert_eq!(
            refusal(&changes, &params(json!({"test_writes": true}))),
            None
        );
        let mut old = proof(vec![get("http://h/a")], &[]);
        old.format = 2;
        assert!(refusal(&old, &none).unwrap().contains("format 2"));
    }

    /// A slot is filled from the header of that name the caller gives, whatever its case.
    #[test]
    fn a_header_slot_is_filled_from_what_is_given() {
        let mut sent = get("http://h/a");
        sent.fields = vec![("X-Api-Token".into(), "{{slot:header.X-Api-Token}}".into())];
        let p = proof(vec![sent], &["header.X-Api-Token"]);
        let given = params(json!({"auth": {"headers": {"x-api-token": "t0"}}}));
        assert_eq!(filled(&p, &given)[0].fields[0].1, "t0");
    }

    /// The same evidence reproduces a finding, and other evidence says it changed.
    #[test]
    fn other_evidence_is_a_change() {
        let fired = |e: &str| Fired {
            matcher: "regex".into(),
            part: "body".into(),
            evidence: e.into(),
        };
        let mut p = proof(vec![get("http://h/a")], &[]);
        p.fired = vec![fired("version 1.2")];
        assert_eq!(judged(&p, &[fired("version 1.2")]), Verdict::Reproduced);
        assert_eq!(judged(&p, &[fired("version 1.3")]), Verdict::Changed);
    }
}
