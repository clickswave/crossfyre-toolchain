//! HTTP request smuggling (desync) detection.
//!
//! A request carrying both `Content-Length` and `Transfer-Encoding` can be
//! framed differently by two hops. When a front-end believes one header and the
//! back-end believes the other, the bytes one considers "the end of this
//! request" are what the other considers "the start of the next one". An
//! attacker then prefixes bytes onto somebody else's request: their session,
//! their response, their credentials.
//!
//! # Why this is opt-in, and stays opt-in
//!
//! Every other probe in cortex asks a question and leaves the target as it
//! found it. This one cannot be that polite. Detection works by leaving one hop
//! waiting for a body that never arrives, and on a real deployment that request
//! may sit in a connection pool shared with other users. A probe that succeeds
//! has, by definition, put a fragment of a request somewhere it does not
//! belong.
//!
//! So: it runs only when the caller names the class, every probe carries
//! `Connection: close` to discourage reuse of the poisoned socket, and the
//! finding says plainly that confirming this disturbs the target.
//!
//! Nothing is smuggled beyond the framing itself. Detection needs only the
//! DISAGREEMENT to be visible, not a payload riding on it, so the probe stops
//! at an unterminated chunk and never appends a second request. That is the
//! difference between proving the door is unlocked and walking through it, and
//! a scanner has no business doing the second.
//!
//! # The oracle
//!
//! Timing, with a control, in the same shape as the blind command-injection
//! check: a signal that only means something when its opposite does not.
//!
//!   1. Send the ambiguous request with a body that TERMINATES for the chunked
//!      parser. Both hops agree, and the answer comes back promptly. If this is
//!      already slow, the target is slow and the probe cannot conclude anything,
//!      so it stops.
//!   2. Send the same request with a body that does NOT terminate for the
//!      chunked parser. If one hop is reading chunked, it waits for a
//!      terminator that will never come.
//!
//! A large gap between those two, reproduced, is the finding. A target that
//! frames both hops the same way answers both in the same time, because the
//! second body is simply a body.
//!
//! Verified against a purpose-built pair: a front-end framing by
//! Content-Length in front of a back-end framing by Transfer-Encoding answers
//! the terminated probe in 0.00s and the unterminated one in 12.01s. The same
//! pair with the ambiguous request rejected answers both in 0.00s.

use cfx_finding::Finding;
use serde_json::Value;
use std::time::Duration;

/// How much slower the unterminated probe must be before it means anything.
const DESYNC_GAP: Duration = Duration::from_secs(5);
/// If the control is already this slow, the target cannot be measured this way.
const CONTROL_CEILING: Duration = Duration::from_secs(3);
/// Ceiling on how long to wait for a hop that is never going to answer.
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);

/// The two ways the disagreement runs, and how each is spelled on the wire.
enum Variant {
    /// Front-end reads Content-Length, back-end reads Transfer-Encoding.
    ClTe,
    /// Front-end reads Transfer-Encoding, back-end reads Content-Length.
    TeCl,
}

impl Variant {
    fn label(&self) -> &'static str {
        match self {
            Variant::ClTe => "CL.TE",
            Variant::TeCl => "TE.CL",
        }
    }

    /// (terminating body, non-terminating body, content-length to declare).
    ///
    /// For CL.TE the Content-Length covers the whole body, so the front-end
    /// forwards all of it and the back-end reads it as chunks.
    ///
    /// For TE.CL the chunked framing is what the front-end honours, and the
    /// declared Content-Length is what the back-end waits on: a length longer
    /// than the bytes that arrive leaves it waiting.
    fn bodies(&self) -> (String, String, usize) {
        match self {
            Variant::ClTe => {
                let ok = "0\r\n\r\n".to_string();
                // A chunk header promising a byte, with no terminating chunk.
                let hang = "1\r\nZ\r\n".to_string();
                let cl = hang.len();
                (ok, hang, cl)
            }
            Variant::TeCl => {
                // A terminated chunked body whose declared length is honest.
                let ok = "0\r\n\r\n".to_string();
                // Same body, but the declared length asks for bytes that never
                // arrive, so a Content-Length reader waits.
                let hang = "0\r\n\r\n".to_string();
                (ok, hang, 4096)
            }
        }
    }
}

fn request(variant: &Variant, host_hdr: &str, target: &str, body: &str, cl: usize) -> Vec<u8> {
    // `Connection: close` on every probe: if this works, the socket carries a
    // fragment of a request that belongs to nobody, and it should not be reused.
    let te_first = matches!(variant, Variant::TeCl);
    let framing = if te_first {
        format!("Transfer-Encoding: chunked\r\nContent-Length: {cl}\r\n")
    } else {
        format!("Content-Length: {cl}\r\nTransfer-Encoding: chunked\r\n")
    };
    format!(
        "POST {target} HTTP/1.1\r\nHost: {host_hdr}\r\n{framing}\
         Connection: close\r\nAccept: */*\r\n\r\n{body}"
    )
    .into_bytes()
}

/// Probe one URL for a framing disagreement. `None` when there is no evidence.
pub async fn probe(url: &str) -> Option<Value> {
    let (https, host, port, target) = crate::rawhttp::split_url(url)?;
    let host_hdr = if (https && port == 443) || (!https && port == 80) {
        host.clone()
    } else {
        format!("{host}:{port}")
    };

    for variant in [Variant::ClTe, Variant::TeCl] {
        let (ok_body, hang_body, cl) = variant.bodies();

        // Control first. A target that is slow to answer the unambiguous
        // version cannot be measured this way, and saying so is better than
        // reporting a delay that was never ours.
        let control = request(&variant, &host_hdr, &target, &ok_body, ok_body.len());
        let (_, control_time) =
            crate::rawhttp::send_exact(&host, port, https, &control, PROBE_TIMEOUT).await;
        if control_time >= CONTROL_CEILING {
            continue;
        }

        let hang = request(&variant, &host_hdr, &target, &hang_body, cl);
        let (_, hang_time) =
            crate::rawhttp::send_exact(&host, port, https, &hang, PROBE_TIMEOUT).await;
        if hang_time < control_time + DESYNC_GAP {
            continue;
        }

        // Reproduce before reporting, as every other oracle here does.
        let (_, again) = crate::rawhttp::send_exact(&host, port, https, &hang, PROBE_TIMEOUT).await;
        if again < control_time + DESYNC_GAP {
            continue;
        }

        return Some(
            Finding::new(
                "cortex-smuggle",
                "smuggling",
                format!("HTTP request smuggling ({} desync)", variant.label()),
                "critical",
                url,
            )
            .method("POST")
            .location("header")
            .describe(format!(
                "A request carrying both `Content-Length` and `Transfer-Encoding` is framed \
                 differently by two hops in front of this endpoint ({}). A body that terminates \
                 for the chunked parser was answered in {:.1}s; the same request with a body that \
                 does not terminate took {:.1}s, twice, because one hop is still waiting for the \
                 rest of a request the other has already finished. Whatever follows that boundary \
                 is prefixed onto the NEXT request on that connection - somebody else's - which \
                 is how this becomes session theft, cache poisoning, or bypass of every control \
                 the front-end enforces. Fix by making both hops agree: reject any request \
                 carrying both headers. NOTE: confirming this necessarily leaves a partial \
                 request on a connection, so run it against systems you are authorised to \
                 disturb.",
                variant.label(),
                control_time.as_secs_f64(),
                hang_time.as_secs_f64()
            ))
            .build(),
        );
    }
    None
}
