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

/// Only CL.TE is tested by timing, and TE.CL deliberately is not.
///
/// The first version of this file tested both, and mirage - a single-process
/// Python server with no front-end at all, so a desync is impossible by
/// construction - reported TE.CL as critical. The probe declared
/// `Content-Length: 4096` and sent four bytes, so the server sat waiting for a
/// body that was never coming. EVERY server honouring Content-Length does that.
/// The delay was the scanner under-sending, not two hops disagreeing, and the
/// oracle had no way to tell those apart.
///
/// TE.CL cannot be established by timing at all, for that reason: its signature
/// delay is a Content-Length reader waiting for bytes, and a lone Content-Length
/// reader waiting for bytes looks identical. Confirming it needs a
/// differential-RESPONSE technique (poison the socket, then show the next
/// request on it answered differently), which is a materially more invasive
/// thing to do to somebody's server and is not something this probe should do
/// uninvited. So it is not attempted, and that is better than reporting a class
/// this method cannot distinguish.
enum Variant {
    /// Front-end reads Content-Length, back-end reads Transfer-Encoding.
    ClTe,
}

impl Variant {
    fn label(&self) -> &'static str {
        match self {
            Variant::ClTe => "CL.TE",
        }
    }

    /// (terminating body, hanging body, content-length to declare).
    ///
    /// The hanging body is the classic shape and the detail matters: a chunk of
    /// one byte followed by a line that is NOT a valid chunk size.
    ///
    ///   * A front-end reading Content-Length forwards exactly `cl` bytes, which
    ///     is the chunk and nothing after it. The back-end reading chunked takes
    ///     the one-byte chunk and then waits for the next chunk header that its
    ///     front-end is never going to send. That wait is the signal.
    ///   * A LONE server reading chunked gets the malformed size line `X` as a
    ///     complete line and rejects it at once. The trailing CRLF is load
    ///     bearing: without it that parser blocks waiting to finish reading a
    ///     line, and a careless single server then looks exactly like a desync.
    ///   * A LONE server reading Content-Length takes its `cl` bytes, finds them
    ///     all present, and answers immediately. It is never left waiting, which
    ///     is the mistake the first version of this file made.
    fn bodies(&self) -> (String, String, usize) {
        let ok = "0\r\n\r\n".to_string();
        let hang = "1\r\nA\r\nX\r\n".to_string();
        // Covers the chunk and nothing after it, so the two hops see different
        // bytes. Every byte of it is sent, so nobody is left short.
        let cl = "1\r\nA\r\n".len();
        (ok, hang, cl)
    }
}

/// How a probe is framed: both headers (the ambiguous request), or one of them.
enum Framing {
    /// Both, which is the request two hops can read differently.
    Ambiguous(usize),
    /// Content-Length only. Unambiguous, and the discriminating control: every
    /// byte it declares is sent, so a server that still takes its time is one
    /// that is slow about this request generally rather than one that is
    /// confused about where the request ends.
    ///
    /// Chunked-only was tried here first and is wrong. On a genuine CL.TE pair
    /// the front-end has no Content-Length to read, forwards no body at all, and
    /// the back-end waits exactly as it does for the real probe - so the control
    /// hangs on precisely the targets that are vulnerable, and suppressed every
    /// true positive.
    LengthOnly(usize),
}

fn request(host_hdr: &str, target: &str, body: &str, framing: Framing) -> Vec<u8> {
    // `Connection: close` on every probe: if this works, the socket carries a
    // fragment of a request that belongs to nobody, and it should not be reused.
    let headers = match framing {
        Framing::Ambiguous(cl) => {
            format!("Content-Length: {cl}\r\nTransfer-Encoding: chunked\r\n")
        }
        Framing::LengthOnly(cl) => format!("Content-Length: {cl}\r\n"),
    };
    format!(
        "POST {target} HTTP/1.1\r\nHost: {host_hdr}\r\n{headers}\
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

    let variant = Variant::ClTe;
    {
        let (ok_body, hang_body, cl) = variant.bodies();

        // Control one: the same ambiguous request with a body that terminates.
        // A target slow to answer this cannot be measured by timing at all, and
        // saying so beats reporting a delay that was never ours.
        let control = request(
            &host_hdr,
            &target,
            &ok_body,
            Framing::Ambiguous(ok_body.len()),
        );
        let (_, control_time) =
            crate::rawhttp::send_exact(&host, port, https, &control, PROBE_TIMEOUT).await;
        if control_time >= CONTROL_CEILING {
            return None;
        }

        let hang = request(&host_hdr, &target, &hang_body, Framing::Ambiguous(cl));
        let (_, hang_time) =
            crate::rawhttp::send_exact(&host, port, https, &hang, PROBE_TIMEOUT).await;
        if hang_time < control_time + DESYNC_GAP {
            return None;
        }

        // Control two, and this is the one mirage's false positive bought.
        //
        // The same body, framed unambiguously by Content-Length alone. Nothing
        // to disagree about, and every declared byte is sent. If THIS is slow,
        // the target is slow about this request for its own reasons and no
        // disagreement has been demonstrated.
        let unambiguous = request(&host_hdr, &target, &hang_body, Framing::LengthOnly(cl));
        let (_, unambiguous_time) =
            crate::rawhttp::send_exact(&host, port, https, &unambiguous, PROBE_TIMEOUT).await;
        if unambiguous_time >= control_time + DESYNC_GAP {
            return None;
        }

        // Reproduce before reporting, as every other oracle here does.
        let (_, again) = crate::rawhttp::send_exact(&host, port, https, &hang, PROBE_TIMEOUT).await;
        if again < control_time + DESYNC_GAP {
            return None;
        }

        Some(
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
                 rest of a request the other has already finished. The same body framed \
                 unambiguously by Content-Length alone, where there is nothing to disagree \
                 about, came back in {:.1}s, so the delay is the disagreement rather than this \
                 endpoint being slow. \
                 Whatever follows that boundary \
                 is prefixed onto the NEXT request on that connection - somebody else's - which \
                 is how this becomes session theft, cache poisoning, or bypass of every control \
                 the front-end enforces. Fix by making both hops agree: reject any request \
                 carrying both headers. NOTE: confirming this necessarily leaves a partial \
                 request on a connection, so run it against systems you are authorised to \
                 disturb.",
                variant.label(),
                control_time.as_secs_f64(),
                hang_time.as_secs_f64(),
                unambiguous_time.as_secs_f64()
            ))
            .build(),
        )
    }
}
