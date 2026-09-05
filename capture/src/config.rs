//! Capture-session configuration, shared by every Web Tracer client.
//!
//! ## Why this module exists
//!
//! The desktop proxy and the mobile netstack both post to `/api/v1/web-trace/ingest`
//! and both send the same [`TraceEvent`](crate::TraceEvent). That much was already
//! shared. What was NOT shared was the decision of *what to put in the event*:
//! mobile fetched `/api/v1/web-trace/config`, read `full_capture`, and filled the
//! full-capture fields; the desktop never fetched the config at all and left those
//! fields empty on every event it ever sent.
//!
//! The result was a silent, one-sided failure. Desktop captures populated the
//! Assets tab (which is built from the privacy-safe shape) and produced an
//! permanently empty Requests tab (which needs the bytes), with nothing anywhere
//! reporting a problem: the server stores what it is given, and it was given a
//! shape. Turning full capture on in the UI did not help, because the server was
//! looking for fields the desktop client never sent.
//!
//! So the fix is not "add the fields to the desktop too" - that is the same bug
//! waiting for the third client. It is to put the *contract* in one place: what
//! endpoint to ask, what the answer means, what the default is when the answer
//! does not arrive, and what a full-capture event must contain. Transport stays
//! with the caller, because desktop and mobile already have their own HTTP client
//! and this crate should not grow one.
//!
//! If you add a Web Tracer client, use this module and [`TraceEvent::attach_full`]
//! and the Requests tab works without you knowing it exists.

use serde::{Deserialize, Serialize};

/// Path on the control plane that answers with a session's capture settings.
pub const CONFIG_PATH: &str = "/api/v1/web-trace/config";

/// Path the reduced events are posted to.
pub const INGEST_PATH: &str = "/api/v1/web-trace/ingest";

/// A capture session's live settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Whether to attach real headers and bodies to each event, which is what
    /// makes the Requests tab and the Bench Repeater work.
    pub full_capture: bool,
    /// `auto` (forward everything) or `manual` (hold each exchange for a decision).
    pub intercept_mode: String,
    /// Hosts to relay WITHOUT interception (exact host, or a bare domain to
    /// cover its subdomains).
    ///
    /// Some hosts cannot be intercepted: an app that pins its API refuses our
    /// certificate and the request fails outright. Capturing such a host does
    /// not merely lose the traffic, it breaks the feature being tested, and the
    /// only workaround before this was to exclude the whole app from capture.
    /// Naming the host instead keeps the rest of the app captured.
    #[serde(default)]
    pub bypass_hosts: Vec<String>,
}

impl Default for CaptureConfig {
    /// Full capture ON.
    ///
    /// It used to default off, on the reasoning that capturing less is safer.
    /// That reasoning does not survive contact with what this tool is: you are
    /// capturing your OWN browsing, on your OWN machine, having deliberately
    /// started a capture session. Defaulting off meant the Requests tab was empty
    /// for everyone who did not know a switch existed, which reads as broken
    /// rather than as private.
    ///
    /// It is still a per-session switch, and the privacy-safe reduction is still
    /// what feeds the asset graph. This only changes where the switch starts.
    fn default() -> Self {
        Self {
            full_capture: true,
            intercept_mode: "auto".to_string(),
            bypass_hosts: Vec::new(),
        }
    }
}

impl CaptureConfig {
    /// The POST body `CONFIG_PATH` expects.
    pub fn request_body(workflow_id: &str, token: &str) -> serde_json::Value {
        serde_json::json!({ "workflow_id": workflow_id, "token": token })
    }

    /// Same, plus what THIS client decided about full capture.
    ///
    /// Full capture takes two yeses: the session asks for it and the device
    /// grants it. Only the client knows the second one, and until it said so the
    /// control plane could not tell "nothing was captured" from "the device
    /// declined", so an empty Requests tab had no explanation anywhere.
    pub fn request_body_with_device(
        workflow_id: &str,
        token: &str,
        device_full_capture: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "workflow_id": workflow_id,
            "token": token,
            "device_full_capture": device_full_capture,
        })
    }

    /// Parse a control-plane response into settings.
    ///
    /// Tolerates the `{ status, data: {...} }` envelope the control plane wraps
    /// payloads in as well as a bare object, because clients have historically
    /// disagreed about which they unwrap. Anything missing falls back to
    /// [`Default`], so a partial answer degrades to the documented default
    /// instead of to `false`.
    pub fn parse(v: &serde_json::Value) -> Self {
        let d = v.get("data").unwrap_or(v);
        let def = Self::default();
        Self {
            full_capture: d
                .get("full_capture")
                .and_then(|b| b.as_bool())
                .unwrap_or(def.full_capture),
            intercept_mode: d
                .get("intercept_mode")
                .and_then(|s| s.as_str())
                .unwrap_or(&def.intercept_mode)
                .to_string(),
            bypass_hosts: d
                .get("bypass_hosts")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .map(|x| x.trim().to_ascii_lowercase())
                        .filter(|x| !x.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// True when the session wants each exchange held for a manual decision.
    pub fn is_manual(&self) -> bool {
        self.intercept_mode == "manual"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn full_capture_is_on_by_default() {
        assert!(CaptureConfig::default().full_capture);
    }

    #[test]
    fn parses_the_wrapped_envelope_and_a_bare_object_identically() {
        let wrapped = json!({"status":200,"data":{"full_capture":false,"intercept_mode":"manual"}});
        let bare = json!({"full_capture":false,"intercept_mode":"manual"});
        assert_eq!(CaptureConfig::parse(&wrapped), CaptureConfig::parse(&bare));
        assert!(!CaptureConfig::parse(&wrapped).full_capture);
        assert!(CaptureConfig::parse(&wrapped).is_manual());
    }

    #[test]
    fn a_missing_field_falls_back_to_the_default_not_to_false() {
        // The whole bug this module exists to prevent: a client that quietly
        // reads "absent" as "off" produces an empty Requests tab and no error.
        let partial = json!({"intercept_mode":"auto"});
        assert!(CaptureConfig::parse(&partial).full_capture);
        let empty = json!({});
        assert!(CaptureConfig::parse(&empty).full_capture);
    }

    #[test]
    fn an_explicit_false_is_still_respected() {
        let off = json!({"full_capture": false});
        assert!(!CaptureConfig::parse(&off).full_capture);
    }

    #[test]
    fn request_body_shape() {
        let b = CaptureConfig::request_body("wf-1", "tok");
        assert_eq!(b["workflow_id"], "wf-1");
        assert_eq!(b["token"], "tok");
    }

    #[test]
    fn request_body_carries_the_device_answer() {
        let b = CaptureConfig::request_body_with_device("wf-1", "tok", false);
        assert_eq!(b["workflow_id"], "wf-1");
        assert_eq!(b["device_full_capture"], false);
    }
}
