//! Following a confirmed finding to the thing that makes it matter.
//!
//! An SSRF reported on its own is a paragraph about what an attacker could
//! theoretically reach. The same SSRF, shown fetching the Redis that another
//! engine found on the same estate, is the actual exposure, and the difference
//! between those two reports is most of what separates a scanner from an
//! operator.
//!
//! # The rule this module exists to keep
//!
//! A chain is reported only when ONE probe demonstrated both halves.
//!
//! "cortex found an SSRF and scout found a Redis, and they are on the same
//! network" is a coincidence dressed as a finding. Nobody checked that the SSRF
//! can reach that Redis, and on a segmented network it very often cannot. So
//! nothing here reads a finding list. The input is a list of ADDRESSES another
//! engine observed, and every one of them is re-tested through the confirmed
//! SSRF before a word is written about it.
//!
//! # Proving a fetch landed, without a signature to match
//!
//! The metadata walk in `ssrf` can be certain because it knows what AWS, GCP,
//! Azure and Kubernetes index pages say. A Redis discovered on somebody's
//! network comes with no such promise, so certainty has to come from controls
//! instead:
//!
//!   * **Control A**, already taken by the SSRF oracle: a closed port on
//!     loopback. This is the shape the application produces when a fetch FAILS.
//!   * **The target**: the discovered `host:port`.
//!   * **Control B**: the same host on a port chosen to be closed. If the
//!     application produces the failure shape here and something different for
//!     the real port, the difference is the service answering, not the host
//!     being reachable and not the app echoing whatever it is handed.
//!
//! Control B is the one that matters. Without it, a host that silently drops
//! packets on every port produces a timeout that looks nothing like a connection
//! refusal, and a scanner reads its own timeout as a discovered service.
//!
//! Where the discovering engine recorded a banner, a match against it is quoted
//! as well. That is corroboration, not the test: banners are often empty, and an
//! oracle that only works when one is present would cover almost nothing.
//!
//! # Scope
//!
//! Every address here belongs to a machine that is not the scan target, so each
//! one is checked against the operator's authorised scope before a single packet
//! is sent. A discovered address is not an authorised address; see `scope`.

use serde::Deserialize;
use serde_json::{Value, json};

/// An address another engine observed on this workspace's estate.
///
/// Deliberately not a finding. Passing findings between engines is how a
/// correlation layer starts inferring; passing addresses keeps the question
/// answerable by a probe.
#[derive(Debug, Clone, Deserialize)]
pub struct InternalTarget {
    pub host: String,
    pub port: u16,
    /// What the discovering engine called it ("redis", "http", ...). Reported,
    /// never used to decide anything.
    #[serde(default)]
    pub service: String,
    /// The banner that engine recorded, when it recorded one. Corroboration.
    #[serde(default)]
    pub banner: String,
}

impl InternalTarget {
    pub fn url(&self) -> String {
        // Always plain HTTP: the point is to make the application open a socket
        // and hand back whatever comes out of it, and a TLS service will simply
        // produce a different failure. Guessing a scheme per port would be
        // guessing.
        format!("http://{}:{}/", self.host, self.port)
    }

    /// A port on the same host chosen to be closed, for control B.
    ///
    /// High, fixed and odd. If this one happens to be open, the control fails
    /// safe: the target's answer no longer looks distinct, and nothing is
    /// reported.
    pub fn control_url(&self) -> String {
        format!("http://{}:{}/", self.host, CONTROL_PORT)
    }
}

/// The port used for control B. Inside the dynamic/ephemeral range and not
/// assigned to anything, so a listener here is a deliberate act.
pub const CONTROL_PORT: u16 = 47_113;

/// How long to wait for the application to come back from a fetch it is making
/// on our behalf.
///
/// Deliberately longer than the metadata walk's deadline. That walk is looking
/// for services which answer instantly or not at all, but here the INFORMATIVE
/// case is often the slow one: control B against a host that drops packets takes
/// as long as the application's own fetch timeout, and cutting it short turns
/// the control into a failure and silently discards the finding it was meant to
/// support. That is exactly what happened the first time this ran.
pub const CHAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// How many discovered addresses one confirmed SSRF is worth chasing.
///
/// Each costs two requests through somebody's application, and the point is to
/// demonstrate the exposure rather than to inventory the network. An operator
/// who wants the inventory runs a port scan, which is a different tool that
/// already exists.
pub const MAX_TARGETS: usize = 8;

/// Did the target answer, given the two controls?
///
/// `failure` is what the application says when a fetch cannot connect (control
/// A). `control_b` is the same host on a closed port. `observed` is the real
/// address.
pub fn answered(observed: &str, failure: &str, control_b: &str) -> bool {
    // Nothing came back at all: no evidence either way.
    if observed.trim().is_empty() {
        return false;
    }
    // The application said the same thing it says when a fetch fails.
    if shape(observed) == shape(failure) {
        return false;
    }
    // The host answers the same way on a port nothing should be listening on,
    // so what we are seeing is a property of the host or the network, not of
    // the service. This is the check that stops a black-holed address being
    // read as a discovery, and it is the one that carries the result.
    //
    // An earlier version also demanded that the two controls AGREE, on the
    // theory that disagreement meant unstable output. A fixture showed that
    // backwards: a host which black-holes packets answers control B with a
    // timeout while control A is a connection refusal, so the two disagree
    // exactly when the host is interesting, and the rule threw away real
    // findings. Control B is the same-host baseline and does the work; control A
    // only catches the case where our own target failed to fetch at all.
    shape(observed) != shape(control_b)
}

/// A response reduced for comparison: numbers collapsed, so a timeout that
/// reports elapsed milliseconds does not look like a different answer each time.
fn shape(body: &str) -> String {
    crate::tamper::read(body).skeleton
}

/// Does the discovering engine's banner show up in what the application
/// fetched? Corroboration when present.
pub fn banner_echo(banner: &str, body: &str) -> Option<String> {
    let b = banner.trim();
    if b.len() < 4 {
        return None;
    }
    // A distinctive slice rather than the whole banner: the fetch is HTTP and
    // the service may answer with a protocol error that still quotes its
    // version string.
    let needle: String = b.chars().take(24).collect();
    body.contains(needle.trim())
        .then(|| needle.trim().to_string())
}

/// The evidence line for one reached service.
pub fn reached_note(t: &InternalTarget, corroboration: Option<String>) -> Value {
    json!({
        "host": t.host,
        "port": t.port,
        "service": if t.service.is_empty() { Value::Null } else { json!(t.service) },
        "banner_echo": corroboration,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_shape_is_not_an_answer() {
        assert!(!answered(
            "could not connect",
            "could not connect",
            "could not connect"
        ));
    }

    #[test]
    fn a_host_that_answers_every_port_the_same_way_is_not_a_discovery() {
        // The black-hole case: the real port and a closed port produce the same
        // thing, which means we are looking at the network, not a service.
        assert!(!answered(
            "timed out after 3000ms",
            "could not connect",
            "timed out after 3000ms"
        ));
    }

    #[test]
    fn a_black_holing_host_does_not_hide_a_real_service() {
        // Control A is a refusal, control B a timeout, because this host drops
        // packets instead of refusing. The service still answered, and an
        // earlier version of this rule discarded it for the controls
        // disagreeing.
        assert!(answered(
            "+PONG",
            "could not connect",
            "timed out after 3000ms"
        ));
    }

    #[test]
    fn the_same_host_baseline_is_what_decides() {
        // Every port on this host times out, including the one we were told
        // held a service.
        assert!(!answered(
            "timed out after 3000ms",
            "could not connect",
            "timed out after 2999ms"
        ));
    }

    #[test]
    fn a_distinct_answer_against_agreeing_controls_is_a_reach() {
        assert!(answered(
            "-ERR unknown command 'GET /'",
            "could not connect",
            "could not connect"
        ));
    }

    #[test]
    fn an_empty_body_proves_nothing() {
        assert!(!answered("   ", "could not connect", "could not connect"));
    }

    #[test]
    fn elapsed_milliseconds_do_not_make_two_failures_look_different() {
        // The reason shapes are compared with numbers collapsed.
        assert!(!answered(
            "fetch failed after 3001ms",
            "fetch failed after 2998ms",
            "fetch failed after 3002ms"
        ));
    }

    #[test]
    fn a_banner_is_corroboration_when_it_shows_up() {
        assert_eq!(
            banner_echo(
                "Redis server v=7.0.11",
                "-ERR ... Redis server v=7.0.11 ..."
            ),
            Some("Redis server v=7.0.11".to_string())
        );
        assert_eq!(
            banner_echo("Redis server v=7.0.11", "nothing like it"),
            None
        );
        // Too short to mean anything.
        assert_eq!(banner_echo("ssh", "ssh"), None);
    }

    #[test]
    fn the_control_port_is_not_a_real_service() {
        let t = InternalTarget {
            host: "10.0.0.5".into(),
            port: 6379,
            service: "redis".into(),
            banner: String::new(),
        };
        assert_eq!(t.url(), "http://10.0.0.5:6379/");
        assert_eq!(t.control_url(), format!("http://10.0.0.5:{CONTROL_PORT}/"));
        assert_ne!(t.port, CONTROL_PORT);
    }
}
