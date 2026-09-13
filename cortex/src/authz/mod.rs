//! Authorization testing (BOLA / BFLA / broken authentication) - open-core boundary.
//!
//! Given a set of endpoints and a set of identities (each a role + resolved auth
//! context), the engine replays every endpoint as every identity and compares the
//! responses to detect authorization flaws (broken authentication, BFLA, BOLA/IDOR,
//! BOPLA excessive-data-exposure).
//!
//! This module's public surface is the job's input schema ([`AuthzParams`]) and a
//! single [`run`] entry point. The differential identity-matrix oracle that powers
//! it - privilege-aware pairing, confirm-before-report, the BOPLA data-exposure
//! probe, and the correctness tuning that keeps false positives near zero - is a
//! private drop-in (`private.rs`, git-ignored) that `build.rs` selects when it is
//! present (first-party builds). A public checkout has only `baseline.rs`, so the
//! open build compiles and runs but does not perform the authorization oracle:
//! authorization testing is a platform feature.
//!
//! Both impls expose the same `run(AuthzParams, tx)` surface, so `daemon.rs` is
//! identical regardless of which is compiled.

use crate::engine::AuthSpec;
use serde::Deserialize;

// The input structs below are the job's wire schema (serde populates them from the
// backend's job payload). Which fields get *read* depends on the compiled impl: the
// private oracle reads them all, the open baseline reads only `target`. `allow(dead_code)`
// keeps the open build warning-clean without pretending fields it ignores don't exist.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct AuthzParams {
    #[serde(default, deserialize_with = "crate::probe::de_null_seq")]
    pub endpoints: Vec<Endpoint>,
    #[serde(default, deserialize_with = "crate::probe::de_null_seq")]
    pub identities: Vec<Identity>,
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub target: String,
    /// Opt-in to the state-changing mass-assignment probe (POST/PUT/PATCH with an
    /// injected privileged body). Off by default: read-only is the safe default,
    /// per the plan's safety rails.
    #[serde(default)]
    pub test_writes: bool,
    /// Evasiveness posture (from the node switch): blend in as a browser (true,
    /// default) vs a neutral honest client (false).
    #[serde(default = "d_true")]
    pub evasive: bool,
    /// Attribution token: when set, advertise it so an authorized program can
    /// allow-list the traffic.
    #[serde(default)]
    pub identify: Option<String>,
    /// Refuse private and reserved destinations at connect time. Absent = false,
    /// which is what an authorised customer scan gets: reaching your own
    /// internal network from your own node is the product. The free public
    /// tools set it, because there the caller is anonymous and the egress is
    /// ours.
    #[serde(default)]
    pub block_internal: bool,
}
fn d_true() -> bool {
    true
}
fn d_timeout() -> u64 {
    10_000
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Endpoint {
    #[serde(default = "d_get")]
    pub method: String,
    pub url: String,
}
fn d_get() -> String {
    "GET".into()
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct Identity {
    pub role: String,
    #[serde(default)]
    pub auth: AuthSpec,
}

// One `mod`, with the path chosen by cfg (set by build.rs), rather than two
// cfg-gated `mod imp;` declarations. Tools that resolve modules without evaluating
// cfg (rustfmt, rustdoc, rust-analyzer) would otherwise try to read BOTH arms and
// hard-error on a public checkout, where private.rs does not exist.
#[cfg_attr(authz_private, path = "private.rs")]
#[cfg_attr(not(authz_private), path = "baseline.rs")]
mod imp;

pub use imp::run;
