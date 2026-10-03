//! Request authentication context shared by every engine.
//!
//! An `AuthSpec` is what the node resolves from a workspace credential (see
//! `core::creds` `AuthContext`) and hands to an engine so its outbound requests
//! run authenticated: a set of custom headers plus an optional `Cookie` value.
//!
//! This lived independently in `cortex`, `mach` and `scout` (three byte-identical
//! copies), which meant only whoever owned the copy could authenticate. Hoisting
//! it here makes authed crawl/fingerprint/scan uniformly available to any engine
//! that pulls in `transport`.

use std::collections::HashMap;

use crate::header::{COOKIE, HeaderMap, HeaderName, HeaderValue};

/// Request auth resolved from a credential: custom headers + an optional Cookie.
/// Deserialized straight from the engine op params (`#[serde(default)] auth`).
#[derive(Debug, serde::Deserialize, Clone, Default)]
pub struct AuthSpec {
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub cookies: String,
}

impl AuthSpec {
    /// Build a [`HeaderMap`] from the resolved auth (custom headers + `Cookie`).
    /// Header names/values that fail to parse are skipped rather than failing the
    /// whole build.
    pub fn to_header_map(&self) -> HeaderMap {
        let mut hm = HeaderMap::new();
        for (k, v) in &self.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                hm.insert(name, val);
            }
        }
        if !self.cookies.is_empty() {
            if let Ok(val) = HeaderValue::from_str(&self.cookies) {
                hm.insert(COOKIE, val);
            }
        }
        hm
    }

    /// True when there is any auth material to apply (so callers can cheaply skip
    /// the merge for the unauthenticated case).
    pub fn is_meaningful(&self) -> bool {
        !self.headers.is_empty() || !self.cookies.is_empty()
    }
}
