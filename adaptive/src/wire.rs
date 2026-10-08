//! Serde types crossing process boundaries: the per-scan config the wizard
//! sends down, and the coordination messages exchanged while a workflow runs.

use crate::health::HealthStats;
use crate::rate::Posture;
use serde::{Deserialize, Serialize};

/// Adaptive settings for one scan, as chosen in the wizard. Deserialized from
/// the engine config; every field defaults so older payloads (no adaptive
/// block) parse as "all manual".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveConfig {
    #[serde(default)]
    pub rate_enabled: bool,
    #[serde(default)]
    pub posture: Posture,
    #[serde(default)]
    pub resilience_enabled: bool,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        AdaptiveConfig {
            rate_enabled: false,
            posture: Posture::Balanced,
            resilience_enabled: false,
        }
    }
}

impl AdaptiveConfig {
    /// Extract from the flat engine-config JSON the wizard emits, tolerating
    /// either the nested `{adaptiveRate:{enabled,posture}}` shape or flat keys.
    pub fn from_engine_json(v: &serde_json::Value) -> Self {
        let rate = &v["adaptiveRate"];
        let res = &v["adaptiveResilience"];
        let rate_enabled = rate["enabled"].as_bool().unwrap_or(false);
        let resilience_enabled = res["enabled"].as_bool().unwrap_or(false);
        let posture = rate["posture"]
            .as_str()
            .map(Posture::from_str_lenient)
            .unwrap_or_default();
        AdaptiveConfig {
            rate_enabled,
            posture,
            resilience_enabled,
        }
    }
}

/// One participant's view of a target host, reported to the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub workflow_id: String,
    pub node_id: String,
    pub host: String,
    pub stats: HealthStats,
    pub score: f64,
    /// What this participant is currently running at.
    pub concurrency: u32,
    pub delay_ms: u64,
}

/// The ceiling one participant may use for a target host. It adapts below this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlDirective {
    pub workflow_id: String,
    pub host: String,
    pub max_concurrency: u32,
    pub min_delay_ms: u64,
    pub max_retries: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_engine_json() {
        let v = serde_json::json!({
            "threads": 10,
            "adaptiveRate": { "enabled": true, "posture": "stealth" },
            "adaptiveResilience": { "enabled": true }
        });
        let c = AdaptiveConfig::from_engine_json(&v);
        assert!(c.rate_enabled);
        assert!(c.resilience_enabled);
        assert_eq!(c.posture, Posture::Stealth);
    }

    #[test]
    fn missing_block_is_all_manual() {
        let v = serde_json::json!({ "threads": 10, "delay": 20 });
        let c = AdaptiveConfig::from_engine_json(&v);
        assert!(!c.rate_enabled);
        assert!(!c.resilience_enabled);
        assert_eq!(c.posture, Posture::Balanced);
    }

    #[test]
    fn posture_roundtrips_lowercase() {
        let json = serde_json::to_string(&Posture::Throughput).unwrap();
        assert_eq!(json, "\"throughput\"");
        let back: Posture = serde_json::from_str("\"stealth\"").unwrap();
        assert_eq!(back, Posture::Stealth);
    }

    #[test]
    fn gentle_is_the_quietest_posture_by_another_name() {
        assert_eq!(Posture::from_str_lenient("gentle"), Posture::Stealth);
        assert_eq!(Posture::from_str_lenient(" Gentle "), Posture::Stealth);
        let back: Posture = serde_json::from_str("\"gentle\"").unwrap();
        assert_eq!(back, Posture::Stealth);
        let c = AdaptiveConfig::from_engine_json(&serde_json::json!({
            "adaptiveRate": { "enabled": true, "posture": "gentle" }
        }));
        assert_eq!(c.posture, Posture::Stealth);
    }
}
