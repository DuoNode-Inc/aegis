//! Feature tier gating for Aiegis runtime capabilities.

use anyhow::{anyhow, Result};

use crate::config::AiegisConfig;
use crate::mode::RuntimeMode;

/// Product tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Shield,
    Developer,
    Sentinel,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Shield => "shield",
            Tier::Developer => "developer",
            Tier::Sentinel => "sentinel",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "shield" => Ok(Tier::Shield),
            "developer" => Ok(Tier::Developer),
            "sentinel" => Ok(Tier::Sentinel),
            other => Err(anyhow!(
                "Invalid tier '{other}'. Expected one of: shield, developer, sentinel"
            )),
        }
    }

    pub fn default_for_mode(mode: RuntimeMode) -> Self {
        match mode {
            // Realm OS has no licensing requirement and should run fully unlocked by default.
            RuntimeMode::RealmOs => Tier::Sentinel,
            RuntimeMode::Standalone => Tier::Shield,
        }
    }
}

/// Runtime feature gate checks.
pub trait TierGate {
    fn allows_tls_mitm(&self) -> bool;
    fn allows_classifier(&self) -> bool;
    fn allows_custom_patterns(&self) -> bool;
    fn allows_rate_limiting(&self) -> bool;
    fn allows_metrics(&self) -> bool;
    fn allows_dashboard(&self) -> bool;
}

impl TierGate for Tier {
    fn allows_tls_mitm(&self) -> bool {
        matches!(self, Tier::Developer | Tier::Sentinel)
    }

    fn allows_classifier(&self) -> bool {
        matches!(self, Tier::Developer | Tier::Sentinel)
    }

    fn allows_custom_patterns(&self) -> bool {
        matches!(self, Tier::Developer | Tier::Sentinel)
    }

    fn allows_rate_limiting(&self) -> bool {
        matches!(self, Tier::Sentinel)
    }

    fn allows_metrics(&self) -> bool {
        matches!(self, Tier::Sentinel)
    }

    fn allows_dashboard(&self) -> bool {
        matches!(self, Tier::Sentinel)
    }
}

/// Resolve the active tier using optional config and runtime mode defaults.
pub fn resolve_tier(config_tier: Option<&str>, mode: RuntimeMode) -> Result<Tier> {
    match config_tier {
        Some(raw) => Tier::parse(raw),
        None => Ok(Tier::default_for_mode(mode)),
    }
}

/// Validate that enabled config features are allowed for the selected tier.
pub fn validate_tier_config(config: &AiegisConfig, tier: Tier) -> Result<()> {
    if config.proxy.tls_mitm.enabled && !tier.allows_tls_mitm() {
        return Err(anyhow!(
            "TLS MITM is enabled but tier '{}' does not allow it",
            tier.as_str()
        ));
    }

    if config.detection.classifier.enabled && !tier.allows_classifier() {
        return Err(anyhow!(
            "Neural classifier is enabled but tier '{}' does not allow it",
            tier.as_str()
        ));
    }

    if config.uses_custom_pattern_paths() && !tier.allows_custom_patterns() {
        return Err(anyhow!(
            "Custom pattern paths are configured but tier '{}' does not allow custom patterns",
            tier.as_str()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_by_mode() {
        assert_eq!(
            Tier::default_for_mode(RuntimeMode::Standalone),
            Tier::Shield
        );
        assert_eq!(Tier::default_for_mode(RuntimeMode::RealmOs), Tier::Sentinel);
    }

    #[test]
    fn resolve_explicit_tier() {
        let t = resolve_tier(Some("developer"), RuntimeMode::Standalone).expect("resolve");
        assert_eq!(t, Tier::Developer);
    }

    #[test]
    fn resolve_invalid_tier_errors() {
        let err = resolve_tier(Some("vip"), RuntimeMode::Standalone).expect_err("must fail");
        assert!(err.to_string().contains("Invalid tier"));
    }

    #[test]
    fn shield_rejects_premium_flags() {
        let mut config = AiegisConfig::default();
        config.proxy.tls_mitm.enabled = true;
        let err = validate_tier_config(&config, Tier::Shield).expect_err("must fail");
        assert!(err.to_string().contains("TLS MITM"));
    }

    #[test]
    fn developer_allows_premium_flags() {
        let mut config = AiegisConfig::default();
        config.proxy.tls_mitm.enabled = true;
        config.detection.classifier.enabled = true;
        assert!(validate_tier_config(&config, Tier::Developer).is_ok());
    }
}
