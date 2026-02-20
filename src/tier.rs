//! Feature tier gating for Aiegis runtime capabilities.
//!
//! Two product tiers:
//! - `Shield`   — free, Aho-Corasick injection detection only
//! - `Sentinel` — paid, full detection stack (neural classifier, LLM, TLS MITM, etc.)
//!
//! "developer" is accepted as an alias for "sentinel" for backward compatibility.

use anyhow::{anyhow, Result};

use crate::config::AiegisConfig;
use crate::mode::RuntimeMode;

/// Product tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Free tier — basic Aho-Corasick injection detection, gateway proxy.
    Shield,
    /// Paid tier — full detection stack: neural classifier, LLM, TLS MITM,
    /// custom rules, rate limiting, metrics, and dashboard.
    Sentinel,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Shield => "shield",
            Tier::Sentinel => "sentinel",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "shield" => Ok(Tier::Shield),
            // "developer" accepted as a backward-compatible alias for "sentinel"
            "developer" | "sentinel" => Ok(Tier::Sentinel),
            other => Err(anyhow!(
                "Invalid tier '{other}'. Expected one of: shield, sentinel"
            )),
        }
    }

    pub fn default_for_mode(mode: RuntimeMode) -> Self {
        match mode {
            // Realm OS has no licensing requirement and runs fully unlocked by default.
            RuntimeMode::RealmOs => Tier::Sentinel,
            RuntimeMode::Standalone => Tier::Shield,
        }
    }
}

/// Runtime feature gate checks.
pub trait TierGate {
    fn allows_tls_mitm(&self) -> bool;
    fn allows_classifier(&self) -> bool;
    fn allows_llm(&self) -> bool;
    fn allows_custom_patterns(&self) -> bool;
    fn allows_rate_limiting(&self) -> bool;
    fn allows_metrics(&self) -> bool;
    fn allows_dashboard(&self) -> bool;
}

impl TierGate for Tier {
    fn allows_tls_mitm(&self) -> bool {
        matches!(self, Tier::Sentinel)
    }

    fn allows_classifier(&self) -> bool {
        matches!(self, Tier::Sentinel)
    }

    fn allows_llm(&self) -> bool {
        matches!(self, Tier::Sentinel)
    }

    fn allows_custom_patterns(&self) -> bool {
        matches!(self, Tier::Sentinel)
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

/// Resolve the active tier.
///
/// Priority: config override (capped by license) > license key > runtime default.
///
/// **Security:** A config override can only *downgrade* the tier, never upgrade it.
/// If the config requests a higher tier than the installed license grants, the
/// license tier is used instead. This prevents anyone from editing the TOML to
/// obtain paid features for free.
pub fn resolve_tier(config_tier: Option<&str>, mode: RuntimeMode) -> Result<Tier> {
    // 1. Try installed license key — establishes the ceiling
    let license_tier = crate::license::tier_from_license();

    // 2. Apply config override, capped at license tier
    if let Some(raw) = config_tier {
        let requested = Tier::parse(raw)?;
        let effective = match license_tier {
            Some(licensed) => {
                // Config can only downgrade, never upgrade
                if requested > licensed {
                    tracing::warn!(
                        requested = requested.as_str(),
                        licensed = licensed.as_str(),
                        "Config tier exceeds license tier — capping at licensed tier"
                    );
                    licensed
                } else {
                    requested
                }
            }
            // No license: config override is accepted as-is (may be Shield)
            None => requested,
        };
        return Ok(effective);
    }

    // 3. License key (no config override)
    if let Some(licensed_tier) = license_tier {
        return Ok(licensed_tier);
    }

    // 4. Fall back to runtime mode default
    Ok(Tier::default_for_mode(mode))
}

/// Validate that enabled config features are allowed for the selected tier.
pub fn validate_tier_config(config: &AiegisConfig, tier: Tier) -> Result<()> {
    if config.proxy.tls_mitm.enabled && !tier.allows_tls_mitm() {
        return Err(anyhow!(
            "TLS MITM is enabled but tier '{}' does not allow it (requires Sentinel)",
            tier.as_str()
        ));
    }

    if config.detection.classifier.enabled && !tier.allows_classifier() {
        return Err(anyhow!(
            "Neural classifier is enabled but tier '{}' does not allow it (requires Sentinel)",
            tier.as_str()
        ));
    }

    if config.detection.llm.enabled && !tier.allows_llm() {
        return Err(anyhow!(
            "Local LLM is enabled but tier '{}' does not allow it (requires Sentinel)",
            tier.as_str()
        ));
    }

    if config.uses_custom_pattern_paths() && !tier.allows_custom_patterns() {
        return Err(anyhow!(
            "Custom pattern paths are configured but tier '{}' does not allow custom patterns (requires Sentinel)",
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
    fn developer_alias_maps_to_sentinel() {
        let t = Tier::parse("developer").expect("should parse");
        assert_eq!(t, Tier::Sentinel);
    }

    #[test]
    fn parse_shield_and_sentinel() {
        assert_eq!(Tier::parse("shield").unwrap(), Tier::Shield);
        assert_eq!(Tier::parse("sentinel").unwrap(), Tier::Sentinel);
        assert_eq!(Tier::parse("SENTINEL").unwrap(), Tier::Sentinel);
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
    fn shield_rejects_llm() {
        let mut config = AiegisConfig::default();
        config.detection.llm.enabled = true;
        let err = validate_tier_config(&config, Tier::Shield).expect_err("must fail");
        assert!(err.to_string().contains("Local LLM"));
    }

    #[test]
    fn sentinel_allows_all_flags() {
        let mut config = AiegisConfig::default();
        config.proxy.tls_mitm.enabled = true;
        config.detection.classifier.enabled = true;
        assert!(validate_tier_config(&config, Tier::Sentinel).is_ok());
    }

    #[test]
    fn tier_ordering_shield_lt_sentinel() {
        assert!(Tier::Shield < Tier::Sentinel);
    }
}
