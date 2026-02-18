//! License claims struct — mirrors `license.rs::LicenseClaims` in the main crate.
//!
//! Kept as a separate copy to avoid any dependency on the main `aiegis` crate.
//! **Must be kept in sync with `src/license.rs`.**

use serde::{Deserialize, Serialize};

/// Claims embedded in a signed Aiegis license key.
///
/// Serialized to JSON, then Ed25519-signed. The resulting bytes become the
/// payload component of the license string (`{sig}.{payload}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// Licensee identifier (email address).
    pub user: String,
    /// Licensed tier: "shield" or "sentinel".
    pub tier: String,
    /// ISO 8601 expiry timestamp (UTC), e.g. "2027-01-01T00:00:00Z".
    pub expiry: String,
    /// Optional feature flags granted by this license.
    #[serde(default)]
    pub features: Vec<String>,
    /// Public key version used to sign this key. Selects the verifying key
    /// compiled into the binary. Defaults to 1.
    pub key_version: u8,
}
