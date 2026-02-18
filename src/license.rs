//! Ed25519 license key verification for Aiegis tier enforcement.
//!
//! License keys are offline-verifiable signed payloads. No phone-home required.
//! Format: `{base64_signature}.{base64_payload}` where payload is JSON:
//! ```json
//! { "user": "alice@example.com", "tier": "sentinel", "expiry": "2027-01-01T00:00:00Z",
//!   "features": [], "key_version": 1 }
//! ```
//!
//! The public key is compiled into the binary. Only DuoNode Inc holds the
//! corresponding private key used to sign licenses.
//!
//! Key rotation: `key_version` in the claims selects which compiled-in public key
//! to verify against. Embed v1 (current) and v2 (next) keys to allow zero-downtime
//! rotation. Increment `key_version` in newly issued keys when rotating.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::tier::Tier;

// ─── Compiled-in public keys ──────────────────────────────────────────────────

/// Key v1 — current production signing key (Ed25519, SPKI DER, base64).
/// **Replace with real production key before shipping.**
const AIEGIS_PUBLIC_KEY_V1_B64: &str =
    "MCowBQYDK2VwAyEAKXFTkGmXzTzwRPXsVUW+L1kZ8hGxTxYJNq0y5vWCDEE=";

/// Key v2 — pre-loaded next key for zero-downtime rotation.
/// Set to the same placeholder until a rotation is needed; will be updated
/// before the v1 private key is retired.
const AIEGIS_PUBLIC_KEY_V2_B64: &str =
    "MCowBQYDK2VwAyEAKXFTkGmXzTzwRPXsVUW+L1kZ8hGxTxYJNq0y5vWCDEE=";

/// Highest accepted key_version. Reject claims above this to prevent confusion
/// when old binaries encounter future key versions.
const MAX_KEY_VERSION: u8 = 2;

// ─── Default license path ────────────────────────────────────────────────────

/// Default license file location.
fn default_license_path() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".aiegis").join("license.key")
    } else {
        PathBuf::from("/etc/realm/aiegis.lic")
    }
}

// ─── Claims ──────────────────────────────────────────────────────────────────

/// Claims embedded in a signed license key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// Licensee identifier (email).
    pub user: String,
    /// Licensed tier: "shield" or "sentinel" ("developer" accepted as alias).
    pub tier: String,
    /// ISO 8601 expiry timestamp (UTC).
    pub expiry: String,
    /// Optional feature flags granted by this license.
    #[serde(default)]
    pub features: Vec<String>,
    /// Public key version used to sign this key. Selects the compiled-in
    /// verifying key. Defaults to 1 for backward compatibility.
    #[serde(default = "default_key_version")]
    pub key_version: u8,
}

fn default_key_version() -> u8 {
    1
}

impl LicenseClaims {
    /// Parse the tier string into a Tier enum.
    pub fn to_tier(&self) -> Result<Tier> {
        Tier::parse(&self.tier)
    }

    /// Check if the license has expired.
    pub fn is_expired(&self) -> bool {
        match self.expiry.parse::<DateTime<Utc>>() {
            Ok(expiry) => Utc::now() > expiry,
            Err(_) => true, // Unparseable expiry = expired
        }
    }

    /// Days remaining until expiry. Returns 0 if expired.
    pub fn days_remaining(&self) -> i64 {
        match self.expiry.parse::<DateTime<Utc>>() {
            Ok(expiry) => {
                let delta = expiry - Utc::now();
                delta.num_days().max(0)
            }
            Err(_) => 0,
        }
    }
}

// ─── Verifier ────────────────────────────────────────────────────────────────

/// Verifies Ed25519-signed license keys.
pub struct LicenseVerifier {
    key_v1: VerifyingKey,
    key_v2: VerifyingKey,
}

impl LicenseVerifier {
    /// Create a verifier using the compiled-in DuoNode public keys.
    pub fn new() -> Result<Self> {
        let key_v1 = decode_verifying_key(AIEGIS_PUBLIC_KEY_V1_B64)
            .context("Failed to decode compiled-in public key v1")?;
        let key_v2 = decode_verifying_key(AIEGIS_PUBLIC_KEY_V2_B64)
            .context("Failed to decode compiled-in public key v2")?;
        Ok(Self { key_v1, key_v2 })
    }

    /// Create a verifier from a single base64-encoded public key (testing).
    #[cfg(test)]
    pub fn from_verifying_key(key: VerifyingKey) -> Self {
        Self {
            key_v1: key,
            key_v2: key,
        }
    }

    /// Verify a license key string and extract claims.
    ///
    /// Format: `{base64_signature}.{base64_payload}`
    ///
    /// The payload is decoded first (without signature check) to read
    /// `key_version`, which selects the correct verifying key. Then the
    /// signature is verified before the claims are trusted.
    pub fn verify(&self, license_key: &str) -> Result<LicenseClaims> {
        let parts: Vec<&str> = license_key.trim().splitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid license format: expected 'signature.payload'"
            ));
        }

        let sig_bytes = BASE64
            .decode(parts[0])
            .context("Invalid base64 in signature")?;
        let payload_bytes = BASE64
            .decode(parts[1])
            .context("Invalid base64 in payload")?;

        // Decode payload first to read key_version (untrusted at this point)
        let raw_claims: LicenseClaims = serde_json::from_slice(&payload_bytes)
            .context("License payload is not valid JSON")?;

        if raw_claims.key_version == 0 || raw_claims.key_version > MAX_KEY_VERSION {
            return Err(anyhow!(
                "Unsupported key_version {} (max supported: {})",
                raw_claims.key_version,
                MAX_KEY_VERSION
            ));
        }

        // Select the verifying key based on the claimed version
        let verifying_key = match raw_claims.key_version {
            1 => &self.key_v1,
            2 => &self.key_v2,
            _ => unreachable!("already checked above"),
        };

        let signature = Signature::from_slice(&sig_bytes)
            .context("Invalid Ed25519 signature (expected 64 bytes)")?;

        // Verify signature over the raw payload bytes — this is where we trust the claims
        use ed25519_dalek::Verifier;
        verifying_key
            .verify(&payload_bytes, &signature)
            .map_err(|_| anyhow!("License signature verification failed"))?;

        Ok(raw_claims)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn decode_verifying_key(key_b64: &str) -> Result<VerifyingKey> {
    let key_bytes = BASE64
        .decode(key_b64)
        .context("Invalid base64 in public key")?;

    // Accept raw 32-byte keys or DER-wrapped SPKI keys (44 bytes for Ed25519)
    let raw_bytes = if key_bytes.len() == PUBLIC_KEY_LENGTH {
        key_bytes
    } else if key_bytes.len() > PUBLIC_KEY_LENGTH {
        // DER/SPKI wrapping: last 32 bytes are the raw key
        key_bytes[key_bytes.len() - PUBLIC_KEY_LENGTH..].to_vec()
    } else {
        return Err(anyhow!("Public key too short: {} bytes", key_bytes.len()));
    };

    let key_array: [u8; PUBLIC_KEY_LENGTH] = raw_bytes
        .try_into()
        .map_err(|_| anyhow!("Failed to convert public key bytes"))?;

    VerifyingKey::from_bytes(&key_array).context("Invalid Ed25519 public key")
}

// ─── Load / Save ─────────────────────────────────────────────────────────────

/// Load a license key from the default file path.
pub fn load_license() -> Result<Option<String>> {
    load_license_from(&default_license_path())
}

/// Load a license key from a specific path.
pub fn load_license_from(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read license file: {}", path.display()))?;
    let key = content.trim().to_string();
    if key.is_empty() {
        return Ok(None);
    }
    Ok(Some(key))
}

/// Save a license key to the default file path.
pub fn save_license(key: &str) -> Result<PathBuf> {
    let path = default_license_path();
    save_license_to(key, &path)?;
    Ok(path)
}

/// Save a license key to a specific path.
pub fn save_license_to(key: &str, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }
    std::fs::write(path, key.trim())
        .with_context(|| format!("Failed to write license file: {}", path.display()))?;

    // chmod 600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Attempt to resolve a tier from an installed license key.
/// Returns None if no license exists or verification fails.
pub fn tier_from_license() -> Option<Tier> {
    let key = match load_license() {
        Ok(Some(k)) => k,
        _ => return None,
    };

    let verifier = match LicenseVerifier::new() {
        Ok(v) => v,
        Err(_) => return None,
    };

    let claims = match verifier.verify(&key) {
        Ok(c) => c,
        Err(_) => return None,
    };

    if claims.is_expired() {
        return None;
    }

    claims.to_tier().ok()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Helper: generate a keypair and create a signed license.
    fn make_signed_license(claims: &LicenseClaims) -> (String, VerifyingKey) {
        // Deterministic test key (32 bytes of repeating pattern)
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        let payload = serde_json::to_vec(claims).unwrap();
        let signature = signing_key.sign(&payload);

        let key_str = format!(
            "{}.{}",
            BASE64.encode(signature.to_bytes()),
            BASE64.encode(&payload),
        );

        (key_str, verifying_key)
    }

    #[test]
    fn valid_license_verifies() {
        let claims = LicenseClaims {
            user: "test@example.com".into(),
            tier: "sentinel".into(),
            expiry: "2099-12-31T23:59:59Z".into(),
            features: vec![],
            key_version: 1,
        };

        let (key_str, verifying_key) = make_signed_license(&claims);
        let verifier = LicenseVerifier::from_verifying_key(verifying_key);
        let result = verifier.verify(&key_str).expect("should verify");
        assert_eq!(result.user, "test@example.com");
        assert_eq!(result.tier, "sentinel");
        assert_eq!(result.key_version, 1);
        assert!(!result.is_expired());
    }

    #[test]
    fn expired_license_detected() {
        let claims = LicenseClaims {
            user: "expired@test.com".into(),
            tier: "sentinel".into(),
            expiry: "2020-01-01T00:00:00Z".into(),
            features: vec![],
            key_version: 1,
        };

        let (key_str, verifying_key) = make_signed_license(&claims);
        let verifier = LicenseVerifier::from_verifying_key(verifying_key);
        let result = verifier.verify(&key_str).expect("sig should verify");
        assert!(result.is_expired());
        assert_eq!(result.days_remaining(), 0);
    }

    #[test]
    fn tampered_payload_rejected() {
        let claims = LicenseClaims {
            user: "legit@test.com".into(),
            tier: "shield".into(),
            expiry: "2099-12-31T23:59:59Z".into(),
            features: vec![],
            key_version: 1,
        };

        let (key_str, verifying_key) = make_signed_license(&claims);

        // Tamper with the payload (change tier to sentinel)
        let parts: Vec<&str> = key_str.splitn(2, '.').collect();
        let tampered_claims = LicenseClaims {
            user: "legit@test.com".into(),
            tier: "sentinel".into(),
            expiry: "2099-12-31T23:59:59Z".into(),
            features: vec![],
            key_version: 1,
        };
        let tampered_payload = BASE64.encode(serde_json::to_vec(&tampered_claims).unwrap());
        let tampered_key = format!("{}.{}", parts[0], tampered_payload);

        let verifier = LicenseVerifier::from_verifying_key(verifying_key);
        let result = verifier.verify(&tampered_key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("verification failed"));
    }

    #[test]
    fn invalid_format_rejected() {
        let verifier = LicenseVerifier::new().unwrap();
        let result = verifier.verify("not-a-license-key");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_key_version_rejected() {
        let claims = LicenseClaims {
            user: "test@test.com".into(),
            tier: "sentinel".into(),
            expiry: "2099-12-31T23:59:59Z".into(),
            features: vec![],
            key_version: 99, // unsupported
        };
        let (key_str, verifying_key) = make_signed_license(&claims);
        let verifier = LicenseVerifier::from_verifying_key(verifying_key);
        let result = verifier.verify(&key_str);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported key_version"));
    }

    #[test]
    fn claims_tier_parsing() {
        let claims = LicenseClaims {
            user: "test".into(),
            tier: "sentinel".into(),
            expiry: "2099-01-01T00:00:00Z".into(),
            features: vec![],
            key_version: 1,
        };
        assert_eq!(claims.to_tier().unwrap(), Tier::Sentinel);
    }

    #[test]
    fn developer_alias_accepted_in_claims() {
        let claims = LicenseClaims {
            user: "test".into(),
            tier: "developer".into(),
            expiry: "2099-01-01T00:00:00Z".into(),
            features: vec![],
            key_version: 1,
        };
        assert_eq!(claims.to_tier().unwrap(), Tier::Sentinel);
    }

    #[test]
    fn days_remaining_future() {
        let claims = LicenseClaims {
            user: "test".into(),
            tier: "sentinel".into(),
            expiry: "2099-12-31T23:59:59Z".into(),
            features: vec![],
            key_version: 1,
        };
        assert!(claims.days_remaining() > 0);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("license.key");
        let key = "sig.payload";

        save_license_to(key, &path).unwrap();
        let loaded = load_license_from(&path).unwrap();
        assert_eq!(loaded.as_deref(), Some("sig.payload"));
    }

    #[test]
    fn load_missing_returns_none() {
        let result = load_license_from(Path::new("/tmp/nonexistent_aiegis_license")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn key_version_defaults_to_1_when_absent() {
        // Simulate an old-format claims JSON without key_version field
        let json = r#"{"user":"test","tier":"sentinel","expiry":"2099-01-01T00:00:00Z","features":[]}"#;
        let claims: LicenseClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.key_version, 1);
    }
}
