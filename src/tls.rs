//! TLS MITM certificate management utilities.
//!
//! v0.2 foundation: generate and persist a local CA certificate/key pair
//! used for transparent HTTPS interception in Developer+ tiers.

use std::path::{Path, PathBuf};

use anyhow::Result;

#[cfg(not(feature = "tls-mitm"))]
use anyhow::anyhow;

#[cfg(feature = "tls-mitm")]
use anyhow::Context;

#[cfg(feature = "tls-mitm")]
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

#[cfg(feature = "tls-mitm")]
pub const CA_CERT_FILE: &str = "ca.pem";
#[cfg(feature = "tls-mitm")]
pub const CA_KEY_FILE: &str = "ca-key.pem";

#[derive(Debug, Clone)]
pub struct CaArtifacts {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Ensure the local CA material exists on disk.
pub fn ensure_ca(ca_dir: &Path) -> Result<CaArtifacts> {
    #[cfg(feature = "tls-mitm")]
    {
        ensure_ca_impl(ca_dir)
    }
    #[cfg(not(feature = "tls-mitm"))]
    {
        let _ = ca_dir;
        Err(anyhow!(
            "TLS MITM is enabled but this binary was built without the 'tls-mitm' feature. Rebuild with: cargo build --features tls-mitm"
        ))
    }
}

#[cfg(feature = "tls-mitm")]
fn ensure_ca_impl(ca_dir: &Path) -> Result<CaArtifacts> {
    std::fs::create_dir_all(ca_dir)
        .with_context(|| format!("Failed to create CA directory: {}", ca_dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(ca_dir, std::fs::Permissions::from_mode(0o700));
    }

    let cert_path = ca_dir.join(CA_CERT_FILE);
    let key_path = ca_dir.join(CA_KEY_FILE);
    if cert_path.exists() && key_path.exists() {
        return Ok(CaArtifacts {
            cert_path,
            key_path,
        });
    }

    let (cert_pem, key_pem) = generate_ca_pem()?;
    std::fs::write(&cert_path, cert_pem)
        .with_context(|| format!("Failed to write CA cert: {}", cert_path.display()))?;
    std::fs::write(&key_path, key_pem)
        .with_context(|| format!("Failed to write CA key: {}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(CaArtifacts {
        cert_path,
        key_path,
    })
}

#[cfg(feature = "tls-mitm")]
fn generate_ca_pem() -> Result<(String, String)> {
    let mut params =
        CertificateParams::new(vec!["aiegis.local".to_string()]).context("Bad CA params")?;
    params
        .distinguished_name
        .push(DnType::CommonName, "Aiegis Local Root CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "DuoNode Aiegis");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let key_pair = KeyPair::generate().context("Failed to generate CA key pair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to self-sign CA certificate")?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "tls-mitm"))]
    #[test]
    fn ensure_ca_requires_feature() {
        let err = ensure_ca(Path::new(".aiegis/ca")).expect_err("must fail");
        assert!(err.to_string().contains("without the 'tls-mitm' feature"));
    }

    #[cfg(feature = "tls-mitm")]
    #[test]
    fn ensure_ca_generates_material() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let artifacts = ensure_ca(tmp.path()).expect("ensure");
        assert!(artifacts.cert_path.exists());
        assert!(artifacts.key_path.exists());

        let cert = std::fs::read_to_string(&artifacts.cert_path).expect("read cert");
        let key = std::fs::read_to_string(&artifacts.key_path).expect("read key");
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }

    #[cfg(feature = "tls-mitm")]
    #[test]
    fn ensure_ca_is_idempotent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let artifacts = ensure_ca(tmp.path()).expect("ensure");
        let cert_before = std::fs::read_to_string(&artifacts.cert_path).expect("read cert");
        let key_before = std::fs::read_to_string(&artifacts.key_path).expect("read key");

        let artifacts_second = ensure_ca(tmp.path()).expect("ensure second");
        let cert_after = std::fs::read_to_string(&artifacts_second.cert_path).expect("read cert");
        let key_after = std::fs::read_to_string(&artifacts_second.key_path).expect("read key");

        assert_eq!(cert_before, cert_after);
        assert_eq!(key_before, key_after);
    }
}
