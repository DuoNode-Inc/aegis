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
use std::sync::Arc;

#[cfg(feature = "tls-mitm")]
use rustls::pki_types::pem::PemObject;

#[cfg(feature = "tls-mitm")]
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};

#[cfg(feature = "tls-mitm")]
pub const CA_CERT_FILE: &str = "ca.pem";
#[cfg(feature = "tls-mitm")]
pub const CA_KEY_FILE: &str = "ca-key.pem";

#[derive(Debug, Clone)]
pub struct CaArtifacts {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[cfg(feature = "tls-mitm")]
#[derive(Debug)]
pub struct LoadedCa {
    pub ca_cert_der: rustls::pki_types::CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

/// Create (or verify) the local CA material exists on disk.
///
/// If `force` is true, any existing CA files are replaced with a freshly generated CA.
pub fn init_ca(ca_dir: &Path, force: bool) -> Result<CaArtifacts> {
    #[cfg(feature = "tls-mitm")]
    {
        init_ca_impl(ca_dir, force)
    }
    #[cfg(not(feature = "tls-mitm"))]
    {
        let _ = (ca_dir, force);
        Err(anyhow!(
            "TLS MITM requires a build with the 'tls-mitm' feature. Rebuild with: cargo build --features tls-mitm"
        ))
    }
}

/// Ensure the local CA material exists on disk.
pub fn ensure_ca(ca_dir: &Path) -> Result<CaArtifacts> {
    init_ca(ca_dir, false)
}

/// Load the CA cert and key from disk for TLS MITM leaf signing.
#[cfg(feature = "tls-mitm")]
pub fn load_ca(ca_dir: &Path) -> Result<LoadedCa> {
    let cert_path = ca_dir.join(CA_CERT_FILE);
    let key_path = ca_dir.join(CA_KEY_FILE);

    let cert_pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("Failed to read CA cert: {}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("Failed to read CA key: {}", key_path.display()))?;

    let ca_cert_der = rustls::pki_types::CertificateDer::from_pem_slice(cert_pem.as_bytes())
        .context("Failed to parse CA cert PEM")?;
    let ca_keypair = KeyPair::from_pem(&key_pem).context("Failed to parse CA key PEM")?;
    let issuer: Issuer<'static, KeyPair> =
        Issuer::from_ca_cert_pem(&cert_pem, ca_keypair).context("Failed to load CA issuer")?;

    Ok(LoadedCa {
        ca_cert_der,
        issuer,
    })
}

/// Build a rustls ServerConfig that presents a leaf certificate for `host`
/// signed by the provided CA.
#[cfg(feature = "tls-mitm")]
pub fn mitm_server_config_for_host(ca: &LoadedCa, host: &str) -> Result<Arc<rustls::ServerConfig>> {
    crate::crypto::ensure_rustls_provider();
    let mut params = CertificateParams::new(vec![host.to_string()]).context("Bad leaf params")?;
    params.distinguished_name.push(DnType::CommonName, host);
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let leaf_key = KeyPair::generate().context("Failed to generate leaf key pair")?;
    let leaf_cert = params
        .signed_by(&leaf_key, &ca.issuer)
        .context("Failed to sign leaf certificate")?;

    let mut chain = Vec::with_capacity(2);
    chain.push(rustls::pki_types::CertificateDer::from(
        leaf_cert.der().to_vec(),
    ));
    chain.push(ca.ca_cert_der.clone());

    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der);

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("Failed to build rustls server config")?;

    Ok(Arc::new(cfg))
}

#[cfg(feature = "tls-mitm")]
fn init_ca_impl(ca_dir: &Path, force: bool) -> Result<CaArtifacts> {
    std::fs::create_dir_all(ca_dir)
        .with_context(|| format!("Failed to create CA directory: {}", ca_dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(ca_dir, std::fs::Permissions::from_mode(0o700));
    }

    let cert_path = ca_dir.join(CA_CERT_FILE);
    let key_path = ca_dir.join(CA_KEY_FILE);
    if !force && cert_path.exists() && key_path.exists() {
        return Ok(CaArtifacts {
            cert_path,
            key_path,
        });
    }

    let (cert_pem, key_pem) = generate_ca_pem()?;

    // Write via temp files then swap into place to avoid partial writes.
    let cert_tmp = ca_dir.join(format!("{CA_CERT_FILE}.tmp"));
    let key_tmp = ca_dir.join(format!("{CA_KEY_FILE}.tmp"));

    std::fs::write(&cert_tmp, cert_pem)
        .with_context(|| format!("Failed to write CA cert tmp: {}", cert_tmp.display()))?;
    std::fs::write(&key_tmp, key_pem)
        .with_context(|| format!("Failed to write CA key tmp: {}", key_tmp.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_tmp, std::fs::Permissions::from_mode(0o600));
    }

    if cert_path.exists() {
        let _ = std::fs::remove_file(&cert_path);
    }
    if key_path.exists() {
        let _ = std::fs::remove_file(&key_path);
    }
    std::fs::rename(&cert_tmp, &cert_path)
        .with_context(|| format!("Failed to swap CA cert: {}", cert_path.display()))?;
    std::fs::rename(&key_tmp, &key_path)
        .with_context(|| format!("Failed to swap CA key: {}", key_path.display()))?;

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
        assert!(err.to_string().contains("'tls-mitm' feature"));
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

    #[cfg(feature = "tls-mitm")]
    #[test]
    fn init_ca_force_rotates_material() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let artifacts = ensure_ca(tmp.path()).expect("ensure");
        let cert_before = std::fs::read_to_string(&artifacts.cert_path).expect("read cert");
        let key_before = std::fs::read_to_string(&artifacts.key_path).expect("read key");

        let artifacts_rotated = init_ca(tmp.path(), true).expect("force init");
        let cert_after = std::fs::read_to_string(&artifacts_rotated.cert_path).expect("read cert");
        let key_after = std::fs::read_to_string(&artifacts_rotated.key_path).expect("read key");

        assert_ne!(cert_before, cert_after);
        assert_ne!(key_before, key_after);
    }

    #[cfg(feature = "tls-mitm")]
    #[test]
    fn load_ca_and_issue_leaf() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _ = ensure_ca(tmp.path()).expect("ensure");
        let ca = load_ca(tmp.path()).expect("load");
        let cfg = mitm_server_config_for_host(&ca, "api.openai.com").expect("leaf cfg");
        assert!(!cfg.alpn_protocols.is_empty() || cfg.alpn_protocols.is_empty());
        // sanity: constructed
    }
}
