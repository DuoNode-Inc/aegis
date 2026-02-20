//! Upstream TLS configuration helpers shared by proxy modes.
//!
//! We keep upstream TLS strict by default (WebPKI roots). For testing and
//! enterprise PKI environments, we optionally add extra roots from a PEM bundle.

use std::fs;
use std::io::BufReader;
use std::path::Path;

use anyhow::{Context, Result};

use crate::crypto;

pub fn build_rustls_client_config(
    extra_ca_bundle_path: Option<&Path>,
) -> Result<rustls::ClientConfig> {
    crypto::ensure_rustls_provider();
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = extra_ca_bundle_path {
        let pem = fs::read(path)
            .with_context(|| format!("Failed to read extra CA bundle: {}", path.display()))?;
        let mut reader = BufReader::new(pem.as_slice());
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("Failed to parse extra CA bundle PEM")?;
        let (added, _ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            anyhow::bail!(
                "Extra CA bundle parsed but no certificates were added (path: {})",
                path.display()
            );
        }
    }

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}
