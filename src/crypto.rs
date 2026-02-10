//! rustls CryptoProvider bootstrap.
//!
//! rustls 0.23 requires installing a process-wide CryptoProvider. We always
//! build with the `ring` provider enabled, so we install it once early.

use std::sync::OnceLock;

static INSTALLED: OnceLock<()> = OnceLock::new();

pub fn ensure_rustls_provider() {
    INSTALLED.get_or_init(|| {
        // Ignore errors if another caller already installed a provider.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
