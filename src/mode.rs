//! Runtime mode detection for Aiegis.
//!
//! Realm OS mode is enabled when a Realm-managed config is present.

use std::path::Path;

/// Canonical Realm OS config location used for mode detection.
pub const REALM_CONFIG_PATH: &str = "/etc/realm/aiegis.toml";

/// Runtime execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    /// Running as part of Realm OS.
    RealmOs,
    /// Standalone binary mode.
    Standalone,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeMode::RealmOs => "realm_os",
            RuntimeMode::Standalone => "standalone",
        }
    }
}

/// Detect runtime mode using the canonical Realm config path.
pub fn detect_mode() -> RuntimeMode {
    detect_mode_at(Path::new(REALM_CONFIG_PATH))
}

/// Detect runtime mode using a specific path (used by tests).
pub fn detect_mode_at(path: &Path) -> RuntimeMode {
    if path.exists() {
        RuntimeMode::RealmOs
    } else {
        RuntimeMode::Standalone
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detect_mode_realm_os_when_file_exists() {
        let file = tempfile::NamedTempFile::new().expect("create temp file");
        let mode = detect_mode_at(file.path());
        assert_eq!(mode, RuntimeMode::RealmOs);
    }

    #[test]
    fn detect_mode_standalone_when_file_missing() {
        let missing = PathBuf::from("/tmp/aiegis-mode-test-not-present.toml");
        let mode = detect_mode_at(&missing);
        assert_eq!(mode, RuntimeMode::Standalone);
    }
}
