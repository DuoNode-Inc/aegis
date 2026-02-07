//! Configuration loading for Aegis.
//!
//! Loads from aegis.toml, merges CLI overrides, and falls back to sane defaults.
//! Config search order: --config flag > ./aegis.toml > ~/.aegis/aegis.toml

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AegisConfig {
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub detection: DetectionConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub endpoints: EndpointsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_tunnel_timeout_secs")]
    pub tunnel_timeout_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DetectionConfig {
    #[serde(default = "default_action")]
    pub default_action: String,
    #[serde(default = "default_confidence")]
    #[allow(dead_code)] // TODO(v0.2): used when ML scoring is added
    pub confidence_threshold: f64,
    #[serde(default)]
    pub injection: InjectionConfig,
    #[serde(default)]
    pub pii: PiiConfig,
    #[serde(default)]
    pub entropy: EntropyConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InjectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_injection_rules_path")]
    pub rules_path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PiiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_pii_rules_path")]
    pub rules_path: PathBuf,
    #[serde(default)]
    #[allow(dead_code)] // TODO(v0.2): per-detector action override
    pub action: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EntropyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_entropy_threshold")]
    pub threshold: f64,
    #[serde(default = "default_min_length")]
    pub min_length: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_output")]
    #[allow(dead_code)] // TODO(v0.2): configurable log output destination
    pub output: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EndpointsConfig {
    #[serde(default = "default_endpoints")]
    pub targets: Vec<String>,
}

// Default value functions
fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    8080
}
fn default_mode() -> String {
    "gateway".into()
}
fn default_action() -> String {
    "block".into()
}
fn default_confidence() -> f64 {
    0.8
}
fn default_true() -> bool {
    true
}
fn default_entropy_threshold() -> f64 {
    5.5
}
fn default_min_length() -> usize {
    100
}
fn default_log_format() -> String {
    "json".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_output() -> String {
    "stdout".into()
}
fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10 MB
}
fn default_max_connections() -> usize {
    1024
}
fn default_tunnel_timeout_secs() -> u64 {
    300 // 5 minutes idle timeout
}
fn default_injection_rules_path() -> PathBuf {
    PathBuf::from("rules/injection.rules")
}
fn default_pii_rules_path() -> PathBuf {
    PathBuf::from("rules/pii.rules")
}

fn default_endpoints() -> Vec<String> {
    vec![
        "api.openai.com".into(),
        "api.anthropic.com".into(),
        "generativelanguage.googleapis.com".into(),
        "api.cohere.com".into(),
        "api.mistral.ai".into(),
        "api.groq.com".into(),
        "api.together.xyz".into(),
        "api.fireworks.ai".into(),
        "api.perplexity.ai".into(),
        "api.deepseek.com".into(),
    ]
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            mode: default_mode(),
            max_body_size: default_max_body_size(),
            max_connections: default_max_connections(),
            tunnel_timeout_secs: default_tunnel_timeout_secs(),
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            default_action: default_action(),
            confidence_threshold: default_confidence(),
            injection: InjectionConfig::default(),
            pii: PiiConfig::default(),
            entropy: EntropyConfig::default(),
        }
    }
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_path: default_injection_rules_path(),
        }
    }
}

impl Default for PiiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_path: default_pii_rules_path(),
            action: None,
        }
    }
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_entropy_threshold(),
            min_length: default_min_length(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: default_log_format(),
            level: default_log_level(),
            output: default_log_output(),
        }
    }
}

impl Default for EndpointsConfig {
    fn default() -> Self {
        Self {
            targets: default_endpoints(),
        }
    }
}

/// Load config from file, falling back to defaults if no file is found.
pub fn load_config(path: Option<&Path>) -> Result<AegisConfig> {
    // Explicit path provided
    if let Some(p) = path {
        let contents = std::fs::read_to_string(p)
            .with_context(|| format!("Failed to read config file: {}", p.display()))?;
        let config: AegisConfig = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", p.display()))?;
        return Ok(config);
    }

    // Search default locations
    let search_paths = [
        PathBuf::from("aegis.toml"),
        dirs_or_home().join("aegis.toml"),
    ];

    for p in &search_paths {
        if p.exists() {
            let contents = std::fs::read_to_string(p)
                .with_context(|| format!("Failed to read config file: {}", p.display()))?;
            let config: AegisConfig = toml::from_str(&contents)
                .with_context(|| format!("Failed to parse config file: {}", p.display()))?;
            return Ok(config);
        }
    }

    // No config file found — use defaults
    Ok(AegisConfig::default())
}

fn dirs_or_home() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".aegis")
    } else {
        PathBuf::from(".aegis")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_config_values() {
        let config = AegisConfig::default();
        assert_eq!(config.proxy.host, "127.0.0.1");
        assert_eq!(config.proxy.port, 8080);
        assert_eq!(config.proxy.mode, "gateway");
        assert_eq!(config.proxy.max_body_size, 10 * 1024 * 1024);
        assert_eq!(config.proxy.max_connections, 1024);
        assert_eq!(config.proxy.tunnel_timeout_secs, 300);
        assert_eq!(config.detection.default_action, "block");
        assert!(config.detection.injection.enabled);
        assert!(config.detection.pii.enabled);
        assert!(config.detection.entropy.enabled);
        assert_eq!(config.detection.entropy.threshold, 5.5);
        assert_eq!(config.detection.entropy.min_length, 100);
        assert_eq!(config.logging.format, "json");
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.endpoints.targets.len(), 10);
    }

    #[test]
    fn default_endpoints_include_major_providers() {
        let config = AegisConfig::default();
        let targets = &config.endpoints.targets;
        assert!(targets.contains(&"api.openai.com".to_string()));
        assert!(targets.contains(&"api.anthropic.com".to_string()));
        assert!(targets.contains(&"api.deepseek.com".to_string()));
    }

    #[test]
    fn parse_minimal_toml() {
        let toml_str = r#"
[proxy]
port = 9090
"#;
        let config: AegisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proxy.port, 9090);
        // Everything else should be defaults
        assert_eq!(config.proxy.host, "127.0.0.1");
        assert_eq!(config.proxy.mode, "gateway");
    }

    #[test]
    fn parse_full_toml() {
        let toml_str = r#"
[proxy]
host = "0.0.0.0"
port = 3000
mode = "proxy"
max_body_size = 5242880
max_connections = 512
tunnel_timeout_secs = 120

[detection]
default_action = "flag"

[detection.injection]
enabled = false

[detection.entropy]
threshold = 4.0
min_length = 50

[logging]
format = "pretty"
level = "debug"

[endpoints]
targets = ["api.openai.com"]
"#;
        let config: AegisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proxy.host, "0.0.0.0");
        assert_eq!(config.proxy.port, 3000);
        assert_eq!(config.proxy.mode, "proxy");
        assert_eq!(config.proxy.max_body_size, 5242880);
        assert_eq!(config.proxy.max_connections, 512);
        assert_eq!(config.proxy.tunnel_timeout_secs, 120);
        assert_eq!(config.detection.default_action, "flag");
        assert!(!config.detection.injection.enabled);
        assert_eq!(config.detection.entropy.threshold, 4.0);
        assert_eq!(config.detection.entropy.min_length, 50);
        assert_eq!(config.logging.format, "pretty");
        assert_eq!(config.endpoints.targets.len(), 1);
    }

    #[test]
    fn invalid_toml_returns_error() {
        let bad = "this is not [valid toml";
        let result: Result<AegisConfig, _> = toml::from_str(bad);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_missing_file_uses_defaults() {
        // load_config with a non-existent explicit path should error
        let result = load_config(Some(Path::new("/nonexistent/aegis.toml")));
        assert!(result.is_err());
    }

    #[test]
    fn load_config_from_temp_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "[proxy]\nport = 7777\n").unwrap();
        let config = load_config(Some(tmp.path())).unwrap();
        assert_eq!(config.proxy.port, 7777);
    }

    #[test]
    fn apply_overrides_mode() {
        let config = AegisConfig::default();
        let config = apply_overrides(config, Some("proxy"), None, None);
        assert_eq!(config.proxy.mode, "proxy");
    }

    #[test]
    fn apply_overrides_host_and_port() {
        let config = AegisConfig::default();
        let config = apply_overrides(config, None, Some("0.0.0.0"), Some(9999));
        assert_eq!(config.proxy.host, "0.0.0.0");
        assert_eq!(config.proxy.port, 9999);
    }

    #[test]
    fn apply_overrides_none_preserves_defaults() {
        let config = AegisConfig::default();
        let config = apply_overrides(config, None, None, None);
        assert_eq!(config.proxy.host, "127.0.0.1");
        assert_eq!(config.proxy.port, 8080);
        assert_eq!(config.proxy.mode, "gateway");
    }
}

/// Apply CLI overrides on top of loaded config.
pub fn apply_overrides(
    mut config: AegisConfig,
    mode: Option<&str>,
    host: Option<&str>,
    port: Option<u16>,
) -> AegisConfig {
    if let Some(m) = mode {
        config.proxy.mode = m.to_string();
    }
    if let Some(h) = host {
        config.proxy.host = h.to_string();
    }
    if let Some(p) = port {
        config.proxy.port = p;
    }
    config
}
