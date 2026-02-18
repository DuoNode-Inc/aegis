//! Configuration loading for Aiegis.
//!
//! Loads from aiegis.toml, merges CLI overrides, and falls back to sane defaults.
//! Config search order: --config flag > ./aiegis.toml > ~/.aiegis/aiegis.toml

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const DEFAULT_INJECTION_RULES_PATH: &str = "rules/injection.rules";
pub const DEFAULT_PII_RULES_PATH: &str = "rules/pii.rules";

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AiegisConfig {
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub detection: DetectionConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub endpoints: EndpointsConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct RuntimeConfig {
    /// Optional explicit tier override. If omitted, tier defaults by runtime mode.
    #[serde(default)]
    pub tier: Option<String>,
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
    #[serde(default)]
    pub upstream_tls: UpstreamTlsConfig,
    #[serde(default)]
    pub tls_mitm: TlsMitmConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct UpstreamTlsConfig {
    /// Optional extra CA bundle PEM to trust for upstream TLS connections.
    /// Useful for testing with local self-signed upstreams or enterprise PKI roots.
    #[serde(default)]
    pub extra_ca_bundle_path: Option<PathBuf>,
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
    pub web3: Option<Web3Config>,
    #[serde(default)]
    pub entropy: EntropyConfig,
    #[serde(default)]
    pub classifier: ClassifierConfig,
    #[serde(default)]
    pub llm: LlmConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Web3Config {
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// Sensitivity mode: "strict", "normal", "permissive".
    #[serde(default = "default_web3_sensitivity")]
    pub sensitivity: String,
}

impl Default for Web3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            sensitivity: default_web3_sensitivity(),
        }
    }
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
pub struct TlsMitmConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_tls_ca_dir")]
    pub ca_dir: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClassifierConfig {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default)]
    pub package: Option<String>,
    #[serde(default = "default_classifier_use_package_defaults")]
    pub use_package_defaults: bool,
    #[serde(default = "default_classifier_model_path")]
    pub model_path: PathBuf,
    #[serde(default = "default_classifier_tokenizer_path")]
    pub tokenizer_path: PathBuf,
    #[serde(default = "default_classifier_confidence_threshold")]
    pub confidence_threshold: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LlmConfig {
    /// Enable local LLM escalation (NO CLOUD). Requires a build with `--features llm-local`.
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// Path to GGUF weights on disk (bundled offline in production artifacts).
    #[serde(default = "default_llm_model_path")]
    pub model_path: PathBuf,
    /// Output contract mode for the local LLM classifier.
    ///
    /// - `json`: strict JSON object `{verdict, confidence, reason}` (more tokens, slower)
    /// - `label`: single label only (fast): `safe|injection|jailbreak|pii|malicious|ambiguous`
    #[serde(default = "default_llm_output_mode")]
    pub output_mode: String,
    /// Number of layers to offload to the GPU (llama.cpp `n_gpu_layers`).
    ///
    /// - `0`: CPU-only
    /// - `>0`: offload that many layers (requires a GPU-enabled build of llama.cpp)
    #[serde(default = "default_llm_gpu_layers")]
    pub gpu_layers: i32,
    /// Optional system prompt file to load at startup ("policy-as-code" entrypoint).
    #[serde(default)]
    pub system_prompt_path: Option<PathBuf>,
    /// llama.cpp context size (tokens). Keep within device RAM limits.
    #[serde(default = "default_llm_n_ctx")]
    pub n_ctx: u32,
    /// llama.cpp threads to use for inference.
    #[serde(default = "default_llm_threads")]
    pub threads: i32,
    /// Maximum tokens to generate for the JSON output.
    #[serde(default = "default_llm_max_tokens")]
    pub max_tokens: usize,
    /// Minimum confidence required to apply the LLM verdict (otherwise remain AMBIGUOUS).
    #[serde(default = "default_llm_confidence_threshold")]
    pub confidence_threshold: f64,
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
fn default_classifier_confidence_threshold() -> f64 {
    0.85
}
fn default_classifier_use_package_defaults() -> bool {
    true
}
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
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
fn default_tls_ca_dir() -> PathBuf {
    PathBuf::from(".aiegis/ca")
}
fn default_injection_rules_path() -> PathBuf {
    PathBuf::from(DEFAULT_INJECTION_RULES_PATH)
}
fn default_pii_rules_path() -> PathBuf {
    PathBuf::from(DEFAULT_PII_RULES_PATH)
}
fn default_classifier_model_path() -> PathBuf {
    PathBuf::from("models/neural-shield.onnx")
}
fn default_classifier_tokenizer_path() -> PathBuf {
    PathBuf::from("models/neural-shield-tokenizer.json")
}
fn default_llm_model_path() -> PathBuf {
    // Bundles copy GGUFs under models/llm/*.gguf by default.
    PathBuf::from("models/llm/model.gguf")
}
fn default_llm_output_mode() -> String {
    "json".into()
}
fn default_llm_gpu_layers() -> i32 {
    0
}
fn default_llm_n_ctx() -> u32 {
    2048
}
fn default_llm_threads() -> i32 {
    4
}
fn default_llm_max_tokens() -> usize {
    // JSON verdict is typically ~20-30 tokens ({verdict, confidence, reason}).
    // Grammar + early JSON parse stop terminates generation before hitting this cap.
    48
}
fn default_llm_confidence_threshold() -> f64 {
    0.80
}

fn default_web3_sensitivity() -> String {
    "normal".into()
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
            upstream_tls: UpstreamTlsConfig::default(),
            tls_mitm: TlsMitmConfig::default(),
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
            web3: None,
            entropy: EntropyConfig::default(),
            classifier: ClassifierConfig::default(),
            llm: LlmConfig::default(),
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

impl Default for TlsMitmConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            ca_dir: default_tls_ca_dir(),
        }
    }
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            package: None,
            use_package_defaults: default_classifier_use_package_defaults(),
            model_path: default_classifier_model_path(),
            tokenizer_path: default_classifier_tokenizer_path(),
            confidence_threshold: default_classifier_confidence_threshold(),
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            model_path: default_llm_model_path(),
            output_mode: default_llm_output_mode(),
            gpu_layers: default_llm_gpu_layers(),
            system_prompt_path: None,
            n_ctx: default_llm_n_ctx(),
            threads: default_llm_threads(),
            max_tokens: default_llm_max_tokens(),
            confidence_threshold: default_llm_confidence_threshold(),
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

impl AiegisConfig {
    /// Whether non-default detector rule file paths are configured.
    pub fn uses_custom_pattern_paths(&self) -> bool {
        self.detection.injection.rules_path != Path::new(DEFAULT_INJECTION_RULES_PATH)
            || self.detection.pii.rules_path != Path::new(DEFAULT_PII_RULES_PATH)
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
pub fn load_config(path: Option<&Path>) -> Result<AiegisConfig> {
    // Explicit path provided
    if let Some(p) = path {
        let contents = std::fs::read_to_string(p)
            .with_context(|| format!("Failed to read config file: {}", p.display()))?;
        let config: AiegisConfig = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", p.display()))?;
        return Ok(config);
    }

    // Search default locations
    let search_paths = [
        PathBuf::from("aiegis.toml"),
        dirs_or_home().join("aiegis.toml"),
    ];

    for p in &search_paths {
        if p.exists() {
            let contents = std::fs::read_to_string(p)
                .with_context(|| format!("Failed to read config file: {}", p.display()))?;
            let config: AiegisConfig = toml::from_str(&contents)
                .with_context(|| format!("Failed to parse config file: {}", p.display()))?;
            return Ok(config);
        }
    }

    // No config file found — use defaults
    Ok(AiegisConfig::default())
}

fn dirs_or_home() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".aiegis")
    } else {
        PathBuf::from(".aiegis")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn default_config_values() {
        let config = AiegisConfig::default();
        assert!(config.runtime.tier.is_none());
        assert_eq!(config.proxy.host, "127.0.0.1");
        assert_eq!(config.proxy.port, 8080);
        assert_eq!(config.proxy.mode, "gateway");
        assert_eq!(config.proxy.max_body_size, 10 * 1024 * 1024);
        assert_eq!(config.proxy.max_connections, 1024);
        assert_eq!(config.proxy.tunnel_timeout_secs, 300);
        assert!(!config.proxy.tls_mitm.enabled);
        assert_eq!(config.proxy.tls_mitm.ca_dir, PathBuf::from(".aiegis/ca"));
        assert_eq!(config.detection.default_action, "block");
        assert!(config.detection.injection.enabled);
        assert!(config.detection.pii.enabled);
        assert!(config.detection.entropy.enabled);
        assert!(!config.detection.classifier.enabled);
        assert_eq!(config.detection.classifier.package, None);
        assert!(config.detection.classifier.use_package_defaults);
        assert_eq!(
            config.detection.classifier.model_path,
            PathBuf::from("models/neural-shield.onnx")
        );
        assert_eq!(
            config.detection.classifier.tokenizer_path,
            PathBuf::from("models/neural-shield-tokenizer.json")
        );
        assert_eq!(config.detection.classifier.confidence_threshold, 0.85);
        assert!(!config.detection.llm.enabled);
        assert_eq!(
            config.detection.llm.model_path,
            PathBuf::from("models/llm/model.gguf")
        );
        assert_eq!(config.detection.llm.output_mode, "json");
        assert_eq!(config.detection.llm.gpu_layers, 0);
        assert_eq!(config.detection.llm.n_ctx, 2048);
        assert_eq!(config.detection.llm.threads, 4);
        assert_eq!(config.detection.llm.max_tokens, 48);
        assert_eq!(config.detection.llm.confidence_threshold, 0.80);
        assert_eq!(config.detection.entropy.threshold, 5.5);
        assert_eq!(config.detection.entropy.min_length, 100);
        assert_eq!(config.logging.format, "json");
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.endpoints.targets.len(), 10);
    }

    #[test]
    fn default_endpoints_include_major_providers() {
        let config = AiegisConfig::default();
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
        let config: AiegisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proxy.port, 9090);
        // Everything else should be defaults
        assert_eq!(config.proxy.host, "127.0.0.1");
        assert_eq!(config.proxy.mode, "gateway");
    }

    #[test]
    fn parse_v01_toml_without_new_sections() {
        let toml_str = r#"
[proxy]
host = "127.0.0.1"
port = 8080
mode = "gateway"

[detection]
default_action = "block"
confidence_threshold = 0.8

[detection.injection]
enabled = true
rules_path = "rules/injection.rules"

[detection.pii]
enabled = true
rules_path = "rules/pii.rules"

[detection.entropy]
enabled = true
threshold = 5.5
min_length = 100

[logging]
format = "json"
level = "info"
output = "stdout"
"#;

        let config: AiegisConfig = toml::from_str(toml_str).unwrap();
        assert!(config.runtime.tier.is_none());
        assert!(!config.proxy.tls_mitm.enabled);
        assert!(!config.detection.classifier.enabled);
        assert_eq!(config.detection.classifier.package, None);
        assert!(config.detection.classifier.use_package_defaults);
        assert_eq!(
            config.detection.classifier.tokenizer_path,
            PathBuf::from("models/neural-shield-tokenizer.json")
        );
    }

    #[test]
    fn parse_classifier_package_fields() {
        let toml_str = r#"
[detection.classifier]
enabled = true
package = "meta_llama_guard_4_12b_int8"
use_package_defaults = false
model_path = "models/custom/model.onnx"
tokenizer_path = "models/custom/tokenizer.json"
confidence_threshold = 0.92
"#;

        let config: AiegisConfig = toml::from_str(toml_str).unwrap();
        assert!(config.detection.classifier.enabled);
        assert_eq!(
            config.detection.classifier.package.as_deref(),
            Some("meta_llama_guard_4_12b_int8")
        );
        assert!(!config.detection.classifier.use_package_defaults);
        assert_eq!(
            config.detection.classifier.model_path,
            PathBuf::from("models/custom/model.onnx")
        );
        assert_eq!(config.detection.classifier.confidence_threshold, 0.92);
    }

    #[test]
    fn parse_llm_fields() {
        let toml_str = r#"
[detection.llm]
enabled = true
model_path = "models/llm/custom.gguf"
output_mode = "json"
gpu_layers = 0
system_prompt_path = "policies/healthcare/system.txt"
n_ctx = 4096
threads = 8
max_tokens = 128
confidence_threshold = 0.9
"#;

        let config: AiegisConfig = toml::from_str(toml_str).unwrap();
        assert!(config.detection.llm.enabled);
        assert_eq!(
            config.detection.llm.model_path,
            PathBuf::from("models/llm/custom.gguf")
        );
        assert_eq!(config.detection.llm.output_mode, "json");
        assert_eq!(config.detection.llm.gpu_layers, 0);
        assert_eq!(
            config.detection.llm.system_prompt_path,
            Some(PathBuf::from("policies/healthcare/system.txt"))
        );
        assert_eq!(config.detection.llm.n_ctx, 4096);
        assert_eq!(config.detection.llm.threads, 8);
        assert_eq!(config.detection.llm.max_tokens, 128);
        assert_eq!(config.detection.llm.confidence_threshold, 0.9);
    }

    #[test]
    fn parse_full_toml() {
        let toml_str = r#"
[runtime]
tier = "developer"

[proxy]
host = "0.0.0.0"
port = 3000
mode = "proxy"
max_body_size = 5242880
max_connections = 512
tunnel_timeout_secs = 120

[proxy.tls_mitm]
enabled = true
ca_dir = ".aiegis/dev-ca"

[detection]
default_action = "flag"

[detection.injection]
enabled = false

[detection.entropy]
threshold = 4.0
min_length = 50

[detection.classifier]
enabled = true
package = "meta_prompt_guard_86m"
use_package_defaults = true
model_path = "models/dev.onnx"
tokenizer_path = "models/dev-tokenizer.json"
confidence_threshold = 0.91

[logging]
format = "pretty"
level = "debug"

[endpoints]
targets = ["api.openai.com"]
"#;
        let config: AiegisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proxy.host, "0.0.0.0");
        assert_eq!(config.proxy.port, 3000);
        assert_eq!(config.proxy.mode, "proxy");
        assert_eq!(config.proxy.max_body_size, 5242880);
        assert_eq!(config.proxy.max_connections, 512);
        assert_eq!(config.proxy.tunnel_timeout_secs, 120);
        assert!(config.proxy.tls_mitm.enabled);
        assert_eq!(
            config.proxy.tls_mitm.ca_dir,
            PathBuf::from(".aiegis/dev-ca")
        );
        assert_eq!(config.detection.default_action, "flag");
        assert!(!config.detection.injection.enabled);
        assert_eq!(config.detection.entropy.threshold, 4.0);
        assert_eq!(config.detection.entropy.min_length, 50);
        assert!(config.detection.classifier.enabled);
        assert_eq!(
            config.detection.classifier.package.as_deref(),
            Some("meta_prompt_guard_86m")
        );
        assert!(config.detection.classifier.use_package_defaults);
        assert_eq!(
            config.detection.classifier.model_path,
            PathBuf::from("models/dev.onnx")
        );
        assert_eq!(
            config.detection.classifier.tokenizer_path,
            PathBuf::from("models/dev-tokenizer.json")
        );
        assert_eq!(config.detection.classifier.confidence_threshold, 0.91);
        assert_eq!(config.logging.format, "pretty");
        assert_eq!(config.endpoints.targets.len(), 1);
        assert_eq!(config.runtime.tier.as_deref(), Some("developer"));
    }

    #[test]
    fn invalid_toml_returns_error() {
        let bad = "this is not [valid toml";
        let result: Result<AiegisConfig, _> = toml::from_str(bad);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_missing_file_uses_defaults() {
        // load_config with a non-existent explicit path should error
        let result = load_config(Some(Path::new("/nonexistent/aiegis.toml")));
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
        let config = AiegisConfig::default();
        let config = apply_overrides(config, Some("proxy"), None, None);
        assert_eq!(config.proxy.mode, "proxy");
    }

    #[test]
    fn apply_overrides_host_and_port() {
        let config = AiegisConfig::default();
        let config = apply_overrides(config, None, Some("0.0.0.0"), Some(9999));
        assert_eq!(config.proxy.host, "0.0.0.0");
        assert_eq!(config.proxy.port, 9999);
    }

    #[test]
    fn apply_overrides_none_preserves_defaults() {
        let config = AiegisConfig::default();
        let config = apply_overrides(config, None, None, None);
        assert_eq!(config.proxy.host, "127.0.0.1");
        assert_eq!(config.proxy.port, 8080);
        assert_eq!(config.proxy.mode, "gateway");
    }

    #[test]
    fn custom_pattern_paths_detection() {
        let mut config = AiegisConfig::default();
        assert!(!config.uses_custom_pattern_paths());

        config.detection.injection.rules_path = PathBuf::from("rules/custom.rules");
        assert!(config.uses_custom_pattern_paths());
    }
}

/// Apply CLI overrides on top of loaded config.
pub fn apply_overrides(
    mut config: AiegisConfig,
    mode: Option<&str>,
    host: Option<&str>,
    port: Option<u16>,
) -> AiegisConfig {
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
