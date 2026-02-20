//! Classifier model package catalog and runtime resolution.
//!
//! Packages map a friendly package id to expected local model/tokenizer paths
//! and a calibrated confidence threshold.

use std::path::PathBuf;

use anyhow::{anyhow, Result};

use crate::config::ClassifierConfig;
use crate::detection::classifier::ClassifierVerdict;

/// Static metadata describing a supported classifier package.
#[derive(Debug, Clone)]
pub struct ClassifierPackageSpec {
    pub id: &'static str,
    pub aliases: &'static [&'static str],
    pub source_model: &'static str,
    pub model_path: &'static str,
    pub tokenizer_path: &'static str,
    pub confidence_threshold: f64,
    pub class_map: &'static [ClassifierVerdict],
}

/// Resolved classifier runtime configuration after package processing.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedClassifierConfig {
    pub package: Option<String>,
    pub source_model: Option<String>,
    pub model_path: PathBuf,
    pub tokenizer_path: PathBuf,
    pub confidence_threshold: f64,
    pub class_map: Vec<ClassifierVerdict>,
}

const CLASS_MAP_CANONICAL_5: [ClassifierVerdict; 5] = [
    ClassifierVerdict::Safe,
    ClassifierVerdict::Injection,
    ClassifierVerdict::Jailbreak,
    ClassifierVerdict::Pii,
    ClassifierVerdict::Malicious,
];

const CLASS_MAP_SAFE_INJECTION: [ClassifierVerdict; 2] =
    [ClassifierVerdict::Safe, ClassifierVerdict::Injection];

const PACKAGE_PROTECTAI_DEBERTA_V3_BASE_PROMPT_INJECTION: ClassifierPackageSpec =
    ClassifierPackageSpec {
        id: "protectai_deberta_v3_base_prompt_injection",
        aliases: &[
            "protectai_prompt_injection",
            "protectai_deberta_prompt_injection",
            "pi_deberta_v3_base",
        ],
        source_model: "protectai/deberta-v3-base-prompt-injection",
        model_path: "models/packages/protectai_deberta_v3_base_prompt_injection/model.onnx",
        tokenizer_path: "models/packages/protectai_deberta_v3_base_prompt_injection/tokenizer.json",
        confidence_threshold: 0.85,
        class_map: &CLASS_MAP_SAFE_INJECTION,
    };

const PACKAGE_META_PROMPT_GUARD_22M: ClassifierPackageSpec = ClassifierPackageSpec {
    id: "meta_prompt_guard_22m",
    aliases: &["prompt_guard_22m", "llama_prompt_guard_2_22m", "pg2_22m"],
    source_model: "meta-llama/Llama-Prompt-Guard-2-22M",
    model_path: "models/packages/meta_prompt_guard_22m/model.onnx",
    tokenizer_path: "models/packages/meta_prompt_guard_22m/tokenizer.json",
    confidence_threshold: 0.76,
    class_map: &CLASS_MAP_SAFE_INJECTION,
};

const PACKAGE_META_PROMPT_GUARD_86M: ClassifierPackageSpec = ClassifierPackageSpec {
    id: "meta_prompt_guard_86m",
    aliases: &["prompt_guard_86m", "llama_prompt_guard_2_86m", "pg2_86m"],
    source_model: "meta-llama/Llama-Prompt-Guard-2-86M",
    model_path: "models/packages/meta_prompt_guard_86m/model.onnx",
    tokenizer_path: "models/packages/meta_prompt_guard_86m/tokenizer.json",
    confidence_threshold: 0.82,
    class_map: &CLASS_MAP_SAFE_INJECTION,
};

const PACKAGE_META_LLAMA_GUARD_4_12B_INT8: ClassifierPackageSpec = ClassifierPackageSpec {
    id: "meta_llama_guard_4_12b_int8",
    aliases: &["llama_guard_4_12b_int8", "llama_guard_4_12b", "lg4_12b"],
    source_model: "meta-llama/Llama-Guard-4-12B",
    model_path: "models/packages/meta_llama_guard_4_12b_int8/model.onnx",
    tokenizer_path: "models/packages/meta_llama_guard_4_12b_int8/tokenizer.json",
    confidence_threshold: 0.88,
    class_map: &CLASS_MAP_CANONICAL_5,
};

const PACKAGE_NVIDIA_NEMOTRON_70B_ADAPTER: ClassifierPackageSpec = ClassifierPackageSpec {
    id: "nvidia_nemotron_70b_guard_adapter",
    aliases: &["nemotron_70b_guard_adapter", "nemotron_70b"],
    source_model: "nvidia/Llama-3.1-Nemotron-70B-Instruct-HF",
    model_path: "models/packages/nvidia_nemotron_70b_guard_adapter/model.onnx",
    tokenizer_path: "models/packages/nvidia_nemotron_70b_guard_adapter/tokenizer.json",
    confidence_threshold: 0.86,
    class_map: &CLASS_MAP_CANONICAL_5,
};

const PACKAGE_DEEPSEEK_R1_DISTILL_70B_ADAPTER: ClassifierPackageSpec = ClassifierPackageSpec {
    id: "deepseek_r1_distill_70b_guard_adapter",
    aliases: &["deepseek_r1_distill_70b", "deepseek_r1_guard_adapter"],
    source_model: "deepseek-ai/DeepSeek-R1-Distill-Llama-70B",
    model_path: "models/packages/deepseek_r1_distill_70b_guard_adapter/model.onnx",
    tokenizer_path: "models/packages/deepseek_r1_distill_70b_guard_adapter/tokenizer.json",
    confidence_threshold: 0.87,
    class_map: &CLASS_MAP_CANONICAL_5,
};

pub const CLASSIFIER_PACKAGES: &[ClassifierPackageSpec] = &[
    PACKAGE_PROTECTAI_DEBERTA_V3_BASE_PROMPT_INJECTION,
    PACKAGE_META_PROMPT_GUARD_22M,
    PACKAGE_META_PROMPT_GUARD_86M,
    PACKAGE_META_LLAMA_GUARD_4_12B_INT8,
    PACKAGE_NVIDIA_NEMOTRON_70B_ADAPTER,
    PACKAGE_DEEPSEEK_R1_DISTILL_70B_ADAPTER,
];

pub fn resolve_classifier_config(config: &ClassifierConfig) -> Result<ResolvedClassifierConfig> {
    let mut resolved = ResolvedClassifierConfig {
        package: None,
        source_model: None,
        model_path: config.model_path.clone(),
        tokenizer_path: config.tokenizer_path.clone(),
        confidence_threshold: config.confidence_threshold,
        class_map: CLASS_MAP_CANONICAL_5.to_vec(),
    };

    if !config.enabled {
        // Preserve v0.1/v0.2 Shield behavior: package metadata should not
        // affect startup unless classifier execution is enabled.
        return Ok(resolved);
    }

    let Some(package_name) = config.package.as_deref() else {
        return Ok(resolved);
    };

    let spec = find_package(package_name).ok_or_else(|| {
        anyhow!(
            "Unknown classifier package '{}'. Supported packages: {}",
            package_name,
            supported_package_ids().join(", ")
        )
    })?;

    resolved.package = Some(spec.id.to_string());
    resolved.source_model = Some(spec.source_model.to_string());
    resolved.class_map = spec.class_map.to_vec();

    if config.use_package_defaults {
        resolved.model_path = PathBuf::from(spec.model_path);
        resolved.tokenizer_path = PathBuf::from(spec.tokenizer_path);
        resolved.confidence_threshold = spec.confidence_threshold;
    }

    Ok(resolved)
}

fn find_package(input: &str) -> Option<&'static ClassifierPackageSpec> {
    let normalized = normalize_package_name(input);
    CLASSIFIER_PACKAGES
        .iter()
        .find(|spec| spec.id == normalized || spec.aliases.iter().any(|alias| *alias == normalized))
}

fn normalize_package_name(input: &str) -> String {
    input.trim().to_ascii_lowercase().replace('-', "_")
}

fn supported_package_ids() -> Vec<&'static str> {
    CLASSIFIER_PACKAGES.iter().map(|spec| spec.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClassifierConfig;

    #[test]
    fn no_package_uses_explicit_paths() {
        let config = ClassifierConfig::default();
        let resolved = resolve_classifier_config(&config).expect("resolve");
        assert_eq!(resolved.package, None);
        assert_eq!(
            resolved.model_path,
            PathBuf::from("models/neural-shield.onnx")
        );
        assert_eq!(resolved.confidence_threshold, 0.85);
        assert_eq!(resolved.class_map, CLASS_MAP_CANONICAL_5.to_vec());
    }

    #[test]
    fn known_package_applies_defaults() {
        let mut config = ClassifierConfig::default();
        config.enabled = true;
        config.package = Some("prompt_guard_86m".into());
        let resolved = resolve_classifier_config(&config).expect("resolve");
        assert_eq!(resolved.package.as_deref(), Some("meta_prompt_guard_86m"));
        assert_eq!(
            resolved.source_model.as_deref(),
            Some("meta-llama/Llama-Prompt-Guard-2-86M")
        );
        assert_eq!(
            resolved.model_path,
            PathBuf::from("models/packages/meta_prompt_guard_86m/model.onnx")
        );
        assert_eq!(resolved.confidence_threshold, 0.82);
        assert_eq!(resolved.class_map, CLASS_MAP_SAFE_INJECTION.to_vec());
    }

    #[test]
    fn package_defaults_can_be_disabled() {
        let mut config = ClassifierConfig::default();
        config.enabled = true;
        config.package = Some("meta_llama_guard_4_12b_int8".into());
        config.use_package_defaults = false;
        config.model_path = PathBuf::from("models/custom/model.onnx");
        config.tokenizer_path = PathBuf::from("models/custom/tokenizer.json");
        config.confidence_threshold = 0.93;

        let resolved = resolve_classifier_config(&config).expect("resolve");
        assert_eq!(
            resolved.package.as_deref(),
            Some("meta_llama_guard_4_12b_int8")
        );
        assert_eq!(
            resolved.model_path,
            PathBuf::from("models/custom/model.onnx")
        );
        assert_eq!(
            resolved.tokenizer_path,
            PathBuf::from("models/custom/tokenizer.json")
        );
        assert_eq!(resolved.confidence_threshold, 0.93);
    }

    #[test]
    fn package_name_accepts_hyphen_aliases() {
        let mut config = ClassifierConfig::default();
        config.enabled = true;
        config.package = Some("meta-prompt-guard-22m".into());
        let resolved = resolve_classifier_config(&config).expect("resolve");
        assert_eq!(resolved.package.as_deref(), Some("meta_prompt_guard_22m"));
    }

    #[test]
    fn unknown_package_errors() {
        let mut config = ClassifierConfig::default();
        config.enabled = true;
        config.package = Some("not-real".into());
        let err = resolve_classifier_config(&config).expect_err("must fail");
        assert!(err.to_string().contains("Unknown classifier package"));
    }

    #[test]
    fn disabled_classifier_ignores_package_validation() {
        let mut config = ClassifierConfig::default();
        config.enabled = false;
        config.package = Some("not-real".into());
        let resolved = resolve_classifier_config(&config).expect("resolve");
        assert_eq!(resolved.package, None);
    }
}
