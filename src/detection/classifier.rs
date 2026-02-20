//! Classifier abstraction for neural escalation in the detection pipeline.
//!
//! The ONNX-backed implementation is introduced later; this module defines
//! the interface and deterministic fallback behavior used by tests.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};

#[cfg(feature = "neural")]
use std::cmp::Ordering;

#[cfg(feature = "neural")]
use anyhow::Context;

#[cfg(feature = "neural")]
use super::tokenizer::{fallback_token_ids, MAX_CLASSIFIER_TOKENS};

#[cfg(feature = "neural")]
use std::sync::Mutex;

#[cfg(feature = "neural")]
use ort::{inputs, session::Session, value::Tensor};

#[cfg(feature = "neural")]
use tokenizers::Tokenizer;

/// Canonical classifier output labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // constructed in feature-gated paths and test coverage
pub enum ClassifierVerdict {
    Safe,
    Injection,
    Jailbreak,
    Pii,
    Malicious,
}

impl ClassifierVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            ClassifierVerdict::Safe => "safe",
            ClassifierVerdict::Injection => "injection",
            ClassifierVerdict::Jailbreak => "jailbreak",
            ClassifierVerdict::Pii => "pii",
            ClassifierVerdict::Malicious => "malicious",
        }
    }

    #[allow(dead_code)]
    pub fn parse(label: &str) -> Result<Self> {
        match label.to_ascii_lowercase().as_str() {
            "safe" => Ok(ClassifierVerdict::Safe),
            "injection" => Ok(ClassifierVerdict::Injection),
            "jailbreak" => Ok(ClassifierVerdict::Jailbreak),
            "pii" => Ok(ClassifierVerdict::Pii),
            "malicious" => Ok(ClassifierVerdict::Malicious),
            other => Err(anyhow!(
                "Unknown classifier label '{other}'. Expected: safe|injection|jailbreak|pii|malicious"
            )),
        }
    }

    #[allow(dead_code)]
    fn from_index(index: usize) -> Result<Self> {
        match index {
            0 => Ok(ClassifierVerdict::Safe),
            1 => Ok(ClassifierVerdict::Injection),
            2 => Ok(ClassifierVerdict::Jailbreak),
            3 => Ok(ClassifierVerdict::Pii),
            4 => Ok(ClassifierVerdict::Malicious),
            other => Err(anyhow!(
                "Model returned class index {other}, expected 0..=4 (safe|injection|jailbreak|pii|malicious)"
            )),
        }
    }
}

/// Neural classifier result.
#[derive(Debug, Clone)]
pub struct ClassifierResult {
    pub verdict: ClassifierVerdict,
    pub confidence: f64,
}

/// Classifier interface used by the detection pipeline.
pub trait Classifier: Send + Sync {
    fn classify(&self, input: &str) -> Result<ClassifierResult>;
}

/// Build a classifier instance from runtime config.
pub fn build_classifier(
    enabled: bool,
    package: Option<&str>,
    class_map: &[ClassifierVerdict],
    model_path: &Path,
    tokenizer_path: &Path,
) -> Result<Option<Arc<dyn Classifier>>> {
    if !enabled {
        return Ok(None);
    }
    build_enabled_classifier(package, class_map, model_path, tokenizer_path).map(Some)
}

#[cfg(feature = "neural")]
fn build_enabled_classifier(
    package: Option<&str>,
    class_map: &[ClassifierVerdict],
    model_path: &Path,
    tokenizer_path: &Path,
) -> Result<Arc<dyn Classifier>> {
    let classifier = OnnxClassifier::load(package, class_map, model_path, tokenizer_path)?;
    Ok(Arc::new(classifier))
}

#[cfg(not(feature = "neural"))]
fn build_enabled_classifier(
    package: Option<&str>,
    class_map: &[ClassifierVerdict],
    model_path: &Path,
    tokenizer_path: &Path,
) -> Result<Arc<dyn Classifier>> {
    let _ = (package, class_map, model_path, tokenizer_path);
    Err(anyhow!(
        "Neural classifier is enabled in config, but this binary was built without the 'neural' feature. Rebuild with: cargo build --features neural"
    ))
}

/// Placeholder classifier used in unit tests.
#[cfg(test)]
pub struct NoopClassifier;

#[cfg(test)]
impl Classifier for NoopClassifier {
    fn classify(&self, _input: &str) -> Result<ClassifierResult> {
        // Route through the shared label parser so label mapping behavior stays
        // consistent with the future ONNX-backed classifier.
        let verdict = ClassifierVerdict::parse("safe")?;
        Ok(ClassifierResult {
            verdict,
            confidence: 0.0,
        })
    }
}

#[cfg(feature = "neural")]
pub struct OnnxClassifier {
    session: Mutex<Session>,
    tokenizer: Option<Tokenizer>,
    class_map: Vec<ClassifierVerdict>,
}

#[cfg(feature = "neural")]
impl OnnxClassifier {
    pub fn load(
        package: Option<&str>,
        class_map: &[ClassifierVerdict],
        model_path: &Path,
        tokenizer_path: &Path,
    ) -> Result<Self> {
        if class_map.len() < 2 {
            return Err(anyhow!(
                "Classifier class_map must contain at least 2 labels (got {})",
                class_map.len()
            ));
        }
        let class_map = class_map.to_vec();

        // `package` is only needed for embedded fallback (feature-gated). Avoid
        // unused warnings in neural-only builds.
        #[cfg(not(feature = "embed-models"))]
        let _ = package;

        #[cfg(feature = "embed-models")]
        let embedded_pkg = package.and_then(|pkg| super::embedded::get(pkg).map(|e| (pkg, e)));
        #[cfg(feature = "embed-models")]
        let disk_override = matches!(std::env::var("AIEGIS_DISK_MODEL_OVERRIDE"), Ok(v) if v == "1" || v.eq_ignore_ascii_case("true"));
        #[cfg(feature = "embed-models")]
        let prefer_embedded = embedded_pkg.is_some() && !disk_override;

        let session = {
            #[cfg(feature = "embed-models")]
            {
                if prefer_embedded {
                    let (pkg, embedded) = embedded_pkg.expect("checked Some");
                    return Ok(Self {
                        session: Mutex::new(
                            Session::builder()
                                .context("Failed to initialize ONNX Runtime session builder")?
                                .commit_from_memory(embedded.model)
                                .with_context(|| {
                                    format!("Failed to load embedded ONNX model bytes for package '{pkg}'")
                                })?,
                        ),
                        tokenizer: Some(
                            Tokenizer::from_bytes(embedded.tokenizer).map_err(|err| {
                                anyhow!("Failed to load embedded tokenizer for package '{pkg}': {err}")
                            })?,
                        ),
                        class_map,
                    });
                }
            }

            if !model_path.exists() {
                #[cfg(feature = "embed-models")]
                {
                    if let Some((pkg, _)) = embedded_pkg {
                        return Err(anyhow!(
                            "Classifier model file does not exist: {} (embedded model '{}' is available, but AIEGIS_DISK_MODEL_OVERRIDE=1 forced disk load)",
                            model_path.display(),
                            pkg
                        ));
                    }
                }
                return Err(anyhow!(
                    "Classifier model file does not exist: {}",
                    model_path.display()
                ));
            }

            Session::builder()
                .context("Failed to initialize ONNX Runtime session builder")?
                .commit_from_file(model_path)
                .with_context(|| format!("Failed to load ONNX model: {}", model_path.display()))?
        };

        let tokenizer =
            if tokenizer_path.exists() {
                Some(Tokenizer::from_file(tokenizer_path).map_err(|err| {
                    anyhow!(
                        "Failed to load tokenizer {}: {err}",
                        tokenizer_path.display()
                    )
                })?)
            } else {
                #[cfg(feature = "embed-models")]
                {
                    // In embed-models builds we prefer embedded tokenizer bytes (handled above)
                    // unless disk override was enabled.
                    if disk_override {
                        None
                    } else {
                        embedded_pkg
                            .map(|(pkg, embedded)| {
                                Tokenizer::from_bytes(embedded.tokenizer).map_err(|err| {
                            anyhow!("Failed to load embedded tokenizer for package '{pkg}': {err}")
                        })
                            })
                            .transpose()?
                    }
                }

                #[cfg(not(feature = "embed-models"))]
                {
                    None
                }
            };

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            class_map,
        })
    }

    fn encode_ids(&self, input: &str) -> Result<Vec<i64>> {
        if let Some(tokenizer) = &self.tokenizer {
            let encoding = tokenizer
                .encode(input, true)
                .map_err(|err| anyhow!("Tokenizer encode failed: {err}"))?;
            let mut ids: Vec<i64> = encoding
                .get_ids()
                .iter()
                .take(MAX_CLASSIFIER_TOKENS)
                .map(|id| i64::from(*id))
                .collect();
            if ids.is_empty() {
                ids.push(0);
            }
            return Ok(ids);
        }

        let mut fallback = fallback_token_ids(input);
        if fallback.is_empty() {
            fallback.push(0);
        }
        Ok(fallback)
    }

    fn run_logits(&self, token_ids: &[i64]) -> Result<Vec<f32>> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| anyhow!("ONNX session lock poisoned"))?;

        let sequence_len = token_ids.len() as i64;
        let outputs = match session.inputs().len() {
            0 => return Err(anyhow!("ONNX model has no input tensors")),
            1 => {
                let input_ids =
                    Tensor::<i64>::from_array(([1i64, sequence_len], token_ids.to_vec()))
                        .context("Failed to build input_ids tensor")?;
                session
                    .run(inputs![input_ids])
                    .context("ONNX inference failed")?
            }
            2 => {
                let input_ids =
                    Tensor::<i64>::from_array(([1i64, sequence_len], token_ids.to_vec()))
                        .context("Failed to build input_ids tensor")?;
                let attention_mask =
                    Tensor::<i64>::from_array(([1i64, sequence_len], vec![1i64; token_ids.len()]))
                        .context("Failed to build attention_mask tensor")?;
                session
                    .run(inputs![input_ids, attention_mask])
                    .context("ONNX inference failed")?
            }
            n => {
                return Err(anyhow!(
                    "ONNX model expects {n} inputs; current classifier supports 1 or 2 input tensors"
                ));
            }
        };

        if outputs.len() == 0 {
            return Err(anyhow!("ONNX inference returned no outputs"));
        }

        let (_, logits) = outputs[0]
            .try_extract_tensor::<f32>()
            .context("Failed to extract f32 logits from ONNX output[0]")?;

        if logits.len() < 2 {
            return Err(anyhow!(
                "Classifier output tensor too small ({} logits); expected at least 2 classes",
                logits.len()
            ));
        }

        Ok(logits.to_vec())
    }
}

#[cfg(feature = "neural")]
impl Classifier for OnnxClassifier {
    fn classify(&self, input: &str) -> Result<ClassifierResult> {
        let token_ids = self.encode_ids(input)?;
        let logits = self.run_logits(&token_ids)?;
        if logits.len() != self.class_map.len() {
            return Err(anyhow!(
                "Classifier returned {} logits, but class_map contains {} labels",
                logits.len(),
                self.class_map.len()
            ));
        }

        let (best_idx, _) = logits
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(Ordering::Equal))
            .ok_or_else(|| anyhow!("Classifier returned empty logits"))?;

        let confidence = softmax_probability(&logits, best_idx);
        let verdict = *self.class_map.get(best_idx).ok_or_else(|| {
            anyhow!(
                "Classifier predicted class index {best_idx}, but class_map has {} labels",
                self.class_map.len()
            )
        })?;
        Ok(ClassifierResult {
            verdict,
            confidence,
        })
    }
}

#[cfg(any(test, feature = "neural"))]
fn softmax_probability(logits: &[f32], winning_index: usize) -> f64 {
    let max = logits
        .iter()
        .fold(f32::NEG_INFINITY, |acc, value| acc.max(*value)) as f64;
    let exp_values: Vec<f64> = logits
        .iter()
        .map(|value| ((*value as f64) - max).exp())
        .collect();
    let denom = exp_values.iter().sum::<f64>().max(f64::EPSILON);
    exp_values[winning_index] / denom
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "neural")]
    use std::path::PathBuf;

    #[test]
    fn parse_known_labels() {
        assert_eq!(
            ClassifierVerdict::parse("safe").expect("parse"),
            ClassifierVerdict::Safe
        );
        assert_eq!(
            ClassifierVerdict::parse("MALICIOUS").expect("parse"),
            ClassifierVerdict::Malicious
        );
    }

    #[test]
    fn parse_unknown_label_errors() {
        let err = ClassifierVerdict::parse("unknown").expect_err("must fail");
        assert!(err.to_string().contains("Unknown classifier label"));
    }

    #[test]
    fn index_mapping_matches_contract() {
        assert_eq!(
            ClassifierVerdict::from_index(0).expect("index 0"),
            ClassifierVerdict::Safe
        );
        assert_eq!(
            ClassifierVerdict::from_index(4).expect("index 4"),
            ClassifierVerdict::Malicious
        );
        assert!(ClassifierVerdict::from_index(9).is_err());
    }

    #[test]
    fn noop_classifier_is_safe() {
        let classifier = NoopClassifier;
        let result = classifier.classify("anything").expect("classify");
        assert_eq!(result.verdict, ClassifierVerdict::Safe);
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn softmax_probability_is_normalized() {
        let logits = [0.1, 1.3, 2.5, 0.2, -1.0];
        let p = softmax_probability(&logits, 2);
        assert!((0.0..=1.0).contains(&p));
        assert!(p > 0.5);
    }

    #[cfg(feature = "neural")]
    #[test]
    fn optional_real_model_smoke_test() {
        let Some(model_path) = std::env::var_os("AIEGIS_TEST_ONNX_MODEL") else {
            return;
        };
        let tokenizer_path = std::env::var_os("AIEGIS_TEST_TOKENIZER");
        let model_path = PathBuf::from(model_path);
        let tokenizer_path = tokenizer_path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("models/neural-shield-tokenizer.json"));

        if !model_path.exists() {
            return;
        }

        let classifier = OnnxClassifier::load(
            None,
            &[
                ClassifierVerdict::Safe,
                ClassifierVerdict::Injection,
                ClassifierVerdict::Jailbreak,
                ClassifierVerdict::Pii,
                ClassifierVerdict::Malicious,
            ],
            &model_path,
            &tokenizer_path,
        )
        .expect("load model");
        let output = classifier.classify("Hello world").expect("classify");
        assert!((0.0..=1.0).contains(&output.confidence));
    }

    #[cfg(not(feature = "neural"))]
    #[test]
    fn enabled_classifier_requires_neural_feature() {
        let result = build_classifier(
            true,
            None,
            &[
                ClassifierVerdict::Safe,
                ClassifierVerdict::Injection,
                ClassifierVerdict::Jailbreak,
                ClassifierVerdict::Pii,
                ClassifierVerdict::Malicious,
            ],
            Path::new("models/neural-shield.onnx"),
            Path::new("models/neural-shield-tokenizer.json"),
        );
        assert!(result.is_err(), "must fail");
        let err = result.err().expect("error should be present");
        assert!(err.to_string().contains("without the 'neural' feature"));
    }
}
