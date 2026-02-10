//! Local LLM classifier (NO CLOUD) used to resolve ambiguous pipeline verdicts.
//!
//! Feature gate: `llm-local`
//! Backend: llama.cpp GGUF via `llama-cpp-2`
//!
//! Contract: the LLM must emit exactly one JSON object (no extra text). We enforce
//! this using a JSON-schema-derived llama grammar and parse into the same
//! `ClassifierVerdict` labels used by the ONNX classifier.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use super::classifier::ClassifierVerdict;

/// Local LLM classifier result.
#[derive(Debug, Clone)]
pub struct LlmResult {
    pub verdict: ClassifierVerdict,
    pub confidence: f64,
    pub reason: String,
}

/// LLM classifier interface used by the pipeline.
pub trait LlmClassifier: Send + Sync {
    fn classify(&self, input: &str, context: LlmScanContext) -> Result<LlmResult>;
}

/// Whether we're classifying request or response data (affects prompting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmScanContext {
    Request,
    Response,
}

/// Build the local LLM classifier when enabled.
pub fn build_llm_classifier(
    enabled: bool,
    model_path: &Path,
    system_prompt_path: Option<&Path>,
    threads: i32,
    n_ctx: u32,
    max_tokens: usize,
) -> Result<Option<Arc<dyn LlmClassifier>>> {
    if !enabled {
        return Ok(None);
    }
    build_enabled_llm_classifier(model_path, system_prompt_path, threads, n_ctx, max_tokens)
        .map(Some)
}

#[cfg(feature = "llm-local")]
fn build_enabled_llm_classifier(
    model_path: &Path,
    system_prompt_path: Option<&Path>,
    threads: i32,
    n_ctx: u32,
    max_tokens: usize,
) -> Result<Arc<dyn LlmClassifier>> {
    Ok(Arc::new(llama_local::LlamaLocalClassifier::new(
        model_path,
        system_prompt_path,
        threads,
        n_ctx,
        max_tokens,
    )?))
}

#[cfg(not(feature = "llm-local"))]
fn build_enabled_llm_classifier(
    model_path: &Path,
    system_prompt_path: Option<&Path>,
    threads: i32,
    n_ctx: u32,
    max_tokens: usize,
) -> Result<Arc<dyn LlmClassifier>> {
    let _ = (model_path, system_prompt_path, threads, n_ctx, max_tokens);
    Err(anyhow!(
        "Local LLM is enabled in config, but this binary was built without the 'llm-local' feature. Rebuild with: cargo build --features llm-local"
    ))
}

/// CLI helper: verify a GGUF model is loadable (feature-gated).
#[cfg(feature = "llm-local")]
pub fn verify_llm_model_loadable(model_path: &Path) -> Result<()> {
    llama_local::LlamaLocalClassifier::verify_loadable(model_path)
}

#[cfg(not(feature = "llm-local"))]
pub fn verify_llm_model_loadable(_model_path: &Path) -> Result<()> {
    Err(anyhow!(
        "This binary was built without the 'llm-local' feature; cannot load GGUF"
    ))
}

#[cfg(feature = "llm-local")]
mod llama_local {
    use super::*;
    use std::num::NonZeroU32;
    use std::sync::OnceLock;

    use anyhow::{Context, Result};
    use llama_cpp_2::context::params::LlamaContextParams;
    use llama_cpp_2::json_schema_to_grammar;
    use llama_cpp_2::llama_backend::LlamaBackend;
    use llama_cpp_2::llama_batch::LlamaBatch;
    use llama_cpp_2::model::{AddBos, LlamaChatMessage, LlamaChatTemplate, LlamaModel};
    use llama_cpp_2::sampling::LlamaSampler;
    use serde::Deserialize;

    /// JSON output contract from the LLM.
    #[derive(Debug, Clone, Deserialize)]
    struct LlmJsonOut {
        verdict: String,
        confidence: f64,
        reason: String,
    }

    fn backend() -> Result<&'static LlamaBackend> {
        // `OnceLock::get_or_try_init` is unstable on some toolchains; store the init result.
        static BACKEND: OnceLock<std::result::Result<LlamaBackend, String>> = OnceLock::new();
        let res = BACKEND.get_or_init(|| {
            LlamaBackend::init().map_err(|e| format!("Failed to init llama backend: {e:?}"))
        });
        match res {
            Ok(b) => Ok(b),
            Err(msg) => Err(anyhow!("{msg}")),
        }
    }

    fn output_schema_json() -> &'static str {
        // Keep this schema tiny; grammar enforcement is the main goal.
        r#"{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "verdict": { "type": "string", "enum": ["safe","injection","jailbreak","pii","malicious"] },
    "confidence": { "type": "number", "minimum": 0, "maximum": 1 },
    "reason": { "type": "string" }
  },
  "required": ["verdict","confidence","reason"]
}"#
    }

    fn default_system_prompt() -> &'static str {
        r#"You are Aiegis, a local-only security classifier. Output exactly one JSON object.
Classify the provided text into one of: safe, injection, jailbreak, pii, malicious.
Return a confidence from 0 to 1 and a short reason. Output JSON only."#
    }

    pub(super) struct LlamaLocalClassifier {
        model: LlamaModel,
        chat_template: LlamaChatTemplate,
        grammar: String,
        threads: i32,
        n_ctx: u32,
        max_tokens: usize,
        system_prompt: String,
    }

    impl LlamaLocalClassifier {
        pub fn new(
            model_path: &Path,
            system_prompt_path: Option<&Path>,
            threads: i32,
            n_ctx: u32,
            max_tokens: usize,
        ) -> Result<Self> {
            if !model_path.exists() {
                return Err(anyhow!("LLM GGUF does not exist: {}", model_path.display()));
            }

            let backend = backend()?;
            let model = LlamaModel::load_from_file(backend, model_path, &Default::default())
                .map_err(|e| anyhow!("Failed to load GGUF model: {e:?}"))?;

            let chat_template = model
                .chat_template(None)
                .map_err(|e| anyhow!("Failed to load model chat template: {e:?}"))?;

            let grammar = json_schema_to_grammar(output_schema_json())
                .map_err(|e| anyhow!("Failed to convert JSON schema to grammar: {e:?}"))?;

            let system_prompt = match system_prompt_path {
                Some(path) => std::fs::read_to_string(path).with_context(|| {
                    format!("Failed to read LLM system prompt file: {}", path.display())
                })?,
                None => default_system_prompt().to_string(),
            };

            Ok(Self {
                model,
                chat_template,
                grammar,
                threads,
                n_ctx,
                max_tokens,
                system_prompt,
            })
        }

        pub fn verify_loadable(model_path: &Path) -> Result<()> {
            let _ = Self::new(model_path, None, 4, 2048, 64)?;
            Ok(())
        }

        fn build_prompt(&self, input: &str, context: LlmScanContext) -> Result<String> {
            let context_label = match context {
                LlmScanContext::Request => "request",
                LlmScanContext::Response => "response",
            };

            let system = format!(
                "{}\n\nYou are classifying a {} payload.\nOutput JSON only.",
                self.system_prompt, context_label
            );
            let user = format!(
                "TEXT_TO_CLASSIFY:\n{}\n\nReturn the JSON object now.",
                input
            );

            let messages = [
                LlamaChatMessage::new("system".to_string(), system)?,
                LlamaChatMessage::new("user".to_string(), user)?,
            ];

            self.model
                .apply_chat_template(&self.chat_template, &messages, true)
                .map_err(|e| anyhow!("Failed to apply chat template: {e:?}"))
        }

        fn build_repair_prompt(&self, broken: &str) -> Result<String> {
            let system = format!(
                "{}\n\nYou will be given a broken or partial output. Fix it and output JSON only.",
                self.system_prompt
            );
            let user = format!(
                "BROKEN_OUTPUT:\n{}\n\nReturn the fixed JSON object now.",
                broken
            );
            let messages = [
                LlamaChatMessage::new("system".to_string(), system)?,
                LlamaChatMessage::new("user".to_string(), user)?,
            ];
            self.model
                .apply_chat_template(&self.chat_template, &messages, true)
                .map_err(|e| anyhow!("Failed to apply chat template (repair): {e:?}"))
        }

        fn generate_json(&self, prompt: &str) -> Result<String> {
            let backend = backend()?;
            let ctx_params = LlamaContextParams::default()
                .with_n_ctx(NonZeroU32::new(self.n_ctx))
                .with_n_threads(self.threads)
                .with_n_threads_batch(self.threads);

            let mut ctx = self
                .model
                .new_context(backend, ctx_params)
                .map_err(|e| anyhow!("Failed to create llama context: {e:?}"))?;

            let tokens = self
                .model
                .str_to_token(prompt, AddBos::Never)
                .map_err(|e| anyhow!("Failed to tokenize prompt: {e:?}"))?;

            // Allocate enough space for prompt + generation.
            let mut batch = LlamaBatch::new(tokens.len() + self.max_tokens + 8, 1);

            // Feed prompt tokens.
            let mut pos: i32 = 0;
            for (i, tok) in tokens.iter().enumerate() {
                let logits = i == tokens.len().saturating_sub(1);
                batch
                    .add(*tok, pos, &[0], logits)
                    .map_err(|e| anyhow!("Failed to add token to batch: {e:?}"))?;
                pos += 1;
            }

            ctx.decode(&mut batch)
                .map_err(|e| anyhow!("Failed to decode prompt: {e:?}"))?;
            batch.clear();

            // Sampler chain: temp(0) + grammar + greedy.
            let grammar_sampler = LlamaSampler::grammar(&self.model, &self.grammar, "root")
                .map_err(|e| anyhow!("Failed to init grammar sampler: {e:?}"))?;
            let mut sampler = LlamaSampler::chain_simple([
                LlamaSampler::temp(0.0),
                grammar_sampler,
                LlamaSampler::greedy(),
            ]);

            let mut decoder = encoding_rs::UTF_8.new_decoder();
            let mut out = String::new();

            for _ in 0..self.max_tokens {
                let token = sampler.sample(&ctx, 0);
                sampler.accept(token);

                if self.model.is_eog_token(token) || token == self.model.token_eos() {
                    break;
                }

                let piece = self
                    .model
                    .token_to_piece(token, &mut decoder, false, None)
                    .map_err(|e| anyhow!("Failed to decode token piece: {e:?}"))?;
                out.push_str(&piece);

                // Early stop once we have a parseable JSON object.
                if try_parse_llm_json(&out).is_ok() {
                    break;
                }

                batch
                    .add(token, pos, &[0], true)
                    .map_err(|e| anyhow!("Failed to add generated token: {e:?}"))?;
                pos += 1;
                ctx.decode(&mut batch)
                    .map_err(|e| anyhow!("Failed to decode generated token: {e:?}"))?;
                batch.clear();
            }

            Ok(out)
        }

        fn parse_output(&self, raw: &str) -> Result<LlmResult> {
            let parsed = try_parse_llm_json(raw)?;
            if !(0.0..=1.0).contains(&parsed.confidence) {
                return Err(anyhow!(
                    "LLM returned invalid confidence {} (expected 0..=1)",
                    parsed.confidence
                ));
            }

            let verdict = ClassifierVerdict::parse(&parsed.verdict)?;
            Ok(LlmResult {
                verdict,
                confidence: parsed.confidence,
                reason: parsed.reason,
            })
        }
    }

    fn try_parse_llm_json(raw: &str) -> Result<LlmJsonOut> {
        let s = raw.trim();
        if !s.starts_with('{') || !s.ends_with('}') {
            return Err(anyhow!("Not a JSON object"));
        }
        serde_json::from_str::<LlmJsonOut>(s).context("LLM output is not valid JSON")
    }

    impl LlmClassifier for LlamaLocalClassifier {
        fn classify(&self, input: &str, context: LlmScanContext) -> Result<LlmResult> {
            let prompt = self.build_prompt(input, context)?;
            let raw = self.generate_json(&prompt)?;

            match self.parse_output(&raw) {
                Ok(r) => Ok(r),
                Err(_) => {
                    // Bounded repair attempt (still grammar-enforced).
                    let repair_prompt = self.build_repair_prompt(&raw)?;
                    let repaired = self.generate_json(&repair_prompt)?;
                    self.parse_output(&repaired)
                }
            }
        }
    }
}
