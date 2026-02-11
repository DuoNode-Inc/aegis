//! Local LLM classifier (NO CLOUD) used to resolve ambiguous pipeline verdicts.
//!
//! Feature gate: `llm-local`
//! Backend: llama.cpp GGUF via `llama-cpp-2`
//!
//! Output contracts:
//! - `json`: the LLM must emit exactly one JSON object (no extra text). We enforce
//!   this using a JSON-schema-derived llama grammar and parse into the same
//!   `ClassifierVerdict` labels used by the ONNX classifier.
//! - `label`: the LLM must emit exactly one label only:
//!   `safe|injection|jailbreak|pii|malicious` (fast path).

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
#[allow(clippy::too_many_arguments)]
pub fn build_llm_classifier(
    enabled: bool,
    model_path: &Path,
    output_mode: &str,
    system_prompt_path: Option<&Path>,
    gpu_layers: i32,
    threads: i32,
    n_ctx: u32,
    max_tokens: usize,
) -> Result<Option<Arc<dyn LlmClassifier>>> {
    if !enabled {
        return Ok(None);
    }
    build_enabled_llm_classifier(
        model_path,
        output_mode,
        system_prompt_path,
        gpu_layers,
        threads,
        n_ctx,
        max_tokens,
    )
    .map(Some)
}

#[cfg(feature = "llm-local")]
fn build_enabled_llm_classifier(
    model_path: &Path,
    output_mode: &str,
    system_prompt_path: Option<&Path>,
    gpu_layers: i32,
    threads: i32,
    n_ctx: u32,
    max_tokens: usize,
) -> Result<Arc<dyn LlmClassifier>> {
    if gpu_layers < 0 {
        return Err(anyhow!(
            "detection.llm.gpu_layers must be >= 0 (got {gpu_layers})"
        ));
    }
    Ok(Arc::new(llama_local::LlamaLocalClassifier::new(
        model_path,
        output_mode,
        system_prompt_path,
        gpu_layers,
        threads,
        n_ctx,
        max_tokens,
    )?))
}

#[cfg(not(feature = "llm-local"))]
fn build_enabled_llm_classifier(
    model_path: &Path,
    output_mode: &str,
    system_prompt_path: Option<&Path>,
    gpu_layers: i32,
    threads: i32,
    n_ctx: u32,
    max_tokens: usize,
) -> Result<Arc<dyn LlmClassifier>> {
    let _ = (
        model_path,
        output_mode,
        system_prompt_path,
        gpu_layers,
        threads,
        n_ctx,
        max_tokens,
    );
    Err(anyhow!(
        "Local LLM is enabled in config, but this binary was built without the 'llm-local' feature. Rebuild with: cargo build --features llm-local"
    ))
}

/// CLI helper: verify a GGUF model is loadable (feature-gated).
#[cfg(feature = "llm-local")]
pub fn verify_llm_model_loadable(model_path: &Path) -> Result<()> {
    if model_path.exists() {
        return llama_local::LlamaLocalClassifier::verify_loadable(model_path);
    }

    #[cfg(feature = "embed-llm-weights")]
    {
        // If the disk model is missing, fall back to the embedded GGUF.
        // This keeps `llm status --verify` useful for single-file binaries.
        llama_local::LlamaLocalClassifier::verify_embedded_loadable()
    }
    #[cfg(not(feature = "embed-llm-weights"))]
    {
        Err(anyhow!(
            "LLM GGUF does not exist: {}",
            model_path.display()
        ))
    }
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
    use std::sync::{Mutex, OnceLock};

    use anyhow::{Context, Result};
    use llama_cpp_2::context::LlamaContext;
    use llama_cpp_2::context::params::LlamaContextParams;
    use llama_cpp_2::json_schema_to_grammar;
    use llama_cpp_2::llama_backend::LlamaBackend;
    use llama_cpp_2::llama_batch::LlamaBatch;
    use llama_cpp_2::model::params::LlamaModelParams;
    use llama_cpp_2::model::{AddBos, LlamaChatMessage, LlamaChatTemplate, LlamaModel};
    use llama_cpp_2::sampling::LlamaSampler;
    use llama_cpp_2::token::logit_bias::LlamaLogitBias;
    use serde::Deserialize;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OutputMode {
        Json,
        Label,
    }

    impl OutputMode {
        fn parse(s: &str) -> Result<Self> {
            match s.to_ascii_lowercase().as_str() {
                "json" => Ok(OutputMode::Json),
                "label" => Ok(OutputMode::Label),
                other => Err(anyhow!(
                    "Unknown detection.llm.output_mode '{other}'. Expected: json|label"
                )),
            }
        }
    }

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
            Ok(b) => {
                // Silence llama.cpp logging by default; it is extremely verbose and
                // will flood stderr during benchmarks and normal runs.
                //
                // Opt back in for debugging by setting `AIEGIS_LLAMA_LOG=1`.
                static LOG_SILENCED: OnceLock<()> = OnceLock::new();
                if std::env::var_os("AIEGIS_LLAMA_LOG").is_none() {
                    LOG_SILENCED.get_or_init(|| unsafe {
                        extern "C" fn quiet_log_cb(
                            _level: llama_cpp_sys_2::ggml_log_level,
                            _text: *const std::ffi::c_char,
                            _user_data: *mut std::ffi::c_void,
                        ) {
                        }
                        llama_cpp_sys_2::llama_log_set(Some(quiet_log_cb), std::ptr::null_mut());
                    });
                }

                Ok(b)
            }
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

    fn output_mode_label_grammar() -> &'static str {
        // Strict grammar: require exactly one verdict label.
        //
        // Tokenization quirk: many models strongly prefer tokens that begin with a
        // leading space (e.g. " safe"). Allow at most one leading space so the
        // model can emit a single-token verdict, while still preventing the "only
        // whitespace forever" failure mode.
        r#"root ::= optspace verdict ws
optspace ::= "" | " "
ws ::= [ \t\n\r]*
verdict ::= "safe" | "injection" | "jailbreak" | "pii" | "malicious"
"#
    }

    fn default_system_prompt() -> &'static str {
        // Keep the base system prompt output-format-agnostic. The output contract is enforced
        // separately via the per-mode output directives + grammar.
        r#"You are Aiegis, a local-only security classifier.
Classify the provided text into one of: safe, injection, jailbreak, pii, malicious.
Return a confidence from 0 to 1 and a short reason."#
    }

    /// Prefix KV cache: pre-evaluated system prompt saved as a llama.cpp session file.
    ///
    /// At init, we create a temporary context, evaluate the system prompt tokens,
    /// and save the resulting KV cache state to a session file via `save_session_file`.
    /// On each classify() call, a fresh context loads this session file (restoring
    /// the KV state in ~1-2ms) instead of re-evaluating ~200 prefix tokens (~5-8ms).
    struct PrefixCache {
        tokens: Vec<llama_cpp_2::token::LlamaToken>,
        /// Saved llama.cpp session file with pre-evaluated KV state.
        session_path: std::path::PathBuf,
    }

    impl Drop for PrefixCache {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.session_path);
        }
    }

    pub(super) struct LlamaLocalClassifier {
        ctx: Mutex<ThreadUnsafeCtx>,
        model: Box<LlamaModel>,
        chat_template: LlamaChatTemplate,
        grammar: String,
        max_tokens: usize,
        system_prompt: String,
        output_mode: OutputMode,
        #[cfg(feature = "embed-llm-weights")]
        _embedded_weights_file: Option<EmbeddedWeightsFile>,
        /// Session-backed prefix KV cache (system prompt pre-evaluated at startup).
        prefix_cache: PrefixCache,
    }

    // `llama.cpp` contexts are not thread-safe for concurrent use. We enforce single-threaded
    // access via a mutex, but still need to allow the context to live behind an `Arc<dyn LlmClassifier>`.
    // This wrapper marks the context as `Send` so the outer classifier can be `Sync`.
    struct ThreadUnsafeCtx(LlamaContext<'static>);
    unsafe impl Send for ThreadUnsafeCtx {}

    #[cfg(feature = "embed-llm-weights")]
    struct EmbeddedWeightsFile {
        pub(super) path: std::path::PathBuf,
    }

    #[cfg(feature = "embed-llm-weights")]
    impl Drop for EmbeddedWeightsFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[cfg(feature = "embed-llm-weights")]
    fn materialize_embedded_gguf_to_temp() -> Result<EmbeddedWeightsFile> {
        use std::io::Write;

        // Write once per process; llama.cpp loads via mmap from a file path.
        let out_path = std::env::temp_dir().join(format!(
            "aiegis_embedded_gguf_{}_{}.gguf",
            std::process::id(),
            crate::detection::embedded_llm::name().replace('/', "_")
        ));

        // Avoid partial files if we crash during write.
        let tmp_path = out_path.with_extension("gguf.tmp");

        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .with_context(|| format!("Failed to create embedded GGUF temp file: {}", tmp_path.display()))?;

        f.write_all(crate::detection::embedded_llm::bytes())
            .context("Failed to write embedded GGUF bytes")?;
        f.sync_all().ok();

        std::fs::rename(&tmp_path, &out_path).with_context(|| {
            format!(
                "Failed to move embedded GGUF temp file into place: {} -> {}",
                tmp_path.display(),
                out_path.display()
            )
        })?;

        Ok(EmbeddedWeightsFile { path: out_path })
    }

    impl LlamaLocalClassifier {
        pub fn new(
            model_path: &Path,
            output_mode: &str,
            system_prompt_path: Option<&Path>,
            gpu_layers: i32,
            threads: i32,
            n_ctx: u32,
            max_tokens: usize,
        ) -> Result<Self> {
            #[cfg(feature = "embed-llm-weights")]
            let mut embedded_weights_file: Option<EmbeddedWeightsFile> = None;

            let output_mode = OutputMode::parse(output_mode)?;

            let model_path = if model_path.exists() {
                model_path.to_path_buf()
            } else {
                #[cfg(feature = "embed-llm-weights")]
                {
                    // If the configured path is missing, fall back to embedded weights so the
                    // single-file binary "just works" in air-gapped deployments.
                    let f = materialize_embedded_gguf_to_temp()?;
                    let path = f.path.clone();
                    embedded_weights_file = Some(f);
                    path
                }
                #[cfg(not(feature = "embed-llm-weights"))]
                {
                    return Err(anyhow!(
                        "LLM GGUF does not exist: {}",
                        model_path.display()
                    ));
                }
            };

            let backend = backend()?;
            // GPU offload is configured via `n_gpu_layers`. If the linked llama.cpp backend
            // does not support GPU acceleration, llama.cpp will fall back to CPU.
            let gpu_layers_u32 = u32::try_from(gpu_layers).map_err(|_| {
                anyhow!("detection.llm.gpu_layers must fit in u32 (got {gpu_layers})")
            })?;
            let model_params = LlamaModelParams::default().with_n_gpu_layers(gpu_layers_u32);
            let model = Box::new(
                LlamaModel::load_from_file(backend, &model_path, &model_params)
                    .map_err(|e| anyhow!("Failed to load GGUF model: {e:?}"))?,
            );

            let chat_template = model
                .chat_template(None)
                .map_err(|e| anyhow!("Failed to load model chat template: {e:?}"))?;

            let grammar = match output_mode {
                OutputMode::Json => json_schema_to_grammar(output_schema_json())
                    .map_err(|e| anyhow!("Failed to convert JSON schema to grammar: {e:?}"))?,
                OutputMode::Label => output_mode_label_grammar().to_string(),
            };
            if std::env::var_os("AIEGIS_LLM_DEBUG_GRAMMAR").is_some() {
                let head = grammar
                    .lines()
                    .take(8)
                    .collect::<Vec<_>>()
                    .join("\n");
                eprintln!("[aiegis-llm] grammar head:\n{head}");
            }

            let system_prompt = match system_prompt_path {
                Some(path) => std::fs::read_to_string(path).with_context(|| {
                    format!("Failed to read LLM system prompt file: {}", path.display())
                })?,
                None => default_system_prompt().to_string(),
            };

            // Pre-tokenize the system prompt prefix for KV cache reuse.
            // We build a "template prefix" using the system message alone so that
            // classify() only needs to tokenize + eval the variable user content.
            let prefix_prompt = {
                let output_directive = match output_mode {
                    OutputMode::Json => "Output JSON only.",
                    OutputMode::Label => "Output label only (safe|injection|jailbreak|pii|malicious).",
                };
                let system_msg = format!("{}\n\nYou are a security classifier.\n{}", &system_prompt, output_directive);
                let messages = [
                    LlamaChatMessage::new("system".to_string(), system_msg)
                        .map_err(|e| anyhow!("Failed to create prefix chat message: {e:?}"))?,
                ];
                model
                    .apply_chat_template(&chat_template, &messages, false)
                    .map_err(|e| anyhow!("Failed to apply prefix chat template: {e:?}"))?
            };
            let prefix_tokens = model
                .str_to_token(&prefix_prompt, AddBos::Never)
                .map_err(|e| anyhow!("Failed to tokenize prefix: {e:?}"))?;

            // Evaluate prefix tokens in a temporary context and persist the KV
            // cache state to a session file.  Each classify() call restores this
            // file (~1-2ms I/O) instead of re-running ~200 tokens through the
            // transformer (~5-8ms compute).
            let session_path = std::env::temp_dir()
                .join(format!("aiegis_prefix_kv_{}.bin", std::process::id()));
            let ctx_params = LlamaContextParams::default()
                .with_n_ctx(NonZeroU32::new(n_ctx))
                .with_n_threads(threads)
                .with_n_threads_batch(threads);
            let ctx = model
                .new_context(backend, ctx_params)
                .map_err(|e| anyhow!("Failed to create llama context: {e:?}"))?;
            // SAFETY: we store the model in a Box so its address is stable for the entire
            // lifetime of the classifier. The context contains a reference to the model;
            // we extend its lifetime to 'static with the above guarantee.
            let mut ctx: LlamaContext<'static> = unsafe { std::mem::transmute(ctx) };

            // Build the prefix KV cache session file once at init, using the persistent context.
            ctx.clear_kv_cache();
            let mut init_batch = LlamaBatch::new(prefix_tokens.len(), 1);
            for (i, tok) in prefix_tokens.iter().enumerate() {
                init_batch
                    .add(
                        *tok,
                        i as i32,
                        &[0],
                        i == prefix_tokens.len().saturating_sub(1),
                    )
                    .map_err(|e| anyhow!("Failed to add prefix init token: {e:?}"))?;
            }
            ctx.decode(&mut init_batch)
                .map_err(|e| anyhow!("Failed to decode prefix for KV cache: {e:?}"))?;
            ctx.save_session_file(&session_path, &prefix_tokens)
                .map_err(|e| anyhow!("Failed to save prefix KV session: {e:?}"))?;
            ctx.clear_kv_cache();

            Ok(Self {
                ctx: Mutex::new(ThreadUnsafeCtx(ctx)),
                model,
                chat_template,
                grammar,
                max_tokens,
                system_prompt,
                output_mode,
                #[cfg(feature = "embed-llm-weights")]
                _embedded_weights_file: embedded_weights_file,
                prefix_cache: PrefixCache {
                    tokens: prefix_tokens,
                    session_path,
                },
            })
        }

        #[cfg(feature = "embed-llm-weights")]
        pub(super) fn verify_embedded_loadable() -> Result<()> {
            let tmp = materialize_embedded_gguf_to_temp()?;
            Self::verify_loadable(&tmp.path)
        }

        pub fn verify_loadable(model_path: &Path) -> Result<()> {
            if !model_path.exists() {
                return Err(anyhow!(
                    "LLM GGUF does not exist: {}",
                    model_path.display()
                ));
            }
            let backend = backend()?;
            let model_params = LlamaModelParams::default().with_n_gpu_layers(0);
            let model = LlamaModel::load_from_file(backend, model_path, &model_params)
                .map_err(|e| anyhow!("Failed to load GGUF model: {e:?}"))?;
            let _ = model
                .chat_template(None)
                .map_err(|e| anyhow!("Failed to load model chat template: {e:?}"))?;
            Ok(())
        }

        fn build_prompt(&self, input: &str, context: LlmScanContext) -> Result<String> {
            let context_label = match context {
                LlmScanContext::Request => "request",
                LlmScanContext::Response => "response",
            };

            let output_directive = match self.output_mode {
                OutputMode::Json => "Output JSON only.",
                OutputMode::Label => "Output label only (safe|injection|jailbreak|pii|malicious).",
            };
            let system = format!(
                "{}\n\nYou are a security classifier.\nSCAN_CONTEXT={}\n{}",
                self.system_prompt, context_label, output_directive
            );
            let user = match self.output_mode {
                OutputMode::Json => {
                    format!("TEXT_TO_CLASSIFY:\n{}\n\nReturn the JSON object now", input)
                }
                OutputMode::Label => format!("TEXT_TO_CLASSIFY:\n{}\n\nReturn the label now", input),
            };

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
                "BROKEN_OUTPUT:\n{}\n\nReturn the fixed JSON object now",
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

        /// Generate JSON using session-file-backed prefix KV cache.
        ///
        /// Strategy:
        /// 1. Load the saved session file to restore KV state for the system prompt
        ///    prefix (~1-2ms I/O vs ~5-8ms re-evaluation).
        /// 2. Eval only the variable user-content tokens (unique per request).
        /// 3. Generate with grammar constraint, short-circuit on valid JSON parse.
        fn generate_json(&self, prompt: &str) -> Result<String> {
            let debug_enabled = std::env::var_os("AIEGIS_LLM_DEBUG_STEPS").is_some();
            let mut step_i: u32 = 0;
            let mut step = |label: &str| {
                if debug_enabled {
                    step_i += 1;
                    eprintln!("[aiegis-llm] step {}: {}", step_i, label);
                }
            };

            let tokens = self
                .model
                .str_to_token(prompt, AddBos::Never)
                .map_err(|e| anyhow!("Failed to tokenize prompt: {e:?}"))?;
            if tokens.is_empty() {
                return Err(anyhow!("LLM prompt tokenization produced 0 tokens"));
            }
            step("str_to_token()");

            let mut ctx = self.ctx.lock().expect("llm ctx mutex poisoned");
            let ctx = &mut ctx.0;
            step("ctx.lock()");
            ctx.clear_kv_cache();
            step("ctx.clear_kv_cache()");

            // Try to restore prefix KV cache from the session file.
            // If the prompt starts with our cached prefix tokens, load the pre-evaluated
            // KV state and only eval the remaining variable (user content) tokens.
            let prefix_len = self.prefix_cache.tokens.len();
            let (variable_tokens, start_pos) = if tokens.len() > prefix_len
                && tokens[..prefix_len] == self.prefix_cache.tokens[..]
            {
                // Prefix matches — restore KV cache from session file.
                // This is the hot path: skips re-evaluating ~200 system prompt tokens.
                ctx.load_session_file(&self.prefix_cache.session_path, prefix_len)
                    .map_err(|e| anyhow!("Failed to load prefix KV session: {e:?}"))?;
                step("load_session_file(prefix)");
                let start = i32::try_from(prefix_len)
                    .map_err(|_| anyhow!("Prefix length overflows i32"))?;
                (&tokens[prefix_len..], start)
            } else {
                // No prefix match (e.g., repair prompt) — eval everything from scratch.
                (&tokens[..], 0i32)
            };

            let mut batch =
                LlamaBatch::new(variable_tokens.len() + self.max_tokens + 8, 1);
            step("LlamaBatch::new()");

            // Eval variable tokens (user content, or full prompt if no prefix match).
            let mut pos = start_pos;
            for (i, tok) in variable_tokens.iter().enumerate() {
                let logits = i == variable_tokens.len().saturating_sub(1);
                batch
                    .add(*tok, pos, &[0], logits)
                    .map_err(|e| anyhow!("Failed to add token: {e:?}"))?;
                pos += 1;
            }
            ctx.decode(&mut batch)
                .map_err(|e| anyhow!("Failed to decode tokens: {e:?}"))?;
            batch.clear();
            step("ctx.decode(variable)");

            // Generate with grammar constraint.
            let grammar_sampler =
                LlamaSampler::grammar(self.model.as_ref(), &self.grammar, "root")
                    .map_err(|e| anyhow!("Failed to init grammar sampler: {e:?}"))?;
            step("LlamaSampler::grammar()");

            // Prevent the model from terminating generation before it produces a valid output.
            // This matters most for label mode where an immediate EOS would yield an empty string.
            let eos_bias = LlamaLogitBias::new(self.model.token_eos(), -100.0);
            let bias_sampler = LlamaSampler::logit_bias(self.model.n_vocab(), &[eos_bias]);
            step("LlamaSampler::logit_bias(eos)");

            let mut sampler = LlamaSampler::chain_simple([
                grammar_sampler,
                bias_sampler,
                LlamaSampler::greedy(),
            ]);
            step("LlamaSampler::chain_simple()");

            let mut decoder = encoding_rs::UTF_8.new_decoder();
            let mut out = String::new();

            // llama.cpp sampler convention: idx = -1 samples from the last decoded token.
            let mut logits_i: i32 = -1;

            for _ in 0..self.max_tokens {
                step("sampler.sample()");
                let token = sampler.sample(ctx, logits_i);
                if token.0 == -1 {
                    return Err(anyhow!(
                        "LLM sampler returned LLAMA_TOKEN_NULL (idx={})",
                        logits_i
                    ));
                }

                // Only hard-stop on EOS. Some models emit other "end of generation" tokens
                // very early; in label mode that can yield an empty output. We therefore:
                // - avoid decoding special EOG tokens to text
                // - still feed them back into the context
                // - rely on max_tokens + parse-based early-stop to terminate.
                if token == self.model.token_eos() {
                    break;
                }

                if !self.model.is_eog_token(token) {
                    let piece = self
                        .model
                        .token_to_piece(token, &mut decoder, false, None)
                        .map_err(|e| anyhow!("Failed to decode token piece: {e:?}"))?;
                    out.push_str(&piece);
                    step("token_to_piece()");
                }

                // Early stop once we have a parseable output.
                match self.output_mode {
                    OutputMode::Json => {
                        if try_parse_llm_json(&out).is_ok() {
                            break;
                        }
                    }
                    OutputMode::Label => {
                        if ClassifierVerdict::parse(out.trim()).is_ok() {
                            break;
                        }
                    }
                }

                batch
                    .add(token, pos, &[0], true)
                    .map_err(|e| anyhow!("Failed to add generated token: {e:?}"))?;
                pos += 1;
                ctx.decode(&mut batch)
                    .map_err(|e| anyhow!("Failed to decode generated token: {e:?}"))?;
                batch.clear();
                logits_i = -1;
                step("ctx.decode(generated)");
            }

            Ok(out)
        }

        fn parse_output(&self, raw: &str) -> Result<LlmResult> {
            match self.output_mode {
                OutputMode::Json => {
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
                OutputMode::Label => {
                    let verdict = ClassifierVerdict::parse(raw.trim())?;
                    Ok(LlmResult {
                        verdict,
                        confidence: 1.0,
                        reason: "label-only".to_string(),
                    })
                }
            }
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
                    // Bounded repair attempt (still grammar-enforced). Only valid for JSON mode.
                    if self.output_mode != OutputMode::Json {
                        return Err(anyhow!(
                            "LLM output failed to parse in label mode (raw='{}')",
                            raw.trim()
                        ));
                    }
                    let repair_prompt = self.build_repair_prompt(&raw)?;
                    let repaired = self.generate_json(&repair_prompt)?;
                    self.parse_output(&repaired)
                }
            }
        }
    }
}
