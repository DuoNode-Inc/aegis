//! Aiegis — AI security firewall proxy.
//!
//! Entry point: parses CLI args, loads config, dispatches to subcommands.

mod cli;
mod config;
mod crypto;
mod detection;
mod endpoints;
mod license;
mod logging;
mod mode;
mod proxy;
mod rules;
mod sidecar;
mod state;
mod tier;
mod tls;

use std::io::{BufRead, BufReader, Seek, SeekFrom};

use anyhow::{Context, Result};
use clap::Parser;
#[cfg(feature = "tls-mitm")]
use cli::{CaAction, TlsAction};
use cli::{Cli, Command, LicenseAction, LlmAction, RulesAction};
use sidecar::{Counters, SidecarState};
use config::{apply_overrides, load_config};
use detection::classifier::build_classifier;
use detection::injection::InjectionScanner;
use detection::llm::build_llm_classifier;
use detection::model_package::resolve_classifier_config;
use detection::pii::PiiScanner;
use detection::pipeline::{Action, Pipeline, PipelineConfig};
use detection::supply_chain::{scan_repo, ScanOptions, Severity};
use detection::llm::LlmScanContext;
use detection::web3::{Sensitivity as Web3Sensitivity, Web3Scanner};
use mode::detect_mode;
use rules::loader;
use tier::{resolve_tier, validate_tier_config, Tier, TierGate};

/// Select the injection rules file appropriate for the active tier.
///
/// Priority:
/// 1. If the user has configured a custom path (not the default), honor it.
/// 2. Sentinel tier: prefer `~/.aiegis/injection-sentinel.rules` (downloaded
///    after `aiegis license activate`), then `rules/injection-sentinel.rules`.
/// 3. Shield tier (or Sentinel without the full ruleset): `rules/injection-shield.rules`.
/// 4. Absolute fallback: `rules/injection-sentinel.rules` (full ruleset).
fn select_injection_rules_path(config: &config::AiegisConfig, tier: Tier) -> std::path::PathBuf {
    use std::path::PathBuf;

    // If the user set a non-default path, respect it regardless of tier.
    if config.uses_custom_pattern_paths() {
        return config.detection.injection.rules_path.clone();
    }

    if tier == Tier::Sentinel {
        // Check for locally downloaded full ruleset first
        if let Some(home) = std::env::var_os("HOME") {
            let user_sentinel = PathBuf::from(home)
                .join(".aiegis")
                .join("injection-sentinel.rules");
            if user_sentinel.exists() {
                return user_sentinel;
            }
        }
        // Fall back to bundled Sentinel rules
        let bundled_sentinel = PathBuf::from("rules/injection-sentinel.rules");
        if bundled_sentinel.exists() {
            return bundled_sentinel;
        }
    }

    // Shield tier (or Sentinel without downloaded rules): use Shield subset
    let shield_rules = PathBuf::from("rules/injection-shield.rules");
    if shield_rules.exists() {
        return shield_rules;
    }

    // Absolute fallback — full sentinel ruleset (injection-shield.rules should always exist)
    PathBuf::from("rules/injection-sentinel.rules")
}

/// Build the detection pipeline from config and rules files.
fn build_pipeline(config: &config::AiegisConfig) -> Result<Pipeline> {
    let injection = if config.detection.injection.enabled {
        let patterns = loader::load_patterns(&config.detection.injection.rules_path)
            .with_context(|| "Failed to load injection rules")?;
        let scanner =
            InjectionScanner::new(patterns).with_context(|| "Failed to build injection scanner")?;
        Some(scanner)
    } else {
        None
    };

    let pii = if config.detection.pii.enabled {
        let pii_rules = loader::load_pii_rules(&config.detection.pii.rules_path)
            .with_context(|| "Failed to load PII rules")?;
        let scanner = PiiScanner::new(&pii_rules).with_context(|| "Failed to build PII scanner")?;
        Some(scanner)
    } else {
        None
    };

    let default_action = match config.detection.default_action.as_str() {
        "flag" => Action::Flag,
        "ambiguous" => Action::Ambiguous,
        "block" => Action::Block,
        _ => Action::Block,
    };

    let classifier_config = resolve_classifier_config(&config.detection.classifier)?;
    let classifier = build_classifier(
        config.detection.classifier.enabled,
        classifier_config.package.as_deref(),
        &classifier_config.class_map,
        &classifier_config.model_path,
        &classifier_config.tokenizer_path,
    )?;

    let llm = build_llm_classifier(
        config.detection.llm.enabled,
        &config.detection.llm.model_path,
        &config.detection.llm.output_mode,
        config.detection.llm.system_prompt_path.as_deref(),
        config.detection.llm.gpu_layers,
        config.detection.llm.threads,
        config.detection.llm.n_ctx,
        config.detection.llm.max_tokens,
    )?;

    let web3_enabled = config.detection.web3.as_ref().map_or(false, |w| w.enabled);
    let web3 = if web3_enabled {
        let sensitivity = match config
            .detection
            .web3
            .as_ref()
            .map(|w| w.sensitivity.as_str())
            .unwrap_or("normal")
        {
            "strict" => Web3Sensitivity::Strict,
            "permissive" => Web3Sensitivity::Permissive,
            _ => Web3Sensitivity::Normal,
        };
        Some(Web3Scanner::new(sensitivity))
    } else {
        None
    };

    Ok(Pipeline::with_web3(
        injection,
        pii,
        web3,
        classifier,
        llm,
        PipelineConfig {
            injection_enabled: config.detection.injection.enabled,
            pii_enabled: config.detection.pii.enabled,
            web3_enabled,
            entropy_enabled: config.detection.entropy.enabled,
            entropy_threshold: config.detection.entropy.threshold,
            entropy_min_length: config.detection.entropy.min_length,
            default_action,
            classifier_enabled: config.detection.classifier.enabled,
            classifier_threshold: classifier_config.confidence_threshold,
            llm_enabled: config.detection.llm.enabled,
            llm_threshold: config.detection.llm.confidence_threshold,
        },
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    crypto::ensure_rustls_provider();
    let cli = Cli::parse();
    let config = load_config(cli.config.as_deref())?;
    let runtime_mode = detect_mode();
    let resolved_tier = resolve_tier(config.runtime.tier.as_deref(), runtime_mode)?;

    match cli.command {
        Command::Start { mode, host, port } => {
            let mut config = apply_overrides(config, mode.as_deref(), host.as_deref(), port);
            logging::init(&config.logging)?;
            validate_tier_config(&config, resolved_tier)?;

            // Override injection rules path based on active tier (unless user set a custom path)
            config.detection.injection.rules_path =
                select_injection_rules_path(&config, resolved_tier);
            let classifier_config = resolve_classifier_config(&config.detection.classifier)?;

            if config.proxy.tls_mitm.enabled {
                let ca = tls::ensure_ca(&config.proxy.tls_mitm.ca_dir)?;
                tracing::info!(
                    ca_dir = %config.proxy.tls_mitm.ca_dir.display(),
                    ca_cert = %ca.cert_path.display(),
                    ca_key = %ca.key_path.display(),
                    "TLS MITM configured"
                );
            }

            if config.detection.classifier.enabled {
                tracing::info!(
                    package = classifier_config.package.as_deref().unwrap_or("none"),
                    source_model = classifier_config.source_model.as_deref().unwrap_or("custom"),
                    model_path = %classifier_config.model_path.display(),
                    tokenizer_path = %classifier_config.tokenizer_path.display(),
                    threshold = classifier_config.confidence_threshold,
                    "Neural classifier configured"
                );
            }

            if config.detection.llm.enabled {
                tracing::info!(
                    model_path = %config.detection.llm.model_path.display(),
                    system_prompt_path = %config
                        .detection
                        .llm
                        .system_prompt_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "builtin".to_string()),
                    n_ctx = config.detection.llm.n_ctx,
                    threads = config.detection.llm.threads,
                    max_tokens = config.detection.llm.max_tokens,
                    threshold = config.detection.llm.confidence_threshold,
                    "Local LLM configured"
                );
            }

            // Write PID file so status/stop can find us
            state::write_pid()?;

            let pipeline = build_pipeline(&config)?;
            let inj_count = pipeline.injection_count();
            let pii_count = pipeline.pii_count();
            let ep_count = config.endpoints.targets.len();
            tracing::info!(
                version = env!("CARGO_PKG_VERSION"),
                mode = %config.proxy.mode,
                host = %config.proxy.host,
                port = %config.proxy.port,
                runtime_mode = runtime_mode.as_str(),
                tier = resolved_tier.as_str(),
                tier_tls_mitm = resolved_tier.allows_tls_mitm(),
                tier_classifier = resolved_tier.allows_classifier(),
                tier_llm = resolved_tier.allows_llm(),
                tier_custom_patterns = resolved_tier.allows_custom_patterns(),
                tier_rate_limiting = resolved_tier.allows_rate_limiting(),
                tier_metrics = resolved_tier.allows_metrics(),
                tier_dashboard = resolved_tier.allows_dashboard(),
                injection_patterns = inj_count,
                injection_rules = %config.detection.injection.rules_path.display(),
                pii_patterns = pii_count,
                endpoints = ep_count,
                "Aiegis Shield Preview starting"
            );

            let result = match config.proxy.mode.as_str() {
                "gateway" => proxy::gateway::run(config, pipeline).await,
                "proxy" => proxy::forward::run(config, pipeline).await,
                other => {
                    anyhow::bail!("Unknown proxy mode: '{other}'. Use 'gateway' or 'proxy'.");
                }
            };

            // Clean up PID file on exit
            let _ = state::remove_pid();
            result?;
        }
        Command::Sidecar { host, port } => {
            logging::init(&config.logging)?;

            let mut config = config;
            config.detection.injection.rules_path =
                select_injection_rules_path(&config, resolved_tier);

            let pipeline = build_pipeline(&config)?;
            tracing::info!(
                version = env!("CARGO_PKG_VERSION"),
                tier = resolved_tier.as_str(),
                injection_patterns = pipeline.injection_count(),
                pii_patterns = pipeline.pii_count(),
                "Aiegis sidecar initialised"
            );

            let state = std::sync::Arc::new(SidecarState {
                pipeline,
                tier: resolved_tier,
                started_at: std::time::Instant::now(),
                counters: std::sync::Arc::new(Counters::default()),
            });

            sidecar::run(&host, port, state).await?;
        }

        Command::Stop => {
            match state::read_pid()? {
                Some(pid) if state::is_pid_alive(pid) => {
                    println!("Stopping Aiegis (PID {pid})...");
                    if state::send_signal(pid, "-TERM")? {
                        // Wait briefly for process to exit
                        for _ in 0..20 {
                            if !state::is_pid_alive(pid) {
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        if state::is_pid_alive(pid) {
                            println!("Process still running. Use 'kill -9 {pid}' to force stop.");
                        } else {
                            let _ = state::remove_pid();
                            println!("Aiegis stopped.");
                        }
                    } else {
                        println!("Failed to send stop signal to PID {pid}.");
                    }
                }
                Some(pid) => {
                    println!("Aiegis is not running (stale PID file for PID {pid}).");
                    let _ = state::remove_pid();
                }
                None => {
                    println!("Aiegis is not running (no PID file found).");
                }
            }
        }
        Command::Status => {
            println!("Aiegis Shield Preview v{}", env!("CARGO_PKG_VERSION"));
            println!("─────────────────────────────────");

            match state::read_pid()? {
                Some(pid) if state::is_pid_alive(pid) => {
                    println!("Status: running (PID {pid})");
                }
                Some(pid) => {
                    println!("Status: stopped (stale PID {pid})");
                    let _ = state::remove_pid();
                }
                None => {
                    println!("Status: stopped");
                }
            }

            println!("Port:   {}", config.proxy.port);
            println!("Mode:   {}", config.proxy.mode);
            println!("Runtime: {}", runtime_mode.as_str());
            println!("Tier:   {}", resolved_tier.as_str());

            let log_file = state::log_path()?;
            if log_file.exists() {
                println!("Log:    {}", log_file.display());
            }
        }
        Command::Logs { tail, follow } => {
            let log_file = state::log_path()?;
            if !log_file.exists() {
                println!("No log file found at {}", log_file.display());
                println!("Start Aiegis first with: aiegis start");
                return Ok(());
            }

            // Read and print last N lines
            let content = std::fs::read_to_string(&log_file)?;
            let lines: Vec<&str> = content.lines().collect();
            let start = lines.len().saturating_sub(tail);
            for line in &lines[start..] {
                println!("{line}");
            }

            // Follow mode: poll for new lines
            if follow {
                let mut file = std::fs::File::open(&log_file)?;
                file.seek(SeekFrom::End(0))?;
                let mut reader = BufReader::new(file);
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) => {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        Ok(_) => {
                            print!("{line}");
                        }
                        Err(err) => {
                            eprintln!("Error reading log: {err}");
                            break;
                        }
                    }
                }
            }
        }
        Command::Rules { action } => match action {
            RulesAction::List => {
                let pipeline = build_pipeline(&config)?;
                println!("Aiegis Shield Preview v{}", env!("CARGO_PKG_VERSION"));
                println!("─────────────────────────────────");
                println!("Injection patterns: {}", pipeline.injection_count());
                println!("PII patterns:       {}", pipeline.pii_count());
                println!("AI endpoints:       {}", config.endpoints.targets.len());
                if !config.endpoints.targets.is_empty() {
                    for ep in &config.endpoints.targets {
                        println!("  - {ep}");
                    }
                }
            }
            RulesAction::Test { input } => {
                let pipeline = build_pipeline(&config)?;
                let verdict = pipeline.scan(&input);
                println!("{verdict}");
            }
            RulesAction::ScanDeps {
                repo,
                staged,
                no_fail,
            } => {
                let report = scan_repo(&ScanOptions {
                    repo_path: repo,
                    staged_only: staged,
                })?;

                println!("Aiegis Supply-Chain Scan");
                println!("─────────────────────────────────");
                println!("Scanned files: {}", report.scanned_files);
                println!("Findings:      {}", report.findings.len());
                println!("High severity: {}", report.high_count());

                for finding in &report.findings {
                    let sev = match finding.severity {
                        Severity::High => "HIGH",
                        Severity::Medium => "MEDIUM",
                    };
                    println!(
                        "[{sev}] {}:{} {} - {}",
                        finding.path.display(),
                        finding.line,
                        finding.category,
                        finding.detail
                    );
                }

                if report.high_count() > 0 && !no_fail {
                    anyhow::bail!(
                        "High-severity supply-chain findings detected. Blocking by default."
                    );
                }
            }
        },

        Command::Llm { action } => match action {
            LlmAction::Status { verify } => {
                println!("Aiegis Local LLM Status");
                println!("─────────────────────────────────");
                println!("Built with llm-local: {}", cfg!(feature = "llm-local"));
                println!(
                    "Built with embed-llm-weights: {}",
                    cfg!(feature = "embed-llm-weights")
                );
                println!("Enabled in config:    {}", config.detection.llm.enabled);
                println!(
                    "Model path:           {}",
                    config.detection.llm.model_path.display()
                );
                println!(
                    "Model present:        {}",
                    if config.detection.llm.model_path.exists() {
                        "yes"
                    } else {
                        "no"
                    }
                );
                #[cfg(feature = "embed-llm-weights")]
                {
                    println!(
                        "Embedded model:       {} ({} bytes)",
                        detection::embedded_llm::name(),
                        detection::embedded_llm::len()
                    );
                }
                println!(
                    "System prompt:        {}",
                    config
                        .detection
                        .llm
                        .system_prompt_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "builtin".to_string())
                );
                println!("n_ctx:                {}", config.detection.llm.n_ctx);
                println!("threads:              {}", config.detection.llm.threads);
                println!("max_tokens:           {}", config.detection.llm.max_tokens);
                println!(
                    "confidence_threshold: {}",
                    config.detection.llm.confidence_threshold
                );

                if verify {
                    match detection::llm::verify_llm_model_loadable(&config.detection.llm.model_path)
                    {
                        Ok(()) => println!("Verify:               OK (model load succeeded)"),
                        Err(e) => println!("Verify:               FAILED ({e})"),
                    }
                }
            }

            LlmAction::Bench {
                iters,
                warmup,
                input,
                json,
            } => {
                // Benchmark should work even if the config doesn't have llm.enabled set.
                // It uses local inference only.
                let llm = build_llm_classifier(
                    true,
                    &config.detection.llm.model_path,
                    &config.detection.llm.output_mode,
                    config.detection.llm.system_prompt_path.as_deref(),
                    config.detection.llm.gpu_layers,
                    config.detection.llm.threads,
                    config.detection.llm.n_ctx,
                    config.detection.llm.max_tokens,
                )?
                .ok_or_else(|| anyhow::anyhow!("Failed to build local LLM classifier"))?;

                // Warmup.
                for _ in 0..warmup {
                    let _ = llm.classify(&input, detection::llm::LlmScanContext::Request)?;
                }

                let mut samples_us: Vec<u128> = Vec::with_capacity(iters);
                for _ in 0..iters {
                    let t0 = std::time::Instant::now();
                    let _ = llm.classify(&input, detection::llm::LlmScanContext::Request)?;
                    samples_us.push(t0.elapsed().as_micros());
                }

                samples_us.sort_unstable();
                let min = *samples_us.first().unwrap_or(&0);
                let max = *samples_us.last().unwrap_or(&0);

                let pct = |p: f64| -> u128 {
                    if samples_us.is_empty() {
                        return 0;
                    }
                    let idx = ((samples_us.len() as f64 - 1.0) * p).round() as usize;
                    samples_us[idx.min(samples_us.len() - 1)]
                };

                let p50 = pct(0.50);
                let p95 = pct(0.95);

                if json {
                    let out = serde_json::json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "platform": {
                            "os": std::env::consts::OS,
                            "arch": std::env::consts::ARCH,
                        },
                        "iters": iters,
                        "warmup": warmup,
                        "unit": "us",
                        "min": min,
                        "p50": p50,
                        "p95": p95,
                        "max": max,
                        "features": {
                            "llm_local": cfg!(feature = "llm-local"),
                            "embed_llm_weights": cfg!(feature = "embed-llm-weights"),
                            "llm_cuda": cfg!(feature = "llm-cuda"),
                            "llm_metal": cfg!(feature = "llm-metal"),
                        },
                        "llm": {
                            "model_path": config.detection.llm.model_path.display().to_string(),
                            "model_file": config
                                .detection
                                .llm
                                .model_path
                                .file_name()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_else(|| "".to_string()),
                            "output_mode": config.detection.llm.output_mode.as_str(),
                            "gpu_layers": config.detection.llm.gpu_layers,
                            "n_ctx": config.detection.llm.n_ctx,
                            "threads": config.detection.llm.threads,
                            "max_tokens": config.detection.llm.max_tokens,
                        }
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                } else {
                    println!("Aiegis Local LLM Benchmark");
                    println!("─────────────────────────────────");
                    println!("iters:    {iters} (warmup: {warmup})");
                    println!("unit:     microseconds");
                    println!("min:      {min}");
                    println!("p50:      {p50}");
                    println!("p95:      {p95}");
                    println!("max:      {max}");
                }
            }

            LlmAction::Classify {
                input,
                context,
                json,
            } => {
                let ctx = match context.as_deref().unwrap_or("request") {
                    "request" => LlmScanContext::Request,
                    "response" => LlmScanContext::Response,
                    other => anyhow::bail!("Invalid --context '{other}'. Expected: request|response"),
                };

                // Classification should work even if detection.llm.enabled is false in config.
                // It uses local inference only (NO CLOUD).
                let llm = build_llm_classifier(
                    true,
                    &config.detection.llm.model_path,
                    &config.detection.llm.output_mode,
                    config.detection.llm.system_prompt_path.as_deref(),
                    config.detection.llm.gpu_layers,
                    config.detection.llm.threads,
                    config.detection.llm.n_ctx,
                    config.detection.llm.max_tokens,
                )?;

                let Some(llm) = llm else {
                    anyhow::bail!("Local LLM is not available (binary not built with --features llm-local)");
                };

                let r = llm.classify(&input, ctx)?;

                if json {
                    #[derive(serde::Serialize)]
                    struct Out<'a> {
                        verdict: &'a str,
                        confidence: f64,
                        reason: &'a str,
                    }
                    println!(
                        "{}",
                        serde_json::to_string(&Out {
                            verdict: r.verdict.as_str(),
                            confidence: r.confidence,
                            reason: &r.reason,
                        })?
                    );
                } else {
                    // Print the label only for fast harness consumption.
                    println!("{}", r.verdict.as_str());
                }
            }
        },

        Command::License { action } => match action {
            LicenseAction::Activate { key } => {
                let verifier = license::LicenseVerifier::new()
                    .context("Failed to initialize license verifier")?;

                match verifier.verify(&key) {
                    Ok(claims) => {
                        if claims.is_expired() {
                            println!("License is EXPIRED (expired on {}).", claims.expiry);
                            println!("Falling back to Shield tier.");
                        } else {
                            let path = license::save_license(&key)
                                .context("Failed to save license key")?;
                            println!("License activated successfully.");
                            println!("  User:    {}", claims.user);
                            println!("  Tier:    {}", claims.tier);
                            println!(
                                "  Expires: {} ({} days remaining)",
                                claims.expiry,
                                claims.days_remaining()
                            );
                            println!("  Saved:   {}", path.display());
                        }
                    }
                    Err(e) => {
                        println!("License verification FAILED: {e}");
                        println!("Falling back to Shield tier.");
                    }
                }
            }
            LicenseAction::Status => {
                println!("Aiegis License Status");
                println!("─────────────────────────────────");

                match license::load_license() {
                    Ok(Some(key)) => {
                        let verifier = license::LicenseVerifier::new()
                            .context("Failed to initialize license verifier")?;
                        match verifier.verify(&key) {
                            Ok(claims) => {
                                if claims.is_expired() {
                                    println!("Status:  EXPIRED");
                                    println!("User:    {}", claims.user);
                                    println!("Tier:    {} (inactive)", claims.tier);
                                    println!("Expired: {}", claims.expiry);
                                    println!("Active:  Shield (fallback)");
                                } else {
                                    println!("Status:  VALID");
                                    println!("User:    {}", claims.user);
                                    println!("Tier:    {}", claims.tier);
                                    println!(
                                        "Expires: {} ({} days remaining)",
                                        claims.expiry,
                                        claims.days_remaining()
                                    );
                                }
                            }
                            Err(e) => {
                                println!("Status:  INVALID ({e})");
                                println!("Active:  Shield (fallback)");
                            }
                        }
                    }
                    Ok(None) => {
                        println!("Status:  No license installed");
                        println!("Active:  {} (default)", resolved_tier.as_str());
                    }
                    Err(e) => {
                        println!("Status:  Error reading license ({e})");
                        println!("Active:  Shield (fallback)");
                    }
                }
            }
        },

        #[cfg(feature = "tls-mitm")]
        Command::Tls { action } => match action {
            TlsAction::Ca { action } => match action {
                CaAction::Init {
                    ca_dir,
                    force,
                    print_cert,
                } => {
                    let ca_dir = ca_dir.unwrap_or_else(|| config.proxy.tls_mitm.ca_dir.clone());
                    let artifacts = tls::init_ca(&ca_dir, force)?;

                    if print_cert {
                        eprintln!("CA directory: {}", ca_dir.display());
                        eprintln!("CA cert:      {}", artifacts.cert_path.display());
                        eprintln!("CA key:       {}", artifacts.key_path.display());
                        let pem = std::fs::read_to_string(&artifacts.cert_path)
                            .with_context(|| "Failed to read CA cert")?;
                        print!("{pem}");
                    } else {
                        println!("CA directory: {}", ca_dir.display());
                        println!("CA cert:      {}", artifacts.cert_path.display());
                        println!("CA key:       {}", artifacts.key_path.display());
                    }
                }
                CaAction::Print { ca_dir } => {
                    let ca_dir = ca_dir.unwrap_or_else(|| config.proxy.tls_mitm.ca_dir.clone());
                    let cert_path = ca_dir.join(tls::CA_CERT_FILE);
                    let pem = std::fs::read_to_string(&cert_path).with_context(|| {
                        format!(
                            "Failed to read CA cert at {} (run: aiegis tls ca init)",
                            cert_path.display()
                        )
                    })?;
                    print!("{pem}");
                }
                CaAction::Status { ca_dir } => {
                    let ca_dir = ca_dir.unwrap_or_else(|| config.proxy.tls_mitm.ca_dir.clone());
                    let cert_path = ca_dir.join(tls::CA_CERT_FILE);
                    let key_path = ca_dir.join(tls::CA_KEY_FILE);

                    println!("CA directory: {}", ca_dir.display());
                    println!(
                        "CA cert:      {} ({})",
                        cert_path.display(),
                        if cert_path.exists() {
                            "present"
                        } else {
                            "missing"
                        }
                    );
                    println!(
                        "CA key:       {} ({})",
                        key_path.display(),
                        if key_path.exists() {
                            "present"
                        } else {
                            "missing"
                        }
                    );
                }
            },
        },
    }

    Ok(())
}
