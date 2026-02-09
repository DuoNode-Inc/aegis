//! Aiegis — AI security firewall proxy.
//!
//! Entry point: parses CLI args, loads config, dispatches to subcommands.

mod cli;
mod config;
mod detection;
mod endpoints;
mod logging;
mod mode;
mod proxy;
mod rules;
mod state;
mod tier;
mod tls;

use std::io::{BufRead, BufReader, Seek, SeekFrom};

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command, RulesAction};
use config::{apply_overrides, load_config};
use detection::classifier::build_classifier;
use detection::injection::InjectionScanner;
use detection::model_package::resolve_classifier_config;
use detection::pii::PiiScanner;
use detection::pipeline::{Action, Pipeline, PipelineConfig};
use mode::detect_mode;
use rules::loader;
use tier::{resolve_tier, validate_tier_config, TierGate};

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

    Ok(Pipeline::new(
        injection,
        pii,
        classifier,
        PipelineConfig {
            injection_enabled: config.detection.injection.enabled,
            pii_enabled: config.detection.pii.enabled,
            entropy_enabled: config.detection.entropy.enabled,
            entropy_threshold: config.detection.entropy.threshold,
            entropy_min_length: config.detection.entropy.min_length,
            default_action,
            classifier_enabled: config.detection.classifier.enabled,
            classifier_threshold: classifier_config.confidence_threshold,
        },
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(cli.config.as_deref())?;
    let runtime_mode = detect_mode();
    let resolved_tier = resolve_tier(config.runtime.tier.as_deref(), runtime_mode)?;

    match cli.command {
        Command::Start { mode, host, port } => {
            let config = apply_overrides(config, Some(&mode), host.as_deref(), port);
            logging::init(&config.logging)?;
            validate_tier_config(&config, resolved_tier)?;
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
                tier_custom_patterns = resolved_tier.allows_custom_patterns(),
                tier_rate_limiting = resolved_tier.allows_rate_limiting(),
                tier_metrics = resolved_tier.allows_metrics(),
                tier_dashboard = resolved_tier.allows_dashboard(),
                injection_patterns = inj_count,
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
        },
    }

    Ok(())
}
