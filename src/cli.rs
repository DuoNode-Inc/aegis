//! CLI subcommand definitions for Aiegis.
//!
//! All user-facing commands are defined here using clap derive macros.
//! The actual implementation logic lives in the respective modules.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "aiegis",
    version,
    about = "AI security firewall proxy — local, fast, no cloud",
    long_about = "Aiegis intercepts traffic between your applications and AI API endpoints.\n\
                  It scans prompts and responses for prompt injection, PII leakage,\n\
                  credential exposure, and encoded data exfiltration.\n\
                  All classification runs on-device. Nothing leaves the machine."
)]
pub struct Cli {
    /// Path to aiegis.toml config file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the Aiegis proxy
    Start {
        /// Proxy mode: "gateway" (reverse proxy) or "proxy" (forward/HTTP_PROXY)
        #[arg(short, long, default_value = "gateway")]
        mode: String,

        /// Host to bind on
        #[arg(long)]
        host: Option<String>,

        /// Port to listen on
        #[arg(short, long)]
        port: Option<u16>,
    },

    /// Stop the running Aiegis proxy
    Stop,

    /// Show Aiegis proxy status
    Status,

    /// View Aiegis logs
    Logs {
        /// Number of recent log lines to show
        #[arg(short = 'n', long, default_value = "20")]
        tail: usize,

        /// Follow log output (like tail -f)
        #[arg(short, long)]
        follow: bool,
    },

    /// Manage detection rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    #[cfg(feature = "tls-mitm")]
    /// TLS tooling (Developer+ builds)
    Tls {
        #[command(subcommand)]
        action: TlsAction,
    },
}

#[derive(Subcommand)]
pub enum RulesAction {
    /// List loaded detection rules with pattern counts
    List,

    /// Test a string against the detection pipeline
    Test {
        /// The text to test against all detectors
        input: String,
    },
}

#[cfg(feature = "tls-mitm")]
#[derive(Subcommand)]
pub enum TlsAction {
    /// Local CA management for TLS MITM.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
}

#[cfg(feature = "tls-mitm")]
#[derive(Subcommand)]
pub enum CaAction {
    /// Create (or verify) the local CA material on disk.
    Init {
        /// CA directory (defaults to proxy.tls_mitm.ca_dir from config)
        #[arg(long)]
        ca_dir: Option<PathBuf>,

        /// Overwrite existing CA files.
        #[arg(long)]
        force: bool,

        /// Print the CA certificate PEM to stdout after creation.
        #[arg(long)]
        print_cert: bool,
    },

    /// Print the CA certificate PEM to stdout.
    Print {
        /// CA directory (defaults to proxy.tls_mitm.ca_dir from config)
        #[arg(long)]
        ca_dir: Option<PathBuf>,
    },

    /// Show CA paths and whether files exist.
    Status {
        /// CA directory (defaults to proxy.tls_mitm.ca_dir from config)
        #[arg(long)]
        ca_dir: Option<PathBuf>,
    },
}
