//! Structured logging setup with tracing-subscriber.
//!
//! Dual output: stdout for interactive use, `~/.aiegis/aiegis.log` for
//! the `aiegis logs` command to read.

pub mod event;

use std::fs::OpenOptions;
use std::sync::Mutex;

use anyhow::Result;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::LoggingConfig;

/// Initialize the tracing subscriber with stdout + file output.
pub fn init(config: &LoggingConfig) -> Result<()> {
    let filter = EnvFilter::try_new(&config.level).unwrap_or_else(|_| EnvFilter::new("info"));

    let log_file = crate::state::log_path()?;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
    let file = Mutex::new(file);

    match config.format.as_str() {
        "json" => {
            let stdout_layer = fmt::layer().json().with_target(false);

            let file_layer = fmt::layer()
                .json()
                .with_target(false)
                .with_ansi(false)
                .with_writer(file);

            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .init();
        }
        _ => {
            let stdout_layer = fmt::layer();

            let file_layer = fmt::layer().with_ansi(false).with_writer(file);

            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .init();
        }
    }

    Ok(())
}
