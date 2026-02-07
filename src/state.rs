//! Runtime state management — PID file and data directory.
//!
//! Aegis writes a PID file when starting and removes it on clean shutdown.
//! The data directory at `~/.aegis/` holds the PID file and log file.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

/// Get the Aegis data directory (`~/.aegis/`), creating it if needed.
pub fn data_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").with_context(|| "HOME environment variable not set")?;
    let dir = PathBuf::from(home).join(".aegis");
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create data directory: {}", dir.display()))?;
    Ok(dir)
}

/// Get the PID file path.
pub fn pid_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("aegis.pid"))
}

/// Get the log file path.
pub fn log_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("aegis.log"))
}

/// Write the current process PID to the PID file.
pub fn write_pid() -> Result<()> {
    let pid = std::process::id();
    fs::write(pid_path()?, pid.to_string())?;
    Ok(())
}

/// Read the PID from the PID file. Returns None if no PID file exists.
pub fn read_pid() -> Result<Option<u32>> {
    let path = pid_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(&path)?;
    let pid: u32 = content
        .trim()
        .parse()
        .with_context(|| "Invalid PID in PID file")?;
    Ok(Some(pid))
}

/// Remove the PID file.
pub fn remove_pid() -> Result<()> {
    let path = pid_path()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Check if a process with the given PID is alive.
pub fn is_pid_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Send a signal to a process.
pub fn send_signal(pid: u32, signal: &str) -> Result<bool> {
    let status = std::process::Command::new("kill")
        .args([signal, &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("Failed to send signal {signal} to PID {pid}"))?;
    Ok(status.success())
}
