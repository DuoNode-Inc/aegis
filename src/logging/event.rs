//! AiegisEvent struct for structured log serialization.
//!
//! Every proxy request generates an AiegisEvent that is serialized to JSON
//! via the tracing-subscriber JSON layer.

use serde::Serialize;

/// Structured event for every request processed by Aiegis.
#[derive(Debug, Serialize)]
pub struct AiegisEvent {
    pub timestamp: String,
    /// "request" | "response" | "system"
    pub event_type: String,
    /// "pass" | "block" | "flag" | "ambiguous"
    pub action: String,
    pub source: String,
    pub destination: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub detector: Option<String>,
    pub reason: Option<String>,
    pub confidence: Option<f64>,
    pub latency_us: u64,
    pub request_size: Option<usize>,
}

impl AiegisEvent {
    /// Emit this event via tracing at the appropriate level.
    pub fn emit(&self) {
        let json = serde_json::to_string(self).unwrap_or_default();
        match self.action.as_str() {
            "block" => tracing::warn!(aiegis_event = %json, "request blocked"),
            "flag" => tracing::info!(aiegis_event = %json, "request flagged"),
            "ambiguous" => tracing::info!(aiegis_event = %json, "request ambiguous"),
            _ => tracing::info!(aiegis_event = %json, "request passed"),
        }
    }

    /// Create a system-level event (startup, shutdown, etc.)
    #[allow(dead_code)] // Used for graceful shutdown logging in v0.2
    pub fn system(message: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: "system".into(),
            action: "info".into(),
            source: String::new(),
            destination: String::new(),
            method: None,
            path: None,
            detector: None,
            reason: Some(message.into()),
            confidence: None,
            latency_us: 0,
            request_size: None,
        }
    }
}
