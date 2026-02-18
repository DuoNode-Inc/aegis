//! Sidecar scan server — lightweight HTTP API for the browser extension.
//!
//! Starts a minimal Hyper server on localhost that the Aiegis extension can
//! POST to for verdict decisions. Complements (not replaces) the proxy modes:
//! when the binary is also running as a gateway or forward proxy, the sidecar
//! runs on a separate port so the extension can always reach it.
//!
//! Endpoints:
//!   GET  /status          — version, tier, uptime, counters
//!   POST /scan            — scan text for injection / PII
//!   POST /scan/wallet     — analyze wallet signing payload
//!   OPTIONS *             — CORS preflight

use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;

use crate::detection::pipeline::{Action, Pipeline};
use crate::tier::Tier;

/// Shared counters visible on /status.
#[derive(Default)]
pub struct Counters {
    pub scanned: AtomicU64,
    pub blocked: AtomicU64,
    pub flagged: AtomicU64,
}

pub struct SidecarState {
    pub pipeline: Pipeline,
    pub tier: Tier,
    pub started_at: Instant,
    pub counters: Arc<Counters>,
}

/// Request body for POST /scan
#[derive(Deserialize)]
struct ScanRequest {
    text: String,
    /// Caller hint: "clipboard_paste" | "wallet_message" | "manual"
    #[serde(default)]
    source: String,
}

/// Request body for POST /scan/wallet — subset of EVM signing analysis
#[derive(Deserialize)]
struct WalletScanRequest {
    method: String,
    /// Serialised params array (JSON string or raw JSON value)
    params: Option<serde_json::Value>,
}

/// Unified scan response
#[derive(Serialize)]
struct ScanResponse {
    action: &'static str, // "PASS" | "FLAG" | "BLOCK"
    reason: Option<String>,
    confidence: f64,
    latency_us: u64,
    detector: Option<String>,
}

/// Status response
#[derive(Serialize)]
struct StatusResponse<'a> {
    version: &'a str,
    tier: &'a str,
    uptime_s: u64,
    scanned: u64,
    blocked: u64,
    flagged: u64,
}

pub async fn run(host: &str, port: u16, state: Arc<SidecarState>) -> Result<()> {
    let addr: SocketAddr = format!("{host}:{port}").parse()?;
    let listener = TcpListener::bind(addr).await?;

    tracing::info!(
        host = host,
        port = port,
        tier = state.tier.as_str(),
        "Aiegis sidecar scan server listening"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        let io = TokioIo::new(stream);

        tokio::task::spawn(async move {
            let svc = service_fn(move |req| {
                let state = Arc::clone(&state);
                handle_request(req, state)
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                tracing::debug!(peer = %peer, error = %e, "sidecar connection error");
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: Arc<SidecarState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // CORS preflight — allow extension origin
    if req.method() == Method::OPTIONS {
        return Ok(cors_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Full::new(Bytes::new()))
                .unwrap(),
        ));
    }

    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_owned();

    let response = match (parts.method.clone(), path.as_str()) {
        (Method::GET, "/status") => handle_status(&state),

        (Method::POST, "/scan") => {
            let bytes = collect_body(body).await;
            handle_scan(bytes, &state)
        }

        (Method::POST, "/scan/wallet") => {
            let bytes = collect_body(body).await;
            handle_wallet_scan(bytes, &state)
        }

        _ => json_error(StatusCode::NOT_FOUND, "not_found"),
    };

    Ok(cors_response(response))
}

async fn collect_body(body: hyper::body::Incoming) -> Bytes {
    body.collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default()
}

fn handle_status(state: &SidecarState) -> Response<Full<Bytes>> {
    let resp = StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        tier: state.tier.as_str(),
        uptime_s: state.started_at.elapsed().as_secs(),
        scanned: state.counters.scanned.load(Ordering::Relaxed),
        blocked: state.counters.blocked.load(Ordering::Relaxed),
        flagged: state.counters.flagged.load(Ordering::Relaxed),
    };
    json_ok(&resp)
}

fn handle_scan(body: Bytes, state: &SidecarState) -> Response<Full<Bytes>> {
    let req: ScanRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid_json"),
    };

    if req.text.is_empty() {
        return json_ok(&ScanResponse {
            action: "PASS",
            reason: None,
            confidence: 0.0,
            latency_us: 0,
            detector: None,
        });
    }

    let t0 = Instant::now();
    let verdict = state.pipeline.scan(&req.text);
    let latency_us = t0.elapsed().as_micros() as u64;

    let (action, confidence) = match verdict.action {
        Action::Block => ("BLOCK", verdict.confidence),
        Action::Flag | Action::Ambiguous => ("FLAG", verdict.confidence),
        Action::Pass => ("PASS", 0.0),
    };

    state.counters.scanned.fetch_add(1, Ordering::Relaxed);
    match action {
        "BLOCK" => {
            state.counters.blocked.fetch_add(1, Ordering::Relaxed);
        }
        "FLAG" => {
            state.counters.flagged.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }

    tracing::debug!(
        source = %req.source,
        action = action,
        latency_us = latency_us,
        "sidecar scan"
    );

    json_ok(&ScanResponse {
        action,
        reason: verdict.reason.clone(),
        confidence,
        latency_us,
        detector: verdict.detector.clone(),
    })
}

fn handle_wallet_scan(body: Bytes, state: &SidecarState) -> Response<Full<Bytes>> {
    let req: WalletScanRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid_json"),
    };

    let t0 = Instant::now();

    // eth_sign is always a BLOCK — raw hash has no human context
    if req.method == "eth_sign" {
        state.counters.scanned.fetch_add(1, Ordering::Relaxed);
        state.counters.blocked.fetch_add(1, Ordering::Relaxed);
        return json_ok(&ScanResponse {
            action: "BLOCK",
            reason: Some("eth_sign is a phishing vector: raw hash signing provides no human-readable context".into()),
            confidence: 1.0,
            latency_us: t0.elapsed().as_micros() as u64,
            detector: Some("wallet".into()),
        });
    }

    // For personal_sign, extract and scan the message text through the pipeline
    if req.method == "personal_sign" {
        if let Some(params) = &req.params {
            if let Some(msg) = params.get(0).and_then(|v| v.as_str()) {
                // Decode hex message to text
                let text = if msg.starts_with("0x") {
                    hex_to_utf8(msg).unwrap_or_else(|| msg.to_string())
                } else {
                    msg.to_string()
                };

                let verdict = state.pipeline.scan(&text);
                let latency_us = t0.elapsed().as_micros() as u64;

                state.counters.scanned.fetch_add(1, Ordering::Relaxed);

                if matches!(verdict.action, Action::Block | Action::Flag | Action::Ambiguous) {
                    state.counters.flagged.fetch_add(1, Ordering::Relaxed);
                    return json_ok(&ScanResponse {
                        action: "FLAG",
                        reason: verdict.reason.clone().or_else(|| Some("Suspicious content in signed message".into())),
                        confidence: verdict.confidence,
                        latency_us,
                        detector: Some("wallet_message".into()),
                    });
                }
            }
        }
    }

    // eth_signTypedData_v4: scan the JSON message values for phishing text
    if req.method.starts_with("eth_signTypedData") {
        if let Some(verdict) = scan_typed_data(&req.params, &state.pipeline, &t0) {
            state.counters.scanned.fetch_add(1, Ordering::Relaxed);
            state.counters.flagged.fetch_add(1, Ordering::Relaxed);
            return json_ok(&verdict);
        }
    }

    state.counters.scanned.fetch_add(1, Ordering::Relaxed);

    json_ok(&ScanResponse {
        action: "PASS",
        reason: None,
        confidence: 0.0,
        latency_us: t0.elapsed().as_micros() as u64,
        detector: Some("wallet".into()),
    })
}

/// Extract string values from EIP-712 typed data and run injection scan on them.
fn scan_typed_data(
    params: &Option<serde_json::Value>,
    pipeline: &Pipeline,
    t0: &Instant,
) -> Option<ScanResponse> {
    let params = params.as_ref()?;
    // params[1] is the typed data JSON (may be a string or object)
    let typed_data_val = params.get(1)?;
    let typed_data: serde_json::Value = if typed_data_val.is_string() {
        serde_json::from_str(typed_data_val.as_str()?).ok()?
    } else {
        typed_data_val.clone()
    };

    // Collect all leaf string values from the message object
    let message = typed_data.get("message")?;
    let strings = collect_strings(message);

    for s in &strings {
        if s.len() < 8 {
            continue;
        }
        let verdict = pipeline.scan(s);
        if matches!(verdict.action, Action::Block | Action::Flag | Action::Ambiguous) {
            return Some(ScanResponse {
                action: "FLAG",
                reason: verdict
                    .reason
                    .clone()
                    .or_else(|| Some("Suspicious content in EIP-712 message".into())),
                confidence: verdict.confidence,
                latency_us: t0.elapsed().as_micros() as u64,
                detector: Some("wallet_eip712".into()),
            });
        }
    }
    None
}

/// Recursively collect all string leaf values from a JSON object.
fn collect_strings(val: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    match val {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Object(map) => {
            for v in map.values() {
                out.extend(collect_strings(v));
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                out.extend(collect_strings(v));
            }
        }
        _ => {}
    }
    out
}

fn hex_to_utf8(hex: &str) -> Option<String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    String::from_utf8(bytes).ok()
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

fn json_ok<T: Serialize>(body: &T) -> Response<Full<Bytes>> {
    let json = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap()
}

fn json_error(status: StatusCode, code: &str) -> Response<Full<Bytes>> {
    let json = serde_json::json!({ "error": code });
    let bytes = serde_json::to_vec(&json).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}

/// Attach CORS headers permitting extension origins.
fn cors_response(mut resp: Response<Full<Bytes>>) -> Response<Full<Bytes>> {
    let headers = resp.headers_mut();
    headers.insert(
        "Access-Control-Allow-Origin",
        // Accept any chrome-extension or moz-extension origin.
        // In production you'd lock this down to your extension ID.
        "*".parse().unwrap(),
    );
    headers.insert(
        "Access-Control-Allow-Methods",
        "GET, POST, OPTIONS".parse().unwrap(),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        "Content-Type".parse().unwrap(),
    );
    resp
}
