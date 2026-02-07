//! Traditional HTTP forward proxy mode (CONNECT tunneling).
//!
//! When configured as HTTP_PROXY/HTTPS_PROXY, Aegis receives:
//! - CONNECT requests for HTTPS destinations → tunnel bytes, log AI endpoints
//! - Plain HTTP requests → inspect body, run detection pipeline, forward
//!
//! v0.1 limitation: HTTPS traffic is tunneled opaquely. Body inspection
//! requires TLS MITM which is deferred to v0.2.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::config::AegisConfig;
use crate::detection::pipeline::Pipeline;
use crate::endpoints::EndpointMatcher;
use crate::logging::event::AegisEvent;
use crate::proxy::handler;

type HttpClient = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    Full<Bytes>,
>;

/// Shared state for the forward proxy.
struct ForwardState {
    pipeline: Pipeline,
    endpoints: EndpointMatcher,
    client: HttpClient,
    max_body_size: usize,
    tunnel_timeout: Duration,
    semaphore: Arc<Semaphore>,
}

/// Start the forward proxy.
pub async fn run(config: AegisConfig, pipeline: Pipeline) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.proxy.host, config.proxy.port).parse()?;
    let endpoints = EndpointMatcher::new(&config.endpoints.targets);
    let semaphore = Arc::new(Semaphore::new(config.proxy.max_connections));

    let connector = hyper_util::client::legacy::connect::HttpConnector::new();
    let client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);

    let state = Arc::new(ForwardState {
        pipeline,
        endpoints,
        client,
        max_body_size: config.proxy.max_body_size,
        tunnel_timeout: Duration::from_secs(config.proxy.tunnel_timeout_secs),
        semaphore,
    });

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "Forward proxy listening");

    // Graceful shutdown on SIGINT/SIGTERM
    let shutdown = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {},
                _ = sigterm.recv() => {},
            }
        }
        #[cfg(not(unix))]
        ctrl_c.await.ok();
    };
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer_addr) = result?;
                let io = TokioIo::new(stream);
                let state = state.clone();
                let permit = state.semaphore.clone().acquire_owned().await;

                tokio::task::spawn(async move {
                    let _permit = match permit {
                        Ok(p) => p,
                        Err(_) => return,
                    };

                    let service = service_fn(move |req: Request<Incoming>| {
                        let state = state.clone();
                        let source = peer_addr.to_string();
                        async move { handle_request(req, &state, &source).await }
                    });

                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                    {
                        tracing::debug!(error = %err, "Forward proxy connection error");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("Shutting down forward proxy...");
                break;
            }
        }
    }

    Ok(())
}

/// Route request based on method.
async fn handle_request(
    req: Request<Incoming>,
    state: &ForwardState,
    source: &str,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == Method::CONNECT {
        return handle_connect(req, state, source);
    }

    handle_plain_http(req, state, source).await
}

/// Handle CONNECT requests — establish a TCP tunnel with idle timeout.
fn handle_connect(
    req: Request<Incoming>,
    state: &ForwardState,
    source: &str,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let target = match req.uri().authority() {
        Some(a) => a.to_string(),
        None => req.uri().to_string(),
    };

    let host = target.split(':').next().unwrap_or("unknown");
    let is_ai = state.endpoints.is_ai_endpoint(host);

    if is_ai {
        let event = AegisEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: "connect".into(),
            action: "pass".into(),
            source: source.into(),
            destination: target.clone(),
            method: Some("CONNECT".into()),
            path: None,
            detector: None,
            reason: Some("HTTPS tunnel — body not inspectable without MITM".into()),
            confidence: None,
            latency_us: 0,
            request_size: None,
        };
        event.emit();
        tracing::info!(
            source = %source,
            destination = %target,
            "AI endpoint CONNECT tunnel (HTTPS — opaque)"
        );
    } else {
        tracing::debug!(
            source = %source,
            destination = %target,
            "Non-AI CONNECT tunnel (passthrough)"
        );
    }

    let target_addr = target.clone();
    let tunnel_timeout = state.tunnel_timeout;
    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => match TcpStream::connect(&target_addr).await {
                Ok(mut target_stream) => {
                    let mut upgraded_io = TokioIo::new(upgraded);
                    // Tunnel with idle timeout
                    let result = tokio::time::timeout(
                        tunnel_timeout,
                        tokio::io::copy_bidirectional(&mut upgraded_io, &mut target_stream),
                    )
                    .await;
                    match result {
                        Ok(Ok(_)) => {}
                        Ok(Err(err)) => {
                            tracing::debug!(error = %err, target = %target_addr, "Tunnel closed");
                        }
                        Err(_) => {
                            tracing::debug!(target = %target_addr, "Tunnel timed out");
                        }
                    }
                }
                Err(err) => {
                    tracing::error!(
                        error = %err,
                        target = %target_addr,
                        "Failed to connect to tunnel target"
                    );
                }
            },
            Err(err) => {
                tracing::error!(error = %err, "CONNECT upgrade failed");
            }
        }
    });

    Ok(Response::new(Full::new(Bytes::new())))
}

/// Handle plain HTTP (non-CONNECT) requests with body size limits.
async fn handle_plain_http(
    req: Request<Incoming>,
    state: &ForwardState,
    source: &str,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let destination = uri.host().unwrap_or("unknown");
    let is_ai = state.endpoints.is_ai_endpoint(destination);
    let path = uri.path().to_string();

    // Buffer body with size limit
    let body_bytes = match Limited::new(req.into_body(), state.max_body_size).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(json_error(
                413,
                "aegis_body_too_large",
                "Request body exceeds maximum allowed size",
            ));
        }
    };

    // Run detection on AI-bound traffic only
    if is_ai && !body_bytes.is_empty() {
        let body_str = String::from_utf8_lossy(&body_bytes);
        if let Some(block_resp) = handler::scan_request(
            &state.pipeline,
            &body_str,
            source,
            destination,
            method.as_str(),
            &path,
        ) {
            return Ok(block_resp);
        }
    }

    // Forward request with headers (client is shared)
    let mut upstream_builder = Request::builder().method(method).uri(uri.to_string());

    for (name, value) in headers.iter() {
        if !matches!(name.as_str(), "proxy-connection" | "proxy-authorization") {
            upstream_builder = upstream_builder.header(name, value);
        }
    }

    let upstream_req = match upstream_builder.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "Failed to build upstream request");
            return Ok(json_error(
                502,
                "aegis_internal",
                "Failed to build upstream request",
            ));
        }
    };

    match state.client.request(upstream_req).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();

            let resp_body = match Limited::new(resp.into_body(), state.max_body_size).collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Ok(json_error(
                        502,
                        "aegis_upstream_error",
                        "Upstream response exceeds maximum allowed size",
                    ));
                }
            };

            // Scan response for PII/entropy on AI traffic
            if is_ai && !resp_body.is_empty() {
                let resp_str = String::from_utf8_lossy(&resp_body);
                handler::scan_response(&state.pipeline, &resp_str, source, destination);
            }

            let mut response = Response::builder().status(status);
            for (name, value) in resp_headers.iter() {
                if !matches!(name.as_str(), "transfer-encoding" | "connection") {
                    response = response.header(name, value);
                }
            }

            Ok(response
                .body(Full::new(resp_body))
                .expect("building proxy response"))
        }
        Err(err) => {
            tracing::error!(error = %err, "Forward proxy upstream request failed");
            Ok(json_error(502, "aegis_upstream_error", &err.to_string()))
        }
    }
}

/// Helper to build a JSON error response using serde_json (injection-safe).
fn json_error(status: u16, error_type: &str, reason: &str) -> Response<Full<Bytes>> {
    let body = json!({
        "error": {
            "type": error_type,
            "reason": reason
        }
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("building error response")
}
