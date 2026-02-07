//! Reverse proxy mode — routes by path prefix to upstream AI APIs.
//!
//! The default mode. User points their SDK base URL at localhost:8080/openai
//! and Aegis forwards to api.openai.com, scanning all traffic through the
//! detection pipeline.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_rustls::ConfigBuilderExt;
use hyper_util::rt::TokioIo;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::config::AegisConfig;
use crate::detection::pipeline::Pipeline;
use crate::endpoints::EndpointMatcher;
use crate::proxy::handler;

type HttpsClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

/// Shared state for the gateway proxy.
struct GatewayState {
    pipeline: Pipeline,
    endpoints: EndpointMatcher,
    client: HttpsClient,
    max_body_size: usize,
    semaphore: Arc<Semaphore>,
}

/// Build an HTTPS client using rustls + webpki roots (built once, reused).
fn build_https_client() -> Result<HttpsClient> {
    use hyper_util::client::legacy::Client;

    let tls = rustls::ClientConfig::builder()
        .with_webpki_roots()
        .with_no_client_auth();

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();

    Ok(Client::builder(hyper_util::rt::TokioExecutor::new()).build(https))
}

/// Start the gateway reverse proxy.
pub async fn run(config: AegisConfig, pipeline: Pipeline) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.proxy.host, config.proxy.port).parse()?;
    let endpoints = EndpointMatcher::new(&config.endpoints.targets);
    let client = build_https_client()?;
    let semaphore = Arc::new(Semaphore::new(config.proxy.max_connections));

    let state = Arc::new(GatewayState {
        pipeline,
        endpoints,
        client,
        max_body_size: config.proxy.max_body_size,
        semaphore,
    });

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "Gateway proxy listening");

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
                        Err(_) => return, // semaphore closed
                    };

                    let service = service_fn(move |req: Request<Incoming>| {
                        let state = state.clone();
                        let source = peer_addr.to_string();
                        async move { handle_request(req, &state, &source).await }
                    });

                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                        tracing::debug!(error = %err, "Connection error");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("Shutting down gateway proxy...");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single gateway request. Never fails — errors become HTTP responses.
async fn handle_request(
    req: Request<Incoming>,
    state: &GatewayState,
    source: &str,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let headers = req.headers().clone();

    // Match the path to a gateway route
    let Some((upstream_url, stripped_path)) = state.endpoints.match_route(&path) else {
        return Ok(json_error(404, "aegis_no_route", "No matching AI provider route"));
    };

    // Buffer the request body with size limit
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
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Extract destination hostname for logging
    let destination = upstream_url
        .split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .unwrap_or("unknown");

    // Run detection pipeline on request body
    if !body_str.is_empty() {
        if let Some(block_resp) = handler::scan_request(
            &state.pipeline,
            &body_str,
            source,
            destination,
            method.as_str(),
            &stripped_path,
        ) {
            return Ok(block_resp);
        }
    }

    // Build upstream request, forwarding all headers
    let mut upstream_builder = Request::builder().method(method).uri(&upstream_url);

    for (name, value) in headers.iter() {
        if matches!(
            name.as_str(),
            "host" | "connection" | "transfer-encoding" | "keep-alive"
        ) {
            continue;
        }
        upstream_builder = upstream_builder.header(name, value);
    }
    upstream_builder = upstream_builder.header("host", destination);

    let upstream_req = match upstream_builder.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(error = %err, "Failed to build upstream request");
            return Ok(json_error(
                500,
                "aegis_internal",
                "Failed to build upstream request",
            ));
        }
    };

    // Send upstream request (client is shared, connection pooled)
    match state.client.request(upstream_req).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();

            // Buffer response with size limit
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

            // Scan response body for PII/entropy (exfiltration detection)
            if !resp_body.is_empty() {
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
            tracing::error!(error = %err, upstream = %upstream_url, "Upstream request failed");
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
