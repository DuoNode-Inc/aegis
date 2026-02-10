//! Traditional HTTP forward proxy mode (CONNECT tunneling).
//!
//! When configured as HTTP_PROXY/HTTPS_PROXY, Aiegis receives:
//! - CONNECT requests for HTTPS destinations → tunnel bytes, log AI endpoints
//! - Plain HTTP requests → inspect body, run detection pipeline, forward
//!
//! v0.1 limitation: HTTPS traffic is tunneled opaquely. Body inspection
//! requires TLS MITM which is deferred to v0.2.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "tls-mitm")]
use anyhow::Context;
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
#[cfg(feature = "tls-mitm")]
use tokio_rustls::TlsAcceptor;

use crate::config::AiegisConfig;
use crate::detection::pipeline::Pipeline;
use crate::endpoints::EndpointMatcher;
use crate::logging::event::AiegisEvent;
use crate::proxy::handler;
#[cfg(feature = "tls-mitm")]
use crate::proxy::upstream_tls;
#[cfg(feature = "tls-mitm")]
use crate::tls;

type HttpClient = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    Full<Bytes>,
>;

#[cfg(feature = "tls-mitm")]
type HttpsClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

#[cfg(feature = "tls-mitm")]
#[derive(Clone)]
struct CachedLeaf {
    server_config: Arc<rustls::ServerConfig>,
    created_at: std::time::Instant,
}

#[cfg(feature = "tls-mitm")]
struct MitmState {
    ca: tls::LoadedCa,
    leaf_ttl: Duration,
    // Low-contention: leaf cert generation is rare per host.
    leaf_cache: std::sync::Mutex<std::collections::HashMap<String, CachedLeaf>>,
    leaf_cache_max_entries: usize,
}

/// Shared state for the forward proxy.
struct ForwardState {
    pipeline: Arc<Pipeline>,
    endpoints: EndpointMatcher,
    client: HttpClient,
    #[cfg(feature = "tls-mitm")]
    tls_client: HttpsClient,
    max_body_size: usize,
    tunnel_timeout: Duration,
    tls_mitm_enabled: bool,
    #[cfg(feature = "tls-mitm")]
    mitm: Option<Arc<MitmState>>,
    semaphore: Arc<Semaphore>,
}

/// Start the forward proxy.
pub async fn run(config: AiegisConfig, pipeline: Pipeline) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.proxy.host, config.proxy.port).parse()?;
    let endpoints = EndpointMatcher::new(&config.endpoints.targets);
    let semaphore = Arc::new(Semaphore::new(config.proxy.max_connections));

    let connector = hyper_util::client::legacy::connect::HttpConnector::new();
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(connector);

    #[cfg(feature = "tls-mitm")]
    let tls_client = {
        let tls = upstream_tls::build_rustls_client_config(
            config.proxy.upstream_tls.extra_ca_bundle_path.as_deref(),
        )?;
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(https)
    };

    #[cfg(feature = "tls-mitm")]
    let mitm = if config.proxy.tls_mitm.enabled {
        // Ensure CA exists (main.rs also does this for `aiegis start`, but tests may call `run` directly).
        let _ = tls::ensure_ca(&config.proxy.tls_mitm.ca_dir)?;
        let ca = tls::load_ca(&config.proxy.tls_mitm.ca_dir)?;
        Some(Arc::new(MitmState {
            ca,
            leaf_ttl: Duration::from_secs(24 * 60 * 60),
            leaf_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            leaf_cache_max_entries: 512,
        }))
    } else {
        None
    };

    let state = Arc::new(ForwardState {
        pipeline: Arc::new(pipeline),
        endpoints,
        client,
        #[cfg(feature = "tls-mitm")]
        tls_client,
        max_body_size: config.proxy.max_body_size,
        tunnel_timeout: Duration::from_secs(config.proxy.tunnel_timeout_secs),
        tls_mitm_enabled: config.proxy.tls_mitm.enabled,
        #[cfg(feature = "tls-mitm")]
        mitm,
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
                        async move { handle_request(req, state, source).await }
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
    state: Arc<ForwardState>,
    source: String,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == Method::CONNECT {
        return handle_connect(req, state, &source);
    }

    handle_plain_http(req, &state, &source).await
}

/// Handle CONNECT requests — establish a TCP tunnel with idle timeout.
fn handle_connect(
    req: Request<Incoming>,
    state: Arc<ForwardState>,
    source: &str,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let target = match req.uri().authority() {
        Some(a) => a.to_string(),
        None => req.uri().to_string(),
    };

    let host = target.split(':').next().unwrap_or("unknown");
    let is_ai = state.endpoints.is_ai_endpoint(host);

    if is_ai {
        let event = AiegisEvent {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: "connect".into(),
            action: "pass".into(),
            source: source.into(),
            destination: target.clone(),
            method: Some("CONNECT".into()),
            path: None,
            detector: None,
            reason: Some(
                if state.tls_mitm_enabled {
                    "HTTPS tunnel — MITM enabled"
                } else {
                    "HTTPS tunnel — body not inspectable without MITM"
                }
                .into(),
            ),
            confidence: None,
            latency_us: 0,
            request_size: None,
        };
        event.emit();
        tracing::info!(
            source = %source,
            destination = %target,
            mitm = state.tls_mitm_enabled,
            "AI endpoint CONNECT"
        );
    } else {
        tracing::debug!(
            source = %source,
            destination = %target,
            "Non-AI CONNECT tunnel (passthrough)"
        );
    }

    // AI endpoints: if TLS MITM is enabled (Developer+ tier), intercept HTTPS inside CONNECT.
    // Non-AI endpoints: always passthrough tunnel to avoid surprising interception.
    if state.tls_mitm_enabled && is_ai {
        #[cfg(feature = "tls-mitm")]
        {
            let port: u16 = target
                .split(':')
                .nth(1)
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(443);
            let host = host.to_string();
            let destination = target.clone();
            let source = source.to_string();
            let state = state.clone();
            tokio::task::spawn(async move {
                if let Err(err) =
                    handle_connect_mitm(req, state, &source, &destination, &host, port).await
                {
                    tracing::error!(error = %err, destination = %destination, "CONNECT MITM failed");
                }
            });
        }
        #[cfg(not(feature = "tls-mitm"))]
        {
            // Should be unreachable because `aiegis start` fails earlier when tls-mitm feature is missing.
            tracing::error!(
                "TLS MITM enabled in config but binary is missing the 'tls-mitm' feature"
            );
        }
    } else {
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
    }

    Ok(Response::new(Full::new(Bytes::new())))
}

#[cfg(feature = "tls-mitm")]
async fn handle_connect_mitm(
    req: Request<Incoming>,
    state: Arc<ForwardState>,
    source: &str,
    destination: &str,
    host: &str,
    port: u16,
) -> Result<()> {
    let Some(mitm) = state.mitm.as_ref() else {
        anyhow::bail!("TLS MITM enabled but MITM state was not initialized");
    };

    let upgraded = hyper::upgrade::on(req).await?;
    let upgraded_io = TokioIo::new(upgraded);

    let server_config = {
        let mut cache = mitm.leaf_cache.lock().expect("leaf cache mutex poisoned");
        if let Some(cached) = cache.get(host) {
            if cached.created_at.elapsed() < mitm.leaf_ttl {
                cached.server_config.clone()
            } else {
                cache.remove(host);
                tls::mitm_server_config_for_host(&mitm.ca, host)?
            }
        } else {
            // Best-effort cap to prevent unbounded growth.
            if cache.len() >= mitm.leaf_cache_max_entries {
                cache.clear();
            }
            tls::mitm_server_config_for_host(&mitm.ca, host)?
        }
    };

    {
        let mut cache = mitm.leaf_cache.lock().expect("leaf cache mutex poisoned");
        cache.insert(
            host.to_string(),
            CachedLeaf {
                server_config: server_config.clone(),
                created_at: std::time::Instant::now(),
            },
        );
    }

    let acceptor = TlsAcceptor::from(server_config);
    let tls_stream = acceptor.accept(upgraded_io).await?;

    // Serve HTTP/1.1 inside the decrypted tunnel.
    let io = TokioIo::new(tls_stream);
    let host = host.to_string();
    let destination = destination.to_string();
    let source = source.to_string();
    let max_body_size = state.max_body_size;
    let pipeline = state.pipeline.clone();
    let client = state.tls_client.clone();

    let service = service_fn(move |req: Request<Incoming>| {
        let host = host.clone();
        let destination = destination.clone();
        let source = source.clone();
        let pipeline = pipeline.clone();
        let client = client.clone();
        async move {
            Ok::<_, Infallible>(
                handle_mitm_http(
                    req,
                    pipeline.as_ref(),
                    &client,
                    max_body_size,
                    &source,
                    &destination,
                    &host,
                    port,
                )
                .await
                .unwrap_or_else(|err| json_error(502, "aiegis_mitm_error", &err.to_string())),
            )
        }
    });

    http1::Builder::new()
        .serve_connection(io, service)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;

    Ok(())
}

#[cfg(feature = "tls-mitm")]
async fn handle_mitm_http(
    req: Request<Incoming>,
    pipeline: &Pipeline,
    client: &HttpsClient,
    max_body_size: usize,
    source: &str,
    destination: &str,
    host: &str,
    port: u16,
) -> Result<Response<Full<Bytes>>> {
    let method = req.method().clone();
    let headers = req.headers().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let body_bytes = match Limited::new(req.into_body(), max_body_size).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(json_error(
                413,
                "aiegis_body_too_large",
                "Request body exceeds maximum allowed size",
            ));
        }
    };

    // AI-only MITM: always scan request bodies when present.
    if !body_bytes.is_empty() {
        let body_str = String::from_utf8_lossy(&body_bytes);
        if let Some(block_resp) = handler::scan_request(
            pipeline,
            &body_str,
            source,
            destination,
            method.as_str(),
            &path_and_query,
        ) {
            return Ok(block_resp);
        }
    }

    let upstream_url = format!("https://{host}:{port}{path_and_query}");
    let mut upstream_builder = Request::builder().method(method).uri(&upstream_url);

    for (name, value) in headers.iter() {
        if matches!(
            name.as_str(),
            "host"
                | "connection"
                | "transfer-encoding"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authorization"
        ) {
            continue;
        }
        upstream_builder = upstream_builder.header(name, value);
    }
    upstream_builder = upstream_builder.header("host", host);

    let upstream_req = upstream_builder
        .body(Full::new(body_bytes))
        .context("Failed to build upstream MITM request")?;

    let resp = client
        .request(upstream_req)
        .await
        .context("Upstream MITM request failed")?;
    let status = resp.status();
    let resp_headers = resp.headers().clone();

    let resp_body = match Limited::new(resp.into_body(), max_body_size)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(json_error(
                502,
                "aiegis_upstream_error",
                "Upstream response exceeds maximum allowed size",
            ));
        }
    };

    if !resp_body.is_empty() {
        let resp_str = String::from_utf8_lossy(&resp_body);
        handler::scan_response(pipeline, &resp_str, source, destination);
    }

    let mut response = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        if !matches!(name.as_str(), "transfer-encoding" | "connection") {
            response = response.header(name, value);
        }
    }

    Ok(response
        .body(Full::new(resp_body))
        .expect("building MITM proxy response"))
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
    let body_bytes = match Limited::new(req.into_body(), state.max_body_size)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Ok(json_error(
                413,
                "aiegis_body_too_large",
                "Request body exceeds maximum allowed size",
            ));
        }
    };

    // Run detection on AI-bound traffic only
    if is_ai && !body_bytes.is_empty() {
        let body_str = String::from_utf8_lossy(&body_bytes);
        if let Some(block_resp) = handler::scan_request(
            state.pipeline.as_ref(),
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
                "aiegis_internal",
                "Failed to build upstream request",
            ));
        }
    };

    match state.client.request(upstream_req).await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();

            let resp_body = match Limited::new(resp.into_body(), state.max_body_size)
                .collect()
                .await
            {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Ok(json_error(
                        502,
                        "aiegis_upstream_error",
                        "Upstream response exceeds maximum allowed size",
                    ));
                }
            };

            // Scan response for PII/entropy on AI traffic
            if is_ai && !resp_body.is_empty() {
                let resp_str = String::from_utf8_lossy(&resp_body);
                handler::scan_response(state.pipeline.as_ref(), &resp_str, source, destination);
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
            Ok(json_error(502, "aiegis_upstream_error", &err.to_string()))
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
