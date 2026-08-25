//! Skill Doctor Execution Service HTTP API (`Commands::Server`).
//!
//! Provides the versioned REST API (`POST /v1/scans`) for the Control Plane (Worker / Queue).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::executor::models::{ScanLifecycleState, ScanRequestV1, ScanResponseV1};
use crate::executor::ScanExecutor;

/// Configuration options for the Execution Service.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub auth_token: Option<String>,
    pub allow_local_urls: bool,
    pub max_payload_bytes: usize,
    pub max_artifact_bytes: usize,
    pub default_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
            auth_token: std::env::var("SKILL_DOCTOR_AUTH_TOKEN").ok(),
            allow_local_urls: true,
            max_payload_bytes: 2 * 1024 * 1024,      // 2 MB
            max_artifact_bytes: 50 * 1024 * 1024,   // 50 MB
            default_timeout_secs: 60,
        }
    }
}

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ServerConfig>,
}

/// Run the Skill Doctor Execution Service server.
pub async fn run(
    port: Option<u16>,
    host: Option<String>,
    auth_token: Option<String>,
    strict_network: bool,
) -> anyhow::Result<()> {
    let mut config = ServerConfig::default();
    if let Some(p) = port {
        config.port = p;
    }
    if let Some(h) = host {
        config.host = h;
    }
    if let Some(t) = auth_token {
        config.auth_token = Some(t);
    }
    if strict_network {
        config.allow_local_urls = false;
    }

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    println!("SKILL DOCTOR EXECUTION SERVICE");
    println!("by Kalaris Labs");
    println!();
    println!("[BIND] Listening on http://{}", addr);
    println!(
        "[AUTH] Bearer Authentication: {}",
        if config.auth_token.is_some() {
            "ENABLED"
        } else {
            "DISABLED (Development)"
        }
    );
    println!(
        "[NETWORK] SSRF Strict Network Policy: {}",
        if config.allow_local_urls {
            "PERMISSIVE (Dev)"
        } else {
            "STRICT (Production)"
        }
    );
    println!();

    let app = create_router(config);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Construct the Axum Router for the Execution Service (exposed for integration testing).
pub fn create_router(config: ServerConfig) -> Router {
    let max_body = config.max_payload_bytes;
    let state = AppState {
        config: Arc::new(config),
    };

    Router::new()
        .route("/health", get(health_handler))
        .route("/v1/version", get(version_handler))
        .route("/v1/scans", post(create_scan_handler))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// `GET /health` endpoint.
async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "service": "skill-doctor-execution-service",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// `GET /v1/version` endpoint.
async fn version_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "api_version": "v1",
        "supported_layers": ["static", "semantic", "sandbox", "threat_db"],
    }))
}

/// `POST /v1/scans` endpoint.
async fn create_scan_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ScanRequestV1>,
) -> impl IntoResponse {
    // 1. Verify Authentication
    if let Some(ref required_token) = state.config.auth_token {
        let auth_header = headers.get("Authorization").and_then(|v| v.to_str().ok());
        let expected = format!("Bearer {}", required_token);
        if auth_header != Some(&expected) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ScanResponseV1 {
                    status: "rejected".to_string(),
                    scan_id: payload.scan_id,
                    state: ScanLifecycleState::Failed,
                    error: Some("Unauthorized: Invalid or missing Bearer token".to_string()),
                }),
            );
        }
    }

    // 2. Validate basic input fields
    if payload.scan_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ScanResponseV1 {
                status: "rejected".to_string(),
                scan_id: "".to_string(),
                state: ScanLifecycleState::Failed,
                error: Some("scan_id must not be empty".to_string()),
            }),
        );
    }

    if payload.artifact.key.trim().is_empty() || payload.artifact.sha256.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ScanResponseV1 {
                status: "rejected".to_string(),
                scan_id: payload.scan_id,
                state: ScanLifecycleState::Failed,
                error: Some("artifact.key and artifact.sha256 are required".to_string()),
            }),
        );
    }

    // 3. Namespace validation check: scans/{scanId}/...
    let expected_namespace = format!("scans/{}/", payload.scan_id);
    if !payload.artifact.key.starts_with(&expected_namespace) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ScanResponseV1 {
                status: "rejected".to_string(),
                scan_id: payload.scan_id.clone(),
                state: ScanLifecycleState::Failed,
                error: Some(format!(
                    "Namespace violation: key '{}' must start with '{}'",
                    payload.artifact.key, expected_namespace
                )),
            }),
        );
    }

    let scan_id = payload.scan_id.clone();
    let allow_local_urls = state.config.allow_local_urls;
    let max_artifact_bytes = state.config.max_artifact_bytes;
    let timeout_secs = payload
        .timeout_secs
        .unwrap_or(state.config.default_timeout_secs);

    // 4. Asynchronously spawn execution pipeline with timeout protection
    tokio::spawn(async move {
        let executor = ScanExecutor::new(payload, allow_local_urls, max_artifact_bytes);
        let timeout_duration = Duration::from_secs(timeout_secs);

        match tokio::time::timeout(timeout_duration, executor.execute()).await {
            Ok(Ok(_result)) => {
                tracing::info!("Scan {} completed successfully", scan_id);
            }
            Ok(Err(e)) => {
                tracing::error!("Scan {} failed: {}", scan_id, e);
            }
            Err(_) => {
                tracing::error!("Scan {} timed out after {}s", scan_id, timeout_secs);
                executor
                    .emit_failure(
                        &format!("Scan execution timed out after {}s", timeout_secs),
                        ScanLifecycleState::Failed,
                    )
                    .await;
            }
        }
    });

    // 5. Respond immediately with 202 Accepted
    (
        StatusCode::ACCEPTED,
        Json(ScanResponseV1 {
            status: "accepted".to_string(),
            scan_id,
            state: ScanLifecycleState::Accepted,
            error: None,
        }),
    )
}
