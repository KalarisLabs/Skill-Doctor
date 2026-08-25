//! Automated Integration and Contract Tests for Skill Doctor Execution Service API.

use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use skill_doctor_cli::commands::server::{ServerConfig, create_router};
use skill_doctor_cli::executor::models::{
    ArtifactSpecV1, ScanEventV1, ScanLayerV1, ScanLifecycleState, ScanRequestV1, ScanResponseV1,
};
use skill_doctor_cli::executor::{ExecutionError, ScanExecutor};
use skill_doctor_core::models::RiskLevel;

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[tokio::test]
async fn test_axum_api_contract_v1() {
    let config = ServerConfig::default();
    let app = create_router(config);

    // Test GET /health
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "skill-doctor-execution-service");

    // Test GET /v1/version
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/version")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["api_version"], "v1");
}

#[tokio::test]
async fn test_authentication_valid_and_invalid() {
    let mut config = ServerConfig::default();
    config.auth_token = Some("secret-token-12345".to_string());
    let app = create_router(config);

    let payload = ScanRequestV1 {
        scan_id: "scan-auth-test".to_string(),
        artifact: ArtifactSpecV1 {
            r#type: "url".to_string(),
            key: "scans/scan-auth-test/artifact.zip".to_string(),
            url: "https://example.com/artifact.zip".to_string(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        },
        layers: vec![ScanLayerV1::Static],
        engine_version: "1.0.0".to_string(),
        event_callback: None,
        timeout_secs: Some(30),
    };

    let body_bytes = serde_json::to_vec(&payload).unwrap();

    // 1. Request with no auth header -> 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/scans")
                .header("Content-Type", "application/json")
                .body(Body::from(body_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 2. Request with incorrect auth token -> 401
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/scans")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer wrong-token")
                .body(Body::from(body_bytes.clone()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 3. Request with valid auth token -> 202 Accepted
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/scans")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer secret-token-12345")
                .body(Body::from(body_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let res: ScanResponseV1 = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.status, "accepted");
    assert_eq!(res.scan_id, "scan-auth-test");
    assert_eq!(res.state, ScanLifecycleState::Accepted);
}

#[tokio::test]
async fn test_key_namespace_validation() {
    let config = ServerConfig::default();
    let app = create_router(config);

    // Invalid namespace: key does not match scans/{scanId}/...
    let payload = ScanRequestV1 {
        scan_id: "scan-999".to_string(),
        artifact: ArtifactSpecV1 {
            r#type: "url".to_string(),
            key: "scans/other-scan-id/artifact.zip".to_string(),
            url: "https://example.com/artifact.zip".to_string(),
            sha256: "abc".to_string(),
        },
        layers: vec![ScanLayerV1::Static],
        engine_version: "1.0.0".to_string(),
        event_callback: None,
        timeout_secs: Some(30),
    };

    let body_bytes = serde_json::to_vec(&payload).unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/scans")
                .header("Content-Type", "application/json")
                .body(Body::from(body_bytes))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let res: ScanResponseV1 = serde_json::from_slice(&body).unwrap();
    assert_eq!(res.status, "rejected");
    assert!(res.error.unwrap().contains("Namespace violation"));
}

#[tokio::test]
async fn test_malformed_request_json() {
    let config = ServerConfig::default();
    let app = create_router(config);

    // Completely invalid JSON
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/scans")
                .header("Content-Type", "application/json")
                .body(Body::from(b"{ malformed json".to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn test_sha256_mismatch_verification() {
    let benign_file = Path::new("tests/corpus/benign-clean-skill/SKILL.md");
    if !benign_file.exists() {
        return; // skip if running in alternate test root
    }

    let file_url = format!("file://{}", benign_file.canonicalize().unwrap().display());
    let bad_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";

    let req = ScanRequestV1 {
        scan_id: "scan-sha-mismatch".to_string(),
        artifact: ArtifactSpecV1 {
            r#type: "file".to_string(),
            key: "scans/scan-sha-mismatch/SKILL.md".to_string(),
            url: file_url,
            sha256: bad_sha256.to_string(),
        },
        layers: vec![ScanLayerV1::Static],
        engine_version: "1.0.0".to_string(),
        event_callback: None,
        timeout_secs: Some(10),
    };

    let executor = ScanExecutor::new(req, true, 10 * 1024 * 1024);
    let result = executor.execute().await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        ExecutionError::Sha256Mismatch { expected, .. } => {
            assert_eq!(expected, bad_sha256);
        }
        _ => panic!("Expected Sha256Mismatch error, got: {:?}", err),
    }
}

#[tokio::test]
async fn test_oversized_artifact_protection() {
    let benign_file = Path::new("tests/corpus/benign-clean-skill/SKILL.md");
    if !benign_file.exists() {
        return;
    }

    let bytes = std::fs::read(benign_file).unwrap();
    let actual_sha256 = compute_sha256(&bytes);
    let file_url = format!("file://{}", benign_file.canonicalize().unwrap().display());

    let req = ScanRequestV1 {
        scan_id: "scan-oversized".to_string(),
        artifact: ArtifactSpecV1 {
            r#type: "file".to_string(),
            key: "scans/scan-oversized/SKILL.md".to_string(),
            url: file_url,
            sha256: actual_sha256,
        },
        layers: vec![ScanLayerV1::Static],
        engine_version: "1.0.0".to_string(),
        event_callback: None,
        timeout_secs: Some(10),
    };

    // Max artifact bytes set to 5 bytes (smaller than the file)
    let executor = ScanExecutor::new(req, true, 5);
    let result = executor.execute().await;

    assert!(result.is_err());
    match result.unwrap_err() {
        ExecutionError::ArtifactTooLarge { max_allowed, .. } => {
            assert_eq!(max_allowed, 5);
        }
        err => panic!("Expected ArtifactTooLarge error, got: {:?}", err),
    }
}

#[tokio::test]
async fn test_benign_fixture_integration() {
    let benign_file = Path::new("tests/corpus/benign-clean-skill/SKILL.md");
    if !benign_file.exists() {
        return;
    }

    let bytes = std::fs::read(benign_file).unwrap();
    let actual_sha256 = compute_sha256(&bytes);
    let file_url = format!("file://{}", benign_file.canonicalize().unwrap().display());

    let req = ScanRequestV1 {
        scan_id: "scan-benign-clean".to_string(),
        artifact: ArtifactSpecV1 {
            r#type: "file".to_string(),
            key: "scans/scan-benign-clean/SKILL.md".to_string(),
            url: file_url,
            sha256: actual_sha256,
        },
        layers: vec![ScanLayerV1::Static],
        engine_version: "1.0.0".to_string(),
        event_callback: None,
        timeout_secs: Some(30),
    };

    let executor = ScanExecutor::new(req, true, 50 * 1024 * 1024);
    let result = executor.execute().await.expect("Scan should succeed");

    assert_eq!(result.scan_id, "scan-benign-clean");
    assert_eq!(result.risk_level, RiskLevel::Safe);
    assert_eq!(result.risk_score, 0.0);
    assert_eq!(result.findings.len(), 0);
    assert!(result.layers_run.contains(&"static".to_string()));
}

#[tokio::test]
async fn test_malicious_fixture_integration() {
    let mal_file = Path::new("tests/corpus/SD-01-Prompt-Injection/prompt_injection_system_override.md");
    if !mal_file.exists() {
        return;
    }

    let bytes = std::fs::read(mal_file).unwrap();
    let actual_sha256 = compute_sha256(&bytes);
    let file_url = format!("file://{}", mal_file.canonicalize().unwrap().display());

    let req = ScanRequestV1 {
        scan_id: "scan-malicious-pi".to_string(),
        artifact: ArtifactSpecV1 {
            r#type: "file".to_string(),
            key: "scans/scan-malicious-pi/prompt_injection_system_override.md".to_string(),
            url: file_url,
            sha256: actual_sha256,
        },
        layers: vec![ScanLayerV1::Static],
        engine_version: "1.0.0".to_string(),
        event_callback: None,
        timeout_secs: Some(30),
    };

    let executor = ScanExecutor::new(req, true, 50 * 1024 * 1024);
    let result = executor.execute().await.expect("Scan should complete");

    assert_eq!(result.scan_id, "scan-malicious-pi");
    assert!(result.findings.len() > 0);
    assert!(result.risk_score > 0.0);
}

#[tokio::test]
async fn test_rust_worker_contract_schema_compatibility() {
    // Verifies JSON structure conforms exactly to what TypeScript Worker expects
    let json_from_worker = r#"{
        "scan_id": "scan-ts-compat-001",
        "artifact": {
            "type": "r2",
            "key": "scans/scan-ts-compat-001/artifact.zip",
            "url": "https://r2.cloudflare.com/presigned-url",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        "layers": ["static", "sandbox"],
        "engine_version": "1.0.0",
        "event_callback": {
            "url": "http://127.0.0.1:8787/api/scans/scan-ts-compat-001/events",
            "auth_token": "bearer-token-xyz"
        },
        "timeout_secs": 60
    }"#;

    let parsed: ScanRequestV1 = serde_json::from_str(json_from_worker).expect("Should deserialize");
    assert_eq!(parsed.scan_id, "scan-ts-compat-001");
    assert_eq!(parsed.layers, vec![ScanLayerV1::Static, ScanLayerV1::Sandbox]);
    assert_eq!(parsed.artifact.key, "scans/scan-ts-compat-001/artifact.zip");
}
