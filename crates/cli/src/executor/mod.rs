//! Execution engine orchestrator for Skill Doctor Execution Service.
//!
//! Enforces the explicit lifecycle:
//! accepted -> fetching -> verifying -> analyzing -> emitting -> completed/failed.

pub mod models;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use url::Url;

use skill_doctor_core::intake::normalize_bundle;
use skill_doctor_core::layer1_static::scan_static;
use skill_doctor_core::layer3_sandbox::run_sandbox;
use skill_doctor_core::layer4_threat::scan_threat_db;
use skill_doctor_core::models::{Finding, ScanResult, Severity};
use skill_doctor_core::scorer::score_findings;

pub use models::*;

/// Error types for execution pipeline failures.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("Namespace violation: key '{key}' does not match expected scan namespace 'scans/{scan_id}/...'")]
    NamespaceViolation { scan_id: String, key: String },

    #[error("SSRF policy rejected URL: {0}")]
    SsrfViolation(String),

    #[error("Failed to fetch artifact from URL: {0}")]
    FetchError(String),

    #[error("Artifact exceeds maximum allowed size ({size} > {max_allowed} bytes)")]
    ArtifactTooLarge { size: usize, max_allowed: usize },

    #[error("SHA-256 digest mismatch. Expected '{expected}', calculated '{calculated}'")]
    Sha256Mismatch { expected: String, calculated: String },

    #[error("Analysis error: {0}")]
    AnalysisError(String),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// Orchestrator for an individual scan execution.
pub struct ScanExecutor {
    pub req: ScanRequestV1,
    pub client: reqwest::Client,
    pub allow_local_urls: bool,
    pub max_artifact_bytes: usize,
}

impl ScanExecutor {
    /// Create a new executor instance for a scan request.
    pub fn new(req: ScanRequestV1, allow_local_urls: bool, max_artifact_bytes: usize) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            req,
            client,
            allow_local_urls,
            max_artifact_bytes,
        }
    }

    /// Primary execution flow driving the full lifecycle.
    pub async fn execute(&self) -> Result<ScanResult, ExecutionError> {
        let start_time = Instant::now();

        // 1. Prepare & Validate Request Constraints
        if let Err(e) = self.prepare().await {
            self.emit_failure(&e.to_string(), ScanLifecycleState::Accepted)
                .await;
            return Err(e);
        }

        // 2. Fetch Artifact
        let (temp_file, path_buf) = match self.fetch_artifact().await {
            Ok(res) => res,
            Err(e) => {
                self.emit_failure(&e.to_string(), ScanLifecycleState::Fetching)
                    .await;
                return Err(e);
            }
        };

        // 3. Verify Artifact Integrity (SHA-256)
        if let Err(e) = self.verify_artifact(&path_buf).await {
            self.emit_failure(&e.to_string(), ScanLifecycleState::Verifying)
                .await;
            return Err(e);
        }

        // 4. Run Analysis Layers
        let result = match self.run_layers(&path_buf, start_time).await {
            Ok(res) => res,
            Err(e) => {
                self.emit_failure(&e.to_string(), ScanLifecycleState::Analyzing)
                    .await;
                return Err(e);
            }
        };

        // 5. Finalize & Emit Completion
        if let Err(e) = self.finalize(&result).await {
            tracing::warn!("Failed to finalize scan {}: {}", self.req.scan_id, e);
        }

        // Retain temp file handle until analysis completes
        drop(temp_file);

        Ok(result)
    }

    /// Step 1: Validate namespace, enforce SSRF protections, and emit initial lifecycle state.
    pub async fn prepare(&self) -> Result<(), ExecutionError> {
        // Enforce storage key namespace: scans/{scanId}/...
        let expected_prefix = format!("scans/{}/", self.req.scan_id);
        if !self.req.artifact.key.starts_with(&expected_prefix) {
            return Err(ExecutionError::NamespaceViolation {
                scan_id: self.req.scan_id.clone(),
                key: self.req.artifact.key.clone(),
            });
        }

        // Enforce URL security / SSRF protection
        self.validate_url(&self.req.artifact.url)?;

        // If webhook is provided, validate its URL too
        if let Some(ref cb) = self.req.event_callback {
            self.validate_url(&cb.url)?;
        }

        self.emit_event(&ScanEventV1::LifecycleUpdate {
            scan_id: self.req.scan_id.clone(),
            state: ScanLifecycleState::Accepted,
            timestamp: Utc::now(),
        })
        .await
        .ok();

        Ok(())
    }

    /// Step 2: Fetch artifact from pre-signed storage URL into a secure temp file.
    pub async fn fetch_artifact(&self) -> Result<(NamedTempFile, PathBuf), ExecutionError> {
        self.emit_event(&ScanEventV1::LifecycleUpdate {
            scan_id: self.req.scan_id.clone(),
            state: ScanLifecycleState::Fetching,
            timestamp: Utc::now(),
        })
        .await
        .ok();

        // Support local file: URLs for test harnesses and local mocking
        if self.req.artifact.url.starts_with("file://") {
            let local_path = self
                .req
                .artifact
                .url
                .trim_start_matches("file://")
                .trim_start_matches('/');
            let src = Path::new(local_path);
            if !src.exists() {
                return Err(ExecutionError::FetchError(format!(
                    "Local file not found: {}",
                    local_path
                )));
            }

            // Determine appropriate suffix from key or source
            let ext = Path::new(&self.req.artifact.key)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("zip");

            let mut temp_file = tempfile::Builder::new()
                .prefix("skill_doc_artifact_")
                .suffix(&format!(".{}", ext))
                .tempfile()
                .map_err(|e| ExecutionError::Internal(e.into()))?;

            let bytes = std::fs::read(src).map_err(|e| ExecutionError::FetchError(e.to_string()))?;
            if bytes.len() > self.max_artifact_bytes {
                return Err(ExecutionError::ArtifactTooLarge {
                    size: bytes.len(),
                    max_allowed: self.max_artifact_bytes,
                });
            }

            use std::io::Write;
            temp_file
                .write_all(&bytes)
                .map_err(|e| ExecutionError::Internal(e.into()))?;

            let path = temp_file.path().to_path_buf();
            return Ok((temp_file, path));
        }

        // Stream from HTTP/HTTPS URL
        let ext = Path::new(&self.req.artifact.key)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("zip");

        let mut temp_file = tempfile::Builder::new()
            .prefix("skill_doc_artifact_")
            .suffix(&format!(".{}", ext))
            .tempfile()
            .map_err(|e| ExecutionError::Internal(e.into()))?;

        let resp = self
            .client
            .get(&self.req.artifact.url)
            .send()
            .await
            .map_err(|e| ExecutionError::FetchError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(ExecutionError::FetchError(format!(
                "HTTP {} fetching artifact",
                resp.status()
            )));
        }

        if let Some(cl) = resp.content_length() {
            if cl as usize > self.max_artifact_bytes {
                return Err(ExecutionError::ArtifactTooLarge {
                    size: cl as usize,
                    max_allowed: self.max_artifact_bytes,
                });
            }
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ExecutionError::FetchError(e.to_string()))?;

        if bytes.len() > self.max_artifact_bytes {
            return Err(ExecutionError::ArtifactTooLarge {
                size: bytes.len(),
                max_allowed: self.max_artifact_bytes,
            });
        }

        use std::io::Write;
        temp_file
            .write_all(&bytes)
            .map_err(|e| ExecutionError::Internal(e.into()))?;

        let path = temp_file.path().to_path_buf();
        Ok((temp_file, path))
    }

    /// Step 3: Verify cryptographic SHA-256 hash of downloaded artifact.
    pub async fn verify_artifact(&self, path: &Path) -> Result<(), ExecutionError> {
        self.emit_event(&ScanEventV1::LifecycleUpdate {
            scan_id: self.req.scan_id.clone(),
            state: ScanLifecycleState::Verifying,
            timestamp: Utc::now(),
        })
        .await
        .ok();

        let bytes =
            std::fs::read(path).map_err(|e| ExecutionError::Internal(anyhow::anyhow!(e)))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let calculated = hex::encode(hasher.finalize());

        let expected = self.req.artifact.sha256.to_lowercase();
        if calculated.to_lowercase() != expected {
            return Err(ExecutionError::Sha256Mismatch {
                expected,
                calculated,
            });
        }

        Ok(())
    }

    /// Step 4: Execute configured security analysis layers.
    pub async fn run_layers(
        &self,
        path: &Path,
        start_time: Instant,
    ) -> Result<ScanResult, ExecutionError> {
        self.emit_event(&ScanEventV1::LifecycleUpdate {
            scan_id: self.req.scan_id.clone(),
            state: ScanLifecycleState::Analyzing,
            timestamp: Utc::now(),
        })
        .await
        .ok();

        // Normalize bundle into working directory
        let bundle_source = path.to_str().unwrap_or_default();
        let normalized = normalize_bundle(bundle_source)
            .await
            .map_err(|e| ExecutionError::AnalysisError(e.to_string()))?;

        let mut all_findings: Vec<Finding> = Vec::new();
        let mut layers_run: Vec<String> = Vec::new();

        // 1. Layer 4: Threat Intelligence (if selected)
        if self.req.layers.contains(&ScanLayerV1::ThreatDb) {
            let stage_start = Instant::now();
            self.emit_event(&ScanEventV1::StageStarted {
                scan_id: self.req.scan_id.clone(),
                layer: "threat_db".to_string(),
                timestamp: Utc::now(),
            })
            .await
            .ok();

            if let Some(cached) = scan_threat_db(&normalized.hash) {
                for finding in &cached {
                    self.emit_event(&ScanEventV1::FindingDetected {
                        scan_id: self.req.scan_id.clone(),
                        finding: finding.clone(),
                        timestamp: Utc::now(),
                    })
                    .await
                    .ok();
                }
                all_findings.extend(cached);
            }

            layers_run.push("threat_db".to_string());
            self.emit_event(&ScanEventV1::StageCompleted {
                scan_id: self.req.scan_id.clone(),
                layer: "threat_db".to_string(),
                findings_count: all_findings.len(),
                duration_ms: stage_start.elapsed().as_millis() as u64,
                timestamp: Utc::now(),
            })
            .await
            .ok();
        }

        // 2. Layer 1: Static Analysis (YARA-X + AST + Entropy + Unicode)
        if self.req.layers.contains(&ScanLayerV1::Static) {
            let stage_start = Instant::now();
            self.emit_event(&ScanEventV1::StageStarted {
                scan_id: self.req.scan_id.clone(),
                layer: "static".to_string(),
                timestamp: Utc::now(),
            })
            .await
            .ok();

            let static_findings = scan_static(&normalized.path);
            for finding in &static_findings {
                self.emit_event(&ScanEventV1::FindingDetected {
                    scan_id: self.req.scan_id.clone(),
                    finding: finding.clone(),
                    timestamp: Utc::now(),
                })
                .await
                .ok();
            }

            let findings_count = static_findings.len();
            all_findings.extend(static_findings);
            layers_run.push("static".to_string());

            self.emit_event(&ScanEventV1::StageCompleted {
                scan_id: self.req.scan_id.clone(),
                layer: "static".to_string(),
                findings_count,
                duration_ms: stage_start.elapsed().as_millis() as u64,
                timestamp: Utc::now(),
            })
            .await
            .ok();
        }

        // 3. Layer 3: Behavioral Sandbox (if selected)
        if self.req.layers.contains(&ScanLayerV1::Sandbox) {
            let stage_start = Instant::now();
            self.emit_event(&ScanEventV1::StageStarted {
                scan_id: self.req.scan_id.clone(),
                layer: "sandbox".to_string(),
                timestamp: Utc::now(),
            })
            .await
            .ok();

            match run_sandbox(&normalized.path).await {
                Ok(sandbox_findings) => {
                    for finding in &sandbox_findings {
                        self.emit_event(&ScanEventV1::FindingDetected {
                            scan_id: self.req.scan_id.clone(),
                            finding: finding.clone(),
                            timestamp: Utc::now(),
                        })
                        .await
                        .ok();
                    }
                    let findings_count = sandbox_findings.len();
                    all_findings.extend(sandbox_findings);
                    layers_run.push("sandbox".to_string());

                    self.emit_event(&ScanEventV1::StageCompleted {
                        scan_id: self.req.scan_id.clone(),
                        layer: "sandbox".to_string(),
                        findings_count,
                        duration_ms: stage_start.elapsed().as_millis() as u64,
                        timestamp: Utc::now(),
                    })
                    .await
                    .ok();
                }
                Err(e) => {
                    tracing::warn!("Sandbox execution failed: {}", e);
                    self.emit_event(&ScanEventV1::StageFailed {
                        scan_id: self.req.scan_id.clone(),
                        layer: "sandbox".to_string(),
                        error: e.to_string(),
                        timestamp: Utc::now(),
                    })
                    .await
                    .ok();
                }
            }
        }

        let duration_ms = start_time.elapsed().as_millis() as u64;
        let scan_result = score_findings(all_findings, &normalized.hash, layers_run, duration_ms);

        Ok(scan_result)
    }

    /// Step 5: Emit structured events to the configured callback endpoint.
    pub async fn emit_event(&self, event: &ScanEventV1) -> Result<(), ExecutionError> {
        let callback = match &self.req.event_callback {
            Some(cb) => cb,
            None => return Ok(()),
        };

        let mut req_builder = self.client.post(&callback.url).json(event);

        if let Some(ref token) = callback.auth_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        let _ = req_builder.send().await;
        Ok(())
    }

    /// Step 6: Finalize scan and emit ScanCompleted.
    pub async fn finalize(&self, result: &ScanResult) -> Result<(), ExecutionError> {
        self.emit_event(&ScanEventV1::ScanCompleted {
            scan_id: self.req.scan_id.clone(),
            result: result.clone(),
            state: ScanLifecycleState::Completed,
            timestamp: Utc::now(),
        })
        .await
        .ok();

        Ok(())
    }

    /// Emit an unrecoverable failure event to avoid hangs in the control plane.
    pub async fn emit_failure(&self, error: &str, state: ScanLifecycleState) {
        self.emit_event(&ScanEventV1::ScanFailed {
            scan_id: self.req.scan_id.clone(),
            error: error.to_string(),
            state,
            timestamp: Utc::now(),
        })
        .await
        .ok();
    }

    /// SSRF and URL validation rule.
    fn validate_url(&self, raw_url: &str) -> Result<(), ExecutionError> {
        if raw_url.starts_with("file://") {
            if self.allow_local_urls {
                return Ok(());
            } else {
                return Err(ExecutionError::SsrfViolation(
                    "file:// URLs disallowed in strict mode".to_string(),
                ));
            }
        }

        let parsed = Url::parse(raw_url)
            .map_err(|_| ExecutionError::SsrfViolation("Malformed URL".to_string()))?;

        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(ExecutionError::SsrfViolation(format!(
                "Unsupported scheme: {}",
                scheme
            )));
        }

        if let Some(host) = parsed.host_str() {
            let host_lower = host.to_lowercase();
            // Disallow metadata endpoints & loopback in non-local modes
            if !self.allow_local_urls {
                if host_lower == "localhost"
                    || host_lower == "127.0.0.1"
                    || host_lower == "::1"
                    || host_lower.starts_with("169.254.")
                    || host_lower.starts_with("10.")
                    || host_lower.starts_with("192.168.")
                {
                    return Err(ExecutionError::SsrfViolation(format!(
                        "Host '{}' forbidden by SSRF policy",
                        host
                    )));
                }
            }
        }

        Ok(())
    }
}
