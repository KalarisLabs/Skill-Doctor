//! Versioned data models and event schemas for the Skill Doctor Execution Service.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use skill_doctor_core::models::{Finding, ScanResult};

/// Version 1 Scan Request submitted from Control Plane (Worker/Queue).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequestV1 {
    /// Unique scan identifier.
    pub scan_id: String,
    /// Artifact specification pointing to controlled storage.
    pub artifact: ArtifactSpecV1,
    /// Security layers requested to execute.
    #[serde(default = "default_layers")]
    pub layers: Vec<ScanLayerV1>,
    /// Engine version requirement.
    #[serde(default = "default_engine_version")]
    pub engine_version: String,
    /// Optional webhook callback for real-time event streaming.
    pub event_callback: Option<CallbackSpecV1>,
    /// Execution timeout in seconds (defaults to 60).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

fn default_layers() -> Vec<ScanLayerV1> {
    vec![ScanLayerV1::Static, ScanLayerV1::Sandbox]
}

fn default_engine_version() -> String {
    "1.0.0".to_string()
}

/// Artifact storage specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSpecV1 {
    /// Artifact storage type ("r2", "url", "file").
    pub r#type: String,
    /// Controlled storage key, e.g., "scans/<scan_id>/artifact.zip".
    pub key: String,
    /// Pre-signed temporary URL for fetching the artifact.
    pub url: String,
    /// Expected SHA-256 hex digest of the artifact.
    pub sha256: String,
}

/// Analysis layers selectable in a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLayerV1 {
    Static,
    Semantic,
    Sandbox,
    ThreatDb,
}

impl std::fmt::Display for ScanLayerV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanLayerV1::Static => write!(f, "static"),
            ScanLayerV1::Semantic => write!(f, "semantic"),
            ScanLayerV1::Sandbox => write!(f, "sandbox"),
            ScanLayerV1::ThreatDb => write!(f, "threat_db"),
        }
    }
}

/// Webhook configuration for event streaming back to Durable Object or Control Plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackSpecV1 {
    /// Target webhook URL.
    pub url: String,
    /// Optional Bearer authentication token for the callback.
    pub auth_token: Option<String>,
}

/// Explicit lifecycle state of a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLifecycleState {
    Accepted,
    Fetching,
    Verifying,
    Analyzing,
    Emitting,
    Completed,
    Failed,
}

/// Structured events emitted throughout the scan execution lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScanEventV1 {
    /// Scan lifecycle state change.
    LifecycleUpdate {
        scan_id: String,
        state: ScanLifecycleState,
        timestamp: DateTime<Utc>,
    },
    /// A specific scanning stage has begun.
    StageStarted {
        scan_id: String,
        layer: String,
        timestamp: DateTime<Utc>,
    },
    /// An individual security finding was detected.
    FindingDetected {
        scan_id: String,
        finding: Finding,
        timestamp: DateTime<Utc>,
    },
    /// A scanning stage has successfully completed.
    StageCompleted {
        scan_id: String,
        layer: String,
        findings_count: usize,
        duration_ms: u64,
        timestamp: DateTime<Utc>,
    },
    /// A scanning stage failed.
    StageFailed {
        scan_id: String,
        layer: String,
        error: String,
        timestamp: DateTime<Utc>,
    },
    /// The entire scan has completed with full results.
    ScanCompleted {
        scan_id: String,
        result: ScanResult,
        state: ScanLifecycleState,
        timestamp: DateTime<Utc>,
    },
    /// The scan failed unrecoverably.
    ScanFailed {
        scan_id: String,
        error: String,
        state: ScanLifecycleState,
        timestamp: DateTime<Utc>,
    },
}

/// Immediate synchronous response to `POST /v1/scans`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResponseV1 {
    pub status: String,
    pub scan_id: String,
    pub state: ScanLifecycleState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
