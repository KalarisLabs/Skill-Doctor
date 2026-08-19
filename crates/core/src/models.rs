//! Data models for Skill Doctor.
//!
//! Equivalent to Python's `skill_doctor/models.py` — all Pydantic models
//! are replaced with serde-derived Rust structs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Severity levels for security findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Weight used in risk score calculation.
    pub fn weight(&self) -> f64 {
        match self {
            Severity::Critical => 9.0,
            Severity::High => 7.0,
            Severity::Medium => 4.0,
            Severity::Low => 1.0,
            Severity::Info => 0.0,
        }
    }

    /// Numeric order for `--fail-on` threshold comparison.
    pub fn order(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// Risk level classification for overall scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RiskLevel {
    Safe,
    Caution,
    Dangerous,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Safe => write!(f, "SAFE"),
            RiskLevel::Caution => write!(f, "CAUTION"),
            RiskLevel::Dangerous => write!(f, "DANGEROUS"),
        }
    }
}

/// Scan engine that produced a finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    Yara,
    Ast,
    Entropy,
    Unicode,
    Llm,
    Sandbox,
    ThreatDb,
}

impl std::fmt::Display for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Engine::Yara => write!(f, "yara"),
            Engine::Ast => write!(f, "ast"),
            Engine::Entropy => write!(f, "entropy"),
            Engine::Unicode => write!(f, "unicode"),
            Engine::Llm => write!(f, "llm"),
            Engine::Sandbox => write!(f, "sandbox"),
            Engine::ThreatDb => write!(f, "threat_db"),
        }
    }
}

/// A security finding from a scan layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding.
    pub id: String,
    /// Severity classification.
    pub severity: Severity,
    /// Attack class category (e.g., "SD-02 · Command Injection").
    pub category: String,
    /// Relative file path within the bundle.
    pub file: String,
    /// Line number in the file (if applicable).
    pub line: Option<usize>,
    /// Plain English description (1-2 sentences).
    pub description: String,
    /// Specific remediation suggestion.
    pub remediation: String,
    /// Engine that produced this finding.
    pub engine: Engine,
    /// Confidence score (0.0 – 1.0).
    pub confidence: f64,
}

impl Finding {
    /// Create a new finding with a generated UUID.
    pub fn new(
        severity: Severity,
        category: impl Into<String>,
        file: impl Into<String>,
        line: Option<usize>,
        description: impl Into<String>,
        remediation: impl Into<String>,
        engine: Engine,
        confidence: f64,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            severity,
            category: category.into(),
            file: file.into(),
            line,
            description: description.into(),
            remediation: remediation.into(),
            engine,
            confidence: confidence.clamp(0.0, 1.0),
        }
    }
}

/// Complete scan result from all layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique scan identifier.
    pub scan_id: String,
    /// SHA-256 hash of the scanned bundle.
    pub bundle_hash: String,
    /// Timestamp of the scan.
    pub scanned_at: DateTime<Utc>,
    /// Total scan duration in milliseconds.
    pub duration_ms: u64,
    /// All findings from all layers (deduplicated).
    pub findings: Vec<Finding>,
    /// Overall risk level.
    pub risk_level: RiskLevel,
    /// Risk score (0.0 – 10.0).
    pub risk_score: f64,
    /// Which scan layers were executed.
    pub layers_run: Vec<String>,
}

/// Scan progress update (for TUI rendering).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub status: ScanStatus,
    pub current_layer: Option<String>,
    pub findings_count: usize,
    pub elapsed_ms: u64,
}

/// Status of a scan in progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Queued,
    Running,
    Done,
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_weights() {
        assert_eq!(Severity::Critical.weight(), 9.0);
        assert_eq!(Severity::Info.weight(), 0.0);
    }

    #[test]
    fn test_finding_creation() {
        let finding = Finding::new(
            Severity::High,
            "SD-02 · Command Injection",
            "script.py",
            Some(42),
            "Dangerous subprocess call",
            "Use allowlists for commands",
            Engine::Ast,
            0.9,
        );
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.file, "script.py");
        assert_eq!(finding.line, Some(42));
        assert!(!finding.id.is_empty());
    }

    #[test]
    fn test_confidence_clamping() {
        let f = Finding::new(
            Severity::Low,
            "test",
            "test.md",
            None,
            "desc",
            "fix",
            Engine::Yara,
            1.5, // Should clamp to 1.0
        );
        assert_eq!(f.confidence, 1.0);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
        assert_eq!(format!("{}", Severity::Info), "INFO");
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::Dangerous), "DANGEROUS");
        assert_eq!(format!("{}", RiskLevel::Safe), "SAFE");
    }
}
