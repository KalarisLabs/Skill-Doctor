//! Finding — a single diagnostic produced by any analysis layer.
//!
//! Findings are the fundamental unit of scanner output. Each finding references
//! a stable rule_id and SDTM-v1 class. The additive-only invariant guarantees
//! that L2/semantic findings can only add to, never remove, L1 findings.

use crate::taxonomy::ThreatClass;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity levels for findings.
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
    /// Parse a severity from a case-insensitive string.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "INFO" => Some(Self::Info),
            "LOW" => Some(Self::Low),
            "MEDIUM" | "MED" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "CRITICAL" | "CRIT" => Some(Self::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Confidence level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// A byte span within a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSpan {
    pub start: usize,
    pub end: usize,
}

/// A single finding produced by the scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier (e.g., "SD-02-cmd-injection-eval").
    pub rule_id: String,
    /// SDTM-v1 threat class.
    pub class: ThreatClass,
    /// Severity of this finding.
    pub severity: Severity,
    /// Confidence in this finding.
    pub confidence: Confidence,
    /// Path to the file where the finding was detected (relative to scan root).
    pub path: PathBuf,
    /// Byte range within the file.
    pub byte_span: Option<ByteSpan>,
    /// Evidence strings explaining the detection.
    pub evidence: Vec<String>,
    /// Suggested remediation.
    pub remediation: Option<String>,
    /// Which analysis layer produced this finding.
    pub layer: AnalysisLayer,
}

/// Which analysis layer produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnalysisLayer {
    /// L1: deterministic static analysis.
    L1,
    /// L2: host-delegated semantic inference (additive-only).
    L2,
    /// L3: behavioral sandbox.
    L3,
    /// L4: threat intelligence.
    L4,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_serde_roundtrip() {
        let finding = Finding {
            rule_id: "SD-02-cmd-injection-eval".to_string(),
            class: ThreatClass::CommandInjection,
            severity: Severity::High,
            confidence: Confidence::High,
            path: PathBuf::from("scripts/setup.sh"),
            byte_span: Some(ByteSpan { start: 42, end: 78 }),
            evidence: vec!["eval $USER_INPUT found in setup.sh".to_string()],
            remediation: Some("Remove eval of untrusted input".to_string()),
            layer: AnalysisLayer::L1,
        };
        let json = serde_json::to_string_pretty(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, back);
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_from_str_loose() {
        assert_eq!(Severity::from_str_loose("high"), Some(Severity::High));
        assert_eq!(Severity::from_str_loose("HIGH"), Some(Severity::High));
        assert_eq!(Severity::from_str_loose("MED"), Some(Severity::Medium));
        assert_eq!(Severity::from_str_loose("CRIT"), Some(Severity::Critical));
        assert_eq!(Severity::from_str_loose("nope"), None);
    }
}
