//! Report — the top-level scan result.
//!
//! A Report contains the bundle digest, all findings, structural coverage,
//! verdict, and a determinism flag. It is the serialization target for
//! `--output json` and the input for SARIF conversion.

use crate::finding::{Finding, Severity};
use crate::taxonomy::ThreatClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Coverage data for a single scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Number of SDTM-v1 classes that were structurally evaluable.
    pub evaluable: usize,
    /// Total number of SDTM-v1 classes (always 11).
    pub total: usize,
    /// Per-class evaluability.
    pub per_class: BTreeMap<String, bool>,
}

impl Coverage {
    /// Create coverage from a set of evaluable classes.
    pub fn from_evaluable(evaluable_classes: &[ThreatClass]) -> Self {
        let mut per_class = BTreeMap::new();
        for class in ThreatClass::ALL {
            per_class.insert(class.id().to_string(), evaluable_classes.contains(&class));
        }
        Self {
            evaluable: evaluable_classes.len(),
            total: ThreatClass::TOTAL,
            per_class,
        }
    }

    /// Coverage ratio (0.0 to 1.0).
    pub fn ratio(&self) -> f64 {
        self.evaluable as f64 / self.total as f64
    }
}

/// Verdict for the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No findings at or above the fail-on threshold.
    Pass,
    /// At least one finding at or above the fail-on threshold.
    Fail,
}

/// Execution state of an analysis layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerRunState {
    /// Layer ran and produced evaluations/findings.
    Ran,
    /// Layer was not executed or not enabled.
    Skipped,
    /// Layer evaluation was degraded, rejected, or timed out.
    Reduced,
}

/// Status of each analysis layer (L0 through L5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerStatus {
    pub l0: LayerRunState,
    pub l1: LayerRunState,
    pub l2: LayerRunState,
    pub l3: LayerRunState,
    pub l4: LayerRunState,
    pub l5: LayerRunState,
}

impl Default for LayerStatus {
    fn default() -> Self {
        Self {
            l0: LayerRunState::Ran,
            l1: LayerRunState::Ran,
            l2: LayerRunState::Skipped,
            l3: LayerRunState::Skipped,
            l4: LayerRunState::Skipped,
            l5: LayerRunState::Ran,
        }
    }
}

/// The complete scan report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// SHA-256 canonical bundle digest.
    pub bundle_digest: String,
    /// All findings from all layers.
    pub findings: Vec<Finding>,
    /// Structural coverage.
    pub coverage: Coverage,
    /// Overall verdict against the fail-on threshold.
    pub verdict: Verdict,
    /// Whether this report was generated in deterministic mode.
    pub deterministic: bool,
    /// Scanner version.
    pub scanner_version: String,
    /// Whether the scan would fail based on the severity threshold.
    #[serde(default)]
    pub would_fail: bool,
    /// The severity threshold used for failure evaluation.
    #[serde(default)]
    pub fail_on: Option<Severity>,
    /// Execution status across analysis layers.
    #[serde(default)]
    pub layers: LayerStatus,
}

impl Report {
    /// Compute the verdict given a fail-on severity threshold.
    pub fn compute_verdict(findings: &[Finding], fail_on: Severity) -> Verdict {
        if findings.iter().any(|f| f.severity >= fail_on) {
            Verdict::Fail
        } else {
            Verdict::Pass
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::*;
    use crate::taxonomy::ThreatClass;
    use std::path::PathBuf;

    #[test]
    fn coverage_ratio() {
        let cov = Coverage::from_evaluable(&[ThreatClass::CommandInjection]);
        assert_eq!(cov.evaluable, 1);
        assert_eq!(cov.total, 11);
        assert!((cov.ratio() - 1.0 / 11.0).abs() < f64::EPSILON);
    }

    #[test]
    fn verdict_pass_when_below_threshold() {
        let findings = vec![Finding {
            rule_id: "test".to_string(),
            class: ThreatClass::PromptInjection,
            severity: Severity::Low,
            confidence: Confidence::High,
            path: PathBuf::from("test.md"),
            byte_span: None,
            evidence: vec![],
            remediation: None,
            layer: AnalysisLayer::L1,
        }];
        assert_eq!(
            Report::compute_verdict(&findings, Severity::High),
            Verdict::Pass
        );
    }

    #[test]
    fn verdict_fail_when_at_threshold() {
        let findings = vec![Finding {
            rule_id: "test".to_string(),
            class: ThreatClass::CommandInjection,
            severity: Severity::High,
            confidence: Confidence::High,
            path: PathBuf::from("test.sh"),
            byte_span: None,
            evidence: vec![],
            remediation: None,
            layer: AnalysisLayer::L1,
        }];
        assert_eq!(
            Report::compute_verdict(&findings, Severity::High),
            Verdict::Fail
        );
    }

    #[test]
    fn report_serde_roundtrip() {
        let report = Report {
            bundle_digest: "abc123".to_string(),
            findings: vec![],
            coverage: Coverage::from_evaluable(&[]),
            verdict: Verdict::Pass,
            deterministic: true,
            scanner_version: "0.1.0".to_string(),
            would_fail: false,
            fail_on: Some(Severity::High),
            layers: LayerStatus::default(),
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }
}
