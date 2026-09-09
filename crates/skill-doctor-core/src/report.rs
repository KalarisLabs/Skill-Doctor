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
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        let back: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }
}
