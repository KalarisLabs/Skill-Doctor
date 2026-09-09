//! Scoring — additive-only invariant enforcement.
//!
//! The core rule: a probabilistic/L2 verdict may add findings or raise
//! confidence. It may **never** remove, downgrade, or suppress a
//! deterministic L1 finding. This is the architectural defense against SD-11.

use crate::finding::{AnalysisLayer, Finding};

/// Error when the additive-only invariant is violated.
#[derive(Debug, thiserror::Error)]
#[error("Additive-only invariant violated: L2 attempted to {action} L1 finding {rule_id}")]
pub struct AdditiveOnlyViolation {
    pub rule_id: String,
    pub action: String,
}

/// Merge L2 findings into L1 findings, enforcing the additive-only invariant.
///
/// Returns the merged finding set. Errors if L2 would remove an L1 finding.
pub fn merge_additive_only(
    l1_findings: &[Finding],
    l2_findings: &[Finding],
) -> Result<Vec<Finding>, AdditiveOnlyViolation> {
    let mut merged = l1_findings.to_vec();

    for l2_finding in l2_findings {
        // L2 findings must never claim to be L1.
        if l2_finding.layer == AnalysisLayer::L1 {
            return Err(AdditiveOnlyViolation {
                rule_id: l2_finding.rule_id.clone(),
                action: "masquerade as L1".to_string(),
            });
        }

        // L2 may add new findings (additive).
        merged.push(l2_finding.clone());
    }

    // Verify all original L1 findings are still present (not removed).
    for l1 in l1_findings {
        let still_present = merged.iter().any(|f| {
            f.rule_id == l1.rule_id
                && f.path == l1.path
                && f.byte_span == l1.byte_span
                && f.layer == AnalysisLayer::L1
        });
        if !still_present {
            return Err(AdditiveOnlyViolation {
                rule_id: l1.rule_id.clone(),
                action: "remove".to_string(),
            });
        }
    }

    Ok(merged)
}

/// Validate that a proposed finding set does not suppress any L1 findings
/// relative to a baseline set.
pub fn validate_no_suppression(
    baseline_l1: &[Finding],
    proposed: &[Finding],
) -> Result<(), AdditiveOnlyViolation> {
    for baseline in baseline_l1 {
        if baseline.layer != AnalysisLayer::L1 {
            continue;
        }
        let still_present = proposed.iter().any(|f| {
            f.rule_id == baseline.rule_id
                && f.path == baseline.path
                && f.byte_span == baseline.byte_span
                && f.layer == AnalysisLayer::L1
        });
        if !still_present {
            return Err(AdditiveOnlyViolation {
                rule_id: baseline.rule_id.clone(),
                action: "suppress".to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::*;
    use crate::taxonomy::ThreatClass;
    use std::path::PathBuf;

    fn make_l1_finding(rule_id: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            class: ThreatClass::CommandInjection,
            severity: Severity::High,
            confidence: Confidence::High,
            path: PathBuf::from("test.sh"),
            byte_span: Some(ByteSpan { start: 0, end: 10 }),
            evidence: vec!["test".to_string()],
            remediation: None,
            layer: AnalysisLayer::L1,
        }
    }

    fn make_l2_finding(rule_id: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            class: ThreatClass::CommandInjection,
            severity: Severity::High,
            confidence: Confidence::Medium,
            path: PathBuf::from("test.sh"),
            byte_span: Some(ByteSpan { start: 20, end: 30 }),
            evidence: vec!["semantic analysis".to_string()],
            remediation: None,
            layer: AnalysisLayer::L2,
        }
    }

    #[test]
    fn additive_only_allows_l2_additions() {
        let l1 = vec![make_l1_finding("SD-02-cmd-eval")];
        let l2 = vec![make_l2_finding("SD-02-cmd-semantic")];

        let merged = merge_additive_only(&l1, &l2).unwrap();
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn additive_only_preserves_all_l1() {
        let l1 = vec![make_l1_finding("rule-1"), make_l1_finding("rule-2")];
        let l2 = vec![make_l2_finding("rule-3")];

        let merged = merge_additive_only(&l1, &l2).unwrap();

        // All L1 findings must still be present.
        for original in &l1 {
            assert!(merged
                .iter()
                .any(|f| f.rule_id == original.rule_id && f.layer == AnalysisLayer::L1));
        }
    }

    #[test]
    fn additive_only_rejects_l2_masquerading_as_l1() {
        let l1 = vec![make_l1_finding("rule-1")];
        let mut fake = make_l2_finding("rule-fake");
        fake.layer = AnalysisLayer::L1; // L2 tries to claim L1

        let result = merge_additive_only(&l1, &[fake]);
        assert!(result.is_err());
    }

    #[test]
    fn validate_no_suppression_catches_removal() {
        let l1 = vec![make_l1_finding("rule-1"), make_l1_finding("rule-2")];
        // Proposed set is missing rule-2.
        let proposed = vec![make_l1_finding("rule-1")];

        let result = validate_no_suppression(&l1, &proposed);
        assert!(result.is_err());
    }

    #[test]
    fn validate_no_suppression_passes_when_all_present() {
        let l1 = vec![make_l1_finding("rule-1")];
        let proposed = vec![make_l1_finding("rule-1"), make_l2_finding("rule-2")];

        let result = validate_no_suppression(&l1, &proposed);
        assert!(result.is_ok());
    }
}
