//! Scoring — additive-only invariant enforcement.
//!
//! The core rule: a probabilistic/L2 verdict may add findings or raise
//! confidence. It may **never** remove, downgrade, or suppress a
//! deterministic L1 finding. This is the architectural defense against SD-11.

use crate::finding::{AnalysisLayer, ByteSpan, Confidence, Finding, Severity};
use crate::report::{LayerRunState, Report};
use crate::taxonomy::ThreatClass;
use skill_doctor_neutralize::{Removal, RemovalKind};
use std::path::Path;

/// Error when the additive-only invariant is violated.
#[derive(Debug, thiserror::Error)]
#[error("Additive-only invariant violated: L2 attempted to {action} L1 finding {rule_id}")]
pub struct AdditiveOnlyViolation {
    pub rule_id: String,
    pub action: String,
}

/// Map neutralization removals into structured L1 security findings.
///
/// Removals recorded during neutralization represent concrete evasion and injection
/// threats (Trojan Source, Zero-Width Smuggling, Tag Injection, and Homoglyphs).
pub fn map_removals_to_findings(removals: &[Removal], path: &Path) -> Vec<Finding> {
    removals
        .iter()
        .map(|removal| {
            let (rule_id, class, severity, evidence, remediation) = match &removal.kind {
                RemovalKind::BidiOverride(c) => (
                    "SD-10-bidi-trojan-source".to_string(),
                    ThreatClass::ObfuscationEvasion,
                    Severity::Critical,
                    vec![format!(
                        "Bidi control character U+{:04X} detected: {}",
                        *c as u32, removal.snippet
                    )],
                    Some(
                        "Remove Unicode bidirectional control characters to prevent visual spoofing (Trojan Source)."
                            .to_string(),
                    ),
                ),
                RemovalKind::ZeroWidth(c) => (
                    "SD-01-zero-width-smuggle".to_string(),
                    ThreatClass::PromptInjection,
                    Severity::High,
                    vec![format!(
                        "Zero-width character U+{:04X} detected: {}",
                        *c as u32, removal.snippet
                    )],
                    Some(
                        "Remove invisible zero-width characters to avoid hidden prompt smuggling."
                            .to_string(),
                    ),
                ),
                RemovalKind::TagChar(c) => (
                    "SD-11-tag-char-smuggle".to_string(),
                    ThreatClass::ScannerMediatedInjection,
                    Severity::Critical,
                    vec![format!(
                        "Unicode tag character U+{:04X} detected (SD-11 smuggling attack): {}",
                        *c as u32, removal.snippet
                    )],
                    Some(
                        "Strip Unicode tag characters (U+E0001..U+E007F) used to bypass filters."
                            .to_string(),
                    ),
                ),
                RemovalKind::Confusable { original, skeleton } => (
                    "SD-10-homoglyph-confusable".to_string(),
                    ThreatClass::ObfuscationEvasion,
                    Severity::High,
                    vec![format!(
                        "Homoglyph confusable '{}' detected (normalized skeleton: '{}')",
                        original, skeleton
                    )],
                    Some(
                        "Use standard ASCII identifiers instead of mixed-script homoglyphs."
                            .to_string(),
                    ),
                ),
            };

            Finding {
                rule_id,
                class,
                severity,
                confidence: Confidence::High,
                path: path.to_path_buf(),
                byte_span: Some(ByteSpan {
                    start: removal.byte_span.0,
                    end: removal.byte_span.1,
                }),
                evidence,
                remediation,
                layer: AnalysisLayer::L1,
            }
        })
        .collect()
}

/// Merge L2 findings additively into an existing L1 report.
///
/// Invariants enforced:
/// - L2 can NEVER remove any L1 finding.
/// - L2 can NEVER downgrade the severity of an L1 finding.
/// - L2 can NEVER alter the threat class of an L1 finding.
/// - If L2 matches an existing L1 finding, it may only raise confidence or add evidence.
/// - An L2 verdict of "benign" or empty findings leaves all L1 findings unchanged.
/// - Sort order is preserved if deterministic mode was requested.
pub fn merge_l1_and_l2(
    l1_report: &Report,
    l2_findings: &[Finding],
    l2_state: LayerRunState,
) -> Report {
    let mut merged = l1_report.findings.clone();

    for l2 in l2_findings {
        // Look for matching L1 finding (same rule_id, path, byte_span)
        let matched = merged.iter_mut().find(|f| {
            f.rule_id == l2.rule_id
                && f.path == l2.path
                && (f.byte_span == l2.byte_span
                    || (f.byte_span.is_none() && l2.byte_span.is_none()))
        });

        if let Some(existing) = matched {
            // Invariant: L2 cannot downgrade severity or change class
            existing.severity = existing.severity.max(l2.severity);
            // Invariant: L2 merges confidence (takes max)
            existing.confidence = existing.confidence.max(l2.confidence);
            // Invariant: Preserves L1 evidence, appends L2 evidence if distinct
            for ev in &l2.evidence {
                if !existing.evidence.contains(ev) {
                    existing.evidence.push(ev.clone());
                }
            }
            if existing.remediation.is_none() {
                existing.remediation = l2.remediation.clone();
            }
        } else {
            // New finding from L2
            let mut new_finding = l2.clone();
            new_finding.layer = AnalysisLayer::L2;
            merged.push(new_finding);
        }
    }

    if l1_report.deterministic {
        merged.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| {
                    let a_start = a.byte_span.as_ref().map_or(0, |s| s.start);
                    let b_start = b.byte_span.as_ref().map_or(0, |s| s.start);
                    a_start.cmp(&b_start)
                })
        });
    }

    let threshold = l1_report.fail_on.unwrap_or(Severity::High);
    let verdict = Report::compute_verdict(&merged, threshold);
    let would_fail = verdict == crate::report::Verdict::Fail;

    let mut layers = l1_report.layers.clone();
    layers.l2 = l2_state;

    Report {
        bundle_digest: l1_report.bundle_digest.clone(),
        findings: merged,
        coverage: l1_report.coverage.clone(),
        verdict,
        deterministic: l1_report.deterministic,
        scanner_version: l1_report.scanner_version.clone(),
        would_fail,
        fail_on: l1_report.fail_on,
        layers,
    }
}

/// Merge L3 behavioral sandbox findings additively into an existing report.
///
/// Invariants enforced:
/// - L3 can NEVER remove any existing L1 or L2 finding.
/// - L3 can NEVER downgrade the severity of an existing finding.
/// - L3 can NEVER alter the threat class of an existing finding.
/// - If L3 matches an existing finding, it may only raise confidence or add evidence.
/// - Duplicate findings take max(confidence) and max(severity).
/// - An L3 verdict of "benign" or empty findings leaves all previous findings unchanged.
/// - Sort order is preserved if deterministic mode was requested.
/// - L1 structural coverage is strictly preserved (unchanged).
pub fn merge_l3_findings(
    report: &Report,
    l3_findings: &[Finding],
    l3_state: LayerRunState,
) -> Report {
    let mut merged = report.findings.clone();

    for l3 in l3_findings {
        let matched = merged.iter_mut().find(|f| {
            f.rule_id == l3.rule_id
                && f.path == l3.path
                && (f.byte_span == l3.byte_span
                    || (f.byte_span.is_none() && l3.byte_span.is_none()))
        });

        if let Some(existing) = matched {
            existing.severity = existing.severity.max(l3.severity);
            existing.confidence = existing.confidence.max(l3.confidence);
            for ev in &l3.evidence {
                if !existing.evidence.contains(ev) {
                    existing.evidence.push(ev.clone());
                }
            }
            if existing.remediation.is_none() {
                existing.remediation = l3.remediation.clone();
            }
        } else {
            let mut new_finding = l3.clone();
            new_finding.layer = AnalysisLayer::L3;
            merged.push(new_finding);
        }
    }

    if report.deterministic {
        merged.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| {
                    let a_start = a.byte_span.as_ref().map_or(0, |s| s.start);
                    let b_start = b.byte_span.as_ref().map_or(0, |s| s.start);
                    a_start.cmp(&b_start)
                })
        });
    }

    let threshold = report.fail_on.unwrap_or(Severity::High);
    let verdict = Report::compute_verdict(&merged, threshold);
    let would_fail = verdict == crate::report::Verdict::Fail;

    let mut layers = report.layers.clone();
    layers.l3 = l3_state;

    Report {
        bundle_digest: report.bundle_digest.clone(),
        findings: merged,
        coverage: report.coverage.clone(),
        verdict,
        deterministic: report.deterministic,
        scanner_version: report.scanner_version.clone(),
        would_fail,
        fail_on: report.fail_on,
        layers,
    }
}

/// Merge L4 threat intelligence findings additively into an existing report.
///
/// Invariants enforced:
/// - Local findings (L1, L2, L3) strictly outrank remote threat intel.
/// - L4 can NEVER remove or suppress any existing local finding.
/// - L4 can NEVER downgrade the severity of an existing finding.
/// - If an L4 finding matches an existing finding, it may raise confidence and append corroborating evidence.
/// - A report with 0 L4 findings leaves all previous findings unchanged.
/// - Preserves sort order if deterministic mode was requested.
/// - Preserves L1 structural coverage unchanged.
/// - Sets `report.layers.l4 = l4_state`.
pub fn merge_l4_findings(
    report: &Report,
    l4_findings: &[Finding],
    l4_state: LayerRunState,
) -> Report {
    let mut merged = report.findings.clone();

    for l4 in l4_findings {
        let matched = merged.iter_mut().find(|f| {
            f.rule_id == l4.rule_id
                && f.path == l4.path
                && (f.byte_span == l4.byte_span
                    || (f.byte_span.is_none() && l4.byte_span.is_none()))
        });

        if let Some(existing) = matched {
            existing.severity = existing.severity.max(l4.severity);
            existing.confidence = existing.confidence.max(l4.confidence);
            for ev in &l4.evidence {
                if !existing.evidence.contains(ev) {
                    existing.evidence.push(ev.clone());
                }
            }
            if existing.remediation.is_none() {
                existing.remediation = l4.remediation.clone();
            }
        } else {
            let mut new_finding = l4.clone();
            new_finding.layer = AnalysisLayer::L4;
            merged.push(new_finding);
        }
    }

    if report.deterministic {
        merged.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| {
                    let a_start = a.byte_span.as_ref().map_or(0, |s| s.start);
                    let b_start = b.byte_span.as_ref().map_or(0, |s| s.start);
                    a_start.cmp(&b_start)
                })
        });
    }

    let threshold = report.fail_on.unwrap_or(Severity::High);
    let verdict = Report::compute_verdict(&merged, threshold);
    let would_fail = verdict == crate::report::Verdict::Fail;

    let mut layers = report.layers.clone();
    layers.l4 = l4_state;

    Report {
        bundle_digest: report.bundle_digest.clone(),
        findings: merged,
        coverage: report.coverage.clone(),
        verdict,
        deterministic: report.deterministic,
        scanner_version: report.scanner_version.clone(),
        would_fail,
        fail_on: report.fail_on,
        layers,
    }
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

    #[test]
    fn map_removals_produces_l1_findings() {
        let removals = vec![
            Removal {
                byte_span: (0, 3),
                kind: RemovalKind::BidiOverride('\u{202E}'),
                snippet: "U+202E".to_string(),
            },
            Removal {
                byte_span: (10, 13),
                kind: RemovalKind::ZeroWidth('\u{200B}'),
                snippet: "U+200B".to_string(),
            },
            Removal {
                byte_span: (20, 24),
                kind: RemovalKind::TagChar('\u{E0001}'),
                snippet: "U+E0001".to_string(),
            },
            Removal {
                byte_span: (30, 35),
                kind: RemovalKind::Confusable {
                    original: "evаl".to_string(),
                    skeleton: "eval".to_string(),
                },
                snippet: "evаl -> eval".to_string(),
            },
        ];

        let findings = map_removals_to_findings(&removals, Path::new("SKILL.md"));
        assert_eq!(findings.len(), 4);
        assert_eq!(findings[0].rule_id, "SD-10-bidi-trojan-source");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].rule_id, "SD-01-zero-width-smuggle");
        assert_eq!(findings[1].severity, Severity::High);
        assert_eq!(findings[2].rule_id, "SD-11-tag-char-smuggle");
        assert_eq!(findings[2].severity, Severity::Critical);
        assert_eq!(findings[3].rule_id, "SD-10-homoglyph-confusable");
        assert_eq!(findings[3].severity, Severity::High);

        for f in &findings {
            assert_eq!(f.layer, AnalysisLayer::L1);
            assert_eq!(f.path, PathBuf::from("SKILL.md"));
        }
    }

    #[test]
    fn merge_l1_and_l2_preserves_l1_critical_when_l2_benign() {
        let mut l1_report = Report {
            bundle_digest: "digest1".to_string(),
            findings: vec![make_l1_finding("SD-02-cmd-eval")],
            coverage: crate::report::Coverage::from_evaluable(&[]),
            verdict: crate::report::Verdict::Fail,
            deterministic: true,
            scanner_version: "0.1.0".to_string(),
            would_fail: true,
            fail_on: Some(Severity::High),
            layers: crate::report::LayerStatus::default(),
        };
        // Explicitly Critical
        l1_report.findings[0].severity = Severity::Critical;

        // L2 reports empty/benign findings
        let merged = merge_l1_and_l2(&l1_report, &[], LayerRunState::Ran);

        assert_eq!(merged.findings.len(), 1);
        assert_eq!(merged.findings[0].severity, Severity::Critical);
        assert_eq!(merged.findings[0].rule_id, "SD-02-cmd-eval");
        assert!(merged.would_fail);
        assert_eq!(merged.verdict, crate::report::Verdict::Fail);
        assert_eq!(merged.layers.l2, LayerRunState::Ran);
    }

    #[test]
    fn merge_l1_and_l2_cannot_downgrade_severity() {
        let l1_report = Report {
            bundle_digest: "digest1".to_string(),
            findings: vec![make_l1_finding("SD-02-cmd-eval")],
            coverage: crate::report::Coverage::from_evaluable(&[]),
            verdict: crate::report::Verdict::Fail,
            deterministic: true,
            scanner_version: "0.1.0".to_string(),
            would_fail: true,
            fail_on: Some(Severity::High),
            layers: crate::report::LayerStatus::default(),
        };

        // L2 attempts to report the same finding with Low severity
        let mut l2_fake = make_l2_finding("SD-02-cmd-eval");
        l2_fake.byte_span = Some(ByteSpan { start: 0, end: 10 });
        l2_fake.severity = Severity::Low;

        let merged = merge_l1_and_l2(&l1_report, &[l2_fake], LayerRunState::Ran);

        assert_eq!(merged.findings.len(), 1);
        assert_eq!(
            merged.findings[0].severity,
            Severity::High,
            "Severity must not be downgraded by L2"
        );
    }

    #[test]
    fn merge_l1_and_l2_merges_confidence_and_appends_evidence() {
        let mut l1_f = make_l1_finding("SD-02-cmd-eval");
        l1_f.confidence = Confidence::Low;
        l1_f.evidence = vec!["l1 evidence".to_string()];

        let l1_report = Report {
            bundle_digest: "digest1".to_string(),
            findings: vec![l1_f],
            coverage: crate::report::Coverage::from_evaluable(&[]),
            verdict: crate::report::Verdict::Fail,
            deterministic: true,
            scanner_version: "0.1.0".to_string(),
            would_fail: true,
            fail_on: Some(Severity::High),
            layers: crate::report::LayerStatus::default(),
        };

        let mut l2_f = make_l2_finding("SD-02-cmd-eval");
        l2_f.byte_span = Some(ByteSpan { start: 0, end: 10 });
        l2_f.confidence = Confidence::High;
        l2_f.evidence = vec!["l2 semantic confirmation".to_string()];

        let merged = merge_l1_and_l2(&l1_report, &[l2_f], LayerRunState::Ran);

        assert_eq!(merged.findings.len(), 1);
        assert_eq!(merged.findings[0].confidence, Confidence::High);
        assert_eq!(
            merged.findings[0].evidence,
            vec![
                "l1 evidence".to_string(),
                "l2 semantic confirmation".to_string()
            ]
        );
    }

    #[test]
    fn merge_l3_findings_preserves_l1_and_adds_l3() {
        let l1_report = Report {
            bundle_digest: "digest1".to_string(),
            findings: vec![make_l1_finding("SD-02-cmd-eval")],
            coverage: crate::report::Coverage::from_evaluable(&[]),
            verdict: crate::report::Verdict::Fail,
            deterministic: true,
            scanner_version: "0.1.0".to_string(),
            would_fail: true,
            fail_on: Some(Severity::High),
            layers: crate::report::LayerStatus::default(),
        };

        let l3_finding = Finding {
            rule_id: "SD-03-behavioral-canary-leak".to_string(),
            class: ThreatClass::DataExfiltration,
            severity: Severity::Critical,
            confidence: Confidence::High,
            path: PathBuf::from("scripts/install.py"),
            byte_span: None,
            evidence: vec!["Canary secret 'AWS_SECRET_ACCESS_KEY' leaked".to_string()],
            remediation: Some("Remove credential access".to_string()),
            layer: AnalysisLayer::L3,
        };

        let merged = merge_l3_findings(&l1_report, &[l3_finding], LayerRunState::Ran);

        assert_eq!(merged.findings.len(), 2);
        assert_eq!(merged.findings[0].rule_id, "SD-02-cmd-eval");
        assert_eq!(merged.findings[0].layer, AnalysisLayer::L1);
        assert_eq!(merged.findings[1].rule_id, "SD-03-behavioral-canary-leak");
        assert_eq!(merged.findings[1].layer, AnalysisLayer::L3);
        assert_eq!(merged.findings[1].severity, Severity::Critical);
        assert_eq!(merged.layers.l3, LayerRunState::Ran);
    }

    #[test]
    fn merge_l4_findings_preserves_local_and_adds_l4() {
        let l1_report = Report {
            bundle_digest: "digest1".to_string(),
            findings: vec![make_l1_finding("SD-02-cmd-eval")],
            coverage: crate::report::Coverage::from_evaluable(&[]),
            verdict: crate::report::Verdict::Fail,
            deterministic: true,
            scanner_version: "0.1.0".to_string(),
            would_fail: true,
            fail_on: Some(Severity::High),
            layers: crate::report::LayerStatus::default(),
        };

        let l4_finding = Finding {
            rule_id: "SD-05-known-malicious-typosquat".to_string(),
            class: ThreatClass::SupplyChainTampering,
            severity: Severity::Critical,
            confidence: Confidence::High,
            path: PathBuf::from("SKILL.md"),
            byte_span: None,
            evidence: vec!["Community threat intel matched bundle digest".to_string()],
            remediation: Some("Remove compromised skill".to_string()),
            layer: AnalysisLayer::L4,
        };

        let merged = merge_l4_findings(&l1_report, &[l4_finding], LayerRunState::Ran);

        assert_eq!(merged.findings.len(), 2);
        assert_eq!(merged.findings[0].rule_id, "SD-02-cmd-eval");
        assert_eq!(merged.findings[0].layer, AnalysisLayer::L1);
        assert_eq!(
            merged.findings[1].rule_id,
            "SD-05-known-malicious-typosquat"
        );
        assert_eq!(merged.findings[1].layer, AnalysisLayer::L4);
        assert_eq!(merged.findings[1].severity, Severity::Critical);
        assert_eq!(merged.layers.l4, LayerRunState::Ran);
    }
}
