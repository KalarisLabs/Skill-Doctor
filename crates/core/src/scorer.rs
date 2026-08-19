//! Risk scoring module — merge, deduplicate, and score findings from all layers.
//!
//! Equivalent to Python's `skill_doctor/scanner/scorer.py`.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use uuid::Uuid;

use crate::models::{Finding, RiskLevel, ScanResult, Severity};

/// Merge, deduplicate, and score findings from all scan layers.
pub fn score_findings(
    all_findings: Vec<Finding>,
    bundle_hash: &str,
    layers_run: Vec<String>,
    duration_ms: u64,
) -> ScanResult {
    let deduplicated = deduplicate_findings(all_findings);
    let risk_score = calculate_risk_score(&deduplicated, &layers_run);
    let risk_level = determine_risk_level(&deduplicated, risk_score);

    ScanResult {
        scan_id: Uuid::new_v4().to_string(),
        bundle_hash: bundle_hash.to_string(),
        scanned_at: Utc::now(),
        duration_ms,
        findings: deduplicated,
        risk_level,
        risk_score,
        layers_run,
    }
}

/// Deduplicate findings based on (category, file, line).
/// Keeps the finding with higher confidence when duplicates are found.
fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen: HashSet<(String, String, Option<usize>)> = HashSet::new();
    let mut result: Vec<Finding> = Vec::new();

    for finding in findings {
        let key = (finding.category.clone(), finding.file.clone(), finding.line);

        if seen.contains(&key) {
            // Replace if higher confidence
            if let Some(existing) = result.iter_mut().find(|f| {
                f.category == finding.category && f.file == finding.file && f.line == finding.line
            }) {
                if finding.confidence > existing.confidence {
                    *existing = finding;
                }
            }
        } else {
            seen.insert(key);
            result.push(finding);
        }
    }

    result
}

/// Calculate overall risk score (0.0–10.0).
///
/// Scoring factors:
/// - Severity weights: CRITICAL=9.0, HIGH=7.0, MEDIUM=4.0, LOW=1.0, INFO=0.0
/// - Confidence multiplier
/// - Cross-layer corroboration bonus
fn calculate_risk_score(findings: &[Finding], _layers_run: &[String]) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    // Base score from severity weights × confidence
    let base_score: f64 = findings
        .iter()
        .map(|f| f.severity.weight() * f.confidence)
        .sum();

    // Normalize to 0–10 range (cap at 10.0)
    let normalized = base_score.min(10.0);

    // Cross-layer corroboration bonus
    let mut engine_counts: HashMap<String, usize> = HashMap::new();
    for f in findings {
        *engine_counts.entry(f.engine.to_string()).or_insert(0) += 1;
    }

    let corroboration_bonus: f64 = engine_counts
        .values()
        .filter(|&&count| count > 1)
        .map(|&count| (count - 1) as f64 * 0.5)
        .sum();

    (normalized + corroboration_bonus).min(10.0)
}

/// Determine risk level based on findings and score.
fn determine_risk_level(findings: &[Finding], risk_score: f64) -> RiskLevel {
    // Any CRITICAL finding → DANGEROUS
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        return RiskLevel::Dangerous;
    }

    // Any HIGH finding → CAUTION
    if findings.iter().any(|f| f.severity == Severity::High) {
        return RiskLevel::Caution;
    }

    // Score-based thresholds
    if risk_score >= 7.0 {
        RiskLevel::Dangerous
    } else if risk_score >= 4.0 {
        RiskLevel::Caution
    } else {
        RiskLevel::Safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Engine;

    fn make_finding(severity: Severity, confidence: f64) -> Finding {
        Finding::new(
            severity,
            "SD-02 · Command Injection",
            "test.py",
            Some(1),
            "Test finding",
            "Fix it",
            Engine::Ast,
            confidence,
        )
    }

    #[test]
    fn test_empty_findings_safe() {
        let result = score_findings(vec![], "abc123", vec!["static".into()], 100);
        assert_eq!(result.risk_level, RiskLevel::Safe);
        assert_eq!(result.risk_score, 0.0);
    }

    #[test]
    fn test_critical_finding_dangerous() {
        let findings = vec![make_finding(Severity::Critical, 0.9)];
        let result = score_findings(findings, "abc123", vec!["static".into()], 100);
        assert_eq!(result.risk_level, RiskLevel::Dangerous);
    }

    #[test]
    fn test_high_finding_caution() {
        let findings = vec![make_finding(Severity::High, 0.8)];
        let result = score_findings(findings, "abc123", vec!["static".into()], 100);
        assert_eq!(result.risk_level, RiskLevel::Caution);
    }

    #[test]
    fn test_deduplication() {
        let f1 = make_finding(Severity::High, 0.5);
        let f2 = make_finding(Severity::High, 0.9);
        let result = deduplicate_findings(vec![f1, f2]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].confidence, 0.9); // Higher confidence wins
    }

    #[test]
    fn test_risk_score_cap() {
        let findings: Vec<Finding> = (0..20)
            .map(|_| make_finding(Severity::Critical, 1.0))
            .collect();
        let score = calculate_risk_score(&findings, &["static".into()]);
        assert!(score <= 10.0);
    }
}
