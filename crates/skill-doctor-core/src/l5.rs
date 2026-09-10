//! L5 — scoring, coverage computation, and report generation.
//!
//! Merges findings from all layers, computes structural coverage,
//! and produces the final Report.

use crate::finding::Severity;
use crate::l0::Bundle;
use crate::l1;
use crate::report::{Coverage, LayerStatus, Report, Verdict};

/// Options for report generation.
pub struct ReportOptions {
    /// Severity threshold: findings at or above this trigger exit code 2.
    pub fail_on: Severity,
    /// Whether to run in deterministic mode.
    pub deterministic: bool,
}

/// Run the full analysis pipeline on a bundle and produce a report.
pub fn analyze(bundle: &Bundle, options: &ReportOptions) -> Report {
    // Run L1 engines.
    let l1_result = l1::run_all_engines(&bundle.entries);

    // Sort findings deterministically.
    let mut findings = l1_result.findings;
    if options.deterministic {
        findings.sort_by(|a, b| {
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

    // Compute coverage.
    let coverage = Coverage::from_evaluable(&l1_result.evaluable_classes);

    // Compute verdict.
    let verdict = Report::compute_verdict(&findings, options.fail_on);
    let would_fail = verdict == Verdict::Fail;

    Report {
        bundle_digest: bundle.digest.clone(),
        findings,
        coverage,
        verdict,
        deterministic: options.deterministic,
        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
        would_fail,
        fail_on: Some(options.fail_on),
        layers: LayerStatus::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l0;
    use crate::report::Verdict;
    use std::fs;

    #[test]
    fn analyze_empty_bundle_produces_pass() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("SKILL.md"),
            "# Clean Skill\n\nNothing bad here.\n",
        )
        .unwrap();

        let bundle = l0::intake(dir.path()).unwrap();
        let report = analyze(
            &bundle,
            &ReportOptions {
                fail_on: Severity::High,
                deterministic: true,
            },
        );

        assert_eq!(report.verdict, Verdict::Pass);
        assert!(report.deterministic);
        assert!(!report.bundle_digest.is_empty());
    }

    #[test]
    fn deterministic_reports_are_identical() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("SKILL.md"), "# Skill\n\nSafe content.\n").unwrap();

        let bundle = l0::intake(dir.path()).unwrap();
        let opts = ReportOptions {
            fail_on: Severity::High,
            deterministic: true,
        };

        let report1 = analyze(&bundle, &opts);
        let report2 = analyze(&bundle, &opts);

        let json1 = serde_json::to_string_pretty(&report1).unwrap();
        let json2 = serde_json::to_string_pretty(&report2).unwrap();

        assert_eq!(json1, json2, "Deterministic reports must be byte-identical");
    }
}
