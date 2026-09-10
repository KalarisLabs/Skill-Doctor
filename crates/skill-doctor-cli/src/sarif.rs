//! SARIF 2.1.0 report generation for GitHub code scanning and CI integration.

use serde_json::json;
use skill_doctor_core::finding::Severity;
use skill_doctor_core::report::Report;

/// Convert a Skill Doctor Report to a SARIF 2.1.0 JSON value.
pub fn report_to_sarif(report: &Report) -> serde_json::Value {
    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical | Severity::High => "error",
                Severity::Medium => "warning",
                Severity::Low | Severity::Info => "note",
            };

            let path_str = f.path.to_string_lossy().replace('\\', "/");

            let mut message_text = format!("[{}] {}", f.class.id(), f.rule_id);
            if !f.evidence.is_empty() {
                message_text.push_str(&format!(": {}", f.evidence.join("; ")));
            }
            if let Some(fix) = &f.remediation {
                message_text.push_str(&format!(" (Remediation: {})", fix));
            }

            let start_line = 1;

            json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": {
                    "text": message_text
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": path_str
                            },
                            "region": {
                                "startLine": start_line
                            }
                        }
                    }
                ]
            })
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Skill Doctor",
                        "version": report.scanner_version,
                        "informationUri": "https://github.com/KalarisLabs/Skill-Doctor"
                    }
                },
                "results": results
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_doctor_core::finding::{AnalysisLayer, Confidence, Finding};
    use skill_doctor_core::report::{Coverage, Report};
    use skill_doctor_core::taxonomy::ThreatClass;
    use std::path::PathBuf;

    #[test]
    fn test_canary_bytes_absent_from_sarif_and_json() {
        let finding = Finding {
            rule_id: "SD-03-behavioral-canary-leak".to_string(),
            class: ThreatClass::DataExfiltration,
            severity: Severity::Critical,
            confidence: Confidence::High,
            path: PathBuf::from("mock_home/workspace/scripts/dump.py"),
            byte_span: None,
            evidence: vec![
                "Canary secret 'AWS_SECRET_ACCESS_KEY' exfiltrated via stdout".to_string(),
            ],
            remediation: Some("Remove credential access and exfiltration code".to_string()),
            layer: AnalysisLayer::L3,
        };

        let report = Report {
            bundle_digest: "test_digest".to_string(),
            findings: vec![finding],
            coverage: Coverage::from_evaluable(&ThreatClass::ALL),
            verdict: skill_doctor_core::report::Verdict::Fail,
            deterministic: false,
            scanner_version: "2.0.0".to_string(),
            would_fail: true,
            fail_on: Some(Severity::High),
            layers: Default::default(),
        };

        let json_str = serde_json::to_string_pretty(&report).unwrap();
        let sarif_val = report_to_sarif(&report);
        let sarif_str = serde_json::to_string_pretty(&sarif_val).unwrap();

        // Invariant: canary secret tokens (AKIA_CANARY, etc.) must NEVER appear in JSON or SARIF
        assert!(!json_str.contains("AKIA_CANARY"));
        assert!(!sarif_str.contains("AKIA_CANARY"));
        assert!(!json_str.contains("ghp_canary"));
        assert!(!sarif_str.contains("ghp_canary"));

        // Only canonical secret_name is present
        assert!(json_str.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(sarif_str.contains("AWS_SECRET_ACCESS_KEY"));
    }
}
