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
