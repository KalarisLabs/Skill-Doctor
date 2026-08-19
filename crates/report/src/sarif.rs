//! SARIF 2.1 report generation for GitHub Code Scanning integration.

use std::path::Path;

use anyhow::Result;
use serde_json::json;
use skill_doctor_core::models::ScanResult;

/// Generate a SARIF 2.1.0 report file from scan results.
pub fn generate_sarif(result: &ScanResult, output_path: &Path) -> Result<()> {
    let rules: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            json!({
                "id": f.category.replace(" · ", "_").replace(' ', "_"),
                "name": f.category,
                "shortDescription": { "text": f.description },
                "defaultConfiguration": {
                    "level": match f.severity {
                        skill_doctor_core::Severity::Critical | skill_doctor_core::Severity::High => "error",
                        skill_doctor_core::Severity::Medium => "warning",
                        _ => "note",
                    }
                }
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = result
        .findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.category.replace(" · ", "_").replace(' ', "_"),
                "level": match f.severity {
                    skill_doctor_core::Severity::Critical | skill_doctor_core::Severity::High => "error",
                    skill_doctor_core::Severity::Medium => "warning",
                    _ => "note",
                },
                "message": { "text": f.description },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.file },
                        "region": {
                            "startLine": f.line.unwrap_or(1)
                        }
                    }
                }],
                "properties": {
                    "confidence": f.confidence,
                    "engine": format!("{}", f.engine),
                    "remediation": f.remediation,
                }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Skill Doctor",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/KalarisLabs/Skill-Doctor",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    });

    let json_str = serde_json::to_string_pretty(&sarif)?;
    std::fs::write(output_path, json_str)?;
    Ok(())
}
