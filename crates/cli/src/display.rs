//! Display module for CLI — handles OpenTUI rendering.

use skill_doctor_core::models::{ScanResult, Severity};

pub fn print_results(result: &ScanResult) {
    println!("\n=== SCAN RESULTS ===");
    println!("Risk Level: {}", result.risk_level);
    println!("Risk Score: {:.1} / 10.0", result.risk_score);
    println!("Findings: {}", result.findings.len());

    if result.findings.is_empty() {
        println!("\nNo issues found. 🚀");
        return;
    }

    // Sort findings by severity then confidence
    let mut findings = result.findings.clone();
    findings.sort_by(|a, b| {
        b.severity.order().cmp(&a.severity.order())
            .then(b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
    });

    for f in &findings {
        let prefix = match f.severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🔵",
            Severity::Info => "⚪",
        };

        println!("\n{} [{}] {}", prefix, f.severity, f.category);
        let line_info = f.line.map_or("".to_string(), |l| format!(":{}", l));
        println!("  File: {}{}", f.file, line_info);
        println!("  Description: {}", f.description);
        println!("  Remediation: {}", f.remediation);
        println!("  Engine: {} (Confidence: {:.0}%)", f.engine, f.confidence * 100.0);
    }
    println!("\n====================");
}
