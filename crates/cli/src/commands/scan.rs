//! The `scan` command — primary entry point for skill scanning.

use std::path::Path;
use std::time::Instant;

use anyhow::Result;
use skill_doctor_core::intake::normalize_bundle;
use skill_doctor_core::layer1_static::scan_static;
use skill_doctor_core::layer2_semantic::scan_semantic_with_overrides;
use skill_doctor_core::layer4_threat::{add_to_threat_db, scan_threat_db};
use skill_doctor_core::models::Severity;
use skill_doctor_core::scorer::score_findings;

use crate::display;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    target: &str,
    output: Option<String>,
    fail_on: Option<String>,
    no_llm: bool,
    _no_sandbox: bool,
    _rule_pack: &str,
    llm_url: Option<String>,
    llm_model: Option<String>,
) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");

    println!("SKILL DOCTOR v{}", version);
    println!("by Kalaris Labs");
    println!();
    println!("[TARGET] {}", target);

    let start = Instant::now();

    // Layer 0: Intake and normalization
    println!("[NORMALIZE] Normalizing bundle...");
    let bundle = normalize_bundle(target).await?;
    println!("[HASH] Bundle hash: {}...", &bundle.hash[..16]);

    // Check threat database first
    println!("[THREAT DB] Checking threat database...");
    let (all_findings, layers_run) = if let Some(cached) = scan_threat_db(&bundle.hash) {
        println!("[CACHE] Found cached results in threat database");
        (cached, vec!["threat_db".to_string()])
    } else {
        // Layer 1: Static analysis
        println!("[STATIC] Running static analysis...");
        let static_findings = scan_static(&bundle.path);
        println!("[STATIC] Found {} static findings", static_findings.len());

        let mut all_findings = static_findings.clone();
        let mut layers_run = vec!["static".to_string()];

        // Layer 2: LLM semantic analysis
        if !no_llm {
            println!("[LLM] Running LLM semantic analysis...");
            let semantic_findings =
                scan_semantic_with_overrides(&bundle.path, &static_findings, llm_url, llm_model)
                    .await;
            println!("   Found {} semantic findings", semantic_findings.len());
            all_findings.extend(semantic_findings);
            layers_run.push("semantic".to_string());
        }

        // Layer 3: Behavioral sandbox (deferred)
        println!("[SANDBOX] Behavioral sandbox — coming soon");

        // Add to threat DB if critical/high findings exist
        let critical_high: Vec<_> = all_findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
            .collect();
        if !critical_high.is_empty() {
            println!(
                "[THREAT DB] Adding {} findings to threat database...",
                critical_high.len()
            );
            add_to_threat_db(&bundle.hash, &all_findings);
        }

        (all_findings, layers_run)
    };

    // Score findings
    let duration_ms = start.elapsed().as_millis() as u64;
    println!(
        "[TIME] Scanning completed in {:.2}s",
        duration_ms as f64 / 1000.0
    );

    let scan_result = score_findings(all_findings, &bundle.hash, layers_run, duration_ms);

    // Display results
    display::print_results(&scan_result);

    // Generate output file if requested
    if let Some(format) = &output {
        let output_path_str = format!(
            "skill-doctor-report-{}.{}",
            &scan_result.scan_id[..8],
            format
        );
        let output_path = Path::new(&output_path_str);
        println!("[OUTPUT] Generating {} report...", format.to_uppercase());

        match format.as_str() {
            "json" => skill_doctor_report::json::generate_json(&scan_result, output_path)?,
            "html" => skill_doctor_report::html::generate_html(&scan_result, output_path)?,
            "sarif" => skill_doctor_report::sarif::generate_sarif(&scan_result, output_path)?,
            _ => println!("[WARN] Unsupported output format: {}", format),
        }

        println!("[DONE] Report saved to {}", output_path.display());
    }

    // Check fail-on condition
    if let Some(fail_level) = &fail_on {
        let threshold = match fail_level.as_str() {
            "CRITICAL" => 4,
            "HIGH" => 3,
            "MEDIUM" => 2,
            "LOW" => 1,
            _ => 0,
        };

        for finding in &scan_result.findings {
            if finding.severity.order() >= threshold as u8 {
                println!(
                    "\n[FAIL] Exiting with code 1 (findings at or above {})",
                    fail_level
                );
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
