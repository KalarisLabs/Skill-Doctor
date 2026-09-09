//! Skill Doctor CLI — security scanner for AI agent skill files.
//!
//! Exit codes:
//!   0 — clean (no findings at or above --fail-on threshold)
//!   1 — usage error or internal error
//!   2 — findings at or above --fail-on threshold
//!   3 — structural coverage below --fail-under-coverage threshold

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sha2::{Digest, Sha256};
use skill_doctor_core::finding::Severity;
use skill_doctor_core::l0;
use skill_doctor_core::l5::{self, ReportOptions};
use skill_doctor_core::report::Verdict;
use std::path::{Path, PathBuf};
use std::process;

/// Skill Doctor — security scanner for AI agent skill files.
///
/// Deterministic, offline-first, zero-dependency static analysis of skill files
/// for the 11 SDTM-v1 threat classes.
#[derive(Parser)]
#[command(name = "skill-doctor", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a single skill directory or file.
    Scan {
        /// Path to the skill directory or file to scan.
        path: PathBuf,

        /// Minimum severity to trigger a non-zero exit code.
        #[arg(long, default_value = "high")]
        fail_on: SeverityArg,

        /// Minimum structural coverage ratio (0.0–1.0) required.
        /// Exit code 3 if coverage is below this threshold.
        #[arg(long)]
        fail_under_coverage: Option<f64>,

        /// Output format.
        #[arg(long, default_value = "text")]
        output: OutputFormat,

        /// Run in deterministic mode (sorted output, pinned timestamps).
        #[arg(long)]
        deterministic: bool,

        /// Run fully offline (no network, no LLM).
        #[arg(long)]
        offline: bool,
    },

    /// Scan all skill directories under a root path.
    ScanAll {
        /// Root path to scan recursively for skill directories.
        path: PathBuf,

        /// Minimum severity to trigger a non-zero exit code.
        #[arg(long, default_value = "high")]
        fail_on: SeverityArg,

        /// Minimum structural coverage ratio (0.0–1.0) required.
        #[arg(long)]
        fail_under_coverage: Option<f64>,

        /// Output format.
        #[arg(long, default_value = "text")]
        output: OutputFormat,

        /// Run in deterministic mode.
        #[arg(long)]
        deterministic: bool,

        /// Run fully offline.
        #[arg(long)]
        offline: bool,
    },

    /// Compare scan results against a baseline.
    Diff {
        /// Path to the current scan target.
        path: PathBuf,

        /// Path to the baseline report (JSON).
        #[arg(long)]
        baseline: PathBuf,

        /// Output format.
        #[arg(long, default_value = "text")]
        output: OutputFormat,

        /// Run in deterministic mode.
        #[arg(long)]
        deterministic: bool,

        /// Run fully offline.
        #[arg(long)]
        offline: bool,
    },

    /// CI gate — scan and enforce policy.
    Gate {
        /// Path to scan.
        path: PathBuf,

        /// Minimum severity to trigger failure.
        #[arg(long, default_value = "high")]
        fail_on: SeverityArg,

        /// Minimum structural coverage ratio required.
        #[arg(long, default_value = "0.0")]
        fail_under_coverage: f64,

        /// Output format.
        #[arg(long, default_value = "text")]
        output: OutputFormat,

        /// Run in deterministic mode.
        #[arg(long)]
        deterministic: bool,

        /// Run fully offline.
        #[arg(long)]
        offline: bool,
    },
}

/// Wrapper for severity argument parsing.
#[derive(Clone, Debug)]
struct SeverityArg(Severity);

impl std::str::FromStr for SeverityArg {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Severity::from_str_loose(s).map(SeverityArg).ok_or_else(|| {
            format!(
                "unknown severity: '{}' (expected: info, low, medium, high, critical)",
                s
            )
        })
    }
}

/// Output format for scan results.
#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Scan {
            path,
            fail_on,
            fail_under_coverage,
            output,
            deterministic,
            offline: _,
        } => run_scan(
            &path,
            fail_on.0,
            fail_under_coverage,
            &output,
            deterministic,
        ),

        Commands::ScanAll {
            path,
            fail_on,
            fail_under_coverage,
            output,
            deterministic,
            offline: _,
        } => run_scan(
            &path,
            fail_on.0,
            fail_under_coverage,
            &output,
            deterministic,
        ),

        Commands::Diff {
            path,
            baseline,
            output,
            deterministic,
            offline: _,
        } => run_diff(&path, &baseline, &output, deterministic),

        Commands::Gate {
            path,
            fail_on,
            fail_under_coverage,
            output,
            deterministic,
            offline: _,
        } => run_scan(
            &path,
            fail_on.0,
            Some(fail_under_coverage),
            &output,
            deterministic,
        ),
    };

    match result {
        Ok(exit_code) => process::exit(exit_code),
        Err(e) => {
            eprintln!("error: {:#}", e);
            process::exit(1);
        }
    }
}

/// Run a scan and return the appropriate exit code.
fn run_scan(
    path: &Path,
    fail_on: Severity,
    fail_under_coverage: Option<f64>,
    output: &OutputFormat,
    deterministic: bool,
) -> Result<i32> {
    let bundle = l0::intake(path).context("L0 intake failed")?;

    let report = l5::analyze(
        &bundle,
        &ReportOptions {
            fail_on,
            deterministic,
        },
    );

    // Output the report.
    match output {
        OutputFormat::Text => {
            print_text_report(&report);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{}", json);
        }
        OutputFormat::Sarif => {
            // SARIF stub: output JSON for now, SARIF conversion comes later.
            let json = serde_json::to_string_pretty(&report)?;
            println!("{}", json);
        }
    }

    // Check coverage threshold.
    if let Some(threshold) = fail_under_coverage {
        if report.coverage.ratio() < threshold {
            eprintln!(
                "Coverage {:.1}% is below threshold {:.1}%",
                report.coverage.ratio() * 100.0,
                threshold * 100.0,
            );
            return Ok(3);
        }
    }

    // Check verdict.
    match report.verdict {
        Verdict::Pass => Ok(0),
        Verdict::Fail => Ok(2),
    }
}

/// Run a diff against a baseline.
fn run_diff(
    path: &Path,
    baseline: &Path,
    output: &OutputFormat,
    deterministic: bool,
) -> Result<i32> {
    // Load baseline report.
    let baseline_json =
        std::fs::read_to_string(baseline).context("Failed to read baseline report")?;
    let baseline_report: skill_doctor_core::report::Report =
        serde_json::from_str(&baseline_json).context("Failed to parse baseline report")?;

    // Run current scan.
    let bundle = l0::intake(path).context("L0 intake failed")?;
    let current_report = l5::analyze(
        &bundle,
        &ReportOptions {
            fail_on: Severity::High,
            deterministic,
        },
    );

    // Compute diff: new findings not in baseline.
    let new_findings: Vec<_> = current_report
        .findings
        .iter()
        .filter(|f| {
            !baseline_report
                .findings
                .iter()
                .any(|b| b.rule_id == f.rule_id && b.path == f.path)
        })
        .collect();

    match output {
        OutputFormat::Text => {
            if new_findings.is_empty() {
                println!("No new findings compared to baseline.");
            } else {
                println!("{} new finding(s):", new_findings.len());
                for f in &new_findings {
                    println!(
                        "  {} [{}] {} in {}",
                        f.severity,
                        f.class.id(),
                        f.rule_id,
                        f.path.display(),
                    );
                }
            }
        }
        OutputFormat::Json | OutputFormat::Sarif => {
            let json = serde_json::to_string_pretty(&new_findings)?;
            println!("{}", json);
        }
    }

    if new_findings.is_empty() {
        Ok(0)
    } else {
        Ok(2)
    }
}

/// Print a human-readable text report.
fn print_text_report(report: &skill_doctor_core::report::Report) {
    println!("Skill Doctor v{}", report.scanner_version);
    println!("Bundle digest: {}", report.bundle_digest);
    println!(
        "Coverage: {}/{} classes ({:.0}%)",
        report.coverage.evaluable,
        report.coverage.total,
        report.coverage.ratio() * 100.0,
    );
    println!();

    if report.findings.is_empty() {
        println!("No findings.");
    } else {
        println!("{} finding(s):", report.findings.len());
        for f in &report.findings {
            println!(
                "  {} [{}] {} in {}",
                f.severity,
                f.class.id(),
                f.rule_id,
                f.path.display(),
            );
            for ev in &f.evidence {
                println!("    evidence: {}", ev);
            }
            if let Some(ref rem) = f.remediation {
                println!("    fix: {}", rem);
            }
        }
    }

    println!();
    println!("Verdict: {:?}", report.verdict);
}

/// Compute SHA-256 of a string (used for determinism verification).
#[allow(dead_code)]
fn sha256_of(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}
