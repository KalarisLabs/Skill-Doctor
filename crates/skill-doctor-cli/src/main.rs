//! Skill Doctor CLI — security scanner for AI agent skill files.
//!
//! Exit codes:
//!   0 — clean (no findings at or above --fail-on threshold)
//!   1 — usage error or internal error
//!   2 — findings at or above --fail-on threshold
//!   3 — structural coverage below --fail-under-coverage threshold

mod progress;
mod sarif;
mod tui;
mod ui;
mod watch;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use progress::ScanProgress;
use skill_doctor_core::finding::Severity;
use skill_doctor_core::l0;
use skill_doctor_core::l5::{self, ReportOptions};
use skill_doctor_core::report::Verdict;
use std::path::{Path, PathBuf};
use std::process;
use ui::{ColorChoice, ProgressStyleChoice, ThemeMode, UiContext};

/// Skill Doctor — security scanner for AI agent skill files.
///
/// Deterministic, offline-first static analysis of skill files
/// for the 11 SDTM-v1 threat classes.
#[derive(Parser)]
#[command(name = "skill-doctor", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output colorization.
    #[arg(long, global = true, default_value = "auto")]
    color: ColorChoice,

    /// Color theme palette.
    #[arg(long, global = true, default_value = "vivid")]
    theme: ThemeMode,

    /// Progress indicator style (TTY only).
    #[arg(long, global = true, default_value = "auto")]
    progress: ProgressStyleChoice,

    /// Launch interactive full-screen dashboard (requires feature `tui`).
    #[arg(long, global = true)]
    tui: bool,

    /// Suppress informational headers and non-essential progress output.
    #[arg(short, long, global = true)]
    quiet: bool,
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

    /// Watch a skill directory for changes and rescan continuously.
    Watch {
        /// Path to the skill directory or file to watch.
        path: PathBuf,

        /// Minimum severity to report.
        #[arg(long, default_value = "high")]
        fail_on: SeverityArg,

        /// Run in deterministic mode.
        #[arg(long)]
        deterministic: bool,
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
#[derive(Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

fn main() {
    let cli = Cli::parse();
    let ui = UiContext::new(cli.color, cli.theme, cli.progress);

    let result = match cli.command {
        Commands::Scan {
            path,
            fail_on,
            fail_under_coverage,
            output,
            deterministic,
            offline: _,
        } => {
            if !cli.quiet && output == OutputFormat::Text && !cli.tui && !deterministic {
                ui.print_banner_if_tty();
            }
            run_scan(
                &path,
                fail_on.0,
                fail_under_coverage,
                &output,
                deterministic,
                cli.tui,
                cli.quiet,
                cli.progress,
                &ui,
            )
        }

        Commands::ScanAll {
            path,
            fail_on,
            fail_under_coverage,
            output,
            deterministic,
            offline: _,
        } => {
            if !cli.quiet && output == OutputFormat::Text && !deterministic {
                ui.print_banner_if_tty();
            }
            run_scan_all(
                &path,
                fail_on.0,
                fail_under_coverage,
                &output,
                deterministic,
                cli.quiet,
                cli.progress,
                &ui,
            )
        }

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
            false,
            cli.quiet,
            cli.progress,
            &ui,
        ),

        Commands::Watch {
            path,
            fail_on,
            deterministic,
        } => watch::run_watch(&path, fail_on.0, deterministic, &ui).map(|_| 0),
    };

    match result {
        Ok(exit_code) => process::exit(exit_code),
        Err(e) => {
            eprintln!("error: {:#}", e);
            process::exit(1);
        }
    }
}

/// Run a scan on a single skill directory or archive.
#[allow(clippy::too_many_arguments)]
fn run_scan(
    path: &Path,
    fail_on: Severity,
    fail_under_coverage: Option<f64>,
    output: &OutputFormat,
    deterministic: bool,
    use_tui: bool,
    quiet: bool,
    progress_choice: ProgressStyleChoice,
    ui: &UiContext,
) -> Result<i32> {
    let progress = ScanProgress::new(ui, deterministic, quiet, progress_choice);
    progress.set_status("L0 intake & canonical hashing...");

    let bundle = l0::intake(path).context("L0 intake failed")?;

    progress.set_status("L1 static analysis engines...");
    let report = l5::analyze(
        &bundle,
        &ReportOptions {
            fail_on,
            deterministic,
        },
    );

    progress.finish_and_clear();

    // Opt-in TUI
    if use_tui && *output == OutputFormat::Text {
        return tui::run_tui(&report);
    }

    // Output formatting (Layer A, JSON, SARIF)
    match output {
        OutputFormat::Text => {
            ui.print_report(&report);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{}", json);
        }
        OutputFormat::Sarif => {
            let sarif_val = sarif::report_to_sarif(&report);
            let json = serde_json::to_string_pretty(&sarif_val)?;
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

/// Scan all discovered skill directories under a root path.
#[allow(clippy::too_many_arguments)]
fn run_scan_all(
    root: &Path,
    fail_on: Severity,
    fail_under_coverage: Option<f64>,
    output: &OutputFormat,
    deterministic: bool,
    quiet: bool,
    progress_choice: ProgressStyleChoice,
    ui: &UiContext,
) -> Result<i32> {
    if !root.exists() {
        anyhow::bail!("path does not exist: {}", root.display());
    }

    // Discover skill directories containing SKILL.md
    // Filter out VCS, build artifacts, internal agent skills, and test attack fixtures
    let mut skill_dirs = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            let path_str = e.path().to_string_lossy().replace('\\', "/");
            !name.starts_with(".git")
                && name != "target"
                && name != "node_modules"
                && name != "dist"
                && name != "skills"
                && !path_str.contains("/skills/")
                && !path_str.contains("/fixtures/attack")
                && !path_str.contains("/corpora/cmd-inject-skill")
                && !path_str.contains("/corpora/prompt-inject-skill")
        })
    {
        let entry = entry?;
        if entry.file_type().is_file() && entry.file_name() == "SKILL.md" {
            if let Some(parent) = entry.path().parent() {
                skill_dirs.push(parent.to_path_buf());
            }
        }
    }

    if skill_dirs.is_empty() {
        return run_scan(
            root,
            fail_on,
            fail_under_coverage,
            output,
            deterministic,
            false,
            quiet,
            progress_choice,
            ui,
        );
    }

    let progress = ScanProgress::new(ui, deterministic, quiet, progress_choice);
    let mut overall_exit_code = 0;
    let mut total_findings = 0;
    let total_dirs = skill_dirs.len();

    for (idx, dir) in skill_dirs.iter().enumerate() {
        let dir_name = dir
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();
        progress.set_item_progress(idx + 1, total_dirs, &dir_name);

        let bundle = l0::intake(dir).context("L0 intake failed")?;
        let report = l5::analyze(
            &bundle,
            &ReportOptions {
                fail_on,
                deterministic,
            },
        );

        match output {
            OutputFormat::Text => {
                println!("=== Skill: {} ===", dir.display());
                ui.print_report(&report);
                println!();
            }
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(&report)?;
                println!("{}", json);
            }
            OutputFormat::Sarif => {
                let sarif_val = sarif::report_to_sarif(&report);
                let json = serde_json::to_string_pretty(&sarif_val)?;
                println!("{}", json);
            }
        }

        total_findings += report.findings.len();
        if report.verdict == Verdict::Fail {
            overall_exit_code = 2;
        }

        if let Some(threshold) = fail_under_coverage {
            if report.coverage.ratio() < threshold {
                eprintln!(
                    "Skill '{}': Coverage {:.1}% is below threshold {:.1}%",
                    dir.display(),
                    report.coverage.ratio() * 100.0,
                    threshold * 100.0,
                );
                overall_exit_code = 3;
            }
        }
    }

    progress.finish_and_clear();

    if *output == OutputFormat::Text {
        println!(
            "Scanned {} skill(s). Total findings: {}. Overall exit: {}",
            total_dirs, total_findings, overall_exit_code
        );
    }

    Ok(overall_exit_code)
}

/// Compare scan results against a baseline.
fn run_diff(
    path: &Path,
    baseline: &Path,
    output: &OutputFormat,
    deterministic: bool,
) -> Result<i32> {
    let baseline_json = std::fs::read_to_string(baseline)
        .with_context(|| format!("Failed to read baseline report: {}", baseline.display()))?;
    let baseline_report: skill_doctor_core::report::Report =
        serde_json::from_str(&baseline_json).context("Failed to parse baseline report")?;

    let bundle = l0::intake(path).context("L0 intake failed")?;
    let current_report = l5::analyze(
        &bundle,
        &ReportOptions {
            fail_on: Severity::High,
            deterministic,
        },
    );

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
