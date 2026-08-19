//! Skill Doctor CLI — command-line interface for skill file scanning.
//!
//! Built with Clap for argument parsing and OpenTUI for terminal rendering.

mod commands;
mod display;

use clap::{Parser, Subcommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "skill-doctor",
    about = "Skill Doctor — Multi-layer security platform for AI agent skill files.",
    version = VERSION,
    author = "Kalaris Labs <sayan@kalarislabs.com>",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a skill file, directory, bundle, URL, or registry reference.
    Scan {
        /// Target to scan (file, directory, URL, skills.sh/owner/repo, or owner/repo).
        target: String,

        /// Output format.
        #[arg(long, value_parser = ["sarif", "json", "html"])]
        output: Option<String>,

        /// Exit with code 1 if findings at this level or above.
        #[arg(long, value_parser = ["CRITICAL", "HIGH", "MEDIUM", "LOW"])]
        fail_on: Option<String>,

        /// Skip LLM semantic analysis pass.
        #[arg(long)]
        no_llm: bool,

        /// Skip E2B behavioral sandbox.
        #[arg(long)]
        no_sandbox: bool,

        /// Select specific rule packs (comma-separated).
        #[arg(long, default_value = "core")]
        rule_pack: String,

        /// LLM provider URL (overrides SKILL_DOCTOR_LLM_URL env var).
        #[arg(long, env = "SKILL_DOCTOR_LLM_URL")]
        llm_url: Option<String>,

        /// LLM model name (overrides SKILL_DOCTOR_LLM_MODEL env var).
        #[arg(long, env = "SKILL_DOCTOR_LLM_MODEL")]
        llm_model: Option<String>,
    },

    /// Scan all skills in a directory tree recursively.
    ScanAll {
        /// Root directory to scan.
        directory: String,
    },

    /// Diff scan two versions of a skill.
    Diff {
        /// First version directory.
        v1: String,
        /// Second version directory.
        v2: String,
    },

    /// Run as MCP server for runtime gating.
    Mcp,

    /// List loaded rule packs.
    Rules,

    /// Print version information.
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            output,
            fail_on,
            no_llm,
            no_sandbox,
            rule_pack,
            llm_url,
            llm_model,
        } => {
            commands::scan::run(
                &target, output, fail_on, no_llm, no_sandbox, &rule_pack, llm_url, llm_model,
            )
            .await
        }
        Commands::ScanAll { directory } => commands::scan_all::run(&directory).await,
        Commands::Diff { v1, v2 } => commands::diff::run(&v1, &v2).await,
        Commands::Mcp => commands::mcp::run().await,
        Commands::Rules => {
            commands::rules::run();
            Ok(())
        }
        Commands::Version => {
            commands::version::run();
            Ok(())
        }
    }
}
