//! Skill Doctor Sandbox — L3-lite behavioral process harness.
//!
//! Provides isolated companion script execution with:
//! - Environment isolation table (HOME is a lie; host credentials & CI/CD flags stripped).
//! - Synthetic canary injection and leak detection (SD-03).
//! - Differential replay across execution profiles for logic bomb detection (SD-10).
//! - Process tree kill on timeout via Windows Job Objects and Unix process groups.
//! - Purity: emits pure `CanaryLeak` and `BehavioralDivergence` records; does not
//!   depend on `Finding`, `Report`, or `skill-doctor-core`.

pub mod canary;
pub mod replay;
pub mod runner;

use std::fs;
use std::path::Path;

pub use canary::{CanaryLeak, CanarySecrets, LeakSource};
pub use replay::BehavioralDivergence;
pub use runner::DEFAULT_TIMEOUT_MS;

/// Execution status of the behavioral sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxRunState {
    /// Sandbox executed companion scripts.
    Ran,
    /// Execution was degraded (e.g. interpreter missing or time axis skipped).
    Reduced,
    /// Sandbox was skipped (e.g. no companion scripts or deterministic mode).
    Skipped,
}

/// Configuration options for L3 sandbox execution.
#[derive(Debug, Clone)]
pub struct SandboxOptions {
    /// Execution timeout per script invocation in milliseconds.
    pub timeout_ms: u64,
    /// Maximum companion scripts to inspect per skill.
    pub max_scripts: usize,
}

impl Default for SandboxOptions {
    fn default() -> Self {
        Self {
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_scripts: runner::MAX_COMPANION_SCRIPTS,
        }
    }
}

/// Consolidated results from L3 behavioral sandbox execution.
#[derive(Debug, Clone)]
pub struct SandboxResult {
    /// Detected credential leaks (SD-03).
    pub leaks: Vec<CanaryLeak>,
    /// Detected behavioral divergences (SD-10).
    pub divergences: Vec<BehavioralDivergence>,
    /// State of L3 execution.
    pub state: SandboxRunState,
    /// Diagnostic messages.
    pub diagnostics: Vec<String>,
}

/// Runs L3 behavioral sandbox analysis on a skill.
///
/// Copies the skill into an isolated temporary workspace, plants synthetic canary
/// credentials into a mock home directory, discovers companion scripts, and
/// executes differential replay across execution profiles.
pub fn run_sandbox(skill_path: &Path, options: &SandboxOptions) -> SandboxResult {
    let mut diagnostics = Vec::new();

    if !skill_path.exists() {
        return SandboxResult {
            leaks: Vec::new(),
            divergences: Vec::new(),
            state: SandboxRunState::Skipped,
            diagnostics: vec![format!(
                "Skill path does not exist: {}",
                skill_path.display()
            )],
        };
    }

    // 1. Create temporary directory for isolated mock home & workspace
    let temp_dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            return SandboxResult {
                leaks: Vec::new(),
                divergences: Vec::new(),
                state: SandboxRunState::Reduced,
                diagnostics: vec![format!("Failed to create sandbox temporary directory: {e}")],
            };
        }
    };

    let mock_home = temp_dir.path().join("mock_home");
    let workspace = mock_home.join("workspace");
    if let Err(e) = fs::create_dir_all(&workspace) {
        return SandboxResult {
            leaks: Vec::new(),
            divergences: Vec::new(),
            state: SandboxRunState::Reduced,
            diagnostics: vec![format!("Failed to create sandbox workspace directory: {e}")],
        };
    }

    // 2. Plant synthetic canary credentials
    let canary_manager = match canary::CanaryManager::plant(&mock_home, CanarySecrets::generate()) {
        Ok(mgr) => mgr,
        Err(e) => {
            return SandboxResult {
                leaks: Vec::new(),
                divergences: Vec::new(),
                state: SandboxRunState::Reduced,
                diagnostics: vec![format!("Failed to plant sandbox canary credentials: {e}")],
            };
        }
    };

    // 3. Copy skill contents into workspace (ensuring we execute a copy, never user's real tree)
    if skill_path.is_dir() {
        if let Err(e) = runner::copy_dir_all(skill_path, &workspace) {
            return SandboxResult {
                leaks: Vec::new(),
                divergences: Vec::new(),
                state: SandboxRunState::Reduced,
                diagnostics: vec![format!("Failed to copy skill directory into sandbox: {e}")],
            };
        }
    } else if skill_path.is_file() {
        let file_name = skill_path.file_name().unwrap_or_default();
        if let Err(e) = fs::copy(skill_path, workspace.join(file_name)) {
            return SandboxResult {
                leaks: Vec::new(),
                divergences: Vec::new(),
                state: SandboxRunState::Reduced,
                diagnostics: vec![format!("Failed to copy skill file into sandbox: {e}")],
            };
        }
    }

    // 4. Discover runnable companion scripts
    let scripts = runner::discover_companion_scripts(&workspace);
    if scripts.is_empty() {
        return SandboxResult {
            leaks: Vec::new(),
            divergences: Vec::new(),
            state: SandboxRunState::Ran,
            diagnostics: vec!["No runnable companion scripts found in skill bundle".to_string()],
        };
    }

    let mut all_leaks = Vec::new();
    let mut all_divergences = Vec::new();
    let mut scripts_ran = 0;
    let mut scripts_reduced = 0;

    let scripts_to_run = scripts.into_iter().take(options.max_scripts);

    for script in scripts_to_run {
        let outcome = replay::replay_script(
            &script,
            &mock_home,
            &workspace,
            &canary_manager,
            options.timeout_ms,
        );

        if let Some(err) = outcome.error {
            diagnostics.push(format!(
                "Script '{}' reduced: {err}",
                script.rel_path.display()
            ));
            scripts_reduced += 1;
            continue;
        }

        scripts_ran += 1;

        if outcome.time_axis_reduced {
            diagnostics.push(format!(
                "Time-shifted profile skipped for '{}' (faketime not available on host)",
                script.rel_path.display()
            ));
        }

        for leak in outcome.leaks {
            if !all_leaks.contains(&leak) {
                all_leaks.push(leak);
            }
        }

        for div in outcome.divergences {
            if !all_divergences.contains(&div) {
                all_divergences.push(div);
            }
        }
    }

    let state = if scripts_ran > 0 {
        SandboxRunState::Ran
    } else if scripts_reduced > 0 {
        SandboxRunState::Reduced
    } else {
        SandboxRunState::Skipped
    };

    SandboxResult {
        leaks: all_leaks,
        divergences: all_divergences,
        state,
        diagnostics,
    }
}
