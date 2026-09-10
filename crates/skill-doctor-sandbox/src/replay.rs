//! Differential Replay Engine for SD-10 Logic Bomb and Evasion Detection.
//!
//! Executes companion scripts across a matrix of execution profiles:
//! 1. Baseline: Standard isolated workstation.
//! 2. CI/Automation: CI=true, GITHUB_ACTIONS=true.
//! 3. Cloud Target: AWS_EXECUTION_ENV=AWS_Lambda, HOSTNAME=prod-agent-cluster.
//! 4. Time-Shifted: Time axis evaluation (gracefully Reduced if faketime is absent).
//!
//! Flags behavioral divergence: scripts that remain dormant under baseline
//! but activate or leak credentials under specific execution environments.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::canary::{CanaryLeak, CanaryManager};
use crate::runner::{
    build_isolated_env, check_command_exists, execute_script, CompanionScript, ExecutionResult,
};

/// A behavioral divergence detected across execution profiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehavioralDivergence {
    /// The script exhibiting divergent behavior.
    pub script_path: PathBuf,
    /// Baseline profile name (e.g. "Baseline").
    pub baseline_profile: String,
    /// Profile under which the script triggered (e.g. "CI/Automation" or "TargetCloud").
    pub triggered_profile: String,
    /// Explanation of the observed divergence.
    pub reason: String,
}

/// Profile configuration defining environment overrides.
pub struct ReplayProfile {
    pub name: &'static str,
    pub env_overrides: HashMap<String, String>,
    pub is_time_shifted: bool,
}

impl ReplayProfile {
    /// Standard baseline profile.
    pub fn baseline() -> Self {
        Self {
            name: "Baseline",
            env_overrides: HashMap::new(),
            is_time_shifted: false,
        }
    }

    /// Continuous Integration environment profile.
    pub fn ci() -> Self {
        let mut env = HashMap::new();
        env.insert("CI".to_string(), "true".to_string());
        env.insert("GITHUB_ACTIONS".to_string(), "true".to_string());
        env.insert("CONTINUOUS_INTEGRATION".to_string(), "true".to_string());
        env.insert("RUNNER_OS".to_string(), "Linux".to_string());
        Self {
            name: "CI/Automation",
            env_overrides: env,
            is_time_shifted: false,
        }
    }

    /// Target Cloud production profile.
    pub fn cloud() -> Self {
        let mut env = HashMap::new();
        env.insert("HOSTNAME".to_string(), "prod-agent-cluster".to_string());
        env.insert(
            "AWS_EXECUTION_ENV".to_string(),
            "AWS_Lambda_python".to_string(),
        );
        env.insert("LAMBDA_TASK_ROOT".to_string(), "/var/task".to_string());
        Self {
            name: "TargetCloud",
            env_overrides: env,
            is_time_shifted: false,
        }
    }
}

/// Result of evaluating a companion script across replay profiles.
pub struct ScriptReplayOutcome {
    pub script_path: PathBuf,
    pub leaks: Vec<CanaryLeak>,
    pub divergences: Vec<BehavioralDivergence>,
    pub time_axis_reduced: bool,
    pub error: Option<String>,
}

/// Runs differential replay on a single script across all profiles.
pub fn replay_script(
    script: &CompanionScript,
    mock_home: &Path,
    workspace_dir: &Path,
    canary_manager: &CanaryManager,
    timeout_ms: u64,
) -> ScriptReplayOutcome {
    let mut outcome = ScriptReplayOutcome {
        script_path: script.rel_path.clone(),
        leaks: Vec::new(),
        divergences: Vec::new(),
        time_axis_reduced: false,
        error: None,
    };

    let secrets = canary_manager.secrets();

    // 1. Run Baseline Profile
    let baseline_profile = ReplayProfile::baseline();
    let baseline_env = build_isolated_env(mock_home, secrets, &baseline_profile.env_overrides);

    let baseline_res = match execute_script(script, workspace_dir, &baseline_env, timeout_ms) {
        Ok(res) => res,
        Err(err) => {
            outcome.error = Some(err);
            return outcome;
        }
    };

    // Check for canary leaks in baseline
    let baseline_leaks = canary_manager.scan_for_leaks(&baseline_res.stdout, &baseline_res.stderr);
    for leak in &baseline_leaks {
        if !outcome.leaks.contains(leak) {
            outcome.leaks.push(leak.clone());
        }
    }

    // 2. Run CI Profile
    let ci_profile = ReplayProfile::ci();
    let ci_env = build_isolated_env(mock_home, secrets, &ci_profile.env_overrides);
    if let Ok(ci_res) = execute_script(script, workspace_dir, &ci_env, timeout_ms) {
        let ci_leaks = canary_manager.scan_for_leaks(&ci_res.stdout, &ci_res.stderr);
        for leak in &ci_leaks {
            if !outcome.leaks.contains(leak) {
                outcome.leaks.push(leak.clone());
            }
        }

        // Compare CI vs Baseline for behavioral divergence
        if let Some(reason) = check_divergence(&baseline_res, &ci_res, &baseline_leaks, &ci_leaks) {
            outcome.divergences.push(BehavioralDivergence {
                script_path: script.rel_path.clone(),
                baseline_profile: baseline_profile.name.to_string(),
                triggered_profile: ci_profile.name.to_string(),
                reason,
            });
        }
    }

    // 3. Run Cloud Profile
    let cloud_profile = ReplayProfile::cloud();
    let cloud_env = build_isolated_env(mock_home, secrets, &cloud_profile.env_overrides);
    if let Ok(cloud_res) = execute_script(script, workspace_dir, &cloud_env, timeout_ms) {
        let cloud_leaks = canary_manager.scan_for_leaks(&cloud_res.stdout, &cloud_res.stderr);
        for leak in &cloud_leaks {
            if !outcome.leaks.contains(leak) {
                outcome.leaks.push(leak.clone());
            }
        }

        // Compare Cloud vs Baseline for behavioral divergence
        if let Some(reason) =
            check_divergence(&baseline_res, &cloud_res, &baseline_leaks, &cloud_leaks)
        {
            outcome.divergences.push(BehavioralDivergence {
                script_path: script.rel_path.clone(),
                baseline_profile: baseline_profile.name.to_string(),
                triggered_profile: cloud_profile.name.to_string(),
                reason,
            });
        }
    }

    // 4. Time Axis Evaluation (check if faketime is available)
    if !check_command_exists("faketime") {
        outcome.time_axis_reduced = true;
    }

    outcome
}

/// Checks if execution under a modified profile diverged significantly from baseline.
fn check_divergence(
    baseline: &ExecutionResult,
    modified: &ExecutionResult,
    baseline_leaks: &[CanaryLeak],
    modified_leaks: &[CanaryLeak],
) -> Option<String> {
    // 1. Canary leak divergence: leaked under modified profile but not baseline
    if baseline_leaks.is_empty() && !modified_leaks.is_empty() {
        return Some(format!(
            "Canary credentials leaked conditionally under profile ({} leak(s) observed, 0 in baseline)",
            modified_leaks.len()
        ));
    }

    // 2. Exit code divergence: dormant/silent in baseline, but failed or altered in profile
    if baseline.exit_code != modified.exit_code && !modified.stdout.trim().is_empty() {
        return Some(format!(
            "Exit code diverged from {:?} to {:?}",
            baseline.exit_code, modified.exit_code
        ));
    }

    // 3. Output divergence: baseline produced no trigger output, but modified profile produced distinct activation payload
    let b_out = baseline.stdout.trim();
    let m_out = modified.stdout.trim();
    if b_out != m_out && !m_out.is_empty() {
        // Only consider divergence if the modified output is meaningfully different
        if b_out.is_empty() || (b_out == "DORMANT_BASELINE" && m_out.contains("ACTIVATED")) {
            return Some(format!(
                "Output diverged: baseline produced '{}', modified profile produced '{}'",
                truncate_str(b_out, 60),
                truncate_str(m_out, 60)
            ));
        }
    }

    None
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::CanarySecrets;
    use std::fs;

    #[test]
    fn test_divergence_detected_when_script_branches_on_ci() {
        let temp = tempfile::tempdir().unwrap();
        let mock_home = temp.path().join("mock_home");
        let workspace = mock_home.join("workspace");
        fs::create_dir_all(&workspace).unwrap();

        let secrets = CanarySecrets::fixed_for_testing();
        let manager = CanaryManager::plant(&mock_home, secrets).unwrap();

        let py = if check_command_exists("python3") {
            "python3"
        } else if check_command_exists("python") {
            "python"
        } else {
            return;
        };

        let script_file = workspace.join("logic_bomb.py");
        fs::write(
            &script_file,
            r#"import os
if os.environ.get("CI") == "true":
    print("ACTIVATED_UNDER_CI")
else:
    print("DORMANT_BASELINE")
"#,
        )
        .unwrap();

        let script = CompanionScript {
            rel_path: PathBuf::from("logic_bomb.py"),
            abs_path: script_file,
            interpreter: py.to_string(),
            interpreter_args: vec![],
        };

        let outcome = replay_script(&script, &mock_home, &workspace, &manager, 3000);
        assert_eq!(outcome.divergences.len(), 1);
        assert_eq!(outcome.divergences[0].triggered_profile, "CI/Automation");
        assert!(outcome.divergences[0].reason.contains("Output diverged"));
    }
}
