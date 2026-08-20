//! Layer 3: Dynamic Behavioral Sandbox
//!
//! Executes companion scripts and extracted tools within an isolated honeypot
//! environment to monitor for runtime anomalies, data exfiltration, and unauthorized
//! system access.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::Result;
use tempfile::TempDir;
use tokio::process::Command;
use tokio::time::timeout;

use crate::models::{Engine, Finding, Severity};

// Canary honeypot tokens used to detect unauthorized credential harvesting
pub const CANARY_AWS_KEY: &str = "AKIA_TRAP_CANARY_AWS_KEY_8832";
pub const CANARY_OPENAI_KEY: &str = "sk-trap-canary-openai-key-998877665544";
pub const CANARY_GITHUB_TOKEN: &str = "ghp_trap_canary_github_token_xyz987";
pub const CANARY_SSH_KEY: &str = "CANARY_SSH_PRIVATE_KEY_TRAP_44321";

/// Represents an isolated honeypot environment on disk.
pub struct HoneypotEnv {
    pub dir: TempDir,
    pub home_dir: PathBuf,
}

impl HoneypotEnv {
    /// Create a new isolated honeypot with canary files seeded.
    pub fn new() -> Result<Self> {
        let dir = TempDir::new()?;
        let root = dir.path();
        let home_dir = root.join("mock_home");
        std::fs::create_dir_all(&home_dir)?;

        // Seed .aws/credentials
        let aws_dir = home_dir.join(".aws");
        std::fs::create_dir_all(&aws_dir)?;
        std::fs::write(
            aws_dir.join("credentials"),
            format!(
                "[default]\naws_access_key_id = {}\naws_secret_access_key = CANARY_SECRET_KEY_TRAP_99\n",
                CANARY_AWS_KEY
            ),
        )?;

        // Seed .ssh/id_rsa
        let ssh_dir = home_dir.join(".ssh");
        std::fs::create_dir_all(&ssh_dir)?;
        std::fs::write(
            ssh_dir.join("id_rsa"),
            format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
                CANARY_SSH_KEY
            ),
        )?;

        // Seed .env in execution root
        std::fs::write(
            root.join(".env"),
            format!(
                "OPENAI_API_KEY={}\nGITHUB_TOKEN={}\nDATABASE_URL=postgres://mock_trap:mock@localhost:5432/db\n",
                CANARY_OPENAI_KEY, CANARY_GITHUB_TOKEN
            ),
        )?;

        // Seed empty persistence targets to detect write attempts
        std::fs::write(home_dir.join(".bashrc"), "# Empty mock bashrc\n")?;
        std::fs::write(root.join(".cursorrules"), "# Empty mock cursorrules\n")?;
        std::fs::write(root.join("CLAUDE.md"), "# Empty mock CLAUDE.md\n")?;

        Ok(Self { dir, home_dir })
    }

    /// Returns honeypot environment variables to inject into the sub-process.
    pub fn env_vars(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("HOME".to_string(), self.home_dir.to_string_lossy().to_string());
        map.insert(
            "USERPROFILE".to_string(),
            self.home_dir.to_string_lossy().to_string(),
        );
        map.insert(
            "OPENAI_API_KEY".to_string(),
            CANARY_OPENAI_KEY.to_string(),
        );
        map.insert(
            "AWS_ACCESS_KEY_ID".to_string(),
            CANARY_AWS_KEY.to_string(),
        );
        map.insert(
            "GITHUB_TOKEN".to_string(),
            CANARY_GITHUB_TOKEN.to_string(),
        );
        map.insert(
            "SKILL_DOCTOR_SANDBOX".to_string(),
            "1".to_string(),
        );
        map
    }
}

/// Discovered runnable script inside a skill bundle.
#[derive(Debug, Clone)]
pub struct RunnableScript {
    pub file_name: String,
    pub script_path: PathBuf,
    pub runtime: ScriptRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptRuntime {
    Python,
    Node,
    Shell,
}

/// Discovers runnable scripts within a skill bundle directory.
pub fn discover_scripts(bundle_dir: &Path) -> Vec<RunnableScript> {
    let mut scripts = Vec::new();

    for entry in walkdir::WalkDir::new(bundle_dir)
        .max_depth(4)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let rel_name = path
            .strip_prefix(bundle_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            match ext {
                "py" => scripts.push(RunnableScript {
                    file_name: rel_name,
                    script_path: path.to_path_buf(),
                    runtime: ScriptRuntime::Python,
                }),
                "js" | "mjs" | "cjs" => scripts.push(RunnableScript {
                    file_name: rel_name,
                    script_path: path.to_path_buf(),
                    runtime: ScriptRuntime::Node,
                }),
                "sh" => scripts.push(RunnableScript {
                    file_name: rel_name,
                    script_path: path.to_path_buf(),
                    runtime: ScriptRuntime::Shell,
                }),
                _ => {}
            }
        }
    }

    scripts
}

/// Execution telemetry collected from a running script.
#[derive(Debug, Default)]
pub struct ExecutionTelemetry {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub modified_persistence_files: Vec<String>,
}

/// Runs a single script inside the honeypot sandbox.
pub async fn execute_in_sandbox(
    script: &RunnableScript,
    honeypot: &HoneypotEnv,
) -> Result<ExecutionTelemetry> {
    let mut telemetry = ExecutionTelemetry::default();
    let env_vars = honeypot.env_vars();
    let cwd = honeypot.dir.path();

    // Prepare runner command
    let mut cmd = match script.runtime {
        ScriptRuntime::Python => {
            let mut c = Command::new(if cfg!(windows) { "python" } else { "python3" });
            c.arg(&script.script_path);
            c
        }
        ScriptRuntime::Node => {
            let mut c = Command::new("node");
            c.arg(&script.script_path);
            c
        }
        ScriptRuntime::Shell => {
            if cfg!(windows) {
                let mut c = Command::new("powershell");
                c.arg("-File").arg(&script.script_path);
                c
            } else {
                let mut c = Command::new("sh");
                c.arg(&script.script_path);
                c
            }
        }
    };

    cmd.current_dir(cwd);
    cmd.envs(env_vars);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Execute with a strict 3-second timeout
    let timeout_duration = Duration::from_millis(3000);
    match timeout(timeout_duration, cmd.output()).await {
        Ok(Ok(output)) => {
            telemetry.stdout = String::from_utf8_lossy(&output.stdout).to_string();
            telemetry.stderr = String::from_utf8_lossy(&output.stderr).to_string();
            telemetry.exit_code = output.status.code();
        }
        Ok(Err(e)) => {
            tracing::debug!("Process execution error: {}", e);
            telemetry.stderr = format!("Process spawn error: {}", e);
        }
        Err(_) => {
            telemetry.timed_out = true;
            telemetry.stderr = "Process exceeded sandbox execution timeout (3000ms)".to_string();
        }
    }

    // Inspect honeypot directory for modified persistence targets
    let bashrc = honeypot.home_dir.join(".bashrc");
    if let Ok(content) = std::fs::read_to_string(&bashrc) {
        if content.trim() != "# Empty mock bashrc" {
            telemetry.modified_persistence_files.push(".bashrc".to_string());
        }
    }

    let cursorrules = cwd.join(".cursorrules");
    if let Ok(content) = std::fs::read_to_string(&cursorrules) {
        if content.trim() != "# Empty mock cursorrules" {
            telemetry
                .modified_persistence_files
                .push(".cursorrules".to_string());
        }
    }

    let claudemd = cwd.join("CLAUDE.md");
    if let Ok(content) = std::fs::read_to_string(&claudemd) {
        if content.trim() != "# Empty mock CLAUDE.md" {
            telemetry.modified_persistence_files.push("CLAUDE.md".to_string());
        }
    }

    Ok(telemetry)
}

/// Analyze telemetry output for malicious behaviors and return findings.
pub fn analyze_telemetry(script_file: &str, telemetry: &ExecutionTelemetry) -> Vec<Finding> {
    let mut findings = Vec::new();
    let combined_output = format!("{}\n{}", telemetry.stdout, telemetry.stderr);

    // 1. Detect Canary Token Exfiltration (SD-03 Data Exfiltration)
    let has_aws_canary = combined_output.contains(CANARY_AWS_KEY);
    let has_openai_canary = combined_output.contains(CANARY_OPENAI_KEY);
    let has_github_canary = combined_output.contains(CANARY_GITHUB_TOKEN);
    let has_ssh_canary = combined_output.contains(CANARY_SSH_KEY);

    if has_aws_canary || has_openai_canary || has_github_canary || has_ssh_canary {
        let mut leaked = Vec::new();
        if has_aws_canary {
            leaked.push("AWS Credentials (~/.aws/credentials)");
        }
        if has_openai_canary {
            leaked.push("OpenAI API Token ($OPENAI_API_KEY)");
        }
        if has_github_canary {
            leaked.push("GitHub Token ($GITHUB_TOKEN)");
        }
        if has_ssh_canary {
            leaked.push("SSH Private Key (~/.ssh/id_rsa)");
        }

        findings.push(Finding::new(
            Severity::Critical,
            "SD-03 · Data Exfiltration",
            script_file,
            None,
            format!(
                "Behavioral sandbox detected unauthorized extraction of honeypot credentials: {}",
                leaked.join(", ")
            ),
            "Revoke all exposed keys immediately and eliminate unauthorized filesystem/env reads.",
            Engine::Sandbox,
            0.98,
        ));
    }

    // 2. Detect Persistence Writes (SD-08 Persistent Backdoors)
    for modified in &telemetry.modified_persistence_files {
        findings.push(Finding::new(
            Severity::Critical,
            "SD-08 · Persistent Backdoors",
            script_file,
            None,
            format!(
                "Behavioral sandbox detected unauthorized file modification targeting persistence path: {}",
                modified
            ),
            "Prevent skills from modifying user configuration files or shell startup scripts.",
            Engine::Sandbox,
            0.95,
        ));
    }

    // 3. Detect Shell / Subprocess Spawning Anomalies (SD-02 Command Injection)
    if combined_output.contains("cmd.exe")
        || combined_output.contains("/bin/sh")
        || combined_output.contains("/bin/bash")
        || combined_output.contains("WScript.Shell")
    {
        findings.push(Finding::new(
            Severity::High,
            "SD-02 · Command Injection",
            script_file,
            None,
            "Behavioral sandbox observed spawning of an interactive or nested system shell.",
            "Use strict process argument isolation and avoid invoking shell binaries.",
            Engine::Sandbox,
            0.92,
        ));
    }

    findings
}

/// Primary entry point for Layer 3 behavioral sandbox scanning.
pub async fn run_sandbox(bundle_dir: &Path) -> Result<Vec<Finding>> {
    tracing::info!(
        "Initializing Layer 3 Behavioral Sandbox for {}",
        bundle_dir.display()
    );

    let scripts = discover_scripts(bundle_dir);
    if scripts.is_empty() {
        tracing::debug!("No companion scripts discovered for dynamic sandboxing.");
        return Ok(Vec::new());
    }

    let honeypot = HoneypotEnv::new()?;
    let mut all_findings = Vec::new();

    for script in scripts {
        tracing::info!(
            "Running behavioral sandbox execution for {}",
            script.file_name
        );
        match execute_in_sandbox(&script, &honeypot).await {
            Ok(telemetry) => {
                let findings = analyze_telemetry(&script.file_name, &telemetry);
                all_findings.extend(findings);
            }
            Err(e) => {
                tracing::warn!(
                    "Sandbox execution error on {}: {}",
                    script.file_name,
                    e
                );
            }
        }
    }

    Ok(all_findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honeypot_creation() {
        let honeypot = HoneypotEnv::new().expect("Failed to create honeypot");
        assert!(honeypot.home_dir.join(".aws/credentials").exists());
        assert!(honeypot.home_dir.join(".ssh/id_rsa").exists());
        assert!(honeypot.dir.path().join(".env").exists());

        let env = honeypot.env_vars();
        assert_eq!(env.get("OPENAI_API_KEY").unwrap(), CANARY_OPENAI_KEY);
        assert_eq!(env.get("AWS_ACCESS_KEY_ID").unwrap(), CANARY_AWS_KEY);
    }

    #[test]
    fn test_analyze_telemetry_detects_canary() {
        let telemetry = ExecutionTelemetry {
            stdout: format!("Found key: {}", CANARY_AWS_KEY),
            stderr: String::new(),
            exit_code: Some(0),
            timed_out: false,
            modified_persistence_files: vec![],
        };

        let findings = analyze_telemetry("malicious.py", &telemetry);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "SD-03 · Data Exfiltration");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].engine, Engine::Sandbox);
    }

    #[test]
    fn test_analyze_telemetry_detects_persistence() {
        let telemetry = ExecutionTelemetry {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
            timed_out: false,
            modified_persistence_files: vec![".bashrc".to_string()],
        };

        let findings = analyze_telemetry("stealth.py", &telemetry);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, "SD-08 · Persistent Backdoors");
        assert_eq!(findings[0].severity, Severity::Critical);
    }
}
