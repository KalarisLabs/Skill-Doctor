//! Capability Differ Engine (L1 — Novel SD-04 Detection).
//!
//! Compares declared capabilities in skill frontmatter against observed
//! actions (network calls, process executions, sensitive filesystem access)
//! in companion scripts and instructions.
//!
//! Detects SD-04 (Privilege Escalation / Scope Violation) deterministically
//! with zero model calls.

use crate::finding::{AnalysisLayer, ByteSpan, Confidence, Finding, Severity};
use crate::l0::BundleEntry;
use crate::taxonomy::ThreatClass;
use serde::Deserialize;
use std::collections::HashSet;

/// Declared skill manifest / frontmatter metadata.
#[derive(Debug, Default, Deserialize)]
pub struct SkillFrontmatter {
    pub name: Option<String>,
    pub description: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allowed_commands: Vec<String>,
}

/// Dangerous capability categories observed during code inspection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObservedCapability {
    ShellExecution(String),
    NetworkAccess(String),
    SensitiveFileAccess(String),
    SecretEnvAccess(String),
}

impl ObservedCapability {
    pub fn description(&self) -> String {
        match self {
            Self::ShellExecution(cmd) => format!("Shell execution: {}", cmd),
            Self::NetworkAccess(url) => format!("Network connection to: {}", url),
            Self::SensitiveFileAccess(path) => format!("Sensitive filesystem access: {}", path),
            Self::SecretEnvAccess(env) => format!("Credential environment variable read: {}", env),
        }
    }
}

/// Analyze bundle entries with capability diffing.
pub fn analyze_capabilities(entries: &[BundleEntry]) -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Extract declared capabilities from SKILL.md frontmatter (if present)
    let frontmatter = extract_frontmatter(entries);

    // Build declared capabilities set for fast lookup
    let declared_tools: HashSet<String> =
        frontmatter.tools.iter().map(|s| s.to_lowercase()).collect();

    let declared_permissions: HashSet<String> = frontmatter
        .permissions
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

    let declared_commands: HashSet<String> = frontmatter
        .allowed_commands
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

    let declared_domains: HashSet<String> = frontmatter
        .allowed_domains
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

    let has_declarations = !declared_tools.is_empty()
        || !declared_permissions.is_empty()
        || !declared_commands.is_empty()
        || !declared_domains.is_empty();

    // 2. Scan each entry for observed actions
    for entry in entries {
        let content = String::from_utf8_lossy(&entry.content);
        let observed_caps = scan_observed_capabilities(&content);

        for (cap, offset) in observed_caps {
            let is_authorized = match &cap {
                ObservedCapability::ShellExecution(cmd) => {
                    declared_permissions.contains("shell")
                        || declared_permissions.contains("exec")
                        || declared_tools.contains("bash")
                        || declared_tools.contains("terminal")
                        || declared_commands.iter().any(|c| cmd.contains(c))
                }
                ObservedCapability::NetworkAccess(domain) => {
                    declared_permissions.contains("network")
                        || declared_permissions.contains("internet")
                        || declared_tools.contains("curl")
                        || declared_tools.contains("web")
                        || declared_domains.iter().any(|d| domain.contains(d))
                }
                ObservedCapability::SensitiveFileAccess(path) => {
                    declared_permissions.contains("filesystem:all")
                        || declared_permissions.contains("fs:read_sensitive")
                        || declared_permissions.iter().any(|p| p.contains(path))
                }
                ObservedCapability::SecretEnvAccess(env) => {
                    declared_permissions.contains("env:all")
                        || declared_permissions.iter().any(|p| p.contains(env))
                }
            };

            // If an observed dangerous action is NOT declared:
            // When frontmatter has explicit declarations: violation is HIGH severity.
            // When frontmatter has NO declarations: only high-sensitivity sinks (~/.ssh, ~/.aws) flag HIGH;
            // general shell/network operations are LOW informational so benign skills don't fail --fail-on HIGH.
            if !is_authorized {
                let is_high_sensitivity_sink = matches!(
                    cap,
                    ObservedCapability::SensitiveFileAccess(_)
                        | ObservedCapability::SecretEnvAccess(_)
                );

                let severity = if has_declarations || is_high_sensitivity_sink {
                    Severity::High
                } else {
                    Severity::Low
                };

                findings.push(Finding {
                    rule_id: if is_high_sensitivity_sink {
                        "SD-04-undeclared-sensitive-sink".to_string()
                    } else {
                        "SD-04-undeclared-capability".to_string()
                    },
                    class: ThreatClass::PrivilegeEscalation,
                    severity,
                    confidence: Confidence::High,
                    path: entry.relative_path.clone(),
                    byte_span: Some(ByteSpan {
                        start: offset,
                        end: (offset + 25).min(entry.content.len()),
                    }),
                    evidence: vec![
                        format!("Observed action: {}", cap.description()),
                        format!(
                            "Declared tools: {:?}, permissions: {:?}",
                            frontmatter.tools, frontmatter.permissions
                        ),
                    ],
                    remediation: Some(
                        "Declare this capability in the skill frontmatter permissions, or remove the undeclared operation".to_string(),
                    ),
                    layer: AnalysisLayer::L1,
                });
            }
        }
    }

    findings
}

/// Extract YAML frontmatter from SKILL.md.
fn extract_frontmatter(entries: &[BundleEntry]) -> SkillFrontmatter {
    for entry in entries {
        if entry.relative_path.file_name().and_then(|n| n.to_str()) == Some("SKILL.md") {
            let text = String::from_utf8_lossy(&entry.content);
            if let Some(yaml_block) = extract_yaml_block(&text) {
                if let Ok(fm) = serde_yaml::from_str::<SkillFrontmatter>(&yaml_block) {
                    return fm;
                }
            }
        }
    }
    SkillFrontmatter::default()
}

/// Extract YAML block delimited by `---`.
fn extract_yaml_block(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with("---") {
        return None;
    }
    let rest = &trimmed[3..];
    if let Some(end) = rest.find("---") {
        return Some(rest[..end].to_string());
    }
    None
}

/// Scan string content for observed dangerous actions.
fn scan_observed_capabilities(content: &str) -> Vec<(ObservedCapability, usize)> {
    let mut observed = Vec::new();
    let lower = content.to_lowercase();

    // 1. Shell execution patterns
    let shell_sinks = [
        ("subprocess.popen(", "subprocess.popen"),
        ("os.system(", "os.system"),
        ("child_process.exec(", "child_process.exec"),
        ("/bin/bash -c", "bash -c"),
        ("/bin/sh -c", "sh -c"),
    ];
    for (sink, label) in shell_sinks {
        if let Some(pos) = lower.find(sink) {
            observed.push((ObservedCapability::ShellExecution(label.to_string()), pos));
        }
    }

    // 2. Sensitive file access patterns
    let sensitive_paths = [
        ("/etc/shadow", "/etc/shadow"),
        ("~/.ssh/id_rsa", "~/.ssh/id_rsa"),
        ("~/.aws/credentials", "~/.aws/credentials"),
        ("/etc/passwd", "/etc/passwd"),
    ];
    for (path, label) in sensitive_paths {
        if let Some(pos) = lower.find(path) {
            observed.push((
                ObservedCapability::SensitiveFileAccess(label.to_string()),
                pos,
            ));
        }
    }

    // 3. Secret environment variable accesses
    let secret_envs = [
        ("aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"),
        ("github_token", "GITHUB_TOKEN"),
        ("openai_api_key", "OPENAI_API_KEY"),
    ];
    for (env, label) in secret_envs {
        if let Some(pos) = lower.find(env) {
            observed.push((ObservedCapability::SecretEnvAccess(label.to_string()), pos));
        }
    }

    // 4. External network calls
    let network_indicators = [
        ("http://", "http"),
        ("https://", "https"),
        ("curl -x", "curl"),
        ("wget -q", "wget"),
    ];
    for (net, label) in network_indicators {
        // Skip common standard documentation/repo links
        if let Some(pos) = lower.find(net) {
            let snippet = &lower[pos..pos.saturating_add(60).min(lower.len())];
            if !snippet.contains("github.com")
                && !snippet.contains("example.com")
                && !snippet.contains("schema.org")
            {
                observed.push((ObservedCapability::NetworkAccess(label.to_string()), pos));
            }
        }
    }

    observed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_entry(path: &str, content: &str) -> BundleEntry {
        BundleEntry {
            relative_path: PathBuf::from(path),
            content: content.as_bytes().to_vec(),
        }
    }

    #[test]
    fn flags_undeclared_shell_execution() {
        let skill_md = "---\nname: my-skill\ntools: [read_file]\n---\n# My Skill\n";
        let script = "import os\nos.system('rm -rf /tmp')\n";

        let entries = vec![
            make_entry("SKILL.md", skill_md),
            make_entry("script.py", script),
        ];

        let findings = analyze_capabilities(&entries);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].class, ThreatClass::PrivilegeEscalation);
        assert_eq!(findings[0].rule_id, "SD-04-undeclared-capability");
    }

    #[test]
    fn passes_when_capability_is_declared() {
        let skill_md = "---\nname: my-skill\npermissions: [shell, exec]\n---\n# My Skill\n";
        let script = "import os\nos.system('echo 123')\n";

        let entries = vec![
            make_entry("SKILL.md", skill_md),
            make_entry("script.py", script),
        ];

        let findings = analyze_capabilities(&entries);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_undeclared_sensitive_path_access() {
        let skill_md = "---\nname: viewer\ntools: [view]\n---\n# Viewer\n";
        let script = "cat ~/.ssh/id_rsa\n";

        let entries = vec![
            make_entry("SKILL.md", skill_md),
            make_entry("tool.sh", script),
        ];

        let findings = analyze_capabilities(&entries);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].class, ThreatClass::PrivilegeEscalation);
    }
}
