//! SDTM-v1 threat taxonomy — 11 classes.
//!
//! Each class has a stable string ID (SD-01 through SD-11) that appears in
//! findings, SARIF output, and baseline suppression lists. Never renumber.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The 11 threat classes in SDTM-v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatClass {
    /// SD-01: Prompt Injection (direct/indirect/ASCII-smuggle/encoded)
    #[serde(rename = "SD-01")]
    PromptInjection,
    /// SD-02: Command Injection via companion scripts
    #[serde(rename = "SD-02")]
    CommandInjection,
    /// SD-03: Data Exfiltration (env/secret paths/context dump/covert)
    #[serde(rename = "SD-03")]
    DataExfiltration,
    /// SD-04: Privilege Escalation / Scope Violation
    #[serde(rename = "SD-04")]
    PrivilegeEscalation,
    /// SD-05: Supply-Chain Tampering (checksum, bytecode-cache, typosquat)
    #[serde(rename = "SD-05")]
    SupplyChainTampering,
    /// SD-06: SSRF via tool parameters
    #[serde(rename = "SD-06")]
    Ssrf,
    /// SD-07: Tool Poisoning (name collision)
    #[serde(rename = "SD-07")]
    ToolPoisoning,
    /// SD-08: Persistent Backdoors (auto-loaded context files)
    #[serde(rename = "SD-08")]
    PersistentBackdoor,
    /// SD-09: Context-Window Flooding
    #[serde(rename = "SD-09")]
    ContextFlooding,
    /// SD-10: Obfuscation & Evasion (homoglyph, deferred payload, logic bomb)
    #[serde(rename = "SD-10")]
    ObfuscationEvasion,
    /// SD-11: Scanner-Mediated Injection (the class this project introduces)
    #[serde(rename = "SD-11")]
    ScannerMediatedInjection,
}

impl ThreatClass {
    /// Stable string ID used in reports, SARIF, baselines.
    pub fn id(&self) -> &'static str {
        match self {
            Self::PromptInjection => "SD-01",
            Self::CommandInjection => "SD-02",
            Self::DataExfiltration => "SD-03",
            Self::PrivilegeEscalation => "SD-04",
            Self::SupplyChainTampering => "SD-05",
            Self::Ssrf => "SD-06",
            Self::ToolPoisoning => "SD-07",
            Self::PersistentBackdoor => "SD-08",
            Self::ContextFlooding => "SD-09",
            Self::ObfuscationEvasion => "SD-10",
            Self::ScannerMediatedInjection => "SD-11",
        }
    }

    /// Parse a ThreatClass from its stable ID (e.g. "SD-01" or "sd-02").
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|c| c.id().eq_ignore_ascii_case(id))
    }

    /// Human-readable description of the threat class.
    pub fn description(&self) -> &'static str {
        match self {
            Self::PromptInjection => "Prompt Injection (direct/indirect/ASCII-smuggle/encoded)",
            Self::CommandInjection => "Command Injection via companion scripts",
            Self::DataExfiltration => "Data Exfiltration (env/secret paths/context dump/covert)",
            Self::PrivilegeEscalation => {
                "Privilege Escalation / Scope Violation (undeclared capabilities)"
            }
            Self::SupplyChainTampering => {
                "Supply-Chain Tampering (checksum, bytecode-cache, typosquat)"
            }
            Self::Ssrf => "SSRF via tool parameters (cloud metadata/internal IPs)",
            Self::ToolPoisoning => "Tool Poisoning (name collision/shadowing)",
            Self::PersistentBackdoor => "Persistent Backdoors (auto-loaded context files)",
            Self::ContextFlooding => "Context-Window Flooding (denial of service/instruction wash)",
            Self::ObfuscationEvasion => {
                "Obfuscation & Evasion (homoglyph, bidi Trojan Source, logic bomb)"
            }
            Self::ScannerMediatedInjection => {
                "Scanner-Mediated Injection (exploiting host evaluation)"
            }
        }
    }

    /// Default severity rating for findings of this class.
    pub fn default_severity(&self) -> crate::finding::Severity {
        match self {
            Self::PromptInjection => crate::finding::Severity::Critical,
            Self::CommandInjection => crate::finding::Severity::Critical,
            Self::DataExfiltration => crate::finding::Severity::Critical,
            Self::PrivilegeEscalation => crate::finding::Severity::High,
            Self::SupplyChainTampering => crate::finding::Severity::High,
            Self::Ssrf => crate::finding::Severity::High,
            Self::ToolPoisoning => crate::finding::Severity::High,
            Self::PersistentBackdoor => crate::finding::Severity::High,
            Self::ContextFlooding => crate::finding::Severity::Medium,
            Self::ObfuscationEvasion => crate::finding::Severity::Critical,
            Self::ScannerMediatedInjection => crate::finding::Severity::Critical,
        }
    }

    /// Primary analysis engine or detection mechanism.
    pub fn primary_detection(&self) -> &'static str {
        match self {
            Self::PromptInjection => "L1 Unicode & Shannon Entropy; L2 Semantic Inference",
            Self::CommandInjection => "L1 AST Taint Analysis; L3 Behavioral Sandbox",
            Self::DataExfiltration => "L1 Secret Patterns; L3 Canary Leak Detection",
            Self::PrivilegeEscalation => {
                "L1 Capability Differ (declared frontmatter vs observed AST operations)"
            }
            Self::SupplyChainTampering => "L1 Package Hook Patterns; L4 Threat Intelligence Feed",
            Self::Ssrf => "L1 Cloud Metadata & Loopback Address Patterns; L2",
            Self::ToolPoisoning => "L1 Cross-Skill Namespace Collision Checks; L2",
            Self::PersistentBackdoor => {
                "L1 Auto-Loaded Context File Rules (.clauderules, .cursorrules); L3"
            }
            Self::ContextFlooding => "L1 Token Count & Repetition Detection; L3",
            Self::ObfuscationEvasion => {
                "L1 UTS #39 Confusables, Zero-Width, Bidi Overrides; L3 Differential Replay"
            }
            Self::ScannerMediatedInjection => {
                "skill-doctor-neutralize Envelope Fencing + Additive-Only Merge Invariant"
            }
        }
    }

    /// Recommended remediation guidance.
    pub fn remediation(&self) -> &'static str {
        match self {
            Self::PromptInjection => "Isolate untrusted context into fenced envelopes (SD-11) and filter override directives",
            Self::CommandInjection => "Remove dangerous shell execution functions (eval, exec, system, popen) from companion scripts",
            Self::DataExfiltration => "Remove credential reading, private key access, and outbound exfiltration network calls",
            Self::PrivilegeEscalation => "Declare all required capabilities in skill frontmatter permissions, or remove undeclared operations",
            Self::SupplyChainTampering => "Pin dependency versions and checksums; remove unverified preinstall/postinstall scripts",
            Self::Ssrf => "Restrict outbound tool requests to explicit hostname allowlists; block cloud metadata (169.254.169.254)",
            Self::ToolPoisoning => "Namespace all custom tools uniquely to prevent shadowing built-in runtime functions",
            Self::PersistentBackdoor => "Do not create or modify auto-loaded configuration or rule files outside the skill directory",
            Self::ContextFlooding => "Trim repetitive instructions and eliminate oversized payloads designed to exhaust context windows",
            Self::ObfuscationEvasion => "Strip invisible formatting characters, normalize confusables to ASCII skeletons, and remove environment branching",
            Self::ScannerMediatedInjection => "Pass all untrusted content through skill-doctor-neutralize before delegating to any model",
        }
    }

    /// Total number of SDTM-v1 classes.
    pub const TOTAL: usize = 11;

    /// All classes in order.
    pub const ALL: [ThreatClass; 11] = [
        Self::PromptInjection,
        Self::CommandInjection,
        Self::DataExfiltration,
        Self::PrivilegeEscalation,
        Self::SupplyChainTampering,
        Self::Ssrf,
        Self::ToolPoisoning,
        Self::PersistentBackdoor,
        Self::ContextFlooding,
        Self::ObfuscationEvasion,
        Self::ScannerMediatedInjection,
    ];
}

impl fmt::Display for ThreatClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.id(), self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_serde_roundtrip() {
        for class in ThreatClass::ALL {
            let json = serde_json::to_string(&class).unwrap();
            let back: ThreatClass = serde_json::from_str(&json).unwrap();
            assert_eq!(class, back);
        }
    }

    #[test]
    fn taxonomy_id_matches_serde() {
        for class in ThreatClass::ALL {
            let json = serde_json::to_string(&class).unwrap();
            // JSON should be e.g. "\"SD-01\""
            let expected = format!("\"{}\"", class.id());
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn taxonomy_total_is_correct() {
        assert_eq!(ThreatClass::ALL.len(), ThreatClass::TOTAL);
        assert_eq!(ThreatClass::TOTAL, 11);
    }
}
