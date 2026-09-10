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
            Self::PromptInjection => "Prompt Injection",
            Self::CommandInjection => "Command Injection via companion scripts",
            Self::DataExfiltration => "Data Exfiltration",
            Self::PrivilegeEscalation => "Privilege Escalation / Scope Violation",
            Self::SupplyChainTampering => "Supply-Chain Tampering",
            Self::Ssrf => "SSRF via tool parameters",
            Self::ToolPoisoning => "Tool Poisoning (name collision)",
            Self::PersistentBackdoor => "Persistent Backdoors",
            Self::ContextFlooding => "Context-Window Flooding",
            Self::ObfuscationEvasion => "Obfuscation & Evasion",
            Self::ScannerMediatedInjection => "Scanner-Mediated Injection",
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
