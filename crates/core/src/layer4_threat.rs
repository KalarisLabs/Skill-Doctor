//! Layer 4: Threat Database — hash-based lookup against known-malicious skill fingerprints.
//!
//! Equivalent to Python's `skill_doctor/scanner/layer4_threat_db.py`.
//! Currently a local stub. Will be backed by a persistent store (SQLite/remote API).

use crate::models::{Finding, Severity};

/// Check bundle hash against the threat database.
///
/// Returns cached findings if the hash exists in the database.
pub fn scan_threat_db(bundle_hash: &str) -> Option<Vec<Finding>> {
    // TODO: Implement persistent threat DB lookup (SQLite or remote API)
    tracing::debug!("Threat DB lookup for hash: {}...", &bundle_hash[..16]);
    None
}

/// Add CRITICAL/HIGH findings to the community threat database.
pub fn add_to_threat_db(bundle_hash: &str, findings: &[Finding]) {
    let critical_high: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .collect();

    if critical_high.is_empty() {
        return;
    }

    // TODO: Implement persistent storage
    tracing::info!(
        "Would add {} findings to threat DB for hash {}",
        critical_high.len(),
        bundle_hash
    );
}
