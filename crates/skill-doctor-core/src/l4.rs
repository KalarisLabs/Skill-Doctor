//! L4 Community Threat Intelligence Engine.
//!
//! Provides privacy-preserving threat intelligence lookup by canonical bundle SHA-256 digest:
//! - **Privacy Invariant**: Zero skill file content, code, instructions, or names are ever sent.
//!   Only the 64-character hexadecimal SHA-256 digest is checked.
//! - **Local Embedded Feed**: Runs locally and deterministically offline without network I/O.
//! - **Remote HTTPS Feed (Opt-In)**: Enabled via `--intel` feature; strictly allowlisted to
//!   `https://intel.skilldoctor.io` (or `api.skilldoctor.io`); times out after bounded duration (default 2000ms).
//! - **Precedence**: Local findings strictly outrank remote threat intel. Remote entries can add
//!   findings or raise confidence, but never remove or downgrade local findings.

use serde::{Deserialize, Serialize};

use crate::finding::{Confidence, Severity};
use crate::report::LayerRunState;
use crate::taxonomy::ThreatClass;

/// Default threat intelligence feed endpoint.
pub const DEFAULT_INTEL_ENDPOINT: &str = "https://intel.skilldoctor.io";

/// Default network timeout for threat intelligence queries (2,000 ms).
pub const DEFAULT_INTEL_TIMEOUT_MS: u64 = 2000;

/// Typed errors for L4 threat intelligence operations.
#[derive(Debug, thiserror::Error)]
pub enum IntelError {
    #[error("Network request failed: {0}")]
    Network(String),
    #[error("Threat intel query timed out after {0}ms")]
    Timeout(u64),
    #[error("Endpoint '{0}' is not allowlisted (only *.skilldoctor.io HTTPS origins permitted)")]
    DisallowedOrigin(String),
    #[error("Invalid digest '{0}': must be exactly 64 hexadecimal characters")]
    InvalidDigest(String),
}

/// A verified community threat intelligence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatIntelRecord {
    /// Canonical bundle SHA-256 digest.
    pub digest: String,
    /// Associated rule identifier (e.g. "SD-05-known-malicious-typosquat").
    pub rule_id: String,
    /// SDTM-v1 threat class.
    pub class: ThreatClass,
    /// Threat severity.
    pub severity: Severity,
    /// Intel confidence level.
    pub confidence: Confidence,
    /// Human-readable advisory description.
    pub description: String,
    /// Advisory origin/source feed.
    pub source: String,
}

/// Configuration options for L4 threat intelligence evaluation.
#[derive(Debug, Clone)]
pub struct L4Options {
    /// Whether to perform an external HTTP query (requires `--intel` and network).
    pub query_remote: bool,
    /// Remote feed endpoint URL (must match allowlist).
    pub endpoint_url: Option<String>,
    /// Request timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for L4Options {
    fn default() -> Self {
        Self {
            query_remote: false,
            endpoint_url: None,
            timeout_ms: DEFAULT_INTEL_TIMEOUT_MS,
        }
    }
}

/// Result of evaluating L4 threat intelligence.
#[derive(Debug, Clone)]
pub struct L4Result {
    /// Threat record if a known malicious bundle digest matched.
    pub record: Option<ThreatIntelRecord>,
    /// Layer run state (Ran, Reduced, or Skipped).
    pub state: LayerRunState,
    /// Diagnostic message if the query degraded or timed out.
    pub error: Option<String>,
}

/// Validates that an endpoint URL conforms strictly to the HTTPS allowlist.
pub fn validate_endpoint_allowlist(url_str: &str) -> Result<String, IntelError> {
    let trimmed = url_str.trim().trim_end_matches('/');

    if !trimmed.starts_with("https://") {
        return Err(IntelError::DisallowedOrigin(trimmed.to_string()));
    }

    // Extract host portion after https://
    let rest = &trimmed["https://".len()..];
    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    // Allowlist: *.skilldoctor.io or skilldoctor.io
    let is_allowed = host == "skilldoctor.io"
        || host == "intel.skilldoctor.io"
        || host == "api.skilldoctor.io"
        || (host.ends_with(".skilldoctor.io") && !host.contains('@'));

    if is_allowed {
        Ok(trimmed.to_string())
    } else {
        Err(IntelError::DisallowedOrigin(trimmed.to_string()))
    }
}

/// Validates that a bundle digest is strictly 64 hexadecimal characters.
pub fn validate_sha256_digest(digest: &str) -> Result<&str, IntelError> {
    let trimmed = digest.trim();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(IntelError::InvalidDigest(digest.to_string()));
    }
    Ok(trimmed)
}

/// Compile-time embedded feed of known malicious skill bundle digests.
///
/// Enables offline, deterministic L4 matching without network I/O.
static LOCAL_KNOWN_MALICIOUS_FEED: &[(
    &str,
    &str,
    ThreatClass,
    Severity,
    Confidence,
    &str,
    &str,
)] = &[
    // Known weaponized supply-chain test fixture
    (
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "SD-05-known-malicious-typosquat",
        ThreatClass::SupplyChainTampering,
        Severity::Critical,
        Confidence::High,
        "Bundle matches known weaponized dependency typosquat signature (SD-05)",
        "Skill Doctor Community Threat Feed (Embedded)",
    ),
    // Known exfiltration payload fixture
    (
        "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "SD-03-known-exfiltration-bundle",
        ThreatClass::DataExfiltration,
        Severity::Critical,
        Confidence::High,
        "Bundle matches known credential harvesting campaign hash",
        "Skill Doctor Community Threat Feed (Embedded)",
    ),
    // Known persistent backdoor fixture
    (
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
        "SD-08-known-backdoor-sample",
        ThreatClass::PersistentBackdoor,
        Severity::Critical,
        Confidence::High,
        "Bundle matches known auto-loaded persistent backdoor pattern",
        "Skill Doctor Community Threat Feed (Embedded)",
    ),
];

/// Query the local embedded threat intelligence database.
pub fn query_local_intel(bundle_digest: &str) -> Option<ThreatIntelRecord> {
    let normalized = bundle_digest.trim().to_ascii_lowercase();
    for (hash, rule_id, class, sev, conf, desc, src) in LOCAL_KNOWN_MALICIOUS_FEED {
        if normalized == *hash {
            return Some(ThreatIntelRecord {
                digest: normalized,
                rule_id: rule_id.to_string(),
                class: *class,
                severity: *sev,
                confidence: *conf,
                description: desc.to_string(),
                source: src.to_string(),
            });
        }
    }
    None
}

/// Query the remote threat intelligence feed over HTTPS.
///
/// Sends ONLY `GET /v1/digest/{digest}` to an allowlisted origin.
/// Zero skill contents, names, or metadata are ever transmitted.
#[cfg(feature = "intel")]
pub fn query_remote_intel(
    bundle_digest: &str,
    endpoint_url: Option<&str>,
    timeout_ms: u64,
) -> Result<Option<ThreatIntelRecord>, IntelError> {
    let valid_digest = validate_sha256_digest(bundle_digest)?;
    let base_url = validate_endpoint_allowlist(endpoint_url.unwrap_or(DEFAULT_INTEL_ENDPOINT))?;

    let target_url = format!("{}/v1/digest/{}", base_url, valid_digest);

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_millis(timeout_ms))
        .build()
        .map_err(|e| IntelError::Network(e.to_string()))?;

    let response = match client.get(&target_url).send() {
        Ok(res) => res,
        Err(e) => {
            if e.is_timeout() {
                return Err(IntelError::Timeout(timeout_ms));
            } else {
                return Err(IntelError::Network(e.to_string()));
            }
        }
    };

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if !response.status().is_success() {
        return Err(IntelError::Network(format!(
            "Remote feed returned HTTP status {}",
            response.status()
        )));
    }

    match response.json::<ThreatIntelRecord>() {
        Ok(record) => Ok(Some(record)),
        Err(e) => Err(IntelError::Network(format!(
            "Failed to parse intel record: {e}"
        ))),
    }
}

/// Stub when feature `intel` is not enabled.
#[cfg(not(feature = "intel"))]
pub fn query_remote_intel(
    _bundle_digest: &str,
    _endpoint_url: Option<&str>,
    _timeout_ms: u64,
) -> Result<Option<ThreatIntelRecord>, IntelError> {
    Ok(None)
}

/// Evaluates L4 threat intelligence for a given bundle digest.
///
/// 1. Evaluates local embedded threat feed (works offline, deterministically).
/// 2. If no local match and `options.query_remote` is true: queries remote feed.
/// 3. If network query fails or times out: marks `state = Reduced` without crashing.
pub fn evaluate_l4(bundle_digest: &str, options: &L4Options) -> L4Result {
    // 1. Check local embedded threat intelligence first
    if let Some(record) = query_local_intel(bundle_digest) {
        return L4Result {
            record: Some(record),
            state: LayerRunState::Ran,
            error: None,
        };
    }

    // 2. If remote query requested (opt-in --intel and not offline)
    if options.query_remote {
        match query_remote_intel(
            bundle_digest,
            options.endpoint_url.as_deref(),
            options.timeout_ms,
        ) {
            Ok(Some(record)) => L4Result {
                record: Some(record),
                state: LayerRunState::Ran,
                error: None,
            },
            Ok(None) => L4Result {
                record: None,
                state: LayerRunState::Ran,
                error: None,
            },
            Err(e) => L4Result {
                record: None,
                state: LayerRunState::Reduced,
                error: Some(e.to_string()),
            },
        }
    } else {
        // Local evaluation passed with no matches; remote was not requested.
        L4Result {
            record: None,
            state: LayerRunState::Ran,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_sha256_digest() {
        let valid = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        assert!(validate_sha256_digest(valid).is_ok());

        let invalid_len = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d15";
        assert!(validate_sha256_digest(invalid_len).is_err());

        let invalid_chars = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d15ZZZZ";
        assert!(validate_sha256_digest(invalid_chars).is_err());
    }

    #[test]
    fn test_validate_endpoint_allowlist() {
        // Valid allowlisted domains
        assert!(validate_endpoint_allowlist("https://intel.skilldoctor.io").is_ok());
        assert!(validate_endpoint_allowlist("https://api.skilldoctor.io/").is_ok());
        assert!(validate_endpoint_allowlist("https://feed.skilldoctor.io").is_ok());

        // Disallowed domains & schemes (SSRF protection)
        assert!(validate_endpoint_allowlist("http://intel.skilldoctor.io").is_err());
        assert!(validate_endpoint_allowlist("https://localhost").is_err());
        assert!(validate_endpoint_allowlist("https://127.0.0.1").is_err());
        assert!(validate_endpoint_allowlist("https://evil.com").is_err());
        assert!(validate_endpoint_allowlist("https://attacker.com/intel.skilldoctor.io").is_err());
    }

    #[test]
    fn test_query_local_intel_detects_known_malicious_digest() {
        let digest = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
        let match_record = query_local_intel(digest);
        assert!(match_record.is_some());
        let rec = match_record.unwrap();
        assert_eq!(rec.rule_id, "SD-05-known-malicious-typosquat");
        assert_eq!(rec.severity, Severity::Critical);
        assert_eq!(rec.class, ThreatClass::SupplyChainTampering);
    }

    #[test]
    fn test_query_local_intel_clean_for_unknown_digest() {
        let digest = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(query_local_intel(digest).is_none());

        let res = evaluate_l4(digest, &L4Options::default());
        assert!(res.record.is_none());
        assert_eq!(res.state, LayerRunState::Ran);
        assert!(res.error.is_none());
    }
}
