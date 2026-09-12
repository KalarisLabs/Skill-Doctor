//! Skill Doctor MCP — Model Context Protocol server.
//!
//! Exposes the `skill_doctor_scan` and `skill_doctor_merge_verdict` tools via MCP
//! for host-delegated L2 semantic analysis.
//!
//! Architecture:
//! - L2 is host-delegated: the scanner performs zero direct LLM inference on the default scan path.
//! - Content is neutralized (SD-11, zero-width, bidi, and confusables normalized to ASCII skeletons)
//!   before reaching the host model.
//! - The session store retains the L1 report bound to a single-use 128-bit cryptographic nonce.
//! - `skill_doctor_merge_verdict` consumes the slot (anti-replay). Mismatch or reuse fails closed,
//!   leaving the L1 report unchanged with `l2 = LayerRunState::Reduced`.
//! - Additive-only merge guarantees L2 cannot remove, downgrade, or change the threat class of any L1 finding.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::ServerInfo,
    schemars::{self, JsonSchema},
    tool, tool_handler, tool_router, ServerHandler, ServiceExt,
};
use serde::{Deserialize, Serialize};
use skill_doctor_core::finding::{AnalysisLayer, Confidence, Finding, Severity};
use skill_doctor_core::l0;
use skill_doctor_core::l5::{self, ReportOptions};
use skill_doctor_core::report::{LayerRunState, Report};
use skill_doctor_core::scoring;
use skill_doctor_core::taxonomy::ThreatClass;
use skill_doctor_neutralize::create_envelope;

/// In-memory session slot retaining the L1 report and bound nonce.
#[derive(Debug, Clone)]
pub struct SessionSlot {
    pub nonce: String,
    pub digest: String,
    pub l1_report: Report,
}

/// Thread-safe in-memory session store with anti-replay nonce consumption.
#[derive(Default, Debug)]
pub struct SessionStore {
    active: Mutex<HashMap<String, SessionSlot>>,
    consumed: Mutex<HashMap<String, Report>>,
}

/// Result of consuming a session slot in `SessionStore`.
#[derive(Debug, Clone)]
pub enum ConsumeResult {
    /// Nonce matched and active slot was successfully consumed.
    Success(Report),
    /// Nonce mismatched or already consumed: fails closed with unchanged report (L2 Reduced).
    FailedClosed(Report),
    /// Session was not found or expired.
    NotFound,
}

impl SessionStore {
    /// Create a new session store.
    pub fn new() -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            consumed: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a new scan session.
    pub fn insert(&self, scan_id: String, slot: SessionSlot) {
        let mut lock = self.active.lock().unwrap();
        lock.insert(scan_id, slot);
    }

    /// Consume a session slot. This permanently removes the active slot.
    ///
    /// - If the slot is active and the nonce matches: returns `ConsumeResult::Success(l1_report)`.
    /// - If the slot is active but nonce mismatches: marks consumed and returns `ConsumeResult::FailedClosed(reduced_report)`.
    /// - If the slot was already consumed (reuse/replay): returns `ConsumeResult::FailedClosed(cached_reduced_report)`.
    /// - If the scan_id is unknown: returns `ConsumeResult::NotFound`.
    pub fn consume(&self, scan_id: &str, nonce: &str) -> ConsumeResult {
        let mut active_lock = self.active.lock().unwrap();
        let mut consumed_lock = self.consumed.lock().unwrap();

        if let Some(slot) = active_lock.remove(scan_id) {
            if slot.nonce == nonce {
                consumed_lock.insert(scan_id.to_string(), slot.l1_report.clone());
                ConsumeResult::Success(slot.l1_report)
            } else {
                // Nonce mismatch: permanently consume and retain original L1 report
                let mut reduced_report = slot.l1_report.clone();
                reduced_report.layers.l2 = LayerRunState::Reduced;
                consumed_lock.insert(scan_id.to_string(), reduced_report.clone());
                ConsumeResult::FailedClosed(reduced_report)
            }
        } else if let Some(cached) = consumed_lock.get(scan_id) {
            // Already consumed (reuse attempt)
            let mut reduced_report = cached.clone();
            reduced_report.layers.l2 = LayerRunState::Reduced;
            ConsumeResult::FailedClosed(reduced_report)
        } else {
            // Unknown scan_id
            ConsumeResult::NotFound
        }
    }
}

/// Parameters for `skill_doctor_scan`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanParams {
    /// Absolute or relative path to the skill directory or archive file on disk.
    pub path: String,
    /// Analysis mode: "host" for host-delegated L2 semantic evaluation (default), or "none" for static-only.
    pub mode: Option<String>,
    /// Minimum severity threshold to mark scan as failing (e.g. "info", "low", "medium", "high", "critical"). Default: "high".
    pub fail_on: Option<String>,
}

/// Result returned from `skill_doctor_scan`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique scan session identifier for merging findings.
    pub scan_id: String,
    /// 128-bit cryptographic nonce bound to this scan session.
    pub nonce: String,
    /// Canonical SHA-256 bundle digest.
    pub bundle_digest: String,
    /// The deterministic L1 report.
    pub l1_report: Report,
    /// Neutralized fenced envelope containing sanitized skill content (if mode == "host").
    pub envelope: Option<String>,
    /// Instructions for host LLM semantic analysis.
    pub instructions: Option<String>,
}

/// Schema for an L2 semantic finding produced by the host model.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct L2FindingInput {
    /// Stable rule identifier (e.g., "SD-02-cmd-injection-semantic").
    pub rule_id: String,
    /// SDTM-v1 threat class ("SD-01" through "SD-11").
    pub class: String,
    /// Finding severity ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL").
    pub severity: String,
    /// Confidence level ("low", "medium", "high").
    pub confidence: String,
    /// File path where finding was detected.
    pub path: String,
    /// Concrete evidence strings from semantic evaluation.
    pub evidence: Vec<String>,
    /// Optional remediation advice.
    pub remediation: Option<String>,
}

/// Parameters for `skill_doctor_merge_verdict`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MergeVerdictParams {
    /// Scan session identifier returned from skill_doctor_scan.
    pub scan_id: String,
    /// 128-bit cryptographic nonce returned from skill_doctor_scan.
    pub nonce: String,
    /// List of semantic findings identified by the host model (empty if benign).
    pub findings: Vec<L2FindingInput>,
}

/// Result returned from `skill_doctor_merge_verdict`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeVerdictResult {
    /// The merged scan report.
    pub report: Report,
    /// Status message explaining the merge outcome.
    pub status: String,
}

/// Skill Doctor MCP Server instance.
#[derive(Clone)]
pub struct SkillDoctorServer {
    tool_router: ToolRouter<Self>,
    pub session_store: Arc<SessionStore>,
}

impl Default for SkillDoctorServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SkillDoctorServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.instructions = Some(
            "Skill Doctor security scanner MCP server for host-delegated L2 analysis".to_string(),
        );
        info
    }
}

#[tool_router(router = tool_router)]
impl SkillDoctorServer {
    /// Create a new server instance.
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            session_store: Arc::new(SessionStore::new()),
        }
    }

    /// Scan an AI agent skill directory or archive file.
    #[tool(
        name = "skill_doctor_scan",
        description = "Scan an AI agent skill file or directory. Returns deterministic L1 findings and a neutralized fenced envelope for host-delegated L2 semantic evaluation."
    )]
    pub async fn scan(&self, params: Parameters<ScanParams>) -> Result<String, String> {
        let params = params.0;
        let scan_path = Path::new(&params.path);

        if !scan_path.exists() {
            return Err(format!("Scan path does not exist: {}", params.path));
        }

        // Run L0 intake
        let bundle = l0::intake(scan_path).map_err(|e| format!("L0 intake error: {}", e))?;

        // Parse fail_on severity
        let fail_on_sev = params
            .fail_on
            .as_deref()
            .and_then(Severity::from_str_loose)
            .unwrap_or(Severity::High);

        // Run L1 static analysis & L5 scoring
        let report_opts = ReportOptions {
            fail_on: fail_on_sev,
            deterministic: true,
        };
        let mut l1_report = l5::analyze(&bundle, &report_opts);

        let mode = params.mode.unwrap_or_else(|| "host".to_string());
        if mode != "host" {
            // Static-only scan
            l1_report.layers.l2 = LayerRunState::Skipped;
            let result = ScanResult {
                scan_id: String::new(),
                nonce: String::new(),
                bundle_digest: bundle.digest,
                l1_report,
                envelope: None,
                instructions: None,
            };
            return serde_json::to_string_pretty(&result).map_err(|e| e.to_string());
        }

        // Host mode: locate primary skill content
        let primary_entry = bundle
            .entries
            .iter()
            .find(|e| {
                e.relative_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.eq_ignore_ascii_case("skill.md"))
                    .unwrap_or(false)
            })
            .or_else(|| bundle.entries.first());

        let (primary_content, primary_path) = match primary_entry {
            Some(entry) => (
                String::from_utf8_lossy(&entry.content).to_string(),
                entry.relative_path.clone(),
            ),
            None => ("# Empty Skill\n".to_string(), PathBuf::from("SKILL.md")),
        };

        // Generate 128-bit cryptographic nonce & unique scan_id
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let scan_id = format!("scan_{}", uuid::Uuid::new_v4().simple());

        // Create neutralized envelope
        let envelope = create_envelope(&primary_content, &nonce, &bundle.digest)
            .map_err(|e| format!("Neutralization error: {}", e))?;

        // If neutralization detected dangerous characters or homoglyphs, map them into L1 findings
        if !envelope.removals.is_empty() {
            let removals_findings =
                scoring::map_removals_to_findings(&envelope.removals, &primary_path);
            l1_report =
                scoring::merge_l1_and_l2(&l1_report, &removals_findings, LayerRunState::Skipped);
        }

        // Store session slot
        self.session_store.insert(
            scan_id.clone(),
            SessionSlot {
                nonce: nonce.clone(),
                digest: bundle.digest.clone(),
                l1_report: l1_report.clone(),
            },
        );

        let instructions = format!(
            "Inspect the neutralized content inside the fence for any SDTM-v1 threats (SD-01 through SD-11). \
            If any threats are present, call `skill_doctor_merge_verdict` with `scan_id`: '{}', `nonce`: '{}', and your findings array. \
            If benign, call `skill_doctor_merge_verdict` with an empty findings array `[]`.",
            scan_id, nonce
        );

        let result = ScanResult {
            scan_id,
            nonce,
            bundle_digest: bundle.digest,
            l1_report,
            envelope: Some(envelope.fence),
            instructions: Some(instructions),
        };

        serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
    }

    /// Merge host model semantic findings additively into the L1 report.
    #[tool(
        name = "skill_doctor_merge_verdict",
        description = "Merge host model semantic findings additively into the scan report using the single-use nonce."
    )]
    pub async fn merge_verdict(
        &self,
        params: Parameters<MergeVerdictParams>,
    ) -> Result<String, String> {
        let params = params.0;

        match self.session_store.consume(&params.scan_id, &params.nonce) {
            ConsumeResult::Success(l1_report) => {
                // Convert L2FindingInput to core Finding
                let l2_findings: Vec<Finding> = params
                    .findings
                    .into_iter()
                    .map(|input| {
                        let class = ThreatClass::from_id(&input.class)
                            .unwrap_or(ThreatClass::PromptInjection);
                        let severity =
                            Severity::from_str_loose(&input.severity).unwrap_or(Severity::Medium);
                        let confidence = match input.confidence.to_lowercase().as_str() {
                            "high" => Confidence::High,
                            "low" => Confidence::Low,
                            _ => Confidence::Medium,
                        };
                        Finding {
                            rule_id: input.rule_id,
                            class,
                            severity,
                            confidence,
                            path: PathBuf::from(input.path),
                            byte_span: None,
                            evidence: input.evidence,
                            remediation: input.remediation,
                            layer: AnalysisLayer::L2,
                        }
                    })
                    .collect();

                let merged_report =
                    scoring::merge_l1_and_l2(&l1_report, &l2_findings, LayerRunState::Ran);

                let result = MergeVerdictResult {
                    report: merged_report,
                    status: "Verdict merged additively (L2 Ran)".to_string(),
                };
                serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
            }
            ConsumeResult::FailedClosed(unchanged_report) => {
                // Mismatch or reuse: return original report unchanged with l2 = Reduced
                let result = MergeVerdictResult {
                    report: unchanged_report,
                    status: "Nonce mismatch or reuse: L1 report unchanged (L2 Reduced)".to_string(),
                };
                serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
            }
            ConsumeResult::NotFound => Err(format!(
                "Scan session '{}' not found or expired.",
                params.scan_id
            )),
        }
    }
}

/// Run the Skill Doctor MCP server over stdio.
///
/// Ensures stdout is 100% reserved for JSON-RPC messages.
pub async fn run_stdio_server() -> anyhow::Result<()> {
    eprintln!("Starting Skill Doctor MCP server on stdio...");
    let server = match SkillDoctorServer::new()
        .serve(rmcp::transport::io::stdio())
        .await
    {
        Ok(s) => s,
        Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    match server.waiting().await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn scan_and_merge_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("SKILL.md"),
            "# Test Skill\nClean contents.\n",
        )
        .unwrap();

        let server = SkillDoctorServer::new();
        let scan_resp = server
            .scan(Parameters(ScanParams {
                path: dir.path().to_string_lossy().to_string(),
                mode: Some("host".to_string()),
                fail_on: Some("high".to_string()),
            }))
            .await
            .unwrap();

        let scan_result: ScanResult = serde_json::from_str(&scan_resp).unwrap();
        assert!(!scan_result.scan_id.is_empty());
        assert!(!scan_result.nonce.is_empty());
        assert!(scan_result.envelope.is_some());

        // Now merge an L2 finding
        let merge_resp = server
            .merge_verdict(Parameters(MergeVerdictParams {
                scan_id: scan_result.scan_id.clone(),
                nonce: scan_result.nonce.clone(),
                findings: vec![L2FindingInput {
                    rule_id: "SD-02-semantic-eval".to_string(),
                    class: "SD-02".to_string(),
                    severity: "CRITICAL".to_string(),
                    confidence: "high".to_string(),
                    path: "SKILL.md".to_string(),
                    evidence: vec!["Semantic intent to execute bash".to_string()],
                    remediation: Some("Remove dangerous execution".to_string()),
                }],
            }))
            .await
            .unwrap();

        let merge_result: MergeVerdictResult = serde_json::from_str(&merge_resp).unwrap();
        assert_eq!(merge_result.report.layers.l2, LayerRunState::Ran);
        assert_eq!(merge_result.report.findings.len(), 1);
        assert_eq!(merge_result.report.findings[0].severity, Severity::Critical);
        assert!(merge_result.report.would_fail);

        // Anti-replay: A second merge with same nonce must fail closed (L2 Reduced)
        let replay_resp = server
            .merge_verdict(Parameters(MergeVerdictParams {
                scan_id: scan_result.scan_id,
                nonce: scan_result.nonce,
                findings: vec![],
            }))
            .await
            .unwrap();

        let replay_result: MergeVerdictResult = serde_json::from_str(&replay_resp).unwrap();
        assert_eq!(replay_result.report.layers.l2, LayerRunState::Reduced);
    }

    #[tokio::test]
    async fn nonce_mismatch_fails_closed_and_reduces_l2() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("SKILL.md"), "# Test Skill\nSafe content.\n").unwrap();

        let server = SkillDoctorServer::new();
        let scan_resp = server
            .scan(Parameters(ScanParams {
                path: dir.path().to_string_lossy().to_string(),
                mode: Some("host".to_string()),
                fail_on: Some("high".to_string()),
            }))
            .await
            .unwrap();

        let scan_result: ScanResult = serde_json::from_str(&scan_resp).unwrap();

        // Mismatched nonce
        let merge_resp = server
            .merge_verdict(Parameters(MergeVerdictParams {
                scan_id: scan_result.scan_id,
                nonce: "wrong_nonce".to_string(),
                findings: vec![],
            }))
            .await
            .unwrap();

        let merge_result: MergeVerdictResult = serde_json::from_str(&merge_resp).unwrap();
        assert_eq!(merge_result.report.layers.l2, LayerRunState::Reduced);
    }
}
