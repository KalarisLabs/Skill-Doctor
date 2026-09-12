use rmcp::handler::server::wrapper::Parameters;
use rmcp::ServiceExt;
use skill_doctor_core::report::LayerRunState;
use skill_doctor_mcp::{
    L2FindingInput, MergeVerdictParams, MergeVerdictResult, ScanParams, ScanResult,
    SkillDoctorServer,
};
use std::fs;
use std::path::PathBuf;

#[tokio::test]
async fn test_mcp_scan_mode_none() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("SKILL.md"), "# Safe Skill\nNothing bad.\n").unwrap();

    let server = SkillDoctorServer::new();
    let resp = server
        .scan(Parameters(ScanParams {
            path: dir.path().to_string_lossy().to_string(),
            mode: Some("none".to_string()),
            fail_on: Some("high".to_string()),
        }))
        .await
        .unwrap();

    let scan_result: ScanResult = serde_json::from_str(&resp).unwrap();
    assert_eq!(scan_result.l1_report.layers.l2, LayerRunState::Skipped);
    assert!(scan_result.envelope.is_none());
    assert!(scan_result.instructions.is_none());
}

#[tokio::test]
async fn test_mcp_scan_neutralizes_and_envelopes() {
    let dir = tempfile::tempdir().unwrap();
    // Skill containing homoglyph (Cyrillic a) and zero-width space
    let raw_content = "# Skill\nExecute ev\u{0430}l\u{200B} code.\n";
    fs::write(dir.path().join("SKILL.md"), raw_content).unwrap();

    let server = SkillDoctorServer::new();
    let resp = server
        .scan(Parameters(ScanParams {
            path: dir.path().to_string_lossy().to_string(),
            mode: Some("host".to_string()),
            fail_on: Some("high".to_string()),
        }))
        .await
        .unwrap();

    let scan_result: ScanResult = serde_json::from_str(&resp).unwrap();
    let envelope = scan_result.envelope.expect("Envelope must be present");

    // The envelope must fence the content
    assert!(envelope.contains("<<<UNTRUSTED_SKILL nonce="));
    assert!(envelope.contains("<<<END_UNTRUSTED_SKILL>>>"));

    // Raw homoglyph and zero-width space must NOT be present inside envelope
    assert!(!envelope.contains('\u{0430}'));
    assert!(!envelope.contains('\u{200B}'));
    // The confusable was normalized to ASCII skeleton 'eval'
    assert!(envelope.contains("eval"));

    // L1 findings must record the neutralizations as findings
    let rule_ids: Vec<&str> = scan_result
        .l1_report
        .findings
        .iter()
        .map(|f| f.rule_id.as_str())
        .collect();
    assert!(rule_ids.contains(&"SD-01-zero-width-smuggle"));
    assert!(rule_ids.contains(&"SD-10-homoglyph-confusable"));
}

#[tokio::test]
async fn test_mcp_additive_merge_preserves_l1_critical() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/attack/SD-02/malicious-skill");

    let server = SkillDoctorServer::new();
    let resp = server
        .scan(Parameters(ScanParams {
            path: fixture_path.to_string_lossy().to_string(),
            mode: Some("host".to_string()),
            fail_on: Some("high".to_string()),
        }))
        .await
        .unwrap();

    let scan_result: ScanResult = serde_json::from_str(&resp).unwrap();
    assert!(scan_result.l1_report.would_fail);

    // Host returns empty array (benign verdict)
    let merge_resp = server
        .merge_verdict(Parameters(MergeVerdictParams {
            scan_id: scan_result.scan_id,
            nonce: scan_result.nonce,
            findings: vec![],
        }))
        .await
        .unwrap();

    let merge_result: MergeVerdictResult = serde_json::from_str(&merge_resp).unwrap();
    // Invariant: L1 finding survives completely
    assert!(merge_result.report.would_fail);
    assert!(!merge_result.report.findings.is_empty());
    assert_eq!(merge_result.report.layers.l2, LayerRunState::Ran);
}

#[tokio::test]
async fn test_mcp_anti_replay_consumes_slot() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("SKILL.md"), "# Clean\nSafe text.\n").unwrap();

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

    // Call 1: valid merge
    let merge_resp1 = server
        .merge_verdict(Parameters(MergeVerdictParams {
            scan_id: scan_result.scan_id.clone(),
            nonce: scan_result.nonce.clone(),
            findings: vec![L2FindingInput {
                rule_id: "SD-03-semantic-leak".to_string(),
                class: "SD-03".to_string(),
                severity: "HIGH".to_string(),
                confidence: "high".to_string(),
                path: "SKILL.md".to_string(),
                evidence: vec!["Semantic leak of credentials".to_string()],
                remediation: None,
            }],
        }))
        .await
        .unwrap();

    let res1: MergeVerdictResult = serde_json::from_str(&merge_resp1).unwrap();
    assert_eq!(res1.report.layers.l2, LayerRunState::Ran);
    assert_eq!(res1.report.findings.len(), 1);

    // Call 2: replay with same nonce
    let merge_resp2 = server
        .merge_verdict(Parameters(MergeVerdictParams {
            scan_id: scan_result.scan_id,
            nonce: scan_result.nonce,
            findings: vec![],
        }))
        .await
        .unwrap();

    let res2: MergeVerdictResult = serde_json::from_str(&merge_resp2).unwrap();
    // Anti-replay: second call fails closed, l2 = Reduced
    assert_eq!(res2.report.layers.l2, LayerRunState::Reduced);
}

#[tokio::test]
async fn test_mcp_stdin_closed_immediately_exits_cleanly() {
    let (client_io, server_io) = tokio::io::duplex(1024);
    // Dropping client_io causes server_io to encounter EOF immediately
    drop(client_io);

    let server = SkillDoctorServer::new();
    let serve_res = server.serve(server_io).await;
    match serve_res {
        Ok(running) => {
            let wait_res = running.waiting().await;
            match wait_res {
                Ok(rmcp::service::QuitReason::Closed)
                | Ok(rmcp::service::QuitReason::Cancelled) => {}
                Ok(rmcp::service::QuitReason::JoinError(e)) => {
                    assert!(e.is_cancelled());
                }
                Ok(_) => {}
                Err(e) => {
                    assert!(e.is_cancelled());
                }
            }
        }
        Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) => {
            // Expected EOF during initialization
        }
        Err(e) => panic!("Expected ConnectionClosed or clean exit, got: {:?}", e),
    }
}
