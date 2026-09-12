//! Security advisories and supply-chain (SD-05) integrity tests.

use skill_doctor_core::finding::{AnalysisLayer, Confidence, Finding, Severity};
use skill_doctor_core::l0;
use skill_doctor_core::l5::{self, ReportOptions};
use skill_doctor_core::taxonomy::ThreatClass;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
}

#[test]
fn test_supply_chain_threat_class_integrity() {
    let sc = ThreatClass::SupplyChainTampering;
    assert_eq!(sc.id(), "SD-05");
    assert!(sc.description().starts_with("Supply-Chain Tampering"));
}

#[test]
fn test_security_advisories_all_classes_mapped() {
    let classes = ThreatClass::ALL;
    assert_eq!(
        classes.len(),
        11,
        "Must have exactly 11 SDTM-v1 threat classes"
    );
    for tc in classes {
        assert!(tc.id().starts_with("SD-"));
        assert!(!tc.description().is_empty());
    }
}

#[test]
fn test_advisory_attack_fixture_detection() {
    let attack_path = fixtures_dir()
        .join("attack")
        .join("SD-02")
        .join("malicious-skill");
    assert!(attack_path.exists(), "Attack fixture must exist");

    let bundle = l0::intake(&attack_path).expect("intake should succeed");
    let report = l5::analyze(
        &bundle,
        &ReportOptions {
            fail_on: Severity::High,
            deterministic: true,
        },
    );

    assert!(
        !report.findings.is_empty(),
        "Attack fixture should produce security findings"
    );
}

#[test]
fn test_advisory_remediation_present_on_findings() {
    let finding = Finding {
        rule_id: "SD-05-untrusted-dep".to_string(),
        class: ThreatClass::SupplyChainTampering,
        severity: Severity::High,
        confidence: Confidence::High,
        path: PathBuf::from("SKILL.md"),
        byte_span: None,
        evidence: vec!["detected untrusted registry dependency".to_string()],
        remediation: Some("Use only verified package sources".to_string()),
        layer: AnalysisLayer::L1,
    };

    assert!(finding.remediation.is_some());
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.class, ThreatClass::SupplyChainTampering);
}
