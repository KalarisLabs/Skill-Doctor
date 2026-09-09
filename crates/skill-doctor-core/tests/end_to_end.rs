//! End-to-end integration tests for Skill Doctor.

use skill_doctor_core::finding::Severity;
use skill_doctor_core::l0;
use skill_doctor_core::l5::{self, ReportOptions};
use skill_doctor_core::report::Verdict;
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
fn scan_benign_fixture_produces_pass() {
    let benign_path = fixtures_dir().join("benign").join("hello-skill");
    assert!(benign_path.exists(), "Benign fixture path must exist");

    let bundle = l0::intake(&benign_path).expect("L0 intake should succeed on benign skill");
    let report = l5::analyze(
        &bundle,
        &ReportOptions {
            fail_on: Severity::High,
            deterministic: true,
        },
    );

    assert_eq!(report.verdict, Verdict::Pass);
    assert!(
        report.findings.is_empty(),
        "Benign skill should produce zero findings"
    );
    assert!(!report.bundle_digest.is_empty());
}

#[test]
fn scan_attack_fixture_produces_fail() {
    let attack_path = fixtures_dir()
        .join("attack")
        .join("SD-02")
        .join("malicious-skill");
    assert!(attack_path.exists(), "Attack fixture path must exist");

    let bundle = l0::intake(&attack_path).expect("L0 intake should succeed on attack skill");
    let report = l5::analyze(
        &bundle,
        &ReportOptions {
            fail_on: Severity::High,
            deterministic: true,
        },
    );

    assert_eq!(report.verdict, Verdict::Fail);
    assert!(
        !report.findings.is_empty(),
        "Attack fixture must trigger findings"
    );

    let has_sd02 = report
        .findings
        .iter()
        .any(|f| f.class == ThreatClass::CommandInjection);
    assert!(has_sd02, "Expected findings in SD-02 class");
}

#[test]
fn deterministic_scans_produce_identical_output() {
    let benign_path = fixtures_dir().join("benign").join("hello-skill");
    let bundle = l0::intake(&benign_path).unwrap();

    let opts = ReportOptions {
        fail_on: Severity::High,
        deterministic: true,
    };

    let report1 = l5::analyze(&bundle, &opts);
    let report2 = l5::analyze(&bundle, &opts);

    let json1 = serde_json::to_string_pretty(&report1).unwrap();
    let json2 = serde_json::to_string_pretty(&report2).unwrap();

    assert_eq!(
        json1, json2,
        "Deterministic report outputs must be byte-identical"
    );
}
