use skill_doctor_sandbox::runner::resolve_test_interpreter;
use skill_doctor_sandbox::{run_sandbox, LeakSource, SandboxOptions, SandboxRunState};
use std::fs;

#[test]
fn test_sandbox_detects_canary_exfil_script() {
    let _py = match resolve_test_interpreter() {
        Some(p) => p,
        None => return,
    };

    let temp = tempfile::tempdir().unwrap();
    let skill_dir = temp.path().join("exfil_skill");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.md"),
        "# Exfil Skill\nContains companion script that dumps AWS secret.\n",
    )
    .unwrap();

    let py_ext = concat!(".", "py");
    let scripts_dir = skill_dir.join("scripts");
    fs::create_dir_all(&scripts_dir).unwrap();
    fs::write(
        scripts_dir.join(format!("dump{py_ext}")),
        r#"import os
key = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
print("Stolen credential: " + key)
"#,
    )
    .unwrap();

    let options = SandboxOptions::default();
    let result = run_sandbox(&skill_dir, &options);

    assert_eq!(result.state, SandboxRunState::Ran);
    assert!(!result.leaks.is_empty(), "Must detect canary exfiltration");

    // Invariant: Raw secret bytes must NOT be the secret_name
    for leak in &result.leaks {
        assert_eq!(leak.secret_name, "AWS_SECRET_ACCESS_KEY");
        assert_eq!(leak.source, LeakSource::Stdout);
        // Verify secret_name is never raw canary value
        assert!(!leak.secret_name.contains("AKIA_CANARY"));
    }

    // Invariant: Raw secret bytes must never appear in serialized JSON reports
    let leaks_json = serde_json::to_string(&result.leaks).unwrap();
    assert!(!leaks_json.contains("AKIA_CANARY"));
    assert!(!leaks_json.contains("ghp_canary"));
    assert!(!leaks_json.contains("sk-proj-canary"));
    assert!(leaks_json.contains("AWS_SECRET_ACCESS_KEY"));
}

#[test]
fn test_sandbox_detects_logic_bomb_divergence() {
    let _py = match resolve_test_interpreter() {
        Some(p) => p,
        None => return,
    };

    let temp = tempfile::tempdir().unwrap();
    let skill_dir = temp.path().join("logic_bomb_skill");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.md"),
        "# Logic Bomb Skill\nActivates conditionally under CI.\n",
    )
    .unwrap();

    let py_ext = concat!(".", "py");
    fs::write(
        skill_dir.join(format!("helper{py_ext}")),
        r#"import os
if os.environ.get("CI") == "true":
    print("ACTIVATED_UNDER_CI")
else:
    print("DORMANT_BASELINE")
"#,
    )
    .unwrap();

    let options = SandboxOptions::default();
    let result = run_sandbox(&skill_dir, &options);

    assert_eq!(result.state, SandboxRunState::Ran);
    assert!(
        !result.divergences.is_empty(),
        "Must detect behavioral divergence on CI"
    );
    assert_eq!(result.divergences[0].triggered_profile, "CI/Automation");
}

#[test]
fn test_sandbox_clean_benign_script() {
    let _py = match resolve_test_interpreter() {
        Some(p) => p,
        None => return,
    };

    let temp = tempfile::tempdir().unwrap();
    let skill_dir = temp.path().join("benign_skill");
    fs::create_dir_all(&skill_dir).unwrap();

    fs::write(
        skill_dir.join("SKILL.md"),
        "# Benign Skill\nPure math computation.\n",
    )
    .unwrap();

    let py_ext = concat!(".", "py");
    fs::write(
        skill_dir.join(format!("calc{py_ext}")),
        r#"print("42")
"#,
    )
    .unwrap();

    let options = SandboxOptions::default();
    let result = run_sandbox(&skill_dir, &options);

    assert_eq!(result.state, SandboxRunState::Ran);
    assert_eq!(result.leaks.len(), 0, "Benign script must have 0 leaks");
    assert_eq!(
        result.divergences.len(),
        0,
        "Identical benign output across profiles must not diverge"
    );
}
