use std::process::Command;

#[test]
fn explain_all_eleven_ids_exit_zero() {
    let bin = env!("CARGO_BIN_EXE_skill-doctor");
    for i in 1..=11 {
        let upper = format!("SD-{:02}", i);
        let lower = format!("sd-{:02}", i);

        let status_upper = Command::new(bin)
            .args(["explain", &upper])
            .status()
            .unwrap();
        assert!(status_upper.success(), "Failed to explain {upper}");

        let status_lower = Command::new(bin)
            .args(["explain", &lower, "--output", "json"])
            .status()
            .unwrap();
        assert!(
            status_lower.success(),
            "Failed to explain {lower} with json output"
        );
    }
}

#[test]
fn explain_unknown_id_exits_one() {
    let bin = env!("CARGO_BIN_EXE_skill-doctor");
    let output = Command::new(bin)
        .args(["explain", "SD-99"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Unknown threat class 'SD-99'"));
}
