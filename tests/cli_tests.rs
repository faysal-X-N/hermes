// CLI integration tests — run the actual hermes binary
use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

fn hermes() -> Command {
    Command::cargo_bin("hermes").unwrap()
}

#[test]
fn test_help_works() {
    hermes()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("audit"))
        .stdout(predicate::str::contains("probe"))
        .stdout(predicate::str::contains("fuzz"))
        .stdout(predicate::str::contains("verify"));
}

#[test]
fn test_audit_finds_issues() {
    hermes()
        .args(["audit", "tests/fixtures/configs"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("Findings"));
}

#[test]
fn test_audit_json_produces_valid_json() {
    hermes()
        .args(["audit", "tests/fixtures/configs", "--format", "json"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains(r#""id""#))
        .stdout(predicate::str::contains(r#""severity""#));
}

#[test]
fn test_preset_dengbao_filters() {
    hermes()
        .args(["audit", "tests/fixtures/configs", "--preset", "dengbao"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("critical"))
        .stdout(predicate::str::contains("high"));
}

#[test]
fn test_preset_basic_only_critical() {
    hermes()
        .args(["audit", "tests/fixtures/configs", "--preset", "basic"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("1 critical"))
        .stdout(predicate::str::contains("0 high"));
}

#[test]
fn test_policy_generates_file() {
    let _ = fs::remove_file(".hermes-policy.json");

    hermes()
        .args(["policy", "--template", "basic"])
        .assert()
        .success();

    assert!(std::path::Path::new(".hermes-policy.json").exists());

    let content = fs::read_to_string(".hermes-policy.json").unwrap();
    assert!(content.contains("basic"));

    let _ = fs::remove_file(".hermes-policy.json");
}

#[test]
fn test_audit_no_issues_on_secure_config() {
    hermes()
        .args(["audit", "tests/fixtures/configs/secure-mcp.json"])
        .assert()
        .success();
}

#[test]
fn test_audit_invalid_path_fails() {
    hermes()
        .args(["audit", "/nonexistent/path"])
        .assert()
        .code(1);
}
