//! CLI discovery and stream contracts used by machine callers.
use std::process::{Command, Output};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

fn invoke(args: &[&str], format: Option<&str>) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env_remove("FORMAT");
    if let Some(format) = format {
        cmd.env("FORMAT", format);
    }
    cmd.output().expect("launch playpen")
}

fn json(bytes: &[u8]) -> Value {
    let value: Value = serde_json::from_slice(bytes).expect("one JSON object");
    assert!(value["advice"].is_array(), "{value}");
    value
}

#[test]
fn every_public_command_is_discoverable_and_has_equivalent_json_help() {
    let root = json(&invoke(&["--help", "--json"], None).stdout);
    assert_eq!(root["command"], "playpen");
    let commands = root["commands"].as_array().expect("commands");
    assert!(commands.iter().any(|c| c["name"] == "run"));
    for command in commands {
        let name = command["name"].as_str().expect("name");
        assert_ne!(name, "probe");
        let long = json(&invoke(&["--format", "json", "help", name], None).stdout);
        let short = json(&invoke(&[name, "-h", "--json"], None).stdout);
        assert_eq!(long, short, "{name}");
        assert_eq!(long["command"], format!("playpen {name}"));
        assert!(
            long["examples"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        );
        assert!(
            long["workflow"]
                .as_str()
                .is_some_and(|workflow| !workflow.is_empty())
        );
        let help = invoke(&[name, "--help"], None);
        let help = String::from_utf8(help.stdout).expect("help");
        for label in ["Usage:", "Examples", "Agent workflow", "--format"] {
            assert!(help.contains(label), "{name}: {label}");
        }
        assert!(!help.contains("--json"));
        assert!(
            long["arguments"]
                .as_array()
                .expect("arguments")
                .iter()
                .all(|arg| arg["long"] != "json")
        );
    }
}

#[test]
fn format_precedence_errors_and_workload_arguments() {
    let env = json(&invoke(&["version"], Some("json")).stdout);
    assert_eq!(env, json(&invoke(&["--json", "--version"], None).stdout));
    assert_eq!(
        env,
        json(&invoke(&["version", "--json"], Some("bogus")).stdout)
    );
    let version_text = invoke(&["version", "--format=text"], Some("json"));
    assert!(version_text.stdout.starts_with(b"playpen "));
    let bad = invoke(&["--json", "rules", "--unknown"], None);
    assert_eq!(bad.status.code(), Some(2));
    assert_eq!(bad.stdout, b"");
    assert_eq!(json(&bad.stderr)["error"]["type"], "invalid-arguments");
    let plan = invoke(
        &["plan", "--no-network", "--", "printf", "--json", "--help"],
        None,
    );
    assert!(plan.status.success());
    assert!(String::from_utf8_lossy(&plan.stdout).contains("digest  "));
    let plan = invoke(
        &["plan", "--no-network", "--", "printf", "--format=text"],
        Some("json"),
    );
    assert_eq!(json(&plan.stdout)["plan"]["command"][1], "--format=text");
    let catalog = json(&invoke(&["qualify", "--list", "--json"], None).stdout);
    assert!(
        catalog["scenarios"]
            .as_array()
            .expect("scenarios")
            .iter()
            .any(|s| s["id"] == "offline-command" && s.get("status").is_none())
    );
}

#[test]
fn policy_test_reports_all_decisions_and_refuses_invalid_input_atomically() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cases-{}.json", std::process::id()));
    let path = path.to_str().expect("path");
    let args = [
        "policy-test",
        path,
        "--allow",
        "192.0.2.1:443/tcp",
        "--json",
    ];
    let case =
        serde_json::json!({"address":"192.0.2.1", "protocol":"tcp","port":443,"expect":"allow"});
    let mut wrong = case.clone();
    wrong["port"] = 80.into();
    std::fs::write(path, serde_json::json!([case, wrong]).to_string()).expect("cases");
    let out = invoke(&args, None);
    assert_eq!(out.status.code(), Some(1));
    let result = json(&out.stdout);
    assert_eq!(result["cases"][0]["actual"], "allow");
    assert_eq!(result["cases"][1]["ok"], false);
    wrong["port"] = 0.into();
    std::fs::write(path, serde_json::json!([case, wrong]).to_string()).expect("cases");
    let invalid = invoke(&args, None);
    assert_eq!(invalid.status.code(), Some(2));
    assert_eq!(invalid.stdout, b"");
    assert_eq!(
        json(&invalid.stderr)["error"]["type"],
        "invalid-policy-test"
    );
}

#[test]
fn json_run_refusal_is_a_report_even_without_a_file() {
    let out = invoke(
        &["run", "--allow", "invalid", "--json", "--", "false"],
        None,
    );
    assert_eq!(out.status.code(), Some(2));
    let report = json(&out.stdout);
    assert_eq!(report["outcome"], "refused");
    assert_eq!(report["startup_evidence"], "not_started");
    let shareable = invoke(
        &[
            "run",
            "--allow",
            "private-invalid",
            "--shareable-report",
            "--json",
            "--",
            "false",
        ],
        None,
    );
    assert_eq!(json(&shareable.stdout)["schema"], "playpen-shareable-v1");
    assert!(!String::from_utf8_lossy(&shareable.stdout).contains("private-invalid"));
}
