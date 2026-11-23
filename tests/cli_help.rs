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
            .any(|s| s["id"] == "routed-peer" && s["evidence"] == "source_tree")
    );
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
fn run_help_lists_the_packet_capture() {
    let help = json(&invoke(&["help", "run", "--format", "json"], None).stdout);
    let capture = help["arguments"]
        .as_array()
        .expect("arguments")
        .iter()
        .find(|arg| arg["long"] == "capture")
        .cloned()
        .expect("--capture");
    assert_eq!(capture["value_names"], serde_json::json!(["FILE"]));
    assert_eq!(capture["takes_value"], true);
    let said = capture["help"].as_str().unwrap_or("");
    assert!(
        said.contains("pcap") && said.contains("credentials"),
        "{said}"
    );
    assert!(
        help["examples"]
            .as_array()
            .expect("examples")
            .iter()
            .any(|e| e.as_str().is_some_and(|e| e.contains("--capture"))),
        "{help}"
    );
    let text = String::from_utf8(invoke(&["run", "--help"], None).stdout).expect("help");
    assert!(text.contains("--capture <FILE>"), "{text}");
}

#[test]
fn run_and_plan_help_list_live_drops() {
    for name in ["run", "plan"] {
        let help = json(&invoke(&["help", name, "--format", "json"], None).stdout);
        let arg = help["arguments"]
            .as_array()
            .expect("arguments")
            .iter()
            .find(|a| a["long"] == "live-drops")
            .cloned()
            .unwrap_or_else(|| panic!("{name}: no --live-drops in {help}"));
        assert_eq!(arg["takes_value"], false, "{name}");
        let said = arg["help"].as_str().unwrap_or("");
        assert!(
            said.contains("while the command runs") && said.contains("--events-fd"),
            "{name}: {said}"
        );
    }
    let help = json(&invoke(&["help", "run", "--format", "json"], None).stdout);
    assert!(
        help["examples"]
            .as_array()
            .expect("examples")
            .iter()
            .any(|e| e.as_str().is_some_and(|e| e.contains("--live-drops"))),
        "{help}"
    );
    let workflow = help["workflow"].as_str().unwrap_or("");
    assert!(
        workflow.contains("denied record") && workflow.contains("--live-drops"),
        "{workflow}"
    );
    let text = String::from_utf8(invoke(&["run", "--help"], None).stdout).expect("help");
    assert!(text.contains("--live-drops"), "{text}");
}

#[test]
fn run_plan_and_rules_help_list_on_drop() {
    for name in ["run", "plan", "rules"] {
        let help = json(&invoke(&["help", name, "--format", "json"], None).stdout);
        let arg = help["arguments"]
            .as_array()
            .expect("arguments")
            .iter()
            .find(|a| a["long"] == "on-drop")
            .cloned()
            .unwrap_or_else(|| panic!("{name}: no --on-drop in {help}"));
        assert_eq!(arg["takes_value"], true, "{name}");
        assert_eq!(arg["values"], serde_json::json!(["cut", "stop"]), "{name}");
        assert_eq!(arg["value_names"], serde_json::json!(["ACTION"]), "{name}");
        let said = arg["help"].as_str().unwrap_or("");
        assert!(
            said.contains("closes all egress") || said.contains("close all egress"),
            "{name}: {said}"
        );
    }
    let help = json(&invoke(&["help", "run", "--format", "json"], None).stdout);
    let said = help["arguments"]
        .as_array()
        .expect("arguments")
        .iter()
        .find(|a| a["long"] == "on-drop")
        .and_then(|a| a["help"].as_str())
        .unwrap_or("")
        .to_owned();
    // Why it is off by default.
    for cause in ["mDNS", "LLMNR", "DNS server", "metadata", "IPv6"] {
        assert!(said.contains(cause), "{cause}: {said}");
    }
    assert!(
        help["examples"]
            .as_array()
            .expect("examples")
            .iter()
            .any(|e| e.as_str().is_some_and(|e| e.contains("--on-drop stop"))),
        "{help}"
    );
    let workflow = help["workflow"].as_str().unwrap_or("");
    assert!(
        workflow.contains("--on-drop stop") && workflow.contains("egress_cut"),
        "{workflow}"
    );
    let text = String::from_utf8(invoke(&["run", "--help"], None).stdout).expect("help");
    assert!(text.contains("--on-drop <ACTION>"), "{text}");
}

#[test]
fn rules_show_the_tripwire_only_with_on_drop() {
    let rules = |flags: &[&str]| {
        let out = invoke(
            &[&["rules", "--allow", "192.0.2.1:443/tcp"][..], flags].concat(),
            None,
        );
        assert!(out.status.success(), "{flags:?}");
        String::from_utf8(out.stdout).expect("rules")
    };
    let plain = rules(&[]);
    assert!(!plain.contains("add @cut"), "{plain}");
    assert!(
        plain.contains("\t\tcounter name \"dropped\"\n\t\treject with icmpx admin-prohibited\n")
    );
    let cut = rules(&["--on-drop", "cut"]);
    assert_eq!(cut, rules(&["--on-drop", "stop"]));
    assert!(
        cut.contains("\t\tadd @cut { 0 }\n\t\tcounter name \"dropped\"\n\t\tdrop\n"),
        "{cut}"
    );
    assert!(!cut.contains("reject"), "{cut}");
    let json_rules = |flags: &[&str]| {
        json(
            &invoke(
                &[
                    &["rules", "--allow", "192.0.2.1:443/tcp", "--format", "json"][..],
                    flags,
                ]
                .concat(),
                None,
            )
            .stdout,
        )
    };
    let without = json_rules(&[]);
    assert!(without.get("on_drop").is_none(), "{without}");
    assert_eq!(without["ruleset"], plain);
    let with = json_rules(&["--on-drop", "stop"]);
    assert_eq!(with["on_drop"], "stop");
    assert_eq!(with["ruleset"], cut);
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

#[test]
fn pass_hosts_is_listed_and_without_pass_is_a_usage_error() {
    for name in ["run", "plan", "rules"] {
        let help = json(&invoke(&["help", name, "--format", "json"], None).stdout);
        let arg = help["arguments"]
            .as_array()
            .expect("arguments")
            .iter()
            .find(|a| a["long"] == "pass-hosts")
            .cloned()
            .unwrap_or_else(|| panic!("{name}: no --pass-hosts in {help}"));
        assert_eq!(arg["takes_value"], false, "{name}");
        assert!(
            arg["help"].as_str().is_some_and(|h| h.contains("--pass")),
            "{name}: {arg}"
        );
    }
    let marker = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("pass-hosts-ran-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let marker = marker.to_str().expect("path");
    for args in [
        &["run", "--pass-hosts", "--no-network", "--", "touch", marker][..],
        &[
            "plan",
            "--pass-hosts",
            "--allow",
            "192.0.2.1:443/tcp",
            "--",
            "true",
        ][..],
        &["rules", "--pass-hosts", "--allow", "192.0.2.1:443/tcp"][..],
    ] {
        let out = invoke(args, None);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(out.stdout, b"", "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--pass <FILE>"),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mut machine = args.to_vec();
        machine.insert(0, "--json");
        let out = invoke(&machine, None);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert_eq!(json(&out.stderr)["error"]["type"], "invalid-arguments");
    }
    assert!(!std::path::Path::new(marker).exists(), "the command ran");
}

#[test]
fn the_contacted_record_and_suggest_are_listed() {
    let root = json(&invoke(&["--help", "--json"], None).stdout);
    assert!(
        root["commands"]
            .as_array()
            .expect("commands")
            .iter()
            .any(|c| c["name"] == "suggest"),
        "{root}"
    );
    for name in ["run", "rules"] {
        let help = json(&invoke(&["help", name, "--format", "json"], None).stdout);
        let arg = help["arguments"]
            .as_array()
            .expect("arguments")
            .iter()
            .find(|a| a["long"] == "report-contacts")
            .cloned()
            .unwrap_or_else(|| panic!("{name}: no --report-contacts in {help}"));
        assert_eq!(arg["takes_value"], false, "{name}");
        assert!(
            help["examples"]
                .as_array()
                .expect("examples")
                .iter()
                .any(|e| e.as_str().is_some_and(|e| e.contains("--report-contacts"))),
            "{name}: {help}"
        );
    }
    let run = json(&invoke(&["help", "run", "--format", "json"], None).stdout);
    assert!(
        run["workflow"]
            .as_str()
            .is_some_and(|w| w.contains("playpen suggest REPORT")),
        "{run}"
    );
    let suggest = json(&invoke(&["help", "suggest", "--format", "json"], None).stdout);
    let workflow = suggest["workflow"].as_str().unwrap_or("");
    assert!(
        workflow.contains("One quiet run does not show that a later run needs less"),
        "{workflow}"
    );
    let report = suggest["arguments"]
        .as_array()
        .expect("arguments")
        .iter()
        .find(|a| a["name"] == "report")
        .cloned()
        .expect("REPORT");
    assert_eq!(report["required"], true);
    let text = String::from_utf8(invoke(&["suggest", "--help"], None).stdout).expect("help");
    assert!(
        text.contains("Usage: playpen suggest [OPTIONS] <REPORT>"),
        "{text}"
    );
}

/// The help says what `--fail-on-drop` counts, `--no-network` included, and
/// what makes the count incomplete.
#[test]
fn run_help_says_what_fail_on_drop_counts() {
    let help = json(&invoke(&["help", "run", "--format", "json"], None).stdout);
    let said = |long: &str| {
        help["arguments"]
            .as_array()
            .expect("arguments")
            .iter()
            .find(|a| a["long"] == long)
            .and_then(|a| a["help"].as_str())
            .unwrap_or_else(|| panic!("no --{long} in {help}"))
            .to_owned()
    };
    let fail = said("fail-on-drop");
    for part in [
        "each packet to another host that no grant allows",
        "--no-network included",
        "loopback, lookups the DNS stub answered and host Unix sockets are not counted",
        "a family with no route",
    ] {
        assert!(fail.contains(part), "{part}: {fail}");
    }
    let offline = said("no-network");
    assert!(
        offline.contains("a packet to any other host is dropped and counted"),
        "{offline}"
    );
    let workflow = help["workflow"].as_str().unwrap_or("");
    assert!(
        workflow.contains("--fail-on-drop counts each packet to another host that no grant allows, with --no-network too")
            && workflow.contains("uncounted"),
        "{workflow}"
    );
    let text = String::from_utf8(invoke(&["run", "--help"], None).stdout).expect("help");
    assert!(text.contains("--fail-on-drop"), "{text}");
}
