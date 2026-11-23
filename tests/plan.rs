use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

#[test]
fn preview_is_deterministic_and_has_no_run_side_effects() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let marker = dir.join(format!("plan-child-{}", std::process::id()));
    let report = dir.join(format!("plan-report-{}", std::process::id()));
    let preview = |rules: &[&str]| {
        let mut cmd = Command::new(BIN);
        cmd.args(["plan", "--format", "json", "--report"])
            .arg(&report);
        for rule in rules {
            cmd.args(["--allow", rule]);
        }
        let out = cmd
            .args(["--", "touch"])
            .arg(&marker)
            .arg(OsStr::from_bytes(b"\xff"))
            .output()
            .expect("plan");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<Value>(&out.stdout).expect("plan JSON")
    };
    let a = "192.0.2.1:443/tcp";
    let b = "[2001:db8::1]:53/udp";
    let p = preview(&[a, b]);
    assert_eq!(p, preview(&[b, a]));
    assert_eq!(p["plan"]["command"][2]["unix_bytes"][0], 255);
    assert!(!marker.exists());
    assert!(!report.exists());
    let refused = Command::new(BIN)
        .args(["plan", "--allow", "invalid", "--", "true"])
        .output()
        .expect("refused plan");
    assert_eq!(refused.status.code(), Some(2));
}

#[test]
fn pin_is_bound_to_command_and_grants_before_start() {
    let base = ["--allow", "192.0.2.1:443/tcp", "--", "true"];
    let plan = Command::new(BIN)
        .args(["plan", "--format", "json"])
        .args(base)
        .output()
        .expect("plan");
    let p: Value = serde_json::from_slice(&plan.stdout).expect("plan JSON");
    let digest = p["digest"].as_str().expect("digest");
    for changed in [
        ["--allow", "192.0.2.1:444/tcp", "--", "true"],
        ["--allow", "192.0.2.1:443/tcp", "--", "false"],
    ] {
        let result = Command::new(BIN)
            .args(["run", "--expect-plan", digest])
            .args(changed)
            .output()
            .expect("pinned run");
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&result.stderr).contains("differs from current scope"));
    }
}

/// `--live-drops` is in the plan and its digest only when given, so the
/// digest of a plan without it is the one it had before the option
/// existed, and a run that adds it to a reviewed plan is refused.
#[test]
fn live_drops_is_in_the_plan_only_when_given() {
    let plan = |flags: &[&str]| {
        let out = Command::new(BIN)
            .args(["plan", "--format", "json", "--allow", "192.0.2.1:443/tcp"])
            .args(flags)
            .args(["--", "true"])
            .output()
            .expect("plan");
        assert!(out.status.success());
        serde_json::from_slice::<Value>(&out.stdout).expect("plan JSON")
    };
    let without = plan(&[]);
    let with = plan(&["--live-drops"]);
    assert!(without["plan"].get("live_drops").is_none(), "{without}");
    assert_eq!(with["plan"]["live_drops"], true);
    assert_ne!(with["digest"], without["digest"]);
    let mut stripped = with["plan"].clone();
    stripped
        .as_object_mut()
        .expect("plan object")
        .remove("live_drops");
    assert_eq!(stripped, without["plan"]);
    let text = Command::new(BIN)
        .args([
            "plan",
            "--allow",
            "192.0.2.1:443/tcp",
            "--live-drops",
            "--",
            "true",
        ])
        .output()
        .expect("text plan");
    assert!(String::from_utf8_lossy(&text.stdout).contains("live_drops  true"));
    let refused = Command::new(BIN)
        .args([
            "run",
            "--expect-plan",
            without["digest"].as_str().expect("digest"),
        ])
        .args(["--allow", "192.0.2.1:443/tcp", "--live-drops", "--", "true"])
        .output()
        .expect("pinned run");
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("differs from current scope"));
}

/// `--on-drop` is in the plan and its digest only when given, with its
/// value: cut and stop are different plans, and a run that adds the option
/// to a reviewed plan, or changes it, is refused.
#[test]
fn on_drop_is_in_the_plan_only_when_given() {
    let plan = |flags: &[&str]| {
        let out = Command::new(BIN)
            .args(["plan", "--format", "json", "--allow", "192.0.2.1:443/tcp"])
            .args(flags)
            .args(["--", "true"])
            .output()
            .expect("plan");
        assert!(out.status.success(), "{flags:?}");
        serde_json::from_slice::<Value>(&out.stdout).expect("plan JSON")
    };
    let without = plan(&[]);
    let cut = plan(&["--on-drop", "cut"]);
    let stop = plan(&["--on-drop", "stop"]);
    assert!(without["plan"].get("on_drop").is_none(), "{without}");
    assert_eq!(cut["plan"]["on_drop"], "cut");
    assert_eq!(stop["plan"]["on_drop"], "stop");
    assert_ne!(cut["digest"], without["digest"]);
    assert_ne!(stop["digest"], cut["digest"]);
    for with in [&cut, &stop] {
        let mut stripped = with["plan"].clone();
        stripped
            .as_object_mut()
            .expect("plan object")
            .remove("on_drop");
        assert_eq!(stripped, without["plan"]);
    }
    let text = Command::new(BIN)
        .args(["plan", "--no-network", "--on-drop", "stop", "--", "true"])
        .output()
        .expect("text plan");
    assert!(text.status.success());
    assert!(String::from_utf8_lossy(&text.stdout).contains("on_drop  \"stop\""));
    for (digest, flags) in [
        (&without["digest"], &["--on-drop", "stop"][..]),
        (&cut["digest"], &["--on-drop", "stop"][..]),
        (&stop["digest"], &[][..]),
    ] {
        let refused = Command::new(BIN)
            .args(["run", "--expect-plan", digest.as_str().expect("digest")])
            .args(["--allow", "192.0.2.1:443/tcp"])
            .args(flags)
            .args(["--", "true"])
            .output()
            .expect("pinned run");
        assert_eq!(refused.status.code(), Some(2), "{flags:?}");
        assert!(String::from_utf8_lossy(&refused.stderr).contains("differs from current scope"));
    }
    let bad = Command::new(BIN)
        .args(["plan", "--no-network", "--on-drop", "warn", "--", "true"])
        .output()
        .expect("invalid value");
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn private_tty_changes_the_reviewed_scope_and_conflicts_with_detachment() {
    let inspect = |flags: &[&str]| {
        Command::new(BIN)
            .args(["plan", "--format", "json", "--no-network"])
            .args(flags)
            .args(["--", "true"])
            .output()
            .expect("plan")
    };
    let plan = |flags: &[&str]| {
        let output = inspect(flags);
        assert!(output.status.success());
        serde_json::from_slice::<Value>(&output.stdout).expect("plan JSON")
    };
    let shared = plan(&[]);
    let private = plan(&["--private-tty"]);
    assert_ne!(shared["digest"], private["digest"]);
    assert_eq!(private["plan"]["private_tty"], true);
    assert_eq!(private["plan"]["new_session"], false);
    let conflict = inspect(&["--private-tty", "--new-session"]);
    assert_eq!(conflict.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&conflict.stderr).expect("structured CLI error");
    assert_eq!(error["error"]["type"], "invalid-arguments");
}
