//! `playpen compare` names the policy fields that differ.
//!
//! The reports are written by hand; no sandbox runs.

use std::process::Command;

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

fn report(allowed: &[&str], hosts: &[&str], network: &str, exposed: &[&str]) -> Value {
    json!({"playpen_version":"0.1.0", "outcome":"ran", "allowed":allowed, "network":network,
        "hosts":hosts, "exposed":exposed, "socket_guard":"landlock", "display":false,
        "dropped":{"packets":0,"destinations_truncated":false,"destinations":[]},
        "lookups":{"names":[],"truncated":false}})
}

fn compare(name: &str, a: &Value, b: &Value, format: &str) -> (Option<i32>, String) {
    let dir = std::env::temp_dir().join(format!("playpen-compare-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    let (before, after) = (dir.join("before.json"), dir.join("after.json"));
    std::fs::write(&before, a.to_string()).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(&after, b.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let out = Command::new(BIN)
        .arg("compare")
        .arg(&before)
        .arg(&after)
        .args(["--format", format])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = std::fs::remove_dir_all(&dir);
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn compare_lists_added_and_removed_policy_items() {
    let wide = report(
        &["192.0.2.0/24:1-65535/tcp"],
        &["a.test=192.0.2.1", "b.test=192.0.2.2"],
        "pasta",
        &["/run/x"],
    );
    let narrow = report(
        &["192.0.2.1:80/tcp", "192.0.2.2:80/tcp"],
        &["a.test=192.0.2.1", "c.test=192.0.2.3"],
        "none",
        &[],
    );
    let (code, out) = compare("json", &wide, &narrow, "json");
    assert_eq!(code, Some(2), "{out}");
    let v: Value = serde_json::from_str(&out).unwrap_or_default();
    assert_eq!(v["policy"], "changed");
    let c = &v["policy_changes"];
    assert_eq!(
        c["allowed"],
        json!({"added":["192.0.2.1:80/tcp","192.0.2.2:80/tcp"],"removed":["192.0.2.0/24:1-65535/tcp"]})
    );
    assert_eq!(
        c["hosts"],
        json!({"added":["c.test=192.0.2.3"],"removed":["b.test=192.0.2.2"]})
    );
    assert_eq!(c["network"], json!({"before":"pasta","after":"none"}));
    assert_eq!(c["exposed"], json!({"added":[],"removed":["/run/x"]}));
    assert!(c.get("socket_guard").is_none(), "{c}");

    let (code, out) = compare("text", &wide, &narrow, "text");
    assert_eq!(code, Some(2));
    for line in [
        "policy-change  added  allowed  192.0.2.1:80/tcp",
        "policy-change  removed  allowed  192.0.2.0/24:1-65535/tcp",
        "policy-change  removed  hosts  b.test=192.0.2.2",
        "policy-change  changed  network  pasta  ->  none",
        "policy-change  removed  exposed  /run/x",
    ] {
        assert!(out.lines().any(|l| l == line), "missing {line:?}: {out}");
    }
    let (_, out) = compare("pretty", &wide, &narrow, "pretty");
    assert!(
        out.contains("policy change: added allowed 192.0.2.1:80/tcp"),
        "{out}"
    );
}

#[test]
fn compare_of_the_same_policy_lists_no_changes() {
    let r = report(&["192.0.2.1:80/tcp"], &[], "pasta", &[]);
    let (code, out) = compare("same", &r, &r, "json");
    assert_eq!(code, Some(0), "{out}");
    let v: Value = serde_json::from_str(&out).unwrap_or_default();
    assert_eq!(v["policy"], "same");
    assert_eq!(v["policy_changes"], json!({}));
}
