//! Integration tests for the DNS stub: what the command looked up, and
//! what it gets back.
//!
//! Every query goes to the stub on the sandbox's own loopback. The runs
//! with `--allow` approve documentation addresses and send nothing to
//! them; nothing is sent to another host.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

mod common;

use common::Guard;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

/// Why the sandbox cannot run here, if it cannot.
fn skip_reason(pasta: bool) -> Option<String> {
    let max = std::fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap_or_default();
    if max.trim().is_empty() || max.trim() == "0" {
        return Some("user namespaces are not available".into());
    }
    let tools: &[&str] = if pasta { &["nft", "pasta"] } else { &["nft"] };
    for tool in tools {
        if which(tool).is_none() {
            return Some(format!("{tool} is not installed"));
        }
    }
    None
}

macro_rules! require_sandbox {
    ($pasta:expr) => {
        if let Some(why) = skip_reason($pasta) {
            eprintln!("SKIPPED: {why}");
            return;
        }
    };
}

/// `tool` in the system directories or on `PATH`.
fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .iter()
        .map(PathBuf::from)
        .chain(std::env::split_paths(&path))
        .map(|d| d.join(tool))
        .find(|p| p.is_file())
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn report_path(name: &str) -> PathBuf {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("lookups-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    dir.join(format!("{name}.json"))
}

/// Runs `playpen run ARGS --report FILE -- COMMAND`; returns the output
/// and the report.
fn run(args: &[&str], report: &Path, command: &[&str]) -> (Output, Value) {
    let out = Command::new(BIN)
        .arg("run")
        .args(args)
        .arg("--report")
        .arg(report)
        .arg("--")
        .args(command)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("cannot run playpen: {e}"));
    let json = serde_json::from_slice(&std::fs::read(report).unwrap_or_default())
        .unwrap_or_else(|e| panic!("{e}: {}", text(&out.stderr)));
    (out, json)
}

fn names(report: &Value) -> Vec<(String, u64, bool)> {
    report["lookups"]["names"]
        .as_array()
        .unwrap_or_else(|| panic!("no lookups in {report}"))
        .iter()
        .map(|n| {
            (
                n["name"].as_str().unwrap_or("").to_owned(),
                n["count"].as_u64().unwrap_or(0),
                n["mapped"].as_bool().unwrap_or(true),
            )
        })
        .collect()
}

/// A DNS query in hex: ID 0xabcd, RD set, one question for `labels`.
fn query(labels: &[&[u8]], qtype: u16) -> String {
    let mut q = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in labels {
        q.push(u8::try_from(l.len()).unwrap_or(0));
        q.extend_from_slice(l);
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    hex(&q)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn probe_lines(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[test]
fn an_unmapped_lookup_fails_at_once_and_is_listed_once() {
    require_sandbox!(false);
    let report = report_path("unmapped");
    // An unanswered query would take the resolver's full second
    // (`timeout:1`); "no such name" comes back at once, as the refused
    // connection did before there was a stub.
    let script = "a=$(date +%s%N); getent hosts unmapped.example; echo rc=$?; b=$(date +%s%N); echo ms=$(( (b - a) / 1000000 ))";
    let (out, json) = run(&["--no-network"], &report, &["sh", "-c", script]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(stdout.contains("rc=2\n"), "{stdout}");
    let ms: u64 = stdout
        .lines()
        .find_map(|l| l.strip_prefix("ms="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(u64::MAX);
    assert!(ms < 500, "getent took {ms} ms");
    let found = names(&json);
    assert_eq!(found.len(), 1, "{found:?}");
    let (name, count, mapped) = &found[0];
    assert_eq!(name, "unmapped.example");
    assert!(*count >= 1);
    assert!(!mapped);
    assert_eq!(json["lookups"]["truncated"], false);
    assert!(json["lookups_error"].is_null());
    let err = text(&out.stderr);
    assert!(
        err.contains("\nplaypen:   no DNS; lookups recorded\n"),
        "{err}"
    );
    assert!(
        err.contains("playpen: The command looked up names that have no --host mapping:\n"),
        "{err}"
    );
    assert!(
        err.contains(&format!("playpen:   unmapped.example: {count} lookup(s)\n")),
        "{err}"
    );
    assert!(err.contains("map it with --host NAME=ADDR"), "{err}");

    // Never in the shareable report.
    let shared = report_path("unmapped-shared");
    let out = Command::new(BIN)
        .args(["run", "--no-network", "--shareable-report", "--report"])
        .arg(&shared)
        .args(["--", "getent", "hosts", "unmapped.example"])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    let artifact = std::fs::read_to_string(&shared).unwrap_or_default();
    assert!(artifact.contains("playpen-shareable-v1"), "{artifact}");
    assert!(!artifact.contains("unmapped"), "{artifact}");
    assert!(!artifact.contains("lookup"), "{artifact}");
}

#[test]
fn clients_that_skip_the_hosts_file_resolve_host_names_through_the_stub() {
    require_sandbox!(true);
    let Some(dig) = which("dig") else {
        eprintln!("SKIPPED: dig is not installed");
        return;
    };
    let dig = dig.display().to_string();
    let report = report_path("dig");
    let flags = "+short +tries=1 +time=1";
    let mut script = format!(
        "{dig} {flags} svc.example.test; {dig} {flags} +tcp svc.example.test; {dig} {flags} AAAA svc.example.test; {dig} +tries=1 +time=1 other.example.test | grep -o 'status: [A-Z]*'"
    );
    let node = which("node");
    if let Some(node) = &node {
        let _ = write!(
            script,
            "; {} -e 'require(\"dns\").resolve4(\"svc.example.test\", (e, a) => console.log(\"node \" + (e ? e.code : a.join(\",\"))))'",
            node.display()
        );
    } else {
        eprintln!("NOTE: node is not installed; only dig was checked");
    }
    let (out, json) = run(
        &[
            "--allow",
            "192.0.2.10:443/tcp",
            "--allow",
            "[2001:db8::10]:443/tcp",
            "--host",
            "svc.example.test=192.0.2.10",
            "--host",
            "svc.example.test=[2001:db8::10]",
        ],
        &report,
        &["sh", "-c", &script],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let mut lines = stdout.lines();
    assert_eq!(lines.next(), Some("192.0.2.10"), "{stdout}");
    assert_eq!(lines.next(), Some("192.0.2.10"), "{stdout}");
    assert_eq!(lines.next(), Some("2001:db8::10"), "{stdout}");
    assert_eq!(lines.next(), Some("status: NXDOMAIN"), "{stdout}");
    if node.is_some() {
        assert_eq!(lines.next(), Some("node 192.0.2.10"), "{stdout}");
    }
    let found = names(&json);
    let svc = found
        .iter()
        .find(|n| n.0 == "svc.example.test")
        .unwrap_or_else(|| panic!("{found:?}"));
    assert!(svc.2, "a --host name is mapped: {found:?}");
    assert!(svc.1 >= 3, "{found:?}");
    assert!(
        found.contains(&("other.example.test".into(), 1, false)),
        "{found:?}"
    );
    let err = text(&out.stderr);
    assert!(
        err.contains("playpen:   other.example.test: 1 lookup(s)\n"),
        "{err}"
    );
    assert!(!err.contains("svc.example.test: "), "{err}");
}

#[test]
fn hostile_names_never_reach_the_terminal_or_the_report_raw() {
    require_sandbox!(false);
    let report = report_path("hostile");
    let title: &[u8] = b"\x1b]0;owned\x07";
    let clear: &[u8] = b"\x1b[2J\x1b[H";
    let a = [b'a'; 63];
    let esc = [0x1b_u8; 61];
    // A label length of 70 is no label: the message is malformed.
    let mut overlong = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 70];
    overlong.extend_from_slice(&[b'a'; 70]);
    overlong.extend_from_slice(&[0, 0, 1, 0, 1]);
    let messages = [
        ("", query(&[title, b"test"], 1)),
        ("--tcp", query(&[clear, b"test"], 28)),
        ("", hex(&overlong)),
        // 255 bytes on the wire; 436 once escaped.
        ("", query(&[&a, &a, &a, &esc], 1)),
        ("", query(&[b"after", b"test"], 1)),
    ];
    let script: Vec<String> = messages
        .iter()
        .map(|(flag, q)| format!("{BIN} probe dns {flag} {q}"))
        .collect();
    let (out, json) = run(
        &["--no-network"],
        &report,
        &["sh", "-c", &script.join("; ")],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let replies = probe_lines(&text(&out.stdout));
    let rcodes: Vec<Option<u64>> = replies.iter().map(|r| r["rcode"].as_u64()).collect();
    // NXDOMAIN for each name, FORMERR for the malformed message; the stub
    // still answers after it.
    assert_eq!(
        rcodes,
        [Some(3), Some(3), Some(1), Some(3), Some(3)],
        "{replies:?}"
    );
    for raw in [&out.stderr, &std::fs::read(&report).unwrap_or_default()] {
        assert!(
            !raw.iter().any(|&b| b == 0x1b || b == 0x07),
            "a control byte got through: {}",
            text(raw)
        );
    }
    let found: Vec<String> = names(&json).into_iter().map(|n| n.0).collect();
    assert_eq!(
        found.len(),
        4,
        "the malformed one is not recorded: {found:?}"
    );
    assert_eq!(found[0], "\\027\\0930\\059owned\\007.test");
    assert_eq!(found[1], "\\027\\0912j\\027\\091h.test");
    assert!(found[2].len() <= 253, "{}", found[2]);
    assert!(found[2].starts_with(&format!("{}.", "a".repeat(63))));
    assert!(found[2].ends_with("\\027..."), "{}", found[2]);
    assert_eq!(found[3], "after.test");
    let err = text(&out.stderr);
    assert!(
        err.contains("playpen:   \\027\\0930\\059owned\\007.test: 1 lookup(s)\n"),
        "{err}"
    );
}

/// The pids of the children of `parent`, in ascending order.
fn children(parent: u32) -> Vec<u32> {
    let raw = std::fs::read_to_string(format!("/proc/{parent}/task/{parent}/children"))
        .unwrap_or_default();
    let mut found: Vec<u32> = raw
        .split_whitespace()
        .filter_map(|n| n.parse().ok())
        .collect();
    found.sort_unstable();
    found
}

#[test]
fn the_command_can_neither_see_nor_signal_the_stub() {
    require_sandbox!(false);
    let report = report_path("unseen");
    let handoff = report_path("unseen-pid").with_extension("txt");
    let _ = std::fs::remove_file(&handoff);
    // The socket on 127.0.0.1:53 is in this network namespace, but no
    // process the command can list holds it. Then the command is given the
    // stub's PID on the host and tries to signal it.
    let script = format!(
        r#"udp=$(awk '$2 == "0100007F:0035" {{ print $10 }}' /proc/net/udp)
tcp=$(awk '$2 == "0100007F:0035" && $4 == "0A" {{ print $10 }}' /proc/net/tcp)
echo "inodes=$udp,$tcp"
held=0
for fd in /proc/[0-9]*/fd/*; do
  case "$(readlink "$fd" 2>/dev/null)" in "socket:[$udp]"|"socket:[$tcp]") held=$((held + 1));; esac
done
echo "held=$held"
while [ ! -s {handoff} ]; do sleep 0.02; done
kill -TERM "$(cat {handoff})" 2>/dev/null; echo "kill=$?"
kill -0 "$(cat {handoff})" 2>/dev/null; echo "seen=$?"
getent hosts after-the-kill.example; echo "rc=$?""#,
        handoff = handoff.display()
    );
    let mut child = Guard::spawn(
        Command::new(BIN)
            .args(["run", "--no-network", "--report"])
            .arg(&report)
            .args(["--", "sh", "-c", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap_or_else(|e| panic!("cannot run playpen: {e}"));
    // P -> C -> (the stub, S): the stub is C's child without children.
    let deadline = Instant::now() + Duration::from_secs(10);
    let stub = loop {
        let found = children(child.id())
            .first()
            .map(|&c| children(c))
            .and_then(|of_c| {
                (of_c.len() == 2)
                    .then(|| of_c.into_iter().find(|&p| children(p).is_empty()))
                    .flatten()
            });
        if let Some(stub) = found {
            break stub;
        }
        assert!(Instant::now() < deadline, "no stub process found");
        std::thread::sleep(Duration::from_millis(20));
    };
    // The stub holds no capability and cannot gain one.
    let status = std::fs::read_to_string(format!("/proc/{stub}/status")).unwrap_or_default();
    for (key, want) in [
        ("CapPrm:", "0000000000000000"),
        ("CapEff:", "0000000000000000"),
        ("NoNewPrivs:", "1"),
    ] {
        let got = status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map_or_else(|| panic!("no {key} in {status}"), str::trim);
        assert_eq!(got, want, "{key}");
    }
    std::fs::write(&handoff, stub.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let out = child.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let inodes = stdout
        .lines()
        .find_map(|l| l.strip_prefix("inodes="))
        .unwrap_or_default();
    assert!(
        inodes
            .split(',')
            .all(|i| i.parse::<u64>().is_ok_and(|n| n > 0)),
        "the stub's sockets are not in /proc/net: {stdout}"
    );
    assert!(stdout.contains("held=0\n"), "{stdout}");
    assert!(stdout.contains("kill=1\n"), "{stdout}");
    assert!(stdout.contains("seen=1\n"), "{stdout}");
    assert!(stdout.contains("rc=2\n"), "{stdout}");
    // The stub ran to the end and sent its record.
    let found: Vec<String> = names(&json_of(&report)).into_iter().map(|n| n.0).collect();
    assert_eq!(found, ["after-the-kill.example"]);
}

fn json_of(report: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(report).unwrap_or_default()).unwrap_or_default()
}

#[test]
fn compare_treats_unmapped_lookups_as_observations() {
    let dir = report_path("compare").with_extension("");
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    let before = dir.join("before.json");
    let after = dir.join("after.json");
    let entry =
        |name: &str, mapped: bool| serde_json::json!({"name": name, "count": 1, "mapped": mapped});
    let report = |names: Vec<Value>, truncated: bool| serde_json::json!({"playpen_version":"0.1.0", "outcome":"ran", "allowed":["192.0.2.1:80/tcp"], "network":"pasta", "hosts":["svc.test=192.0.2.1"], "exposed":[], "socket_guard":"landlock", "display":false, "dropped":{"packets":0,"destinations_truncated":false,"destinations":[]}, "lookups":{"names":names,"truncated":truncated}});
    let compare = |a: &Value, b: &Value| {
        std::fs::write(&before, a.to_string()).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(&after, b.to_string()).unwrap_or_else(|e| panic!("{e}"));
        let out = Command::new(BIN)
            .arg("compare")
            .arg(&before)
            .arg(&after)
            .args(["--format", "json"])
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
        (out.status.code(), v)
    };
    let base = report(vec![entry("svc.test", true), entry("a.test", false)], false);
    // A newly looked-up unmapped name is new, like a new denial.
    let more = report(
        vec![
            entry("svc.test", true),
            entry("a.test", false),
            entry("b.test", false),
        ],
        false,
    );
    let (code, v) = compare(&base, &more);
    assert_eq!(code, Some(1), "{v}");
    assert_eq!(v["new_unmapped_lookups"], serde_json::json!(["b.test"]));
    assert_eq!(v["evidence"], "complete");
    // One no longer looked up is reported, and is not a failure.
    let fewer = report(vec![entry("svc.test", true)], false);
    let (code, v) = compare(&base, &fewer);
    assert_eq!(code, Some(0), "{v}");
    assert_eq!(
        v["unmapped_lookups_no_longer_observed"],
        serde_json::json!(["a.test"])
    );
    // Mapped names and counts are not observations of failure.
    let (code, _) = compare(&base, &report(vec![entry("a.test", false)], false));
    assert_eq!(code, Some(0));
    // A missing list and an entry no stub could have written are
    // incomplete evidence; nothing is claimed from them.
    let hostile = report(vec![entry("\u{1b}[2J", false)], false);
    let mut missing = base.clone();
    missing.as_object_mut().map(|o| o.remove("lookups"));
    for later in [&missing, &hostile] {
        let (code, v) = compare(&base, later);
        assert_eq!(code, Some(2), "{v}");
        assert_eq!(v["evidence"], "incomplete");
        assert_eq!(v["new_unmapped_lookups"], serde_json::json!([]));
        assert_eq!(
            v["unmapped_lookups_no_longer_observed"],
            serde_json::json!([])
        );
        assert!(!v.to_string().contains('\u{1b}'), "{v}");
    }
    // A truncated list is incomplete too, but what it does list is still
    // observed: a new name in it is new, and nothing counts as gone.
    let (code, v) = compare(&base, &report(vec![entry("c.test", false)], true));
    assert_eq!(code, Some(1), "{v}");
    assert_eq!(v["evidence"], "incomplete");
    assert_eq!(v["new_unmapped_lookups"], serde_json::json!(["c.test"]));
    assert_eq!(
        v["unmapped_lookups_no_longer_observed"],
        serde_json::json!([])
    );
    // Text output too.
    std::fs::write(&after, hostile.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let out = Command::new(BIN)
        .arg("compare")
        .arg(&before)
        .arg(&after)
        .args(["--format", "text"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(!out.stdout.contains(&0x1b), "{}", text(&out.stdout));
    std::fs::write(&after, more.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let out = Command::new(BIN)
        .arg("compare")
        .arg(&before)
        .arg(&after)
        .args(["--format", "text"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        text(&out.stdout).contains("new-lookup  b.test\n"),
        "{}",
        text(&out.stdout)
    );
}
