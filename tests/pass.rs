//! Integration tests for `--pass`: run the built binary with a hallpass
//! pass written by the test.
//!
//! As in `run.rs`, every destination is a documentation address added to
//! the sandbox's own `lo` (hidden `--lo-addr`), so nothing leaves the
//! machine even if the filter were broken. Windows are set relative to the
//! real clock (an hour either side), so no test clock is needed.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

fn skip_reason() -> Option<String> {
    let max = std::fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap_or_default();
    if max.trim().is_empty() || max.trim() == "0" {
        return Some("user namespaces are not available".into());
    }
    for tool in ["nft", "pasta"] {
        let found = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
            .iter()
            .any(|d| Path::new(d).join(tool).exists());
        if !found {
            return Some(format!("{tool} is not installed"));
        }
    }
    None
}

macro_rules! require_sandbox {
    () => {
        if let Some(why) = skip_reason() {
            eprintln!("SKIPPED: {why}");
            return;
        }
    };
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn tmpdir(name: &str) -> PathBuf {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("pass-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn stamp(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .unwrap_or(t)
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn hours(h: i64) -> String {
    stamp(OffsetDateTime::now_utc() + time::Duration::hours(h))
}

fn secs_from_now(s: i64) -> String {
    stamp(OffsetDateTime::now_utc() + time::Duration::seconds(s))
}

const WEB: &str = r#"
[[destination]]
label = "web"
address = "192.0.2.1"
protocol = "tcp"
ports = [9101, "9103-9104"]
hostname = "app.example.test"
"#;

const SIP: &str = r#"
[[destination]]
label = "sip"
address = "192.0.2.2"
protocol = "udp"
ports = 5060
"#;

const V6: &str = r#"
[[destination]]
label = "v6"
network = "2001:db8::/120"
protocol = "tcp"
ports = 9301
"#;

/// A pass valid from `from` until `until`, with these destinations.
fn pass_text(from: &str, until: &str, revoked: bool, destinations: &[&str]) -> String {
    format!(
        "format = 1\nid = \"test-pass-1\"\nname = \"Practice range\"\n\n[approval]\nowner = \"Pat Owner, Example Corp\"\nreference = \"email of 2026-11-18\"\noperator = \"Sam Tester\"\nvalid_from = {from}\nvalid_until = {until}\nrevoked = {revoked}\n{}\n[ceilings]\ncalls = 6\n",
        destinations.join("")
    )
}

fn valid_pass(destinations: &[&str]) -> String {
    pass_text(&hours(-1), &hours(1), false, destinations)
}

/// Writes `contents` to `path` with mode 0600, atomically (a new file
/// renamed over the old one), so a re-read never sees half a file.
fn write_pass(path: &Path, contents: &str) {
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .unwrap_or_else(|e| panic!("cannot create {}: {e}", tmp.display()));
    f.write_all(contents.as_bytes())
        .unwrap_or_else(|e| panic!("{e}"));
    drop(f);
    std::fs::rename(&tmp, path).unwrap_or_else(|e| panic!("{e}"));
}

fn new_pass(dir: &Path, contents: &str) -> PathBuf {
    let path = dir.join("test.pass.toml");
    write_pass(&path, contents);
    path
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap_or("")
}

const LO: &[&str] = &[
    "--lo-addr",
    "192.0.2.1",
    "--lo-addr",
    "192.0.2.2",
    "--lo-addr",
    "2001:db8::1",
];

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("cannot run playpen: {e}"))
}

fn spawn(args: &[&str]) -> Child {
    Command::new(BIN)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run playpen: {e}"))
}

fn report(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_default()).unwrap_or_default()
}

fn parse_reach(stdout: &str) -> Vec<(String, bool)> {
    stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| {
            (
                v["target"].as_str().unwrap_or("").to_owned(),
                v["reached"].as_bool().unwrap_or(true),
            )
        })
        .collect()
}

fn reached(results: &[(String, bool)], target: &str) -> bool {
    results.iter().find(|(t, _)| t == target).map_or_else(
        || panic!("no result for {target} in {results:?}"),
        |(_, r)| *r,
    )
}

/// Runs a reach probe under `extra` (`--pass FILE` and so on); every
/// target is both served and tried.
fn reach(extra: &[&str], targets: &[&str]) -> (Vec<(String, bool)>, Output) {
    let mut args = vec!["run"];
    args.extend_from_slice(extra);
    args.extend_from_slice(LO);
    args.extend_from_slice(&["--", BIN, "probe", "reach"]);
    for t in targets {
        args.extend_from_slice(&["--serve", t]);
    }
    for t in targets {
        args.extend_from_slice(&["--try", t]);
    }
    let out = run(&args);
    (parse_reach(&text(&out.stdout)), out)
}

/// Asserts a refusal: exit 2, `expect` and "nothing was run" on stderr,
/// the command not run, and a report with outcome "refused".
fn assert_refused(extra: &[&str], expect: &str) {
    let dir = tmpdir(&format!(
        "refused-{}",
        expect.replace(|c: char| !c.is_ascii_alphanumeric(), "")
    ));
    let marker = dir.join("ran");
    let _ = std::fs::remove_file(&marker);
    let rep = dir.join("report.json");
    let mut args = vec!["run"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--report", s(&rep), "--", "touch", s(&marker)]);
    let out = run(&args);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains(expect), "expected {expect:?} in: {err}");
    assert!(err.contains("nothing was run"), "{err}");
    assert!(!marker.exists(), "the command ran");
    let json = report(&rep);
    assert_eq!(json["outcome"], "refused", "{json}");
}

#[test]
fn pass_destinations_are_reachable_and_nothing_else_and_the_report_names_the_pass() {
    require_sandbox!();
    let dir = tmpdir("reach");
    let pass = new_pass(&dir, &valid_pass(&[WEB, SIP, V6]));
    let rep = dir.join("report.json");
    let (r, out) = reach(
        &["--pass", s(&pass), "--report", s(&rep)],
        &[
            "192.0.2.1:9101/tcp",
            "192.0.2.1:9104/tcp",
            "192.0.2.1:9102/tcp",
            "192.0.2.1:9101/udp",
            "192.0.2.2:5060/udp",
            "192.0.2.2:9101/tcp",
            "[2001:db8::1]:9301/tcp",
            "[2001:db8::1]:9302/tcp",
        ],
    );
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(reached(&r, "192.0.2.1:9101/tcp"));
    assert!(reached(&r, "192.0.2.1:9104/tcp"));
    assert!(!reached(&r, "192.0.2.1:9102/tcp"));
    assert!(!reached(&r, "192.0.2.1:9101/udp"));
    assert!(reached(&r, "192.0.2.2:5060/udp"));
    assert!(!reached(&r, "192.0.2.2:9101/tcp"));
    assert!(reached(&r, "[2001:db8::1]:9301/tcp"));
    assert!(!reached(&r, "[2001:db8::1]:9302/tcp"));

    // The start line names the pass and says nothing about ceilings.
    let start = err
        .lines()
        .find(|l| l.contains("allowing only"))
        .unwrap_or_default();
    assert!(start.contains("under pass test-pass-1"), "{start}");
    assert!(
        start.contains("owner \"Pat Owner, Example Corp\""),
        "{start}"
    );
    assert!(start.contains("destinations web, sip, v6"), "{start}");
    assert!(start.contains("sha256:"), "{start}");
    assert!(!start.contains("calls"), "{start}");
    assert!(!start.contains("ceiling"), "{start}");
    // The host name is not used, but the operator is told how to map it.
    assert!(
        start.contains("--host app.example.test=192.0.2.1"),
        "{start}"
    );
    assert!(
        start.contains("--pass-hosts maps the name of each single-address destination"),
        "{start}"
    );

    let json = report(&rep);
    assert_eq!(json["outcome"], "ran");
    let p = &json["pass"];
    assert_eq!(p["file"], s(&pass));
    assert_eq!(p["id"], "test-pass-1");
    assert_eq!(p["name"], "Practice range");
    assert_eq!(p["owner"], "Pat Owner, Example Corp");
    assert!(p["digest"].as_str().unwrap_or("").starts_with("sha256:"));
    assert_eq!(p["labels"], serde_json::json!(["web", "sip", "v6"]));
    assert_eq!(p["valid_until"], json["until"]);
    assert_eq!(
        json["allowed"],
        serde_json::json!([
            "192.0.2.1:9101/tcp",
            "192.0.2.1:9103-9104/tcp",
            "192.0.2.2:5060/udp",
            "[2001:db8::/120]:9301/tcp"
        ])
    );
    assert_eq!(json["stopped_by_pass"], false);
    // Dropped-packet reporting is unchanged.
    assert!(
        json["dropped"]["packets"].as_u64().unwrap_or(0) >= 1,
        "{json}"
    );
}

#[test]
fn only_narrows_to_the_named_destinations() {
    require_sandbox!();
    let dir = tmpdir("only");
    let pass = new_pass(&dir, &valid_pass(&[WEB, SIP]));
    let rep = dir.join("report.json");
    let (r, out) = reach(
        &["--pass", s(&pass), "--only", "sip", "--report", s(&rep)],
        &["192.0.2.1:9101/tcp", "192.0.2.2:5060/udp"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(!reached(&r, "192.0.2.1:9101/tcp"));
    assert!(reached(&r, "192.0.2.2:5060/udp"));
    assert_eq!(report(&rep)["pass"]["labels"], serde_json::json!(["sip"]));
}

#[test]
fn unknown_label_is_refused() {
    let dir = tmpdir("unknown-label");
    let pass = new_pass(&dir, &valid_pass(&[WEB, SIP]));
    assert_refused(
        &["--pass", s(&pass), "--only", "sip", "--only", "nope"],
        "the pass has no destination with this label; its labels are web, sip",
    );
}

#[test]
fn pass_with_allow_is_refused_and_says_why() {
    let dir = tmpdir("with-allow");
    let pass = new_pass(&dir, &valid_pass(&[WEB]));
    assert_refused(
        &["--pass", s(&pass), "--allow", "192.0.2.9:443/tcp"],
        "would add a destination the owner did not approve",
    );
    assert_refused(
        &["--only", "web", "--allow", "192.0.2.9:443/tcp"],
        "needs --pass FILE",
    );
    assert_refused(&["--pass", s(&pass), "--no-network"], "contradict");
}

#[test]
fn passes_that_permit_nothing_refuse_and_run_nothing() {
    let dir = tmpdir("bad-passes");
    let expired = dir.join("expired.pass.toml");
    write_pass(&expired, &pass_text(&hours(-3), &hours(-1), false, &[WEB]));
    assert_refused(&["--pass", s(&expired)], "expired");

    let early = dir.join("early.pass.toml");
    write_pass(&early, &pass_text(&hours(1), &hours(3), false, &[WEB]));
    assert_refused(&["--pass", s(&early)], "not-yet-valid");

    let revoked = dir.join("revoked.pass.toml");
    write_pass(&revoked, &pass_text(&hours(-1), &hours(1), true, &[WEB]));
    assert_refused(&["--pass", s(&revoked)], "revoked");

    let invalid = dir.join("invalid.pass.toml");
    write_pass(
        &invalid,
        &valid_pass(&[WEB]).replace("address = \"192.0.2.1\"", "address = \"app.example.test\""),
    );
    assert_refused(&["--pass", s(&invalid)], "invalid-pass");
    assert_refused(&["--pass", s(&invalid)], "destination[1].address");

    let link = dir.join("link.pass.toml");
    let target = dir.join("real.pass.toml");
    write_pass(&target, &valid_pass(&[WEB]));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|e| panic!("{e}"));
    assert_refused(&["--pass", s(&link)], "symbolic link");

    let open = dir.join("open.pass.toml");
    write_pass(&open, &valid_pass(&[WEB]));
    std::fs::set_permissions(&open, std::os::unix::fs::PermissionsExt::from_mode(0o666))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_refused(&["--pass", s(&open)], "insecure-permissions");

    assert_refused(
        &["--pass", s(&dir.join("missing.pass.toml"))],
        "no such file",
    );

    // playpen cannot enforce a loopback destination (hallpass accepts one
    // when listed); it refuses rather than drop it silently.
    let lo = dir.join("lo.pass.toml");
    write_pass(&lo, &valid_pass(&[&WEB.replace("192.0.2.1", "127.0.0.1")]));
    assert_refused(&["--pass", s(&lo)], "loopback");
}

#[test]
fn a_later_until_is_refused() {
    let dir = tmpdir("later-until");
    let pass = new_pass(&dir, &valid_pass(&[WEB]));
    assert_refused(
        &["--pass", s(&pass), "--until", &hours(2)],
        "can only end the run earlier",
    );
}

#[test]
fn an_earlier_until_is_honoured() {
    require_sandbox!();
    let dir = tmpdir("earlier-until");
    let pass = new_pass(&dir, &valid_pass(&[WEB]));
    let rep = dir.join("report.json");
    let until = secs_from_now(2);
    let started = Instant::now();
    let out = run(&[
        "run",
        "--pass",
        s(&pass),
        "--until",
        &until,
        "--report",
        s(&rep),
        "--",
        "sleep",
        "30",
    ]);
    let took = started.elapsed();
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(128 + 15), "{err}");
    assert!(took < Duration::from_secs(8), "took {took:?}");
    assert!(err.contains("approval ended"), "{err}");
    let json = report(&rep);
    assert_eq!(json["stopped_by_until"], true);
    assert_eq!(json["stopped_by_pass"], false);
    assert_eq!(json["until"].as_str(), Some(until.as_str()));
    assert_ne!(json["until"], json["pass"]["valid_until"]);
}

const RECHECK_MS: &str = "200";

/// Starts `sleep 30` under the pass, waits `after`, applies `change`, and
/// returns playpen's output, how long the whole run took, and the report.
fn run_then(
    pass: &Path,
    after: Duration,
    change: impl FnOnce(),
) -> (Output, Duration, serde_json::Value) {
    run_cmd_then(pass, &["sleep", "30"], after, change)
}

/// Like [`run_then`], with any command.
fn run_cmd_then(
    pass: &Path,
    command: &[&str],
    after: Duration,
    change: impl FnOnce(),
) -> (Output, Duration, serde_json::Value) {
    let rep = pass.with_extension("report.json");
    let started = Instant::now();
    let mut args = vec![
        "run",
        "--pass",
        s(pass),
        "--pass-recheck-ms",
        RECHECK_MS,
        "--report",
        s(&rep),
        "--",
    ];
    args.extend_from_slice(command);
    let child = spawn(&args);
    std::thread::sleep(after);
    change();
    let out = child.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
    (out, started.elapsed(), report(&rep))
}

#[test]
fn revoking_the_pass_stops_the_command() {
    require_sandbox!();
    let dir = tmpdir("revoke");
    let contents = valid_pass(&[WEB]);
    let pass = new_pass(&dir, &contents);
    let (out, took, json) = run_then(&pass, Duration::from_secs(1), || {
        write_pass(
            &pass,
            &contents.replace("revoked = false", "revoked = true"),
        );
    });
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(128 + 15), "{err}");
    // 1 s before the edit, then at most the interval and the grace.
    assert!(
        took < Duration::from_millis(1000 + 200 + 3000 + 1500),
        "took {took:?}"
    );
    assert!(err.contains("revoked"), "{err}");
    assert!(err.contains("SIGTERM"), "{err}");
    assert_eq!(json["stopped_by_pass"], true);
    assert_eq!(json["stopped_by_until"], false);
    assert!(
        json["stop_reason"]
            .as_str()
            .unwrap_or("")
            .contains("revoked"),
        "{json}"
    );
}

#[test]
fn deleting_the_pass_stops_the_command() {
    require_sandbox!();
    let dir = tmpdir("delete");
    let pass = new_pass(&dir, &valid_pass(&[WEB]));
    let (out, took, json) = run_then(&pass, Duration::from_secs(1), || {
        std::fs::remove_file(&pass).unwrap_or_else(|e| panic!("{e}"));
    });
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(128 + 15), "{err}");
    assert!(took < Duration::from_millis(5700), "took {took:?}");
    assert!(err.contains("can no longer be read"), "{err}");
    assert_eq!(json["stopped_by_pass"], true);
}

#[test]
fn a_revoked_pass_kills_a_command_that_ignores_sigterm() {
    require_sandbox!();
    let dir = tmpdir("revoke-kill");
    let contents = valid_pass(&[WEB]);
    let pass = new_pass(&dir, &contents);
    let (out, took, json) = run_cmd_then(
        &pass,
        &["sh", "-c", "trap '' TERM; while :; do sleep 0.2; done"],
        Duration::from_millis(800),
        || {
            write_pass(
                &pass,
                &contents.replace("revoked = false", "revoked = true"),
            );
        },
    );
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(128 + 9), "{err}");
    // The grace must have been waited out before SIGKILL...
    assert!(took >= Duration::from_millis(800 + 3000), "took {took:?}");
    // ...and not much more than the edit, one interval and the grace.
    assert!(
        took < Duration::from_millis(800 + 200 + 3000 + 1500),
        "took {took:?}"
    );
    assert!(err.contains("revoked"), "{err}");
    assert!(err.contains("SIGKILL"), "{err}");
    assert_eq!(json["stopped_by_pass"], true);
    assert_eq!(json["signal"], 9);
}

#[test]
fn a_pass_swapped_for_a_symlink_stops_the_command() {
    require_sandbox!();
    let dir = tmpdir("swap-symlink");
    let contents = valid_pass(&[WEB]);
    let pass = new_pass(&dir, &contents);
    // The link points at an identical, valid pass: only the link itself
    // is wrong.
    let target = dir.join("elsewhere.pass.toml");
    write_pass(&target, &contents);
    let (out, took, json) = run_then(&pass, Duration::from_millis(800), || {
        let tmp = dir.join("link.tmp");
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(&target, &tmp).unwrap_or_else(|e| panic!("{e}"));
        std::fs::rename(&tmp, &pass).unwrap_or_else(|e| panic!("{e}"));
    });
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(128 + 15), "{err}");
    assert!(took < Duration::from_millis(5500), "took {took:?}");
    assert!(err.contains("symlink"), "{err}");
    assert_eq!(json["stopped_by_pass"], true);
}

#[test]
fn a_pass_made_writable_by_others_stops_the_command() {
    use std::os::unix::fs::PermissionsExt as _;
    require_sandbox!();
    for mode in [0o620, 0o602] {
        let dir = tmpdir(&format!("chmod-{mode:o}"));
        let pass = new_pass(&dir, &valid_pass(&[WEB]));
        let (out, took, json) = run_then(&pass, Duration::from_millis(800), || {
            std::fs::set_permissions(&pass, std::fs::Permissions::from_mode(mode))
                .unwrap_or_else(|e| panic!("{e}"));
        });
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(128 + 15), "mode {mode:o}: {err}");
        assert!(took < Duration::from_millis(5500), "took {took:?}");
        assert!(err.contains("insecure-permissions"), "{err}");
        assert_eq!(json["stopped_by_pass"], true);
    }
}

#[test]
fn editing_a_destination_in_use_stops_the_command() {
    require_sandbox!();
    let dir = tmpdir("edit-in-use");
    let contents = valid_pass(&[WEB, SIP]);
    let pass = new_pass(&dir, &contents);
    let (out, took, json) = run_then(&pass, Duration::from_millis(800), || {
        write_pass(&pass, &contents.replace("ports = 5060", "ports = 5061"));
    });
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(128 + 15), "{err}");
    assert!(took < Duration::from_millis(5500), "took {took:?}");
    assert!(err.contains("destination `sip`"), "{err}");
    assert_eq!(json["stopped_by_pass"], true);
}

#[test]
fn a_harmless_edit_keeps_the_run_under_the_rules_loaded_at_start() {
    require_sandbox!();
    let dir = tmpdir("harmless");
    let before = valid_pass(&[WEB]);
    let pass = new_pass(&dir, &before);
    // After the edit: a raised ceiling, a later window end, and a new
    // destination. The run continues, and the new destination stays
    // blocked: an edit never widens the rules in the kernel.
    let after =
        pass_text(&hours(-1), &hours(5), false, &[WEB, SIP]).replace("calls = 6", "calls = 60");
    let rep = dir.join("report.json");
    let started = Instant::now();
    let script = format!(
        "sleep 1.2; exec {BIN} probe reach --serve 192.0.2.2:5060/udp --serve 192.0.2.1:9101/tcp --try 192.0.2.2:5060/udp --try 192.0.2.1:9101/tcp"
    );
    let mut args = vec![
        "run",
        "--pass",
        s(&pass),
        "--pass-recheck-ms",
        RECHECK_MS,
        "--report",
        s(&rep),
    ];
    args.extend_from_slice(LO);
    args.extend_from_slice(&["--", "sh", "-c", &script]);
    let child = spawn(&args);
    std::thread::sleep(Duration::from_millis(400));
    write_pass(&pass, &after);
    let out = child.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
    let took = started.elapsed();
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(took < Duration::from_secs(6), "took {took:?}");
    assert!(
        err.contains("continues under the rules loaded at start"),
        "{err}"
    );
    let r = parse_reach(&text(&out.stdout));
    assert!(reached(&r, "192.0.2.1:9101/tcp"));
    assert!(!reached(&r, "192.0.2.2:5060/udp"));
    let json = report(&rep);
    assert_eq!(json["stopped_by_pass"], false);
    assert_eq!(
        json["allowed"],
        serde_json::json!(["192.0.2.1:9101/tcp", "192.0.2.1:9103-9104/tcp"])
    );
}

#[test]
fn host_must_map_to_an_address_in_the_pass() {
    let dir = tmpdir("host");
    let pass = new_pass(&dir, &valid_pass(&[WEB, SIP]));
    assert_refused(
        &["--pass", s(&pass), "--host", "app.example.test=192.0.2.77"],
        "is not in any destination of the pass in use",
    );
    // An address of the pass outside --only is not in use either.
    assert_refused(
        &[
            "--pass",
            s(&pass),
            "--only",
            "web",
            "--host",
            "sip.example.test=192.0.2.2",
        ],
        "is not in any destination of the pass in use (web)",
    );
}

#[test]
fn host_mapped_to_a_pass_address_resolves() {
    require_sandbox!();
    let dir = tmpdir("host-ok");
    let pass = new_pass(&dir, &valid_pass(&[WEB]));
    let out = run(&[
        "run",
        "--pass",
        s(&pass),
        "--host",
        "app.example.test=192.0.2.1",
        "--",
        BIN,
        "probe",
        "resolve",
        "app.example.test",
    ]);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(
        text(&out.stdout).contains("192.0.2.1"),
        "{}",
        text(&out.stdout)
    );
    // Once mapped, the start line no longer suggests mapping it.
    assert!(!err.contains("map them with"), "{err}");
}

#[test]
fn rules_prints_the_ruleset_for_a_pass() {
    let dir = tmpdir("rules");
    let pass = new_pass(&dir, &valid_pass(&[WEB, SIP]));
    let out = run(&["rules", "--pass", s(&pass), "--only", "sip"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let ruleset = text(&out.stdout);
    assert!(
        ruleset.contains("ip daddr 192.0.2.2 udp dport 5060 accept"),
        "{ruleset}"
    );
    assert!(!ruleset.contains("192.0.2.1"), "{ruleset}");

    let out = run(&["rules", "--pass", s(&pass), "--format", "json"]);
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(json["pass"]["id"], "test-pass-1");
    assert_eq!(json["allowed"].as_array().map(Vec::len), Some(3));

    let out = run(&["rules", "--pass", s(&pass), "--allow", "192.0.2.9:1/tcp"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(text(&out.stdout), "");
    let out = run(&["rules", "--pass", s(&pass), "--only", "nope"]);
    assert_eq!(out.status.code(), Some(2));
    let revoked = dir.join("revoked.pass.toml");
    write_pass(&revoked, &pass_text(&hours(-1), &hours(1), true, &[WEB]));
    let out = run(&["rules", "--pass", s(&revoked)]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("revoked"));
}

#[test]
fn a_pass_that_limits_names_is_enforced_by_address_only_and_playpen_says_so() {
    require_sandbox!();
    let dir = tmpdir("names");
    let web = WEB.replace(
        "hostname = \"app.example.test\"",
        "names = [\"app.example.test\", \"admin.example.test\"]",
    );
    assert!(web.contains("names = "));
    let pass = new_pass(&dir, &valid_pass(&[&web, SIP]));
    let (r, out) = reach(
        &["--pass", s(&pass)],
        &["192.0.2.1:9101/tcp", "192.0.2.1:9102/tcp"],
    );
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    // The address and port rules are unchanged by the names.
    assert!(reached(&r, "192.0.2.1:9101/tcp"));
    assert!(!reached(&r, "192.0.2.1:9102/tcp"));
    let note = err.lines().find(|l| l.contains("NOTE")).unwrap_or_default();
    assert!(
        note.contains("web (app.example.test, admin.example.test)"),
        "{err}"
    );
    assert!(note.contains("does NOT enforce"), "{note}");
    assert!(!note.contains("sip"), "{note}");

    // A pass without names prints no such note.
    let plain = new_pass(&dir, &valid_pass(&[WEB, SIP]));
    let (_, out) = reach(&["--pass", s(&plain)], &["192.0.2.1:9101/tcp"]);
    assert!(!text(&out.stderr).contains("NOTE"));
}

#[test]
fn preview_refuses_a_revoked_pass() {
    let dir = tmpdir("preview-revoked");
    let path = new_pass(&dir, &pass_text(&hours(-1), &hours(1), true, &[WEB]));
    let result = Command::new(BIN)
        .args(["plan", "--format", "json", "--pass"])
        .arg(path)
        .args(["--", "true"])
        .output()
        .expect("preview");
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(result.stdout, [] as [u8; 0]);
    assert!(text(&result.stderr).contains("revoked"));
}

#[test]
fn pin_refuses_an_edit_even_when_grants_are_identical() {
    let dir = tmpdir("pin-edited");
    let contents = valid_pass(&[WEB]);
    let path = new_pass(&dir, &contents);
    let result = Command::new(BIN)
        .args(["plan", "--format", "json", "--pass"])
        .arg(&path)
        .args(["--", "true"])
        .output()
        .expect("plan");
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).expect("plan JSON");
    write_pass(&path, &format!("{contents}\n# edit\n"));
    let out = Command::new(BIN)
        .args([
            "run",
            "--expect-plan",
            value["digest"].as_str().expect("digest"),
            "--pass",
        ])
        .arg(path)
        .args(["--", "true"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("differs from current scope"));
}

#[test]
fn live_events_record_atomic_revocation_after_the_command_is_ready() {
    use std::io::{BufRead as _, BufReader};
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    require_sandbox!();
    let dir = tmpdir("events-revoked");
    let contents = valid_pass(&[WEB]);
    let path = new_pass(&dir, &contents);
    let (r, w) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).expect("pipe");
    let mut cmd = Command::new(BIN);
    cmd.args(["run", "--events-fd", "42", "--pass"])
        .arg(&path)
        .args([
            "--pass-recheck-ms",
            RECHECK_MS,
            "--",
            "sh",
            "-c",
            "printf 'ready\\n'; exec sleep 20",
        ]);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let raw = w.as_raw_fd();
    // SAFETY: descriptor w is open through spawn and dup2/fcntl are async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 42) < 0 || libc::fcntl(42, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn");
    drop(w);
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("stdout"))
        .read_line(&mut ready)
        .expect("readiness");
    assert_eq!(ready, "ready\n");
    write_pass(
        &path,
        &contents.replace("revoked = false", "revoked = true"),
    );
    let out = child.wait_with_output().expect("exit");
    assert_eq!(out.status.code(), Some(143), "{}", text(&out.stderr));
    let records = BufReader::new(std::fs::File::from(r))
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(&l.expect("record")).expect("event"))
        .collect::<Vec<_>>();
    assert_eq!(
        records
            .iter()
            .map(|r| r["event"].as_str())
            .collect::<Vec<_>>(),
        [
            Some("validated"),
            Some("starting"),
            Some("stopping"),
            Some("terminal")
        ]
    );
    assert_eq!(records[2]["details"]["reason"], "pass_withdrawn");
    assert_eq!(records[2]["details"]["egress_closed"], true);
    assert_eq!(records[3]["details"]["signal"], 15);
}

#[test]
fn atomic_revocation_during_setup_prevents_release() {
    use std::os::unix::fs::PermissionsExt as _;
    require_sandbox!();
    let dir = tmpdir("setup-revocation");
    let contents = valid_pass(&[WEB]);
    let pass = new_pass(&dir, &contents);
    let wrapper = dir.join("nft");
    let checkpoint = dir.join("readback");
    let release = dir.join("resume");
    let marker = dir.join("payload");
    // Relay the real nft result untouched. Pause once, at the initial readback.
    std::fs::write(&wrapper, "#!/bin/sh\nif [ \"$1\" = --json ]; then\n : > \"$CHECKPOINT\"\n i=0; while [ ! -f \"$RESUME\" ] && [ \"$i\" -lt 500 ]; do sleep 0.01; i=$((i+1)); done\nfi\nexec nft \"$@\"\n").expect("wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let child = Command::new(BIN)
        .env("PLAYPEN_NFT", &wrapper)
        .env("CHECKPOINT", &checkpoint)
        .env("RESUME", &release)
        .args(["run", "--pass"])
        .arg(&pass)
        .args(["--", "touch"])
        .arg(&marker)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let end = Instant::now() + Duration::from_secs(5);
    while !checkpoint.exists() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    write_pass(
        &pass,
        &contents.replace("revoked = false", "revoked = true"),
    );
    std::fs::write(release, []).expect("resume");
    let out = child.wait_with_output().expect("supervisor");
    assert!(checkpoint.exists(), "{}", text(&out.stderr));
    assert!(!marker.exists());
    assert!(
        text(&out.stderr).contains("revoked"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn strict_pass_reports_external_terms_and_respects_selection() {
    let dir = tmpdir("strict-coverage");
    let limited = WEB.replace(
        "hostname = \"app.example.test\"",
        "names = [\"app.example.test\"]",
    );
    let contents = valid_pass(&[&limited, SIP]).replace("[ceilings]\ncalls = 6\n", "");
    let pass = new_pass(&dir, &contents);
    let rep = dir.join("report.json");
    let out = run(&[
        "run",
        "--pass",
        s(&pass),
        "--only",
        "web",
        "--require-enforced",
        "--report",
        s(&rep),
        "--",
        "true",
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    let json = report(&rep);
    assert_eq!(
        json["enforcement_coverage"]["external_names"],
        serde_json::json!(["web"])
    );
    assert_eq!(
        json["enforcement_coverage"]["external_ceilings"],
        serde_json::json!([])
    );
    let out = run(&[
        "plan",
        "--pass",
        s(&pass),
        "--only",
        "sip",
        "--require-enforced",
        "--format",
        "json",
        "--",
        "true",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let plan: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(plan["plan"]["require_enforced"], true);
    assert_eq!(
        plan["plan"]["pass"]["coverage"]["external_names"],
        serde_json::json!([])
    );
    write_pass(&pass, &valid_pass(&[WEB]));
    let out = run(&[
        "run",
        "--pass",
        s(&pass),
        "--require-enforced",
        "--report",
        s(&rep),
        "--",
        "true",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(
        report(&rep)["enforcement_coverage"]["external_ceilings"],
        serde_json::json!(["calls"])
    );
    write_pass(
        &pass,
        &valid_pass(&[WEB]).replace("[ceilings]\ncalls = 6\n", ""),
    );
    let out = run(&[
        "plan",
        "--pass",
        s(&pass),
        "--require-enforced",
        "--",
        "true",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

#[test]
fn strict_running_job_stops_if_selected_names_are_added() {
    require_sandbox!();
    let dir = tmpdir("strict-edit");
    let before = valid_pass(&[WEB]).replace("[ceilings]\ncalls = 6\n", "");
    let pass = new_pass(&dir, &before);
    let rep = dir.join("report.json");
    let child = spawn(&[
        "run",
        "--pass",
        s(&pass),
        "--require-enforced",
        "--pass-recheck-ms",
        "200",
        "--report",
        s(&rep),
        "--",
        "sleep",
        "30",
    ]);
    std::thread::sleep(Duration::from_secs(1));
    write_pass(
        &pass,
        &before.replace(
            "hostname = \"app.example.test\"",
            "names = [\"app.example.test\"]",
        ),
    );
    let out = child.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(out.status.code(), Some(0));
    assert_eq!(report(&rep)["stopped_by_pass"], true);
}

#[test]
fn policy_test_respects_selected_pass_and_revocation() {
    let dir = tmpdir("policy-cases");
    let pass = new_pass(&dir, &valid_pass(&[WEB, SIP]));
    let cases = dir.join("cases.json");
    std::fs::write(&cases, r#"[{"name":"web","address":"192.0.2.1","protocol":"tcp","port":9101,"expect":"allow"},{"name":"excluded","address":"192.0.2.2","protocol":"udp","port":5060,"expect":"deny"}]"#).unwrap_or_else(|e| panic!("{e}"));
    let args = [
        "policy-test",
        s(&cases),
        "--pass",
        s(&pass),
        "--only",
        "web",
    ];
    assert_eq!(run(&args).status.code(), Some(0));
    write_pass(
        &pass,
        &valid_pass(&[WEB, SIP]).replace("revoked = false", "revoked = true"),
    );
    assert_eq!(run(&args).status.code(), Some(2));
}

#[test]
fn broad_ipv6_pass_prefix_is_refused_but_narrow_native_prefix_works() {
    let dir = tmpdir("v6-transition-scope");
    let broad = V6.replace("2001:db8::/120", "2001:db8::/32");
    let pass = new_pass(&dir, &valid_pass(&[&broad]));
    let out = run(&["plan", "--pass", s(&pass), "--", "true"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("transition"));
    write_pass(&pass, &valid_pass(&[V6]));
    let out = run(&["plan", "--pass", s(&pass), "--", "true"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
}

#[test]
fn grant_use_preserves_pass_labels_for_each_port_range() {
    require_sandbox!();
    let dir = tmpdir("grant-provenance");
    let pass = new_pass(&dir, &valid_pass(&[WEB, SIP]));
    let report_path = dir.join("grant-use.json");
    let out = run(&[
        "run",
        "--pass",
        s(&pass),
        "--only",
        "web",
        "--report-grant-use",
        "--report",
        s(&report_path),
        "--",
        "/usr/bin/true",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let report = report(&report_path);
    let rows = report["grant_use"]["grants"]
        .as_array()
        .expect("reported grant use");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["label"], "web");
    assert_eq!(rows[0]["rule"], "192.0.2.1:9101/tcp");
    assert_eq!(rows[1]["label"], "web");
    assert_eq!(rows[1]["rule"], "192.0.2.1:9103-9104/tcp");
}

/// `sip` and `v6` with a `hostname` each, beside `web`'s.
fn named_sip() -> String {
    SIP.replace(
        "ports = 5060",
        "ports = 5060\nhostname = \"sip.example.test\"",
    )
}

fn named_v6() -> String {
    V6.replace(
        "ports = 9301",
        "ports = 9301\nhostname = \"lab.example.test\"",
    )
}

/// The addresses `getent hosts` printed for `name`, in order.
fn getent(stdout: &str, name: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            let addr = words.next()?;
            words.any(|w| w == name).then(|| addr.to_owned())
        })
        .collect()
}

fn start_line(stderr: &str) -> &str {
    stderr
        .lines()
        .find(|l| l.contains("allowing only"))
        .unwrap_or_default()
}

fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()))
}

#[test]
fn pass_hosts_map_the_pass_names_and_curl_by_name_reaches_a_local_listener() {
    require_sandbox!();
    if !on_path("curl") || !on_path("getent") {
        eprintln!("SKIPPED: curl or getent is not installed");
        return;
    }
    let dir = tmpdir("pass-hosts");
    let pass = new_pass(&dir, &valid_pass(&[WEB, &named_sip(), &named_v6()]));
    let rep = dir.join("report.json");
    let log = dir.join("listen.out");
    let _ = std::fs::remove_file(&log);
    // The listener is on a documentation address on the sandbox's own lo,
    // so nothing leaves the machine. It closes each connection at once, so
    // curl gets no HTTP answer; the listener records that it connected.
    let script = format!(
        r"getent hosts app.example.test; getent hosts sip.example.test
getent hosts lab.example.test || echo lab-unresolved
{BIN} probe listen 192.0.2.1:9101/tcp --ms 2000 >> {listen} &
i=0
until grep -q listening {listen} 2>/dev/null; do
  i=$((i+1)); [ $i -gt 200 ] && exit 9; sleep 0.02
done
curl -q -sS --noproxy '*' --max-time 3 -o /dev/null -w 'curl reached %{{remote_ip}}:%{{remote_port}}\n' http://app.example.test:9101/
wait",
        listen = s(&log)
    );
    let mut args = vec![
        "run",
        "--pass",
        s(&pass),
        "--pass-hosts",
        "--report",
        s(&rep),
    ];
    args.extend_from_slice(LO);
    args.extend_from_slice(&["--", "sh", "-c", &script]);
    let out = run(&args);
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert_eq!(
        getent(&stdout, "app.example.test"),
        ["192.0.2.1"],
        "{stdout}"
    );
    assert_eq!(
        getent(&stdout, "sip.example.test"),
        ["192.0.2.2"],
        "{stdout}"
    );
    assert!(stdout.contains("lab-unresolved"), "{stdout}");
    assert!(
        stdout.contains("curl reached 192.0.2.1:9101"),
        "{stdout}\n{err}"
    );
    let accepted = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(accepted.contains("\"accepted\""), "{accepted}");

    let start = start_line(&err);
    assert!(
        start.contains(
            "(no DNS, names app.example.test=192.0.2.1 (pass: web), sip.example.test=192.0.2.2 (pass: sip); lookups recorded)"
        ),
        "{start}"
    );
    assert!(!start.contains("map them with"), "{start}");
    assert!(start.contains("host Unix sockets"), "{start}");
    assert!(
        err.contains(
            "playpen: NOTE: --pass-hosts does not map lab.example.test: destination `v6` is a network (2001:db8::/120)"
        ),
        "{err}"
    );
    let json = report(&rep);
    assert_eq!(
        json["hosts"],
        serde_json::json!([
            "app.example.test=192.0.2.1 (pass: web)",
            "sip.example.test=192.0.2.2 (pass: sip)"
        ])
    );
    // No grant is added.
    assert_eq!(
        json["allowed"],
        serde_json::json!([
            "192.0.2.1:9101/tcp",
            "192.0.2.1:9103-9104/tcp",
            "192.0.2.2:5060/udp",
            "[2001:db8::/120]:9301/tcp"
        ])
    );
}

#[test]
fn pass_hosts_follow_only_an_explicit_host_wins_and_a_shared_name_gets_both() {
    require_sandbox!();
    let dir = tmpdir("pass-hosts-only");
    let pass = new_pass(&dir, &valid_pass(&[WEB, &named_sip()]));
    let rep = dir.join("report.json");
    let lookup =
        "getent hosts sip.example.test; getent hosts app.example.test || echo app-unresolved";
    let out = run(&[
        "run",
        "--pass",
        s(&pass),
        "--only",
        "sip",
        "--pass-hosts",
        "--report",
        s(&rep),
        "--",
        "sh",
        "-c",
        lookup,
    ]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        getent(&stdout, "sip.example.test"),
        ["192.0.2.2"],
        "{stdout}"
    );
    assert!(stdout.contains("app-unresolved"), "{stdout}");
    assert_eq!(
        report(&rep)["hosts"],
        serde_json::json!(["sip.example.test=192.0.2.2 (pass: sip)"])
    );

    // --host for a name the pass maps wins, and the start line says so.
    let out = run(&[
        "run",
        "--pass",
        s(&pass),
        "--pass-hosts",
        "--host",
        "APP.example.test=192.0.2.2",
        "--report",
        s(&rep),
        "--",
        "getent",
        "ahosts",
        "app.example.test",
    ]);
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(stdout.contains("192.0.2.2"), "{stdout}");
    assert!(!stdout.contains("192.0.2.1"), "{stdout}");
    let start = start_line(&err);
    assert!(
        start.contains(
            "names app.example.test=192.0.2.2, sip.example.test=192.0.2.2 (pass: sip); --host app.example.test replaces app.example.test=192.0.2.1 (pass: web); lookups recorded)"
        ),
        "{start}"
    );
    assert_eq!(
        report(&rep)["hosts"],
        serde_json::json!([
            "APP.example.test=192.0.2.2",
            "sip.example.test=192.0.2.2 (pass: sip)"
        ])
    );

    // Two destinations with the same hostname give that name both addresses.
    let web2 = WEB
        .replace("label = \"web\"", "label = \"web2\"")
        .replace("192.0.2.1", "192.0.2.3");
    write_pass(&pass, &valid_pass(&[WEB, &web2]));
    let out = run(&[
        "run",
        "--pass",
        s(&pass),
        "--pass-hosts",
        "--",
        BIN,
        "probe",
        "resolve",
        "app.example.test",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let resolved: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(
        resolved["addresses"],
        serde_json::json!(["192.0.2.1", "192.0.2.3"]),
        "{resolved}"
    );
}

#[test]
fn rules_are_the_same_with_and_without_pass_hosts() {
    let dir = tmpdir("pass-hosts-rules");
    let pass = new_pass(&dir, &valid_pass(&[WEB, &named_sip(), &named_v6()]));
    for extra in [&[][..], &["--only", "sip"][..], &["--format", "json"][..]] {
        let mut without = vec!["rules", "--pass", s(&pass)];
        without.extend_from_slice(extra);
        let mut with = without.clone();
        with.push("--pass-hosts");
        let (a, b) = (run(&without), run(&with));
        assert_eq!(a.status.code(), Some(0), "{}", text(&a.stderr));
        assert_eq!(b.status.code(), Some(0), "{}", text(&b.stderr));
        assert_ne!(a.stdout, b"");
        assert_eq!(text(&a.stdout), text(&b.stdout), "{extra:?}");
    }
}

#[test]
fn a_hostname_edit_mid_run_keeps_the_names_loaded_at_start() {
    require_sandbox!();
    let dir = tmpdir("pass-hosts-edit");
    let before = valid_pass(&[WEB]);
    let pass = new_pass(&dir, &before);
    let rep = dir.join("report.json");
    let child = spawn(&[
        "run",
        "--pass",
        s(&pass),
        "--pass-hosts",
        "--pass-recheck-ms",
        RECHECK_MS,
        "--report",
        s(&rep),
        "--",
        "sh",
        "-c",
        "sleep 1.2; getent hosts app.example.test; getent hosts www.example.test || echo www-unresolved",
    ]);
    std::thread::sleep(Duration::from_millis(400));
    write_pass(
        &pass,
        &before.replace("app.example.test", "www.example.test"),
    );
    let out = child.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    // The existing rule for an edit that changes no rule: the run
    // continues, with a notice, under what was loaded at start.
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(
        err.contains("the hostname of destination `web` changed"),
        "{err}"
    );
    assert!(err.contains("/etc/hosts keeps the names"), "{err}");
    assert_eq!(
        getent(&stdout, "app.example.test"),
        ["192.0.2.1"],
        "{stdout}"
    );
    assert!(stdout.contains("www-unresolved"), "{stdout}");
    let json = report(&rep);
    assert_eq!(json["stopped_by_pass"], false);
    assert_eq!(
        json["hosts"],
        serde_json::json!(["app.example.test=192.0.2.1 (pass: web)"])
    );
}

#[test]
fn plan_and_pin_cover_pass_hosts() {
    let dir = tmpdir("pass-hosts-plan");
    let pass = new_pass(&dir, &valid_pass(&[WEB, &named_sip()]));
    let plan = |extra: &[&str]| {
        let mut args = vec!["plan", "--format", "json", "--pass", s(&pass)];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--", "true"]);
        let out = run(&args);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap_or_default()
    };
    let without = plan(&[]);
    let with = plan(&["--pass-hosts"]);
    assert!(without["plan"].get("pass_hosts").is_none(), "{without}");
    assert_eq!(without["plan"]["hosts"], serde_json::json!([]));
    assert_eq!(with["plan"]["pass_hosts"], true);
    assert_eq!(
        with["plan"]["hosts"],
        serde_json::json!([
            "app.example.test=192.0.2.1 (pass: web)",
            "sip.example.test=192.0.2.2 (pass: sip)"
        ])
    );
    assert_eq!(with["plan"]["allowed"], without["plan"]["allowed"]);
    assert_ne!(with["digest"], without["digest"]);
    let only = plan(&["--pass-hosts", "--only", "web"]);
    assert_eq!(
        only["plan"]["hosts"],
        serde_json::json!(["app.example.test=192.0.2.1 (pass: web)"])
    );

    // A digest reviewed with the option does not admit a run without it,
    // nor the other way round.
    for (digest, extra) in [(&with, &[][..]), (&without, &["--pass-hosts"][..])] {
        let mut args = vec![
            "run",
            "--expect-plan",
            digest["digest"].as_str().unwrap_or(""),
            "--pass",
            s(&pass),
        ];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--", "true"]);
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains("differs from current scope"));
    }
    if skip_reason().is_none() {
        let out = run(&[
            "run",
            "--expect-plan",
            with["digest"].as_str().unwrap_or(""),
            "--pass",
            s(&pass),
            "--pass-hosts",
            "--",
            "true",
        ]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }
}
