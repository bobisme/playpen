//! Integration tests: the command cannot read or replace playpen's own
//! files, the `--pass` and the `--report`, or fails closed when it tries.
//!
//! Each test runs the built binary with a command that attacks one of the
//! files the way an evaluation did (bn-2sa, bn-33k), or by a variant: a
//! rename of the parent directory, a hard link, a symbolic link.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

mod common;

use common::Guard;

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

/// A new, empty directory for one test.
fn tmpdir(name: &str) -> PathBuf {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("own-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    dir
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap_or("")
}

fn hours(h: i64) -> String {
    let t = OffsetDateTime::now_utc() + time::Duration::hours(h);
    t.replace_nanosecond(0)
        .unwrap_or(t)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// A valid pass for one TCP destination, named `name`.
fn pass_text(name: &str, revoked: bool) -> String {
    format!(
        "format = 1\nid = \"test-pass-1\"\nname = \"{name}\"\n\n[approval]\nowner = \"Pat Owner, Example Corp\"\nreference = \"email of 2026-11-18\"\noperator = \"Sam Tester\"\nvalid_from = {}\nvalid_until = {}\nrevoked = {revoked}\n\n[[destination]]\nlabel = \"web\"\naddress = \"192.0.2.1\"\nprotocol = \"tcp\"\nports = 9101\n",
        hours(-1),
        hours(1)
    )
}

/// Writes `contents` to `path` with mode 0600 the way most editors and
/// `sed -i` do: a new file renamed over the old one.
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

const LO: &[&str] = &["--lo-addr", "192.0.2.1", "--lo-addr", "192.0.2.2"];

fn spawn(args: &[&str]) -> Guard {
    Guard::spawn(
        Command::new(BIN)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap_or_else(|e| panic!("cannot run playpen: {e}"))
}

fn run(args: &[&str]) -> Output {
    finish(spawn(args))
}

/// Waits for playpen. A run that outlives 20 s means an attack kept it
/// alive: playpen is killed (which kills the sandbox) and the test fails,
/// instead of hanging.
fn finish(mut child: Guard) -> Output {
    let started = Instant::now();
    while child.try_wait().ok().flatten().is_none() {
        if started.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
            panic!(
                "the run was still going after 20 s\n{}\n{}",
                text(&out.stdout),
                text(&out.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap_or_else(|e| panic!("{e}"))
}

fn report(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_default()).unwrap_or_default()
}

/// `playpen run --pass PASS --report REPORT [extra] -- sh -c SCRIPT sh
/// ARGS...`, with a 200 ms re-read of the pass.
fn pass_args<'a>(
    pass: &'a Path,
    rep: &'a Path,
    extra: &[&'a str],
    script: &'a str,
    script_args: &[&'a str],
) -> Vec<&'a str> {
    let mut args = vec![
        "run",
        "--pass",
        s(pass),
        "--pass-recheck-ms",
        "200",
        "--report",
        s(rep),
    ];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", "sh", "-c", script, "sh"]);
    args.extend_from_slice(script_args);
    args
}

const NOT_HIDDEN: &str = "is not hidden from the command";

/// The evaluation's attack: the command copies its pass at start and puts
/// the copy back whenever the file changes. The pass is /dev/null inside,
/// so the copy is empty; putting it back over the owner's revocation makes
/// the pass invalid, and the run stops within the re-read interval.
#[test]
fn the_restore_loop_of_the_evaluation_is_stopped_and_never_read_the_pass() {
    require_sandbox!();
    let dir = tmpdir("restore-loop");
    let pass = dir.join("test.pass.toml");
    let contents = pass_text("Practice range", false);
    write_pass(&pass, &contents);
    let rep = dir.join("report.json");
    let script = r#"P=$1
cp "$P" "$P.saved" && echo "copied $(wc -c < "$P.saved") bytes"
stat -c %F "$P"
while :; do
  if ! cmp -s "$P" "$P.saved"; then
    cp "$P.saved" "$P.tmp" && chmod 600 "$P.tmp" && mv -f "$P.tmp" "$P" && echo restored
  fi
  sleep 0.05
done"#;
    let args = pass_args(&pass, &rep, &[], script, &[s(&pass)]);
    let started = Instant::now();
    let child = spawn(&args);
    std::thread::sleep(Duration::from_secs(1));
    write_pass(
        &pass,
        &contents.replace("revoked = false", "revoked = true"),
    );
    let out = finish(child);
    let took = started.elapsed();
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    let json = report(&rep);
    assert_eq!(out.status.code(), Some(128 + 15), "{stdout}\n{err}");
    // 1 s to the edit, then at most the interval, the grace and slack.
    assert!(
        took < Duration::from_millis(1000 + 200 + 3000 + 1500),
        "took {took:?}"
    );
    assert_eq!(json["stopped_by_pass"], true, "{json}");
    let reason = json["stop_reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("revoked") || reason.contains("can no longer be read"),
        "{reason}"
    );
    // The command read /dev/null, not the pass.
    assert!(stdout.contains("copied 0 bytes"), "{stdout}");
    assert!(stdout.contains("character special file"), "{stdout}");
    assert_eq!(
        std::fs::metadata(dir.join("test.pass.toml.saved"))
            .map(|m| m.len())
            .ok(),
        Some(0)
    );
    // The pass's directory is the command's to write: playpen says so.
    assert!(err.contains(NOT_HIDDEN), "{err}");
}

/// Inside, the pass and its ledger are /dev/null: the command reads
/// nothing, and cannot link, rename, remove or replace either; a write
/// goes to /dev/null.
#[test]
fn the_pass_and_its_ledger_are_dev_null_inside_and_cannot_be_linked_moved_or_removed() {
    require_sandbox!();
    let dir = tmpdir("pass-dev-null");
    let pass = dir.join("test.pass.toml");
    let contents = pass_text("Practice range", false);
    write_pass(&pass, &contents);
    let ledger = dir.join("test.pass.toml.ledger");
    std::fs::write(&ledger, "spent = 1\n").unwrap_or_else(|e| panic!("{e}"));
    let rep = dir.join("report.json");
    let script = r#"D=$1; shift
for f in "$@"; do
  echo "$(stat -c %F "$f") $(wc -c < "$f")"
  ln "$f" "$D/hard" 2>/dev/null || echo hardlink-failed
  mv "$f" "$D/moved" 2>/dev/null || echo move-failed
  rm -f "$f" 2>/dev/null || echo remove-failed
  ln -sf /etc/hostname "$f" 2>/dev/null || echo symlink-failed
  echo forged > "$f"
done"#;
    let args = pass_args(&pass, &rep, &[], script, &[s(&dir), s(&pass), s(&ledger)]);
    let out = run(&args);
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}\n{err}");
    for line in [
        "character special file 0",
        "hardlink-failed",
        "move-failed",
        "remove-failed",
        "symlink-failed",
    ] {
        let seen = stdout.lines().filter(|l| *l == line).count();
        assert_eq!(seen, 2, "{line}: {stdout}");
    }
    assert_eq!(
        std::fs::read_to_string(&pass).ok().as_deref(),
        Some(contents.as_str())
    );
    assert_eq!(
        std::fs::read_to_string(&ledger).ok().as_deref(),
        Some("spent = 1\n")
    );
    assert!(!dir.join("hard").exists());
    assert!(!dir.join("moved").exists());
}

/// The command moves the pass's directory away and puts a new one with a
/// forged, valid pass at its path. playpen reads the pass through the
/// directory it opened at start, sees that the path now leads elsewhere,
/// and stops the run.
#[test]
fn a_moved_pass_directory_with_a_forged_pass_in_its_place_stops_the_run() {
    require_sandbox!();
    let dir = tmpdir("pass-dir-moved");
    let sub = dir.join("p");
    std::fs::create_dir(&sub).unwrap_or_else(|e| panic!("{e}"));
    let pass = sub.join("test.pass.toml");
    write_pass(&pass, &pass_text("Practice range", false));
    let forged = dir.join("forged.pass.toml");
    write_pass(&forged, &pass_text("Forged", false));
    let rep = dir.join("report.json");
    let script = r#"mv "$1/p" "$1/p.moved" && mkdir "$1/p" &&
cp "$1/forged.pass.toml" "$1/p/test.pass.toml" && chmod 600 "$1/p/test.pass.toml" && echo swapped
exec sleep 30"#;
    let args = pass_args(&pass, &rep, &[], script, &[s(&dir)]);
    let started = Instant::now();
    let out = run(&args);
    let took = started.elapsed();
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    assert!(stdout.contains("swapped"), "{stdout}\n{err}");
    assert_eq!(out.status.code(), Some(128 + 15), "{stdout}\n{err}");
    assert!(took < Duration::from_millis(5500), "took {took:?}");
    let json = report(&rep);
    assert_eq!(json["stopped_by_pass"], true, "{json}");
    let reason = json["stop_reason"].as_str().unwrap_or("");
    assert!(reason.contains("was moved or replaced"), "{reason}");
    assert!(err.contains("was moved or replaced"), "{err}");
}

/// With the pass in a directory of its own, hidden with `--hide`, the
/// command cannot see the pass at all, so it cannot undo a revocation even
/// after the owner's edit replaced the file. playpen does not print the
/// NOTE about an unhidden directory.
#[test]
fn with_its_directory_hidden_the_pass_cannot_be_seen_or_replaced() {
    require_sandbox!();
    let dir = tmpdir("pass-dir-hidden");
    let sealed = dir.join("sealed");
    std::fs::create_dir(&sealed).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("{e}"));
    let pass = sealed.join("test.pass.toml");
    let contents = pass_text("Practice range", false);
    write_pass(&pass, &contents);
    let rep = dir.join("report.json");
    // Un-revoke the pass whenever it says revoked = true.
    let script = r#"P=$1
echo "entries: $(ls -A "$(dirname "$P")" | wc -l)"
echo x > "$P.t" 2>/dev/null || echo write-failed
while :; do
  if grep -q '^revoked = true' "$P" 2>/dev/null; then
    sed 's/^revoked = true/revoked = false/' "$P" > "$P.t" && chmod 600 "$P.t" &&
      mv -f "$P.t" "$P" && echo unrevoked
  fi
  sleep 0.02
done"#;
    let args = pass_args(&pass, &rep, &["--hide", s(&sealed)], script, &[s(&pass)]);
    let child = spawn(&args);
    std::thread::sleep(Duration::from_secs(1));
    write_pass(
        &pass,
        &contents.replace("revoked = false", "revoked = true"),
    );
    let out = finish(child);
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(128 + 15), "{stdout}\n{err}");
    assert!(stdout.contains("entries: 0"), "{stdout}");
    assert!(stdout.contains("write-failed"), "{stdout}");
    assert!(!stdout.contains("unrevoked"), "{stdout}");
    let json = report(&rep);
    assert_eq!(json["stopped_by_pass"], true, "{json}");
    assert!(
        json["stop_reason"]
            .as_str()
            .unwrap_or("")
            .contains("revoked"),
        "{json}"
    );
    assert!(!err.contains(NOT_HIDDEN), "{err}");
}

/// The evaluation's report forgery, and the direct variants: the command
/// tries to rename a forged report over the `--report` file, put a
/// symbolic link in its place, hard-link it and write to it. Inside, the
/// path is /dev/null, so each fails or writes nothing, and the real report
/// is on disk.
#[test]
fn the_report_forgery_of_the_evaluation_leaves_the_real_report() {
    require_sandbox!();
    let dir = tmpdir("report-forge");
    let rep = dir.join("report.json");
    let victim = dir.join("victim");
    std::fs::write(&victim, "keep").unwrap_or_else(|e| panic!("{e}"));
    let script = r#"B=$1 R=$2
"$B" probe reach --try 192.0.2.2:9601/tcp --try 192.0.2.2:9602/udp >/dev/null
printf '{"drop_assertion":"pass","playpen_exit_status":0}\n' > "$R.forged"
mv -f "$R.forged" "$R" 2>/dev/null || echo move-failed
ln -sf "$3" "$R" 2>/dev/null || echo symlink-failed
ln "$R" "$R.hard" 2>/dev/null || echo hardlink-failed
echo "$(stat -c %F "$R") $(wc -c < "$R")"
echo forged > "$R"
exit 0"#;
    let mut args = vec![
        "run",
        "--allow",
        "192.0.2.1:9101/tcp",
        "--fail-on-drop",
        "--report",
        s(&rep),
    ];
    args.extend_from_slice(LO);
    args.extend_from_slice(&["--", "sh", "-c", script, "sh", BIN, s(&rep), s(&victim)]);
    let out = run(&args);
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{err}");
    for line in [
        "move-failed",
        "symlink-failed",
        "hardlink-failed",
        "character special file 0",
    ] {
        assert!(stdout.contains(line), "{line}: {stdout}");
    }
    let json = report(&rep);
    assert_eq!(json["drop_assertion"], "violated", "{json}");
    assert!(
        json["dropped"]["packets"].as_u64().unwrap_or(0) >= 2,
        "{json}"
    );
    assert_eq!(json["playpen_exit_status"], 1, "{json}");
    assert_eq!(json["exit_code"], 0, "{json}");
    assert!(
        err.contains("UNAPPROVED destinations were dropped"),
        "{err}"
    );
    // Nothing was replaced, so there is nothing to warn about.
    assert!(!err.contains("was replaced while the command ran"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&victim).ok().as_deref(),
        Some("keep")
    );
    assert!(!dir.join("report.json.hard").exists());
}

/// Runs a command that moves the report's directory away and calls
/// `forge` to put something at the report path in a new directory. The
/// command exits 0 and nothing is dropped; returns playpen's output.
fn moved_report_dir(name: &str, forge: &str, victim: &Path) -> (Output, PathBuf) {
    let dir = tmpdir(name);
    let out_dir = dir.join("out");
    std::fs::create_dir(&out_dir).unwrap_or_else(|e| panic!("{e}"));
    let rep = out_dir.join("report.json");
    let script = format!(
        r#"D=$1 V=$2
mv "$D/out" "$D/out.moved" && mkdir "$D/out" && {forge} && echo swapped
exit 0"#
    );
    let out = run(&[
        "run",
        "--allow",
        "192.0.2.1:9101/tcp",
        "--report",
        s(&rep),
        "--",
        "sh",
        "-c",
        &script,
        "sh",
        s(&dir),
        s(victim),
    ]);
    (out, dir)
}

/// The report's directory moved away and a forged report put at the
/// path: playpen finds it at the end, writes the real report there again,
/// warns, and exits 1 although the command exited 0.
#[test]
fn a_moved_report_directory_with_a_forged_report_is_found_and_rewritten() {
    require_sandbox!();
    let (out, dir) = moved_report_dir(
        "report-dir-moved",
        r#"printf '{"playpen_exit_status":0}\n' > "$D/out/report.json""#,
        Path::new("/nonexistent"),
    );
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    assert!(stdout.contains("swapped"), "{stdout}\n{err}");
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{err}");
    assert!(
        err.contains("playpen: WARNING: the report file")
            && err.contains(
                "was replaced while the command ran (its directory was moved or replaced)"
            )
            && err.contains("exits with status 1"),
        "{err}"
    );
    let rep = dir.join("out/report.json");
    let json = report(&rep);
    assert_eq!(json["exit_code"], 0, "{json}");
    assert_eq!(json["playpen_exit_status"], 1, "{json}");
    assert!(
        json["message"]
            .as_str()
            .unwrap_or("")
            .contains("the report file was replaced"),
        "{json}"
    );
    // The file playpen created at start, now elsewhere, holds the same
    // report, and the new file has its mode.
    let first = dir.join("out.moved/report.json");
    assert_eq!(report(&first), json);
    let mode = |p: &Path| {
        std::fs::metadata(p)
            .map(|m| m.permissions().mode() & 0o777)
            .ok()
    };
    assert_eq!(mode(&rep), mode(&first));
}

/// The same with a symbolic link at the report path, to a file the
/// command wants overwritten: playpen replaces the link and does not
/// write through it.
#[test]
fn a_symbolic_link_at_the_report_path_is_replaced_and_not_followed() {
    require_sandbox!();
    let victim_dir = tmpdir("report-victim");
    let victim = victim_dir.join("victim");
    std::fs::write(&victim, "keep").unwrap_or_else(|e| panic!("{e}"));
    let (out, dir) = moved_report_dir(
        "report-dir-link",
        r#"ln -s "$V" "$D/out/report.json""#,
        &victim,
    );
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    assert!(stdout.contains("swapped"), "{stdout}\n{err}");
    assert_eq!(out.status.code(), Some(1), "{stdout}\n{err}");
    assert!(err.contains("was replaced while the command ran"), "{err}");
    assert_eq!(
        std::fs::read_to_string(&victim).ok().as_deref(),
        Some("keep")
    );
    let rep = dir.join("out/report.json");
    let meta = std::fs::symlink_metadata(&rep).unwrap_or_else(|e| panic!("{e}"));
    assert!(meta.is_file(), "{meta:?}");
    assert_eq!(report(&rep)["playpen_exit_status"], 1);
}
