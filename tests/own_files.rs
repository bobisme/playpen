//! Integration tests: the command cannot read or replace playpen's own
//! files, the `--pass` and the `--report`, or fails closed when it tries.
//!
//! Each test runs the built binary with a command that attacks one of the
//! files the way an evaluation did (bn-2sa, bn-33k), or by a variant: a
//! rename of the parent directory, a hard link, a symbolic link. The tests
//! of the pass's directory (bn-r5m) run the command that puts back an
//! unrevoked pass after the owner's edit against each layout: a directory
//! of its own (hidden), one that holds other files (read-only), the working
//! directory or one above it (refused), and `--pass-dir-writable`.

#![allow(
    clippy::disallowed_macros,
    reason = "test code may print with the std macros"
)]

use std::fs::OpenOptions;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{ChildStdout, Command, Output, Stdio};
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
    spawn_in(args, Path::new("."))
}

/// Starts playpen with `cwd` as its working directory, and the command's.
fn spawn_in(args: &[&str], cwd: &Path) -> Guard {
    Guard::spawn(
        Command::new(BIN)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap_or_else(|e| panic!("cannot run playpen: {e}"))
}

fn run(args: &[&str]) -> Output {
    finish(spawn(args))
}

fn run_in(args: &[&str], cwd: &Path) -> Output {
    finish(spawn_in(args, cwd))
}

/// Starts playpen in `cwd` and reads the command's output up to its line
/// `ready`. Returns the guarded child, what was read, and the rest of the
/// output.
fn spawn_ready(args: &[&str], cwd: &Path) -> (Guard, String, BufReader<ChildStdout>) {
    let mut child = spawn_in(args, cwd);
    let Some(stdout) = child.stdout.take() else {
        panic!("no stdout")
    };
    let mut out = BufReader::new(stdout);
    let mut seen = String::new();
    loop {
        let mut line = String::new();
        if out.read_line(&mut line).unwrap_or(0) == 0 {
            let rest = finish(child);
            panic!(
                "the command never got ready\n{seen}\n{}",
                text(&rest.stderr)
            );
        }
        if line == "ready\n" {
            return (child, seen, out);
        }
        seen.push_str(&line);
    }
}

/// [`finish`], then the rest of the command's output.
fn finish_ready(child: Guard, mut out: BufReader<ChildStdout>) -> (Output, String) {
    let done = finish(child);
    let mut rest = String::new();
    let _ = out.read_to_string(&mut rest);
    (done, rest)
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

/// The NOTE of `--pass-dir-writable`.
const WRITABLE: &str = "is writable by the command (--pass-dir-writable)";

/// The evaluation's attack, in its layout (the pass in the working
/// directory, which playpen now refuses) with `--pass-dir-writable`: the
/// command copies its pass at start and puts the copy back whenever the
/// file changes. The pass is /dev/null inside, so the copy is empty;
/// putting it back over the owner's revocation makes the pass invalid, and
/// the run stops within the re-read interval.
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
echo ready
while :; do
  if ! cmp -s "$P" "$P.saved"; then
    cp "$P.saved" "$P.tmp" && chmod 600 "$P.tmp" && mv -f "$P.tmp" "$P" && echo restored
  fi
  sleep 0.05
done"#;
    let relative = Path::new("test.pass.toml");
    let args = pass_args(
        relative,
        &rep,
        &["--pass-dir-writable"],
        script,
        &[s(relative)],
    );
    // Revoke once the command is running, not after a fixed sleep: on a
    // loaded machine the sandbox can take longer than any fixed delay.
    let (child, seen, rest) = spawn_ready(&args, &dir);
    write_pass(
        &pass,
        &contents.replace("revoked = false", "revoked = true"),
    );
    let edited = Instant::now();
    let (out, after) = finish_ready(child, rest);
    let took = edited.elapsed();
    let (stdout, err) = (format!("{seen}{after}"), text(&out.stderr));
    let json = report(&rep);
    assert_eq!(out.status.code(), Some(128 + 15), "{stdout}\n{err}");
    // After the edit: at most the interval, the grace and slack.
    assert!(
        took < Duration::from_millis(200 + 3000 + 2500),
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
    assert!(err.contains(WRITABLE), "{err}");
    assert_eq!(report(&rep)["pass"]["directory"], "writable");
}

/// Inside, the pass and its ledger are /dev/null: the command reads
/// nothing, and cannot link, rename, remove or replace either; a write
/// goes to /dev/null. With `--pass-dir-writable`, so that the directory is
/// writable and the refusals come from the `/dev/null` binds themselves.
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
done
touch "$D/writable" && echo dir-writable"#;
    let args = pass_args(
        &pass,
        &rep,
        &["--pass-dir-writable"],
        script,
        &[s(&dir), s(&pass), s(&ledger)],
    );
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
    assert!(stdout.contains("dir-writable"), "{stdout}");
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

/// The command moves the directory above the pass's away and puts a new
/// one with a forged, valid pass at the pass's path (the pass's directory
/// itself is a mount point inside, so it cannot be moved). playpen reads
/// the pass through the directory it opened at start, sees that the path
/// now leads elsewhere, and stops the run.
#[test]
fn a_moved_pass_directory_with_a_forged_pass_in_its_place_stops_the_run() {
    require_sandbox!();
    let dir = tmpdir("pass-dir-moved");
    let sub = dir.join("eng/p");
    std::fs::create_dir_all(&sub).unwrap_or_else(|e| panic!("{e}"));
    let pass = sub.join("test.pass.toml");
    write_pass(&pass, &pass_text("Practice range", false));
    let forged = dir.join("forged.pass.toml");
    write_pass(&forged, &pass_text("Forged", false));
    let rep = dir.join("report.json");
    let script = r#"mv "$1/eng/p" "$1/eng/p.moved" 2>/dev/null || echo cannot-move-it
mv "$1/eng" "$1/eng.moved" && mkdir -p "$1/eng/p" &&
cp "$1/forged.pass.toml" "$1/eng/p/test.pass.toml" && chmod 600 "$1/eng/p/test.pass.toml" && echo swapped
exec sleep 30"#;
    let args = pass_args(&pass, &rep, &[], script, &[s(&dir)]);
    let started = Instant::now();
    let out = run(&args);
    let took = started.elapsed();
    let (stdout, err) = (text(&out.stdout), text(&out.stderr));
    assert!(stdout.contains("cannot-move-it"), "{stdout}\n{err}");
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
echo ready
while :; do
  if grep -q '^revoked = true' "$P" 2>/dev/null; then
    sed 's/^revoked = true/revoked = false/' "$P" > "$P.t" && chmod 600 "$P.t" &&
      mv -f "$P.t" "$P" && echo unrevoked
  fi
  sleep 0.02
done"#;
    let args = pass_args(&pass, &rep, &["--hide", s(&sealed)], script, &[s(&pass)]);
    let (child, seen, rest) = spawn_ready(&args, &dir);
    write_pass(
        &pass,
        &contents.replace("revoked = false", "revoked = true"),
    );
    let (out, after) = finish_ready(child, rest);
    let (stdout, err) = (format!("{seen}{after}"), text(&out.stderr));
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
    // The operator hid it: playpen adds nothing and says nothing.
    assert!(!err.contains("pass directory:"), "{err}");
    assert!(!err.contains("pass's directory"), "{err}");
    assert_eq!(json["pass"]["directory"], "hidden", "{json}");
}

/// The un-revoke attack of the bn-2sa evaluation, made smart: the command
/// tries every way to change the pass's directory, then waits for the
/// owner's edit and puts back a pass that says `revoked = false`. `$1` is
/// the pass, `$2` a writable directory beside the pass's directory, which
/// is the working directory.
const UNREVOKE: &str = r#"P=$1 W=$2 D=$(dirname "$1")
try() { name=$1; shift; if "$@" 2>/dev/null; then echo "$name: done"; else echo "$name: failed"; fi; }
echo "entries: $(ls -A "$D" 2>/dev/null | tr '\n' ' ')"
echo "notes: $(cat "$D/notes.txt" 2>/dev/null)"
echo forged > "$W/forged"
ln -s "$D" "$W/link"
try create sh -c "echo x > '$D/new'"
try rename-in mv -f "$W/forged" "$D/new"
try link-in ln "$W/forged" "$D/new"
try symlink-in ln -s "$W/forged" "$D/new"
try mkdir mkdir "$D/new"
try mkfifo mkfifo "$D/new"
try remove rm "$D/notes.txt"
try rename-within mv "$D/notes.txt" "$D/new"
try rename-dir mv "$D" "$W/moved"
try via-symlink sh -c "echo x > '$W/link/new'"
try via-relative sh -c "echo x > '../$(basename "$D")/new'"
try via-subdir sh -c "cd '$D/sub' && echo x > ../new"
try via-proc-cwd sh -c "cd '$D/sub' && echo x > /proc/self/cwd/../new"
try in-subdir sh -c "echo x > '$D/sub/new'"
echo ready
while :; do
  if grep -q '^revoked = true' "$P" 2>/dev/null; then
    echo saw-revoked
    sed 's/^revoked = true/revoked = false/' "$P" > "$W/unrevoked" && chmod 600 "$W/unrevoked"
    cp "$W/unrevoked" "$D/p.t" 2>/dev/null && mv -f "$D/p.t" "$P" && echo unrevoked
    mv -f "$W/unrevoked" "$P" 2>/dev/null && echo unrevoked
    { cat "$W/unrevoked" > "$P"; } 2>/dev/null && echo unrevoked
  fi
  sleep 0.02
done"#;

/// Every attempt of [`UNREVOKE`] to change the directory.
const ATTEMPTS: [&str; 14] = [
    "create",
    "rename-in",
    "link-in",
    "symlink-in",
    "mkdir",
    "mkfifo",
    "remove",
    "rename-within",
    "rename-dir",
    "via-symlink",
    "via-relative",
    "via-subdir",
    "via-proc-cwd",
    "in-subdir",
];

/// A layout for [`UNREVOKE`]: `ROOT/passes/test.pass.toml`, with `extra`
/// files beside it (and `sub/`, empty, when there are any), and
/// `ROOT/work`, the working directory. Returns the root and the pass.
fn layout(name: &str, extra: bool) -> (PathBuf, PathBuf) {
    let root = tmpdir(name);
    let passes = root.join("passes");
    std::fs::create_dir_all(root.join("work")).unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir(&passes).unwrap_or_else(|e| panic!("{e}"));
    if extra {
        std::fs::create_dir(passes.join("sub")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(passes.join("notes.txt"), "shared notes\n")
            .unwrap_or_else(|e| panic!("{e}"));
    }
    let pass = passes.join("test.pass.toml");
    write_pass(&pass, &pass_text("Practice range", false));
    (root, pass)
}

/// Runs [`UNREVOKE`] in a layout, revokes the pass once the command is
/// ready, and checks what holds in every layout playpen guards: the run
/// stops for the revocation, nothing in the directory changed, and the
/// command never put back an unrevoked pass. Returns what the command
/// printed, playpen's stderr and the report.
fn unrevoke_attack(root: &Path, pass: &Path) -> (String, String, serde_json::Value) {
    let rep = root.join("report.json");
    let work = root.join("work");
    let passes = root.join("passes");
    let before: Vec<String> = entries(&passes);
    let args = pass_args(pass, &rep, &[], UNREVOKE, &[s(pass), s(&work)]);
    let started = Instant::now();
    let (child, seen, rest) = spawn_ready(&args, &work);
    let contents = pass_text("Practice range", false);
    write_pass(pass, &contents.replace("revoked = false", "revoked = true"));
    let edited = Instant::now();
    let (out, after) = finish_ready(child, rest);
    let stdout = format!("{seen}{after}");
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(128 + 15), "{stdout}\n{err}");
    // The interval, the grace and slack after the edit.
    assert!(
        edited.elapsed() < Duration::from_millis(200 + 3000 + 2500),
        "took {:?} in all",
        started.elapsed()
    );
    for name in ATTEMPTS {
        assert!(
            stdout.contains(&format!("{name}: failed")),
            "{name}: {stdout}"
        );
    }
    assert!(!stdout.contains(": done"), "{stdout}");
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
    // On the host: the owner's revocation, and nothing else changed.
    let now = std::fs::read_to_string(pass).unwrap_or_default();
    assert!(now.contains("revoked = true"), "{now}");
    assert_eq!(entries(&passes), before);
    if passes.join("sub").exists() {
        assert_eq!(entries(&passes.join("sub")), Vec::<String>::new());
    }
    assert!(!err.contains("NOTE"), "{err}");
    (stdout, err, json)
}

/// The names in a directory, sorted.
fn entries(dir: &Path) -> Vec<String> {
    let Ok(list) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = list
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// A pass alone in its directory, outside the working directory: playpen
/// hides the directory. The command sees nothing there, even after the
/// owner's edit, and cannot write there.
#[test]
fn a_pass_alone_in_its_directory_is_hidden_and_the_unrevoke_attack_fails() {
    require_sandbox!();
    let (root, pass) = layout("unrevoke-alone", false);
    let (stdout, err, json) = unrevoke_attack(&root, &pass);
    assert!(stdout.contains("entries: \n"), "{stdout}");
    assert!(!stdout.contains("saw-revoked"), "{stdout}");
    let dir = std::fs::canonicalize(root.join("passes")).unwrap_or_default();
    assert!(
        err.contains(&format!(
            "\nplaypen:   pass directory: {} (hidden from the command)\n",
            dir.display()
        )),
        "{err}"
    );
    assert_eq!(json["pass"]["directory"], "hidden", "{json}");
}

/// A pass in a directory that holds other files, outside the working
/// directory: playpen makes the directory read-only for the command. The
/// command reads the other files, and after the owner's edit the new pass,
/// but cannot create, rename, link or remove anything there, by any path.
#[test]
fn a_pass_beside_other_files_is_read_only_and_the_unrevoke_attack_fails() {
    require_sandbox!();
    let (root, pass) = layout("unrevoke-shared", true);
    let (stdout, err, json) = unrevoke_attack(&root, &pass);
    assert!(
        stdout.contains("entries: notes.txt sub test.pass.toml \n"),
        "{stdout}"
    );
    assert!(stdout.contains("notes: shared notes"), "{stdout}");
    // The edit detached the /dev/null bind: the new pass is visible, and
    // stays the owner's.
    assert!(stdout.contains("saw-revoked"), "{stdout}");
    let dir = std::fs::canonicalize(root.join("passes")).unwrap_or_default();
    assert!(
        err.contains(&format!(
            "\nplaypen:   pass directory: {} (read-only for the command)\n",
            dir.display()
        )),
        "{err}"
    );
    assert_eq!(json["pass"]["directory"], "read_only", "{json}");
}

/// The pass in the working directory (the evaluation's layout), in a
/// directory above it, or inside an `--expose` path: playpen refuses before
/// anything runs, and says why and what to do. `plan` refuses the same.
#[test]
fn a_pass_in_or_above_the_working_directory_or_exposed_is_refused() {
    let (root, pass) = layout("refused", true);
    let passes = std::fs::canonicalize(root.join("passes")).unwrap_or_default();
    let marker = root.join("work/ran");
    let rep = root.join("report.json");
    let refused = |cwd: &Path, extra: &[&str], why: &str| {
        let _ = std::fs::remove_file(&rep);
        let mut args = vec!["run", "--pass", s(&pass), "--report", s(&rep)];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--", "touch", s(&marker)]);
        let out = run_in(&args, cwd);
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{err}");
        let said = format!(
            "playpen: refused: --pass {}: the pass's directory, {}, {why}: the command could write there",
            pass.display(),
            passes.display()
        );
        assert!(err.contains(&said), "{said}\n{err}");
        assert!(err.contains("--pass-dir-writable"), "{err}");
        assert!(err.contains("nothing was run"), "{err}");
        assert!(!marker.exists(), "the command ran");
        let json = report(&rep);
        assert_eq!(json["outcome"], "refused", "{json}");
        assert!(json["pass"].get("directory").is_none(), "{json}");
        // plan validates the same way.
        let mut plan = vec!["plan", "--pass", s(&pass)];
        plan.extend_from_slice(extra);
        plan.extend_from_slice(&["--", "true"]);
        let out = run_in(&plan, cwd);
        assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
        assert!(text(&out.stderr).contains(why), "{}", text(&out.stderr));
        err
    };
    let err = refused(&root.join("passes"), &[], "is the working directory");
    assert!(
        err.contains("Move the pass to a directory of its own outside the working directory"),
        "{err}"
    );
    let sub = std::fs::canonicalize(root.join("passes/sub")).unwrap_or_default();
    refused(
        &root.join("passes/sub"),
        &[],
        &format!("holds the working directory {}", sub.display()),
    );
    let exposed = std::fs::canonicalize(&root).unwrap_or_default();
    let err = refused(
        &root.join("work"),
        &["--expose", s(&root)],
        &format!("is inside --expose {}", exposed.display()),
    );
    assert!(
        err.contains(&format!("--hide {}", passes.display())),
        "{err}"
    );
    // A relative path to the pass is the same pass.
    let out = run_in(
        &["plan", "--pass", "test.pass.toml", "--", "true"],
        &root.join("passes"),
    );
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("is the working directory"),
        "{}",
        text(&out.stderr)
    );
}

/// With `--pass-dir-writable` the pass may be in the working directory, and
/// the start line, a NOTE, the plan and the report say that its directory
/// is writable. The documented risk, shown without a race: after the
/// owner's edit saved a new pass, the command reads it and puts its own in
/// its place. The command waits for the owner's text, not for a regular
/// file: the kernel detaches the `/dev/null` bind before it moves the new
/// file into the name, so under load a lookup can briefly find the old
/// pass, unmasked (`docs/DESIGN.md`, "That lasts only until the owner's
/// edit").
#[test]
fn with_pass_dir_writable_the_command_can_replace_an_edited_pass() {
    require_sandbox!();
    let (root, pass) = layout("writable", false);
    let passes = root.join("passes");
    let rep = root.join("report.json");
    let script = r#"P=$1
echo ready
i=0
until grep -q "^reference = .the owner's edit" "$P" 2>/dev/null; do i=$((i+1)); [ $i -gt 500 ] && exit 9; sleep 0.02; done
grep '^reference' "$P"
sed 's/^reference = .*/reference = "the command'"'"'s"/' "$P" > p.t && chmod 600 p.t && mv -f p.t "$P" && echo replaced
sleep 0.5"#;
    let args = pass_args(
        Path::new("test.pass.toml"),
        &rep,
        &["--pass-dir-writable"],
        script,
        &["test.pass.toml"],
    );
    let (child, _, rest) = spawn_ready(&args, &passes);
    let contents = pass_text("Practice range", false);
    write_pass(
        &pass,
        &contents.replace("email of 2026-11-18", "the owner's edit"),
    );
    let (out, stdout) = finish_ready(child, rest);
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stdout}\n{err}");
    assert!(
        stdout.contains("reference = \"the owner's edit\""),
        "{stdout}"
    );
    assert!(stdout.contains("replaced"), "{stdout}");
    let now = std::fs::read_to_string(&pass).unwrap_or_default();
    assert!(now.contains("reference = \"the command's\""), "{now}");
    let dir = std::fs::canonicalize(&passes).unwrap_or_default();
    assert!(
        err.contains(&format!(
            "\nplaypen:   pass directory: {} (writable by the command, --pass-dir-writable)\n",
            dir.display()
        )),
        "{err}"
    );
    assert!(
        err.contains(&format!(
            "playpen: NOTE: the pass's directory, {}, {WRITABLE}",
            dir.display()
        )),
        "{err}"
    );
    let json = report(&rep);
    assert_eq!(json["pass"]["directory"], "writable", "{json}");
    assert_eq!(json["stopped_by_pass"], false, "{json}");
    // The plan names the option only when it is given.
    let plan = |extra: &[&str]| {
        let mut args = vec!["plan", "--format", "json", "--pass", "test.pass.toml"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--", "true"]);
        let out = run_in(&args, &passes);
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap_or_default()
    };
    assert_eq!(
        plan(&["--pass-dir-writable"])["plan"]["pass_dir_writable"],
        true
    );
    let other = run_in(
        &["plan", "--format", "json", "--pass", s(&pass), "--", "true"],
        &root.join("work"),
    );
    let other: serde_json::Value = serde_json::from_slice(&other.stdout).unwrap_or_default();
    assert!(other["plan"].get("pass_dir_writable").is_none(), "{other}");
    assert!(other["plan"]["pass"].is_object(), "{other}");
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
