//! End-to-end tests that egress ends in the firewall itself: when the
//! approval's end time comes, even while playpen is stopped, and as soon as
//! a re-read withdraws a pass, while the command is still alive in its
//! grace.
//!
//! As in `gateway.rs`, a throwaway network namespace (`unshare --user
//! --map-root-user --net`) plays "the host". Its interfaces are `lo` and
//! two `dummy` interfaces, which discard what is sent to them. A UDP
//! listener on the fake host's address 198.51.100.7 (a documentation
//! address on its own dummy interface) is the fixture. playpen runs inside
//! as the caller's uid, and pasta delivers what the command sends to the
//! fixture. Nothing can leave the machine even if the filter were wrong.
//!
//! The command inside is `playpen probe send`, which sends a numbered
//! datagram every 50 ms and logs each attempt with the wall-clock time. The
//! listener logs each datagram it gets with the wall-clock time. Both read
//! the clock that the firewall's `meta time` reads.

use std::collections::BTreeSet;
use std::io::{BufRead as _, BufReader};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");
const FIXTURE: &str = "198.51.100.7";
const SEND_EVERY_MS: &str = "50";
const EPERM: &str = "Operation not permitted";

fn pasta() -> Option<PathBuf> {
    ["/usr/bin/pasta", "/usr/sbin/pasta", "/bin/pasta"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// Why the fake host cannot be built here, if it cannot.
fn skip_reason() -> Option<String> {
    if pasta().is_none() {
        return Some("pasta is not installed".into());
    }
    let ok = Command::new("unshare")
        .args([
            "--user",
            "--map-root-user",
            "--net",
            "ip",
            "link",
            "add",
            "d0",
            "type",
            "dummy",
        ])
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        return Some("cannot make a network namespace with a dummy interface (unshare, ip)".into());
    }
    None
}

macro_rules! require_fake_host {
    () => {
        if let Some(why) = skip_reason() {
            eprintln!("SKIPPED: {why}");
            return;
        }
    };
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("egress-end-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    p
}

/// The fake host: as mapped root in a fresh network namespace, sets up the
/// interfaces and the UDP fixture, then runs playpen as the caller's uid in
/// the background and writes playpen's process id to `PIDFILE`.
const OUTER: &str = r#"#!/bin/sh
set -e
BIN="$1"; PORT="$2"; LOG="$3"; U="$4"; G="$5"; PIDFILE="$6"; shift 6
ip link set lo up
ip link add dummy0 type dummy
ip addr add 192.0.2.10/24 dev dummy0
ip -6 addr add 2001:db8::10/64 dev dummy0 nodad
ip link set dummy0 up
ip route add default via 192.0.2.1
ip -6 route add default via 2001:db8::1 dev dummy0
ip link add fixture0 type dummy
ip addr add 198.51.100.7/32 dev fixture0
ip link set fixture0 up
"$BIN" probe listen "0.0.0.0:$PORT/udp" --ms 60000 >"$LOG" &
L=$!
n=0
until grep -q listening "$LOG"; do n=$((n+1)); [ $n -lt 200 ] || exit 3; sleep 0.02; done
set +e
unshare --user --map-user="$U" --map-group="$G" "$@" &
P=$!
echo "$P" >"$PIDFILE"
wait "$P"
rc=$?
# Let the listener log a datagram that is still on its way.
sleep 0.3
kill $L
exit $rc
"#;

/// Wall-clock nanoseconds since 1970.
fn wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

fn ns_of(t: OffsetDateTime) -> u64 {
    u64::try_from(t.unix_timestamp_nanos()).unwrap_or(0)
}

fn sleep_until_ns(at: u64) {
    let now = wall_ns();
    if at > now {
        std::thread::sleep(Duration::from_nanos(at - now));
    }
}

/// One attempt of `probe send`.
#[derive(Debug)]
struct Send {
    seq: u64,
    at_ns: u64,
    sent: bool,
    error: String,
}

/// One datagram the fixture received.
#[derive(Debug)]
struct Received {
    seq: u64,
    at_ns: u64,
}

fn json_lines(text: &str) -> impl Iterator<Item = serde_json::Value> + '_ {
    text.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
}

fn sends(path: &Path) -> Vec<Send> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    json_lines(&text)
        .filter_map(|v| {
            Some(Send {
                seq: v["seq"].as_u64()?,
                at_ns: v["at_ns"].as_u64()?,
                sent: v["sent"].as_bool()?,
                error: v["error"].as_str().unwrap_or("").to_owned(),
            })
        })
        .collect()
}

fn received(path: &Path) -> Vec<Received> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    json_lines(&text)
        .filter_map(|v| {
            Some(Received {
                seq: v["received"].as_str()?.parse().ok()?,
                at_ns: v["at_ns"].as_u64()?,
            })
        })
        .collect()
}

/// playpen's stderr, each line with the wall-clock time the test read it.
type Lines = Arc<Mutex<Vec<(u64, String)>>>;

struct Run {
    child: Child,
    dir: PathBuf,
    stderr: Lines,
    reader: std::thread::JoinHandle<()>,
}

impl Run {
    fn sends(&self) -> PathBuf {
        self.dir.join("sends.jsonl")
    }
    fn listener(&self) -> PathBuf {
        self.dir.join("listener.jsonl")
    }
    fn report_path(&self) -> PathBuf {
        self.dir.join("report.json")
    }
    fn pid(&self) -> Pid {
        let file = self.dir.join("playpen.pid");
        for _ in 0..500 {
            if let Some(pid) = std::fs::read_to_string(&file)
                .ok()
                .and_then(|t| t.trim().parse().ok())
            {
                return Pid::from_raw(pid);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("playpen did not start in the fake host");
    }
    /// Waits for playpen; returns its exit code, its stderr and the report.
    fn finish(mut self) -> (Option<i32>, Vec<(u64, String)>, serde_json::Value) {
        let status = self.child.wait().unwrap_or_else(|e| panic!("{e}"));
        let report_path = self.report_path();
        let _ = self.reader.join();
        let lines = self
            .stderr
            .lock()
            .map_or_else(|_| Vec::new(), |l| l.clone());
        let report =
            serde_json::from_str(&std::fs::read_to_string(report_path).unwrap_or_default())
                .unwrap_or_default();
        (status.code(), lines, report)
    }
}

/// Starts playpen with `options` in the fake host, running `command`.
fn start(name: &str, port: &str, options: &[&str], command: &[&str]) -> Run {
    let dir = tmpdir(name);
    let outer = write_script(&dir, "outer.sh", OUTER);
    for file in [
        "sends.jsonl",
        "listener.jsonl",
        "report.json",
        "playpen.pid",
    ] {
        let _ = std::fs::remove_file(dir.join(file));
    }
    let uid = nix::unistd::getuid().to_string();
    let gid = nix::unistd::getgid().to_string();
    let out = std::fs::File::create(dir.join("sends.jsonl")).unwrap_or_else(|e| panic!("{e}"));
    let mut child = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "sh"])
        .arg(&outer)
        .args([BIN, port])
        .arg(dir.join("listener.jsonl"))
        .args([&uid, &gid])
        .arg(dir.join("playpen.pid"))
        .args([BIN, "run"])
        .args(options)
        .arg("--report")
        .arg(dir.join("report.json"))
        .arg("--")
        .args(command)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{e}"));
    let stderr: Lines = Arc::default();
    let pipe = child.stderr.take();
    let lines = Arc::clone(&stderr);
    let reader = std::thread::spawn(move || {
        let Some(pipe) = pipe else { return };
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            if let Ok(mut l) = lines.lock() {
                l.push((wall_ns(), line));
            }
        }
    });
    Run {
        child,
        dir,
        stderr,
        reader,
    }
}

fn all(lines: &[(u64, String)]) -> String {
    lines
        .iter()
        .map(|(_, l)| l.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every datagram the fixture got is one the command was told was sent,
/// and the other way round.
fn assert_listener_agrees(sends: &[Send], got: &[Received], context: &str) {
    let sent: BTreeSet<u64> = sends.iter().filter(|s| s.sent).map(|s| s.seq).collect();
    let arrived: BTreeSet<u64> = got.iter().map(|r| r.seq).collect();
    assert_eq!(
        arrived, sent,
        "the fixture's log and the sender's log disagree; {context}"
    );
}

/// `--until` a few seconds ahead, and playpen stopped with SIGSTOP from
/// before the end time until after it. Nothing in playpen can act while it
/// is stopped; the ruleset's time rule refuses every datagram from the end
/// second on, and the fixture gets nothing sent after it.
#[test]
fn the_end_time_closes_egress_while_playpen_is_stopped() {
    require_fake_host!();
    let port = "9561";
    let fixture = format!("{FIXTURE}:{port}/udp");
    let end = (OffsetDateTime::now_utc() + time::Duration::seconds(5))
        .replace_nanosecond(0)
        .unwrap_or_else(|e| panic!("{e}"));
    let until = end.format(&Rfc3339).unwrap_or_default();
    let end_ns = ns_of(end);
    let run = start(
        "expiry",
        port,
        &["--allow", &fixture, "--until", &until],
        &[BIN, "probe", "send", &fixture, "--every-ms", SEND_EVERY_MS],
    );
    let pid = run.pid();
    // Stopped 1.5 s before the end and continued 2.5 s after it: 4 s, less
    // than the 5 s of silence after which the sandbox's init freezes the
    // command, so the command runs on past the end time with only the
    // firewall to stop it.
    sleep_until_ns(end_ns - 1_500_000_000);
    kill(pid, Signal::SIGSTOP).unwrap_or_else(|e| panic!("SIGSTOP: {e}"));
    let stopped_ns = wall_ns();
    sleep_until_ns(end_ns + 2_500_000_000);
    let continued_ns = wall_ns();
    kill(pid, Signal::SIGCONT).unwrap_or_else(|e| panic!("SIGCONT: {e}"));
    let sends_path = run.sends();
    let listener_path = run.listener();
    let (code, stderr, report) = run.finish();
    let err = all(&stderr);
    assert!(
        stopped_ns < end_ns - 500_000_000,
        "playpen was stopped too late for this test: {err}"
    );
    let sends = sends(&sends_path);
    let got = received(&listener_path);
    let context = format!("end {end_ns}; sends {sends:?}; received {got:?}; stderr {err}");

    // Datagrams reached the fixture before the end...
    let before = sends.iter().filter(|s| s.sent).count();
    assert!(before >= 10, "too few datagrams before the end; {context}");
    // ...and not one that was sent at or after it.
    for s in sends.iter().filter(|s| s.sent) {
        assert!(s.at_ns < end_ns, "sent after the end: {s:?}; {context}");
    }
    for s in sends.iter().filter(|s| s.at_ns >= end_ns) {
        assert!(
            !s.sent && s.error.contains(EPERM),
            "not refused: {s:?}; {context}"
        );
    }
    // While playpen was stopped the command kept sending; the firewall
    // alone refused it.
    let while_stopped = sends
        .iter()
        .filter(|s| s.at_ns >= end_ns && s.at_ns < continued_ns)
        .count();
    assert!(
        while_stopped >= 20,
        "the command did not send while playpen was stopped; {context}"
    );
    // The fixture's own log agrees.
    assert_listener_agrees(&sends, &got, &context);
    for r in &got {
        assert!(
            r.at_ns < end_ns + 100_000_000,
            "the fixture got a datagram after the end: {r:?}; {context}"
        );
    }

    assert_eq!(code, Some(128 + 15), "{context}");
    assert!(err.contains("the approval ended at"), "{err}");
    assert!(
        err.contains("the firewall now refuses all traffic but loopback; sending SIGTERM"),
        "{err}"
    );
    assert_eq!(report["stopped_by_until"], true, "{report}");
    // Refused after the end, not dropped as unapproved.
    let refused = sends.iter().filter(|s| !s.sent).count() as u64;
    let counted = report["refused_after_end"].as_u64().unwrap_or(0);
    assert!(
        counted >= refused && counted <= refused + 4,
        "{refused} refused sends, counted {counted}: {report}"
    );
    assert_eq!(report["dropped"]["packets"], 0, "{report}");
    assert!(
        err.contains(&format!(
            "playpen: {counted} packet(s) refused after the approval ended"
        )),
        "{err}"
    );
    assert!(
        err.contains("no packets to unapproved destinations were dropped"),
        "{err}"
    );
}

/// A pass revoked while the command runs, with a command that ignores
/// SIGTERM. From the "stopping" notice on, the command is alive for its
/// grace and keeps sending, and the fixture receives nothing.
#[test]
fn a_revoked_pass_closes_egress_before_the_notice() {
    require_fake_host!();
    let port = "9562";
    let fixture = format!("{FIXTURE}:{port}/udp");
    let dir = tmpdir("revoke");
    let now = OffsetDateTime::now_utc();
    let stamp = |t: OffsetDateTime| {
        t.replace_nanosecond(0)
            .unwrap_or(t)
            .format(&Rfc3339)
            .unwrap_or_default()
    };
    let contents = format!(
        "format = 1\nid = \"egress-end-1\"\nname = \"Fixture\"\n\n[approval]\nowner = \"Pat Owner, Example Corp\"\nreference = \"test\"\noperator = \"Sam Tester\"\nvalid_from = {}\nvalid_until = {}\nrevoked = false\n\n[[destination]]\nlabel = \"fixture\"\naddress = \"{FIXTURE}\"\nprotocol = \"udp\"\nports = {port}\n",
        stamp(now - time::Duration::hours(1)),
        stamp(now + time::Duration::hours(1)),
    );
    let pass = dir.join("fixture.pass.toml");
    write_pass(&pass, &contents);
    let pass_arg = pass.to_str().unwrap_or("");
    let script =
        format!("trap '' TERM; exec \"$0\" probe send {fixture} --every-ms {SEND_EVERY_MS}");
    let run = start(
        "revoke",
        port,
        &["--pass", pass_arg, "--pass-recheck-ms", "200"],
        &["sh", "-c", &script, BIN],
    );
    let listener_path = run.listener();
    let sends_path = run.sends();
    // Revoke once the fixture has had a few datagrams.
    let mut waited = 0;
    while received(&listener_path).len() < 5 {
        waited += 1;
        assert!(waited < 500, "the fixture got nothing: {:?}", run.stderr);
        std::thread::sleep(Duration::from_millis(20));
    }
    write_pass(
        &pass,
        &contents.replace("revoked = false", "revoked = true"),
    );
    let (code, stderr, report) = run.finish();
    let err = all(&stderr);
    let notice = stderr
        .iter()
        .find(|(_, l)| l.contains("revoked") && l.contains("SIGTERM"))
        .map_or_else(|| panic!("no notice: {err}"), |(at, _)| *at);
    let sends = sends(&sends_path);
    let got = received(&listener_path);
    let context = format!("notice {notice}; sends {sends:?}; received {got:?}; stderr {err}");

    // Every datagram that left was sent before the notice; the fixture got
    // none after it.
    for s in sends.iter().filter(|s| s.sent) {
        assert!(s.at_ns < notice, "sent after the notice: {s:?}; {context}");
    }
    assert_listener_agrees(&sends, &got, &context);
    for r in &got {
        assert!(
            r.at_ns < notice,
            "the fixture got a datagram after the notice: {r:?}; {context}"
        );
    }
    // The command was alive in its grace and kept trying.
    let after: Vec<&Send> = sends.iter().filter(|s| s.at_ns >= notice).collect();
    assert!(after.len() >= 20, "too few sends in the grace; {context}");
    assert!(
        after.iter().all(|s| !s.sent && s.error.contains(EPERM)),
        "{context}"
    );
    let last = after.last().map_or(0, |s| s.at_ns);
    assert!(
        last >= notice + 2_500_000_000,
        "the command was not alive in its grace; {context}"
    );

    assert_eq!(code, Some(128 + 9), "{context}");
    assert!(
        err.contains("the firewall now refuses all traffic but loopback; sending SIGTERM"),
        "{err}"
    );
    assert_eq!(report["stopped_by_pass"], true, "{report}");
    let refused = sends.iter().filter(|s| !s.sent).count() as u64;
    let counted = report["refused_after_end"].as_u64().unwrap_or(0);
    assert!(
        counted >= refused && counted <= refused + 4,
        "{refused} refused sends, counted {counted}: {report}"
    );
    assert_eq!(report["dropped"]["packets"], 0, "{report}");
}

/// Writes a pass with mode 0600, atomically.
fn write_pass(path: &Path, contents: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
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
