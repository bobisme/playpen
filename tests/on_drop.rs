//! End-to-end tests of `--on-drop`: the first packet the firewall drops
//! closes all egress, and with `stop` playpen stops the command.
//!
//! The first test uses the fake host of `egress_end.rs`: a throwaway
//! network namespace (`unshare --user --map-root-user --net`) whose
//! interfaces are `lo` and two `dummy` interfaces, which discard what is
//! sent to them. Three UDP listeners on the fake host's own addresses are
//! the fixtures: two approved, one not. playpen runs inside as the caller's
//! uid, and pasta delivers what the firewall lets through. Nothing can
//! leave the machine even if the filter were wrong.
//!
//! The others, as in `live_drops.rs`, send to an address on the sandbox's
//! own `lo` (the hidden `--lo-addr` test aid), so a packet to it never
//! leaves the sandbox. The output chain drops and counts it all the same.
//!
//! The commands inside are `playpen probe send`, which sends a numbered
//! datagram every MS milliseconds and logs each attempt with the
//! wall-clock time.

use std::collections::BTreeSet;
use std::io::{BufRead as _, BufReader};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::fcntl::OFlag;
use nix::unistd::pipe2;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");
const EPERM: &str = "Operation not permitted";
/// How often playpen reads the drop counter while the command runs.
const INTERVAL_NS: u64 = 2_000_000_000;
/// The grace between SIGTERM and SIGKILL.
const GRACE_NS: u64 = 3_000_000_000;
/// What the bounds allow on top: the reading itself, the cut request, and
/// scheduling on a machine busy with the other tests.
const SLACK_NS: u64 = 1_500_000_000;
/// Around the stray packet, sends of the other senders may come in either
/// order: they are not checked within this margin.
const MARGIN_NS: u64 = 100_000_000;

fn tool(name: &str) -> bool {
    ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .iter()
        .any(|d| Path::new(d).join(name).exists())
}

/// Why the sandbox cannot run here, if it cannot.
fn skip_reason(fake_host: bool) -> Option<String> {
    let max = std::fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap_or_default();
    if max.trim().is_empty() || max.trim() == "0" {
        return Some("user namespaces are not available".into());
    }
    let tools: &[&str] = if fake_host {
        &["nft", "pasta"]
    } else {
        &["nft"]
    };
    for t in tools {
        if !tool(t) {
            return Some(format!("{t} is not installed"));
        }
    }
    if fake_host {
        let ok = Command::new("unshare")
            .args(["--user", "--map-root-user", "--net"])
            .args(["ip", "link", "add", "d0", "type", "dummy"])
            .output()
            .is_ok_and(|o| o.status.success());
        if !ok {
            return Some(
                "cannot make a network namespace with a dummy interface (unshare, ip)".into(),
            );
        }
    }
    None
}

macro_rules! require {
    ($fake_host:expr) => {
        if let Some(why) = skip_reason($fake_host) {
            eprintln!("SKIPPED: {why}");
            return;
        }
    };
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("on-drop-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Wall-clock nanoseconds since 1970.
fn wall_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

/// A report time (RFC 3339) in wall-clock nanoseconds.
fn report_ns(v: &Value) -> u64 {
    v.as_str()
        .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
        .and_then(|t| u64::try_from(t.unix_timestamp_nanos()).ok())
        .unwrap_or_else(|| panic!("not a time: {v}"))
}

fn json_lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// One attempt of `probe send`.
#[derive(Debug)]
struct Send {
    seq: u64,
    at_ns: u64,
    sent: bool,
    error: String,
}

fn sends(path: &Path) -> Vec<Send> {
    json_lines(path)
        .iter()
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

/// The sequence numbers and times of the datagrams a listener got.
fn received(path: &Path) -> Vec<(u64, u64)> {
    json_lines(path)
        .iter()
        .filter_map(|v| Some((v["received"].as_str()?.parse().ok()?, v["at_ns"].as_u64()?)))
        .collect()
}

/// Lines of a stream, each with the wall-clock time the test read it.
type Lines = Arc<Mutex<Vec<(u64, String)>>>;

fn read_lines(
    stream: impl std::io::Read + std::marker::Send + 'static,
) -> (Lines, std::thread::JoinHandle<()>) {
    let lines: Lines = Arc::default();
    let into = Arc::clone(&lines);
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            if let Ok(mut l) = into.lock() {
                l.push((wall_ns(), line));
            }
        }
    });
    (lines, reader)
}

/// What a finished run left.
struct Finished {
    code: Option<i32>,
    stderr: Vec<(u64, String)>,
    events: Vec<Value>,
    report: Value,
}

impl Finished {
    fn err(&self) -> String {
        self.stderr
            .iter()
            .map(|(_, l)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
    /// When the test read the first stderr line that contains `text`.
    fn line_at(&self, text: &str) -> u64 {
        self.stderr
            .iter()
            .find(|(_, l)| l.contains(text))
            .map_or_else(|| panic!("no {text:?} in {}", self.err()), |(at, _)| *at)
    }
}

fn wait(
    mut child: Child,
    dir: &Path,
    stderr: (Lines, std::thread::JoinHandle<()>),
    events: Option<(Lines, std::thread::JoinHandle<()>)>,
) -> Finished {
    let status = child.wait().unwrap_or_else(|e| panic!("{e}"));
    let _ = stderr.1.join();
    let take = |lines: &Lines| lines.lock().map_or_else(|_| Vec::new(), |l| l.clone());
    let events = events.map_or_else(Vec::new, |(lines, reader)| {
        let _ = reader.join();
        take(&lines)
            .into_iter()
            .map(|(_, l)| serde_json::from_str(&l).unwrap_or_else(|e| panic!("{e}: {l:?}")))
            .collect()
    });
    let report =
        serde_json::from_str(&std::fs::read_to_string(dir.join("report.json")).unwrap_or_default())
            .unwrap_or_default();
    Finished {
        code: status.code(),
        stderr: take(&stderr.0),
        events,
        report,
    }
}

/// Runs `playpen run --events-fd 42 --report DIR/report.json ARGS` to the
/// end.
fn run_inside(dir: &Path, args: &[&str]) -> Finished {
    let (r, w) = pipe2(OFlag::O_CLOEXEC).unwrap_or_else(|e| panic!("pipe: {e}"));
    let raw = w.as_raw_fd();
    let mut cmd = Command::new(BIN);
    cmd.args(["run", "--events-fd", "42", "--report"])
        .arg(dir.join("report.json"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: dup2 and fcntl are async-signal-safe; `w` stays open until
    // after the spawn.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 42) < 0 || libc::fcntl(42, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("{e}"));
    drop(w);
    let stderr = read_lines(child.stderr.take().unwrap_or_else(|| panic!("stderr")));
    let events = read_lines(std::fs::File::from(r));
    wait(child, dir, stderr, Some(events))
}

/// The fake host: as mapped root in a fresh network namespace, sets up the
/// interfaces and three UDP listeners, then runs playpen as the caller's
/// uid. The listeners log to DIR/listen-{a,b,u}.jsonl.
const OUTER: &str = r#"#!/bin/sh
set -e
BIN="$1"; DIR="$2"; U="$3"; G="$4"; PA="$5"; PB="$6"; PU="$7"; shift 7
ip link set lo up
ip link add dummy0 type dummy
ip addr add 192.0.2.10/24 dev dummy0
ip -6 addr add 2001:db8::10/64 dev dummy0 nodad
ip link set dummy0 up
ip route add default via 192.0.2.1
ip -6 route add default via 2001:db8::1 dev dummy0
ip link add fixture0 type dummy
ip addr add 198.51.100.7/32 dev fixture0
ip addr add 198.51.100.17/32 dev fixture0
ip addr add 198.51.100.9/32 dev fixture0
ip link set fixture0 up
"$BIN" probe listen "0.0.0.0:$PA/udp" --ms 60000 >"$DIR/listen-a.jsonl" &
LA=$!
"$BIN" probe listen "0.0.0.0:$PB/udp" --ms 60000 >"$DIR/listen-b.jsonl" &
LB=$!
"$BIN" probe listen "0.0.0.0:$PU/udp" --ms 60000 >"$DIR/listen-u.jsonl" &
LU=$!
for f in a b u; do
    n=0
    until grep -q listening "$DIR/listen-$f.jsonl"; do n=$((n+1)); [ $n -lt 200 ] || exit 3; sleep 0.02; done
done
set +e
unshare --user --map-user="$U" --map-group="$G" "$@"
rc=$?
# Let the listeners log a datagram that is still on its way.
sleep 0.3
kill $LA $LB $LU
exit $rc
"#;

/// The command inside: sends to the first approved listener (A) every
/// 50 ms; after 1 s one datagram to the unapproved one (U); 0.3 s later
/// starts sending to the second approved listener (B) as well; 3 s later
/// stops both and exits 0.
const INNER: &str = r#"B="$0"; A="$1"; BB="$2"; UU="$3"; D="$4"
"$B" probe send "$A" --every-ms 50 >"$D/send-a.jsonl" &
AP=$!
sleep 1
"$B" probe send "$UU" --every-ms 60000 >"$D/send-u.jsonl" &
UP=$!
sleep 0.3
kill $UP
"$B" probe send "$BB" --every-ms 50 >"$D/send-b.jsonl" &
BP=$!
sleep 3
kill $AP $BP
wait
exit 0
"#;

/// What the senders and the listeners of the fake host logged.
struct Traffic {
    to_a: Vec<Send>,
    to_b: Vec<Send>,
    to_stray: Vec<Send>,
    at_a: Vec<(u64, u64)>,
    at_b: Vec<(u64, u64)>,
    at_stray: Vec<(u64, u64)>,
}

/// Runs playpen with `options` in the fake host, with [`INNER`] sending to
/// `a` and `b` (approved) and `stray` (not).
fn run_fake_host(dir: &Path, ports: [&str; 3], options: &[&str]) -> (Finished, Traffic) {
    let [a, b, stray] = [
        format!("198.51.100.7:{}/udp", ports[0]),
        format!("198.51.100.17:{}/udp", ports[1]),
        format!("198.51.100.9:{}/udp", ports[2]),
    ];
    let outer = dir.join("outer.sh");
    std::fs::write(&outer, OUTER).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    let uid = nix::unistd::getuid().to_string();
    let gid = nix::unistd::getgid().to_string();
    let mut child = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "sh"])
        .arg(&outer)
        .arg(BIN)
        .arg(dir)
        .args([&uid, &gid])
        .args(ports)
        .args([BIN, "run", "--allow", &a, "--allow", &b])
        .args(options)
        .arg("--report")
        .arg(dir.join("report.json"))
        .args(["--", "sh", "-c", INNER, BIN, &a, &b, &stray])
        .arg(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{e}"));
    let stderr = read_lines(child.stderr.take().unwrap_or_else(|| panic!("stderr")));
    let finished = wait(child, dir, stderr, None);
    let traffic = Traffic {
        to_a: sends(&dir.join("send-a.jsonl")),
        to_b: sends(&dir.join("send-b.jsonl")),
        to_stray: sends(&dir.join("send-u.jsonl")),
        at_a: received(&dir.join("listen-a.jsonl")),
        at_b: received(&dir.join("listen-b.jsonl")),
        at_stray: received(&dir.join("listen-u.jsonl")),
    };
    (finished, traffic)
}

/// Checks the logs of a run whose cut tripped: datagrams to A arrive until
/// the one datagram to the unapproved address, and from then on none to A
/// or B leaves; the listeners agree. Returns when the stray datagram was
/// sent and how many datagrams were refused after it.
fn check_traffic(t: &Traffic, context: &str) -> (u64, u64) {
    assert_eq!(t.to_stray.len(), 1, "{context}");
    let stray = &t.to_stray[0];
    assert!(!stray.sent && stray.error.contains(EPERM), "{context}");
    let tripped = stray.at_ns;
    let before: Vec<&Send> = t
        .to_a
        .iter()
        .filter(|s| s.at_ns + MARGIN_NS < tripped)
        .collect();
    assert!(before.len() >= 10, "too few datagrams before; {context}");
    assert!(before.iter().all(|s| s.sent), "{context}");
    let after: Vec<&Send> = t
        .to_a
        .iter()
        .chain(&t.to_b)
        .filter(|s| s.at_ns > tripped + MARGIN_NS)
        .collect();
    assert!(after.len() >= 60, "too few datagrams after; {context}");
    for s in &after {
        assert!(
            !s.sent && s.error.contains(EPERM),
            "not refused: {s:?}; {context}"
        );
    }
    assert!(t.to_b.len() >= 30, "{context}");
    assert!(t.to_b.iter().all(|s| !s.sent), "{context}");
    // A got exactly what left, and nothing after the trip; B and the
    // unapproved address got nothing.
    let sent: BTreeSet<u64> = t.to_a.iter().filter(|s| s.sent).map(|s| s.seq).collect();
    let arrived: BTreeSet<u64> = t.at_a.iter().map(|r| r.0).collect();
    assert_eq!(
        arrived, sent,
        "A's log and the sender's disagree; {context}"
    );
    assert!(
        t.at_a.iter().all(|r| r.1 < tripped + MARGIN_NS),
        "{context}"
    );
    assert!(t.at_b.is_empty() && t.at_stray.is_empty(), "{context}");
    (tripped, after.len() as u64)
}

/// `--on-drop cut` with two approved listeners and one unapproved address.
/// Datagrams to the first approved listener arrive; one datagram goes to
/// the unapproved address; from then on every datagram to either approved
/// listener is refused, and the command runs on. The listeners' own logs
/// agree, and the report names the unapproved destination.
#[test]
fn the_first_unapproved_packet_closes_egress_to_every_destination() {
    require!(true);
    let dir = tmpdir("cut");
    let (f, traffic) = run_fake_host(&dir, ["9571", "9572", "9573"], &["--on-drop", "cut"]);
    let err = f.err();
    let report = &f.report;
    let context = format!(
        "a {:?}; b {:?}; stray {:?}; got a {:?}; got b {:?}; got stray {:?}; stderr {err}; report {report}",
        traffic.to_a, traffic.to_b, traffic.to_stray, traffic.at_a, traffic.at_b, traffic.at_stray,
    );
    let (tripped, refused) = check_traffic(&traffic, &context);

    // The command ran on to its own end, and its status is playpen's.
    assert_eq!(f.code, Some(0), "{context}");
    assert_eq!(report["exit_code"], 0, "{context}");
    assert_eq!(report["playpen_exit_status"], 0, "{context}");
    assert_eq!(report["on_drop"], "cut", "{context}");
    assert_eq!(report["stopped_by_drop"], false, "{context}");
    assert_eq!(report["stopped_by_until"], false, "{context}");
    assert!(report["stop_reason"].is_null(), "{context}");
    let dest = json!({"address": "198.51.100.9", "protocol": "udp", "port": 9573, "packets": 1});
    assert_eq!(
        report["egress_cut"]["tripped_by"],
        json!([dest]),
        "{context}"
    );
    assert_eq!(report["dropped"]["packets"], 1, "{context}");
    assert_eq!(
        report["dropped"]["destinations"],
        json!([dest]),
        "{context}"
    );
    // What was refused after the trip is counted by the cut, not as dropped
    // or as refused after the end.
    let counted = report["egress_cut"]["refused"].as_u64().unwrap_or(0);
    assert!(
        counted >= refused && counted <= refused + 8,
        "{refused} refused sends after the trip, counted {counted}; {context}"
    );
    assert_eq!(report["refused_after_end"], 0, "{context}");

    // playpen said so while the command ran, naming the destination.
    assert!(
        err.contains("everything else is dropped; at the first dropped packet the firewall itself refuses all traffic but loopback, and the command runs on (--on-drop cut)"),
        "{err}"
    );
    let at = f.line_at(
        "playpen: a packet to an unapproved destination was dropped: 198.51.100.9 udp port 9573 (--on-drop cut); the firewall now refuses all traffic but loopback, and the command keeps running",
    );
    let ended = report_ns(&report["ended_at"]);
    assert!(
        at > tripped && at - tripped <= INTERVAL_NS + SLACK_NS && at < ended,
        "the notice came {} ms after the trip; {context}",
        at.saturating_sub(tripped) / 1_000_000
    );
    assert!(
        err.contains(&format!(
            "playpen: the firewall closed all egress at the first dropped packet (--on-drop cut): 198.51.100.9 udp port 9573; {counted} packet(s) refused after that"
        )),
        "{err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--on-drop cut` with `--report-contacts`, on the fake host. The start-up
/// readback accepts the ruleset with both. What reached A before the trip
/// is in `contacted`, datagram for datagram; nothing after it is, B never
/// is, and the unapproved address is in `dropped` and
/// `egress_cut.tripped_by`. `suggest` then proposes A alone.
#[test]
fn contacts_are_recorded_until_the_tripwire_closes_egress() {
    require!(true);
    let dir = tmpdir("contacts");
    let (f, traffic) = run_fake_host(
        &dir,
        ["9571", "9572", "9573"],
        &["--on-drop", "cut", "--report-contacts"],
    );
    let err = f.err();
    let report = &f.report;
    let context = format!(
        "a {:?}; b {:?}; stray {:?}; got a {:?}; got b {:?}; got stray {:?}; stderr {err}; report {report}",
        traffic.to_a, traffic.to_b, traffic.to_stray, traffic.at_a, traffic.at_b, traffic.at_stray,
    );
    // The run started, so the readback of the combined ruleset passed.
    assert!(!err.contains("not the one playpen built"), "{context}");
    assert_eq!(report["outcome"], "ran", "{context}");
    assert_eq!(f.code, Some(0), "{context}");
    check_traffic(&traffic, &context);

    // Each datagram to A is a flow start (A never answers), so the record
    // counts exactly the ones that left: all before the trip. A never
    // answers, so the destination has no answer.
    let left = traffic.to_a.iter().filter(|s| s.sent).count();
    assert!(left >= 10, "{context}");
    assert_eq!(
        report["contacted"],
        json!({
            "destinations": [
                {"address": "198.51.100.7", "protocol": "udp", "port": 9571, "packets": left, "answered": false, "reset": false}
            ],
            "truncated": false
        }),
        "{context}"
    );
    let dest = json!({"address": "198.51.100.9", "protocol": "udp", "port": 9573, "packets": 1});
    assert_eq!(
        report["dropped"]["destinations"],
        json!([dest]),
        "{context}"
    );
    assert_eq!(
        report["egress_cut"]["tripped_by"],
        json!([dest]),
        "{context}"
    );
    assert_eq!(report["on_drop"], "cut", "{context}");

    // The start line has the record, then the tripwire.
    assert!(
        err.contains("; contacted destinations recorded; at the first dropped packet the firewall itself refuses all traffic but loopback, and the command runs on (--on-drop cut)"),
        "{err}"
    );
    assert!(
        err.contains("playpen: the command contacted 1 approved destination(s)"),
        "{err}"
    );
    assert!(
        err.contains("playpen: the firewall closed all egress at the first dropped packet (--on-drop cut): 198.51.100.9 udp port 9573"),
        "{err}"
    );

    let out = Command::new(BIN)
        .args(["--format", "json", "suggest"])
        .arg(dir.join("report.json"))
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let suggested: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(out.status.code(), Some(0), "{suggested}");
    assert_eq!(
        suggested["allow"],
        json!(["198.51.100.7:9571/udp"]),
        "{suggested}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--on-drop stop` and a command that exits 0 on SIGTERM: playpen learns
/// of the trip within one reading, closes egress, sends SIGTERM, and exits
/// 1 although the command exited 0.
#[test]
fn stop_ends_the_command_within_one_reading_and_never_exits_0() {
    require!(false);
    let dir = tmpdir("stop");
    let log = dir.join("send.jsonl");
    let log_arg = log.to_str().unwrap_or("");
    let f = run_inside(
        &dir,
        &[
            "--no-network",
            "--lo-addr",
            "192.0.2.2",
            "--on-drop",
            "stop",
            "--",
            "sh",
            "-c",
            "trap 'exit 0' TERM; \"$0\" probe send 192.0.2.2:9581/udp --every-ms 60000 >\"$1\" & sleep 30 & wait $!; exit 3",
            BIN,
            log_arg,
        ],
    );
    let err = f.err();
    let sends = sends(&log);
    let context = format!(
        "events {:?}; stderr {err}; sends {sends:?}; report {}",
        f.events, f.report
    );
    assert_eq!(sends.len(), 1, "{context}");
    let tripped = sends[0].at_ns;
    let r = &f.report;

    assert_eq!(f.code, Some(1), "{context}");
    assert_eq!(r["exit_code"], 0, "{context}");
    assert!(r["signal"].is_null(), "{context}");
    assert_eq!(r["playpen_exit_status"], 1, "{context}");
    assert_eq!(r["on_drop"], "stop", "{context}");
    assert_eq!(r["stopped_by_drop"], true, "{context}");
    assert_eq!(r["stopped_by_until"], false, "{context}");
    assert_eq!(r["stopped_by_pass"], false, "{context}");
    let reason = "a packet to an unapproved destination was dropped: 192.0.2.2 udp port 9581 (--on-drop stop)";
    assert_eq!(r["stop_reason"], reason, "{context}");
    let dest = json!({"address": "192.0.2.2", "protocol": "udp", "port": 9581, "packets": 1});
    assert_eq!(r["egress_cut"]["tripped_by"], json!([dest]), "{context}");
    assert_eq!(r["dropped"]["packets"], 1, "{context}");

    // The command ended within one reading interval of the packet.
    let ended = report_ns(&r["ended_at"]);
    assert!(
        ended > tripped && ended - tripped <= INTERVAL_NS + SLACK_NS,
        "the command ended {} ms after the trip; {context}",
        ended.saturating_sub(tripped) / 1_000_000
    );
    let notice = f.line_at(&format!(
        "playpen: {reason}; the firewall now refuses all traffic but loopback; sending SIGTERM to the command (SIGKILL in 3 s)"
    ));
    assert!(
        notice > tripped && notice <= ended + 100_000_000,
        "{context}"
    );
    assert!(
        err.contains(&format!("playpen: stopped the command because {reason}")),
        "{err}"
    );

    // The records: the destination, then the stop, with egress closed.
    let names: Vec<&str> = f
        .events
        .iter()
        .map(|e| e["event"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        names,
        ["validated", "starting", "denied", "stopping", "terminal"],
        "{context}"
    );
    assert_eq!(
        f.events[3]["details"],
        json!({"reason": "drop", "egress_closed": true})
    );
    assert_eq!(f.events[4]["details"]["child_exit"], 0);
    assert_eq!(f.events[4]["details"]["wrapper_exit"], 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--on-drop stop` and a command that ignores SIGTERM: it is killed with
/// SIGKILL after the grace, within one reading interval and the grace of
/// the packet, and keeps its signal status.
#[test]
fn stop_kills_a_command_that_ignores_sigterm_after_the_grace() {
    require!(false);
    let dir = tmpdir("kill");
    let log = dir.join("send.jsonl");
    let log_arg = log.to_str().unwrap_or("");
    let f = run_inside(
        &dir,
        &[
            "--no-network",
            "--lo-addr",
            "192.0.2.2",
            "--on-drop",
            "stop",
            "--",
            "sh",
            "-c",
            "trap '' TERM; exec \"$0\" probe send 192.0.2.2:9582/udp --every-ms 100 >\"$1\"",
            BIN,
            log_arg,
        ],
    );
    let err = f.err();
    let sends = sends(&log);
    let context = format!(
        "events {:?}; stderr {err}; sends {}; report {}",
        f.events,
        sends.len(),
        f.report
    );
    let tripped = sends
        .first()
        .map_or_else(|| panic!("{context}"), |s| s.at_ns);
    let r = &f.report;
    assert_eq!(f.code, Some(128 + 9), "{context}");
    assert_eq!(r["signal"], 9, "{context}");
    assert_eq!(r["stopped_by_drop"], true, "{context}");
    let notice = f.line_at(
        "(--on-drop stop); the firewall now refuses all traffic but loopback; sending SIGTERM",
    );
    let ended = report_ns(&r["ended_at"]);
    assert!(
        ended > tripped && ended - tripped <= INTERVAL_NS + GRACE_NS + SLACK_NS,
        "the command ended {} ms after the trip; {context}",
        ended.saturating_sub(tripped) / 1_000_000
    );
    assert!(
        ended + 200_000_000 >= notice + GRACE_NS,
        "killed before the grace; {context}"
    );
    // Every datagram was refused; after the first, by the cut.
    assert!(
        sends.iter().all(|s| !s.sent && s.error.contains(EPERM)),
        "{context}"
    );
    assert_eq!(r["dropped"]["packets"], 1, "{context}");
    let counted = r["egress_cut"]["refused"].as_u64().unwrap_or(0);
    let later = sends.len() as u64 - 1;
    assert!(
        counted >= later && counted <= later + 2,
        "{later} later sends, counted {counted}; {context}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--on-drop cut` keeps the command running and its exit status, and the
/// shareable report has the option and the stop flag, not the destination.
#[test]
fn cut_keeps_the_command_status_and_the_shareable_report_names_no_destination() {
    require!(false);
    let dir = tmpdir("share");
    let f = run_inside(
        &dir,
        &[
            "--no-network",
            "--lo-addr",
            "192.0.2.2",
            "--on-drop",
            "cut",
            "--shareable-report",
            "--",
            "sh",
            "-c",
            "\"$0\" probe send 192.0.2.2:9583/udp --every-ms 60000 & P=$!; sleep 2.5; kill $P; exit 5",
            BIN,
        ],
    );
    let err = f.err();
    let context = format!("stderr {err}; report {}", f.report);
    let r = &f.report;
    assert_eq!(f.code, Some(5), "{context}");
    assert_eq!(r["schema"], "playpen-shareable-v1", "{context}");
    assert_eq!(r["exit_code"], 5, "{context}");
    assert_eq!(r["playpen_exit_status"], 5, "{context}");
    assert_eq!(r["on_drop"], "cut", "{context}");
    assert_eq!(r["stopped_by_drop"], false, "{context}");
    assert_eq!(r["dropped_packets"], 1, "{context}");
    assert!(r.get("egress_cut").is_none(), "{context}");
    assert!(!r.to_string().contains("192.0.2.2"), "{context}");
    assert!(err.contains("(--on-drop cut); the firewall now refuses all traffic but loopback, and the command keeps running"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Without `--on-drop` a dropped packet closes nothing: the report has none
/// of the option's keys, and the drop is counted as before.
#[test]
fn without_the_option_nothing_trips_and_the_report_is_unchanged() {
    require!(false);
    let dir = tmpdir("off");
    let f = run_inside(
        &dir,
        &[
            "--no-network",
            "--lo-addr",
            "192.0.2.2",
            "--",
            "sh",
            "-c",
            "\"$0\" probe send 192.0.2.2:9584/udp --every-ms 100 & P=$!; sleep 2.5; kill $P; exit 0",
            BIN,
        ],
    );
    let err = f.err();
    let context = format!("stderr {err}; report {}", f.report);
    let r = &f.report;
    assert_eq!(f.code, Some(0), "{context}");
    for key in ["on_drop", "egress_cut", "stopped_by_drop"] {
        assert!(r.get(key).is_none(), "{key}; {context}");
    }
    assert!(
        r["dropped"]["packets"].as_u64().unwrap_or(0) >= 20,
        "{context}"
    );
    assert_eq!(r["refused_after_end"], 0, "{context}");
    assert!(!err.contains("--on-drop"), "{err}");
    let names: Vec<&str> = f
        .events
        .iter()
        .map(|e| e["event"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(
        names,
        ["validated", "starting", "denied", "terminal"],
        "{context}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `playpen compare` counts a report whose cut tripped and refused packets
/// as incomplete drop evidence: the cut refuses them before the drop sets.
#[test]
fn compare_counts_a_tripped_cut_as_incomplete_evidence() {
    let dir = tmpdir("compare");
    let (a, b) = (dir.join("a.json"), dir.join("b.json"));
    let dest = json!({"address": "192.0.2.2", "protocol": "udp", "port": 53, "packets": 1});
    let mut report = json!({"playpen_version":"0.1.0", "outcome":"ran",
        "allowed":["192.0.2.1:80/tcp"], "network":"pasta", "hosts":[], "exposed":[],
        "socket_guard":"landlock", "display":false,
        "dropped":{"packets":1,"destinations_truncated":false,"destinations":[dest]},
        "lookups":{"names":[],"truncated":false},
        "on_drop":"cut", "stopped_by_drop":false,
        "egress_cut":{"tripped_by":[dest], "refused":0}});
    let compare = |before: &Value, after: &Value| {
        std::fs::write(&a, before.to_string()).unwrap_or_else(|e| panic!("{e}"));
        std::fs::write(&b, after.to_string()).unwrap_or_else(|e| panic!("{e}"));
        let out = Command::new(BIN)
            .arg("compare")
            .args([&a, &b])
            .args(["--format", "json"])
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
        (out.status.code(), v)
    };
    // Nothing refused after the trip: the drop sets have every drop.
    let (code, v) = compare(&report, &report);
    assert_eq!((code, &v["evidence"]), (Some(0), &json!("complete")), "{v}");
    assert_eq!(v["policy"], "same", "{v}");
    let mut plain = report.clone();
    for key in ["on_drop", "stopped_by_drop", "egress_cut"] {
        plain.as_object_mut().map(|o| o.remove(key));
    }
    let (code, v) = compare(&plain, &report);
    assert_eq!((code, &v["policy"]), (Some(0), &json!("same")), "{v}");
    // Packets refused after the trip, or an unknown count: incomplete.
    for refused in [json!(12), Value::Null] {
        report["egress_cut"]["refused"] = refused;
        let (code, v) = compare(&plain, &report);
        assert_eq!(code, Some(2), "{v}");
        assert_eq!(v["evidence"], "incomplete", "{v}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
