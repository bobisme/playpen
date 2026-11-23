//! End-to-end tests of drops reported while the command runs: the `denied`
//! records on `--events-fd`, and the lines `--live-drops` prints.
//!
//! As in `run.rs`, every destination is an address on the sandbox's own `lo`
//! (the hidden `--lo-addr` test aid), so a packet to it never reaches pasta,
//! even if the filter were broken. The output chain drops and counts it all
//! the same. The commands inside are `playpen probe send`, which sends a
//! numbered datagram every 100 ms and logs each attempt with the wall-clock
//! time, and `playpen probe reach`, which tries each target once.

use std::collections::BTreeSet;
use std::io::{BufRead as _, BufReader};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::fcntl::OFlag;
use nix::unistd::pipe2;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

/// How often playpen reads the drop counter.
const INTERVAL_NS: u64 = 2_000_000_000;
/// What the bounds allow on top of one interval: the reading itself, and
/// scheduling on a machine busy with the other tests.
const SLACK_NS: u64 = 1_500_000_000;

/// Why the sandbox cannot run here, if it cannot.
fn skip_reason(pasta: bool) -> Option<String> {
    let max = std::fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap_or_default();
    if max.trim().is_empty() || max.trim() == "0" {
        return Some("user namespaces are not available".into());
    }
    let tools: &[&str] = if pasta { &["nft", "pasta"] } else { &["nft"] };
    for tool in tools {
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
    ($pasta:expr) => {
        if let Some(why) = skip_reason($pasta) {
            eprintln!("SKIPPED: {why}");
            return;
        }
    };
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("live-drops-{name}-{}", std::process::id()));
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

/// Lines of a stream, each with the wall-clock time the test read it.
type Lines = Arc<Mutex<Vec<(u64, String)>>>;

fn read_lines(stream: impl std::io::Read + Send + 'static) -> (Lines, std::thread::JoinHandle<()>) {
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

/// A run of playpen with its stderr and its `--events-fd` stream read as
/// they come.
struct Run {
    child: Child,
    stderr: (Lines, std::thread::JoinHandle<()>),
    events: (Lines, std::thread::JoinHandle<()>),
}

/// What a finished run left: exit code, stderr lines and event records
/// (each with the time it was read), and the report.
struct Finished {
    code: Option<i32>,
    stderr: Vec<(u64, String)>,
    events: Vec<(u64, Value)>,
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
    fn denied(&self) -> Vec<(u64, Value)> {
        self.events
            .iter()
            .filter(|(_, e)| e["event"] == "denied")
            .cloned()
            .collect()
    }
    /// The lines `--live-drops` prints.
    fn live_lines(&self) -> Vec<(u64, String)> {
        self.stderr
            .iter()
            .filter(|(_, l)| l.starts_with("playpen: dropped:"))
            .cloned()
            .collect()
    }
}

/// Starts `playpen run --events-fd 42 ARGS --report DIR/report.json`.
fn start(dir: &Path, args: &[&str]) -> Run {
    let (r, w) = pipe2(OFlag::O_CLOEXEC).unwrap_or_else(|e| panic!("pipe: {e}"));
    let raw = w.as_raw_fd();
    let _ = std::fs::remove_file(dir.join("report.json"));
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
    Run {
        child,
        stderr,
        events,
    }
}

impl Run {
    fn finish(mut self, dir: &Path) -> Finished {
        let status = self.child.wait().unwrap_or_else(|e| panic!("{e}"));
        let _ = self.stderr.1.join();
        let _ = self.events.1.join();
        let take = |lines: &Lines| lines.lock().map_or_else(|_| Vec::new(), |l| l.clone());
        let events = take(&self.events.0)
            .into_iter()
            .map(|(at, l)| {
                let v = serde_json::from_str(&l).unwrap_or_else(|e| panic!("{e}: {l:?}"));
                (at, v)
            })
            .collect();
        let report = serde_json::from_str(
            &std::fs::read_to_string(dir.join("report.json")).unwrap_or_default(),
        )
        .unwrap_or_default();
        Finished {
            code: status.code(),
            stderr: take(&self.stderr.0),
            events,
            report,
        }
    }
}

/// One attempt of `probe send`: when, and whether it left.
fn sends(path: &Path) -> Vec<(u64, bool, String)> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| {
            Some((
                v["at_ns"].as_u64()?,
                v["sent"].as_bool()?,
                v["error"].as_str().unwrap_or("").to_owned(),
            ))
        })
        .collect()
}

/// A command that sends to a denied address every 100 ms and is alive for
/// 6 s: the `denied` record and the line come within one reading interval
/// of the first packet, while the command is still alive, and once only,
/// although more packets follow over several readings.
#[test]
fn a_denied_destination_is_reported_once_while_the_command_runs() {
    require_sandbox!(true);
    let dir = tmpdir("once");
    let log = dir.join("sends.jsonl");
    let _ = std::fs::remove_file(&log);
    let log_arg = log.to_str().unwrap_or("");
    let run = start(
        &dir,
        &[
            "--allow",
            "192.0.2.1:9101/tcp",
            "--lo-addr",
            "192.0.2.1",
            "--lo-addr",
            "192.0.2.2",
            "--live-drops",
            "--",
            "sh",
            "-c",
            "\"$0\" probe send 192.0.2.2:9602/udp --every-ms 100 >\"$1\" & sleep 6",
            BIN,
            log_arg,
        ],
    );
    let f = run.finish(&dir);
    let err = f.err();
    let sends = sends(&log);
    let context = format!("events {:?}; stderr {err}; sends {}", f.events, sends.len());
    assert_eq!(f.code, Some(0), "{context}");

    let first = sends.first().map_or_else(|| panic!("{context}"), |s| s.0);
    assert!(
        sends.iter().all(|s| !s.1 && s.2.contains("not permitted")),
        "{context}"
    );
    let ended = report_ns(&f.report["ended_at"]);

    // One record, with the destination.
    let denied = f.denied();
    assert_eq!(denied.len(), 1, "{context}");
    let (at, record) = &denied[0];
    let details = &record["details"];
    assert_eq!(details["address"], "192.0.2.2", "{context}");
    assert_eq!(details["protocol"], "udp", "{context}");
    assert_eq!(details["port"], 9602, "{context}");
    assert!(details["packets"].as_u64().unwrap_or(0) >= 1, "{context}");
    // Within one interval of the first packet, and while the command ran.
    assert!(
        *at > first && *at - first <= INTERVAL_NS + SLACK_NS,
        "the record came {} ms after the first packet; {context}",
        at.saturating_sub(first) / 1_000_000
    );
    assert!(
        *at < ended,
        "the record came after the command ended; {context}"
    );
    // The command went on sending through at least one more reading, and
    // there was no second record.
    let later = sends
        .iter()
        .filter(|s| s.0 > at + INTERVAL_NS + 100_000_000)
        .count();
    assert!(later >= 5, "too few packets after the record; {context}");

    // The same on stderr, once.
    let live = f.live_lines();
    assert_eq!(
        live.iter().map(|(_, l)| l.as_str()).collect::<Vec<_>>(),
        ["playpen: dropped: 192.0.2.2 udp port 9602 (not approved)"],
        "{context}"
    );
    let line_at = live[0].0;
    assert!(
        line_at > first && line_at - first <= INTERVAL_NS + SLACK_NS && line_at < ended,
        "{context}"
    );
    assert!(
        err.contains("; dropped destinations printed while the command runs (the first 8);"),
        "{err}"
    );

    // The records are in order, and the report is the full count.
    let names: Vec<&str> = f
        .events
        .iter()
        .map(|(_, e)| e["event"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(names, ["validated", "starting", "denied", "terminal"]);
    for (i, (_, e)) in f.events.iter().enumerate() {
        assert_eq!(e["seq"], i + 1);
    }
    let packets = f.report["dropped"]["packets"].as_u64().unwrap_or(0);
    let logged = sends.len() as u64;
    assert!(
        packets >= logged && packets <= logged + 1,
        "{packets} counted, {logged} sends logged: {}",
        f.report
    );
    assert_eq!(
        f.report["dropped"]["destinations"],
        serde_json::json!([{"address": "192.0.2.2", "protocol": "udp", "port": 9602, "packets": packets}]),
        "{}",
        f.report
    );
    assert_eq!(f.report["dropped"]["destinations_truncated"], false);
    assert_eq!(f.report["live_drops"], true);
}

/// Twenty destinations at once: eight lines and one "more" line on
/// stderr, a record for each on the events stream, and every one in the
/// report.
#[test]
fn a_burst_is_bounded_on_stderr_and_complete_in_the_report() {
    require_sandbox!(false);
    let dir = tmpdir("burst");
    let mut targets = Vec::new();
    for port in 9701..9711 {
        targets.push(format!("192.0.2.2:{port}/udp"));
    }
    for port in 9711..9716 {
        targets.push(format!("192.0.2.2:{port}/tcp"));
    }
    for port in 9716..9721 {
        targets.push(format!("[2001:db8::2]:{port}/udp"));
    }
    let mut script = String::from("\"$0\" probe reach");
    for t in &targets {
        script.push_str(" --try ");
        script.push_str(t);
    }
    script.push_str(" >/dev/null; sleep 3");
    let run = start(
        &dir,
        &[
            "--no-network",
            "--lo-addr",
            "192.0.2.2",
            "--lo-addr",
            "2001:db8::2",
            "--live-drops",
            "--",
            "sh",
            "-c",
            &script,
            BIN,
        ],
    );
    let f = run.finish(&dir);
    let err = f.err();
    assert_eq!(f.code, Some(0), "{err}");
    let ended = report_ns(&f.report["ended_at"]);

    let expected: BTreeSet<(String, String, u64)> = targets
        .iter()
        .map(|t| {
            let (addr, proto) = t.rsplit_once('/').unwrap_or_default();
            let (host, port) = addr.rsplit_once(':').unwrap_or_default();
            (
                host.trim_matches(['[', ']']).to_owned(),
                proto.to_owned(),
                port.parse().unwrap_or(0),
            )
        })
        .collect();
    let key = |d: &Value| {
        (
            d["address"].as_str().unwrap_or("").to_owned(),
            d["protocol"].as_str().unwrap_or("").to_owned(),
            d["port"].as_u64().unwrap_or(0),
        )
    };

    // A record for each destination, once, while the command ran.
    let denied = f.denied();
    let recorded: BTreeSet<_> = denied.iter().map(|(_, e)| key(&e["details"])).collect();
    assert_eq!(denied.len(), targets.len(), "{:?}", f.events);
    assert_eq!(recorded, expected);
    assert!(denied.iter().all(|(at, _)| *at < ended), "{:?}", f.events);

    // Eight lines, then one line that says there are more.
    let live: Vec<String> = f.live_lines().into_iter().map(|(_, l)| l).collect();
    assert_eq!(live.len(), 9, "{err}");
    for line in &live[..8] {
        let dest = line
            .strip_prefix("playpen: dropped: ")
            .and_then(|l| l.strip_suffix(" (not approved)"))
            .unwrap_or_else(|| panic!("{line:?}"));
        let mut parts = dest.split(' ');
        let (addr, proto, word, port) = (parts.next(), parts.next(), parts.next(), parts.next());
        assert_eq!(word, Some("port"), "{line:?}");
        let k = (
            addr.unwrap_or("").to_owned(),
            proto.unwrap_or("").to_owned(),
            port.and_then(|p| p.parse().ok()).unwrap_or(0),
        );
        assert!(expected.contains(&k), "{line:?}");
    }
    assert_eq!(
        live[8],
        "playpen: dropped: more than 8 destinations; see the summary at the end"
    );

    // The report and the summary have them all.
    let dests = f.report["dropped"]["destinations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert_eq!(dests.iter().map(key).collect::<BTreeSet<_>>(), expected);
    assert_eq!(dests.len(), targets.len());
    assert_eq!(f.report["dropped"]["destinations_truncated"], false);
    for (addr, proto, port) in &expected {
        assert!(
            err.contains(&format!(
                "playpen:   {addr} {proto} port {port}: 1 packet(s)"
            )),
            "{err}"
        );
    }
}

/// A run with nothing dropped prints what it printed before, and the
/// event stream has no `denied` record, although the counter is read
/// while the command runs (`--events-fd`).
#[test]
fn a_run_without_drops_has_unchanged_output() {
    require_sandbox!(false);
    let dir = tmpdir("quiet");
    for live in [false, true] {
        let mut args = vec!["--no-network"];
        if live {
            args.push("--live-drops");
        }
        // Long enough for a reading, with a packet only on loopback.
        args.extend_from_slice(&[
            "--",
            "sh",
            "-c",
            "\"$0\" probe reach --serve 127.0.0.1:9731/udp --try 127.0.0.1:9731/udp >/dev/null; sleep 2.5",
            BIN,
        ]);
        let f = start(&dir, &args).finish(&dir);
        let err = f.err();
        assert_eq!(f.code, Some(0), "{err}");
        let lines: Vec<&str> = f.stderr.iter().map(|(_, l)| l.as_str()).collect();
        assert_eq!(lines.len(), 3, "{err}");
        assert!(
            lines[0].starts_with("playpen: no network, loopback only"),
            "{err}"
        );
        assert_eq!(
            lines[0].contains("dropped destinations printed while the command runs"),
            live,
            "{err}"
        );
        assert_eq!(lines[1], "playpen: command exited with status 0");
        assert_eq!(
            lines[2],
            "playpen: no packets to unapproved destinations were dropped"
        );
        let names: Vec<&str> = f
            .events
            .iter()
            .map(|(_, e)| e["event"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(names, ["validated", "starting", "terminal"]);
        assert_eq!(f.report["dropped"]["packets"], 0);
        assert_eq!(f.report["live_drops"], live);
    }
}

/// After the end of the approval the cut and the time rule refuse every
/// packet before the drop rule, so a command that sends to a denied
/// address in its grace gets no `denied` record and no line; the packets
/// are counted as refused after the end.
#[test]
fn packets_refused_after_the_end_make_no_denied_record() {
    require_sandbox!(false);
    let dir = tmpdir("after-end");
    let until = (OffsetDateTime::now_utc() + time::Duration::seconds(3))
        .format(&Rfc3339)
        .unwrap_or_default();
    let log = dir.join("sends.jsonl");
    let _ = std::fs::remove_file(&log);
    let log_arg = log.to_str().unwrap_or("");
    // The command ignores SIGTERM and starts sending 4 s after the start,
    // after the end; SIGKILL comes 3 s after the end.
    let f = start(
        &dir,
        &[
            "--no-network",
            "--lo-addr",
            "192.0.2.2",
            "--until",
            &until,
            "--live-drops",
            "--",
            "sh",
            "-c",
            "trap '' TERM; sleep 4; exec \"$0\" probe send 192.0.2.2:9602/udp --every-ms 100 >\"$1\"",
            BIN,
            log_arg,
        ],
    )
    .finish(&dir);
    let err = f.err();
    let sends = sends(&log);
    let context = format!("events {:?}; stderr {err}; sends {sends:?}", f.events);
    assert_eq!(f.code, Some(128 + 9), "{context}");
    assert!(sends.len() >= 5, "too few sends in the grace; {context}");
    assert!(sends.iter().all(|s| !s.1), "{context}");
    assert!(f.denied().is_empty(), "{context}");
    assert!(f.live_lines().is_empty(), "{context}");
    assert_eq!(f.report["dropped"]["packets"], 0, "{context}");
    assert!(
        f.report["refused_after_end"].as_u64().unwrap_or(0) >= sends.len() as u64,
        "{context}"
    );
}

/// `compare` reads `live_drops` as a presentation choice, not policy.
#[test]
fn compare_ignores_live_drops() {
    let dir = tmpdir("compare");
    let (a, b) = (dir.join("a.json"), dir.join("b.json"));
    let mut report = serde_json::json!({"playpen_version":"0.1.0", "outcome":"ran",
        "allowed":["192.0.2.1:80/tcp"], "network":"pasta", "hosts":[], "exposed":[],
        "socket_guard":"landlock", "display":false, "live_drops":false,
        "dropped":{"packets":0,"destinations_truncated":false,"destinations":[]},
        "lookups":{"names":[],"truncated":false}});
    std::fs::write(&a, report.to_string()).unwrap_or_else(|e| panic!("{e}"));
    report["live_drops"] = true.into();
    std::fs::write(&b, report.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let out = Command::new(BIN)
        .arg("compare")
        .args([&a, &b])
        .args(["--format", "json"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let result: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(out.status.code(), Some(0), "{result}");
    assert_eq!(result["policy"], "same");
    assert_eq!(result["evidence"], "complete");
    let _ = std::fs::remove_dir_all(&dir);
}
