//! `run --capture FILE` and the run's timestamps.
//!
//! The capture tests build the throwaway host of `tests/gateway.rs`: a user
//! and network namespace whose only way out is a `dummy` interface (it
//! discards everything sent to it), with a service address on a second
//! dummy interface that pasta does not copy into the sandbox. A listener on
//! that address is the approved destination. Nothing can leave the
//! machine, even if the filter were wrong.

#![allow(
    clippy::disallowed_macros,
    reason = "test code may print with the std macros"
)]

use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");
/// The listener's port on the fake host.
const PORT: &str = "9557";
/// The service address on the fake host: approved.
const APPROVED: [u8; 4] = [198, 51, 100, 7];
/// Routed out through the dummy interface: never approved.
const DENIED: [u8; 4] = [198, 51, 100, 8];

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A fresh directory only the caller can write to.
fn tmpdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("capture-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("{e}"));
    dir
}

fn tool(name: &str) -> bool {
    ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .iter()
        .any(|d| Path::new(d).join(name).exists())
}

/// Why the sandbox cannot run here, if it cannot.
fn sandbox_skip() -> Option<String> {
    let max = std::fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap_or_default();
    if max.trim().is_empty() || max.trim() == "0" {
        return Some("user namespaces are not available".into());
    }
    ["nft", "pasta"]
        .into_iter()
        .find(|t| !tool(t))
        .map(|t| format!("{t} is not installed"))
}

/// Why the fake host cannot be built here, if it cannot.
fn fake_host_skip() -> Option<String> {
    if let Some(why) = sandbox_skip() {
        return Some(why);
    }
    if !tool("curl") {
        return Some("curl is not installed".into());
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
    (!ok).then(|| "cannot make a network namespace with a dummy interface (unshare, ip)".into())
}

/// The fake host: runs as mapped root in a fresh network namespace, sets up
/// the dummy interfaces, starts the listener, then runs playpen as the
/// caller's uid again.
const OUTER: &str = r#"#!/bin/sh
set -e
BIN="$1"; PORT="$2"; LOG="$3"; U="$4"; G="$5"; shift 5
ip link set lo up
ip link add dummy0 type dummy
ip addr add 192.0.2.10/24 dev dummy0
ip link set dummy0 up
ip route add default via 192.0.2.1
ip link add fixture0 type dummy
ip addr add 198.51.100.7/32 dev fixture0
ip link set fixture0 up
"$BIN" probe listen "0.0.0.0:$PORT/tcp" --ms 30000 >"$LOG" &
L=$!
n=0
until grep -q listening "$LOG"; do n=$((n+1)); [ $n -lt 200 ] || exit 3; sleep 0.02; done
set +e
unshare --user --map-user="$U" --map-group="$G" "$@"
rc=$?
kill $L
exit $rc
"#;

/// Runs `playpen ARGS` in the fake host.
fn in_fake_host(dir: &Path, args: &[&str]) -> Output {
    let outer = dir.join("outer.sh");
    std::fs::write(&outer, OUTER).unwrap_or_else(|e| panic!("{e}"));
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "sh"])
        .arg(&outer)
        .args([BIN, PORT])
        .arg(dir.join("listener.log"))
        .arg(nix::unistd::getuid().to_string())
        .arg(nix::unistd::getgid().to_string())
        .arg(BIN)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{e}"))
}

fn read_report(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_default()).unwrap_or_default()
}

/// The frames of a pcap file (Ethernet link type). Every record must be
/// complete: a file cut in the middle of a packet does not parse.
fn frames(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let header = bytes.get(..24).ok_or("shorter than a pcap header")?;
    let le = match header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => return Err(format!("not a pcap file: {:02x?}", &header[..4])),
    };
    let u32_at = |b: &[u8], at: usize| -> u32 {
        let four = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        if le {
            u32::from_le_bytes(four)
        } else {
            u32::from_be_bytes(four)
        }
    };
    if u32_at(header, 20) != 1 {
        return Err(format!("link type {} is not Ethernet", u32_at(header, 20)));
    }
    let mut out = Vec::new();
    let mut at = 24;
    while at < bytes.len() {
        let record = bytes
            .get(at..at + 16)
            .ok_or_else(|| format!("a record header is cut off at byte {at}"))?;
        let len = u32_at(record, 8) as usize;
        if len > u32_at(record, 12) as usize {
            return Err(format!(
                "record at byte {at}: captured length above wire length"
            ));
        }
        let data = bytes
            .get(at + 16..at + 16 + len)
            .ok_or_else(|| format!("the packet at byte {at} is cut off"))?;
        out.push(data.to_vec());
        at += 16 + len;
    }
    Ok(out)
}

/// An IPv4 TCP segment in an Ethernet frame.
struct Tcp<'a> {
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    flags: u8,
    payload: &'a [u8],
}

fn tcp(frame: &[u8]) -> Option<Tcp<'_>> {
    if frame.get(12..14)? != [0x08, 0x00] {
        return None;
    }
    let ip = frame.get(14..)?;
    let ihl = usize::from(ip.first()? & 0x0f) * 4;
    if *ip.get(9)? != 6 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
    let seg = ip.get(ihl..total)?;
    let off = usize::from(seg.get(12)? >> 4) * 4;
    Some(Tcp {
        src: ip.get(12..16)?.try_into().ok()?,
        dst: ip.get(16..20)?.try_into().ok()?,
        sport: u16::from_be_bytes([*seg.first()?, *seg.get(1)?]),
        dport: u16::from_be_bytes([*seg.get(2)?, *seg.get(3)?]),
        flags: *seg.get(13)?,
        payload: seg.get(off..)?,
    })
}

fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Whether `frame` is an IPv4 packet from or to `addr`, or ARP about it.
fn mentions(frame: &[u8], addr: [u8; 4]) -> bool {
    match frame.get(12..14) {
        Some([0x08, 0x00]) => {
            frame.get(26..30) == Some(&addr[..]) || frame.get(30..34) == Some(&addr[..])
        }
        Some([0x08, 0x06]) => {
            frame.get(28..32) == Some(&addr[..]) || frame.get(38..42) == Some(&addr[..])
        }
        _ => false,
    }
}

/// The capture's bytes, checked against the report: size, digest, mode.
fn checked_capture(path: &Path, report: &serde_json::Value) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mode = std::fs::metadata(path).map_or(0, |m| m.permissions().mode() & 0o7777);
    assert_eq!(mode, 0o600, "capture mode");
    let canonical = std::fs::canonicalize(path).unwrap_or_default();
    assert_eq!(
        report["capture"]["file"],
        canonical.display().to_string(),
        "{report}"
    );
    assert_eq!(report["capture"]["bytes"], bytes.len(), "{report}");
    let digest = hallpass::Digest::of(&bytes).to_string();
    assert_eq!(
        Some(digest.trim_start_matches("sha256:")),
        report["capture"]["sha256"].as_str(),
        "{report}"
    );
    bytes
}

#[test]
fn the_capture_holds_the_approved_exchange_and_nothing_to_the_denied_address() {
    if let Some(why) = fake_host_skip() {
        eprintln!("SKIPPED: {why}");
        return;
    }
    let dir = tmpdir("exchange");
    let pcap = dir.join("run.pcap");
    let rep = dir.join("report.json");
    let allow = format!("198.51.100.7:{PORT}/tcp");
    let script = format!(
        "curl -qsS --noproxy '*' --max-time 3 http://198.51.100.7:{PORT}/approved-marker; \
         curl -qsS --noproxy '*' --max-time 3 http://198.51.100.8:{PORT}/denied-marker; \
         test -c '{}' && echo capture-hidden; exit 0",
        pcap.display()
    );
    let out = in_fake_host(
        &dir,
        &[
            "run",
            "--allow",
            &allow,
            "--capture",
            pcap.to_str().unwrap_or(""),
            "--report",
            rep.to_str().unwrap_or(""),
            "--",
            "sh",
            "-c",
            &script,
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let report = read_report(&rep);
    assert_eq!(report["outcome"], "ran", "{report}");
    let canonical = std::fs::canonicalize(&pcap).unwrap_or_default();
    assert!(
        stderr.contains(&format!(
            "\nplaypen:   packet capture: {}",
            canonical.display()
        )),
        "{stderr}"
    );
    // The capture file is hidden, but the start line lists it only once.
    assert!(!stderr.contains("hidden:"), "{stderr}");
    // Inside, the capture file is /dev/null: the command cannot change it.
    assert!(
        text(&out.stdout).contains("capture-hidden"),
        "{}",
        text(&out.stdout)
    );
    // The denied attempt happened, and was dropped and counted.
    let dests = report["dropped"]["destinations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        dests
            .iter()
            .any(|d| d["address"] == "198.51.100.8" && d["port"].as_u64() == PORT.parse().ok()),
        "{report}"
    );

    let bytes = checked_capture(&pcap, &report);
    let frames = frames(&bytes).unwrap_or_else(|e| panic!("{e}"));
    let port: u16 = PORT.parse().unwrap_or_default();
    let tcp: Vec<Tcp<'_>> = frames.iter().filter_map(|f| tcp(f)).collect();
    assert!(
        tcp.iter().any(|t| t.dst == APPROVED
            && t.dport == port
            && has(t.payload, b"GET /approved-marker")),
        "no request to the approved address in {} frames",
        frames.len()
    );
    assert!(
        tcp.iter()
            .any(|t| t.src == APPROVED && t.sport == port && t.flags & 0x12 == 0x12),
        "no SYN-ACK from the approved address"
    );
    assert!(
        !frames.iter().any(|f| mentions(f, DENIED)),
        "a packet to the denied address"
    );
    assert!(
        !frames.iter().any(|f| has(f, b"denied-marker")),
        "the denied request"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_run_stopped_by_its_deadline_leaves_a_complete_capture() {
    if let Some(why) = fake_host_skip() {
        eprintln!("SKIPPED: {why}");
        return;
    }
    let dir = tmpdir("deadline");
    let pcap = dir.join("deadline.pcap");
    let rep = dir.join("report.json");
    let allow = format!("198.51.100.7:{PORT}/tcp");
    let until = (OffsetDateTime::now_utc() + time::Duration::seconds(4))
        .format(&Rfc3339)
        .unwrap_or_default();
    // Traffic to the approved address until the very end.
    let script = format!(
        "while :; do curl -qs --noproxy '*' --max-time 1 http://198.51.100.7:{PORT}/loop; done"
    );
    let out = in_fake_host(
        &dir,
        &[
            "run",
            "--allow",
            &allow,
            "--until",
            &until,
            "--capture",
            pcap.to_str().unwrap_or(""),
            "--report",
            rep.to_str().unwrap_or(""),
            "--",
            "sh",
            "-c",
            &script,
        ],
    );
    let report = read_report(&rep);
    assert_eq!(
        report["stopped_by_until"],
        true,
        "{report} {}",
        text(&out.stderr)
    );
    // pasta had exited when playpen read the file: nothing was added after.
    // The full path has the test's PID in it, so no other run of the test
    // on the host matches.
    let path = pcap.as_os_str().as_bytes();
    let pasta_left = std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
        .any(|c| c.windows(path.len()).any(|w| w == path));
    assert!(!pasta_left, "pasta still runs");
    let bytes = checked_capture(&pcap, &report);
    let frames = frames(&bytes).unwrap_or_else(|e| panic!("{e}"));
    // The check above would see a capture cut in the middle of a packet.
    assert!(frames_refuse_every_cut(&bytes));
    let to_approved = frames
        .iter()
        .filter_map(|f| tcp(f))
        .filter(|t| t.dst == APPROVED)
        .count();
    assert!(
        to_approved > 10,
        "{to_approved} packets to the approved address"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Whether [`frames`] refuses `bytes` cut short anywhere inside its last
/// record.
fn frames_refuse_every_cut(bytes: &[u8]) -> bool {
    let Ok(all) = frames(bytes) else {
        return false;
    };
    let last = all.last().map_or(0, Vec::len) + 16;
    (1..last).all(|cut| frames(&bytes[..bytes.len() - cut]).is_err())
}

/// pasta goes on without a capture when it cannot open the file. A pasta
/// that never got `--pcap` behaves the same; playpen must notice.
#[test]
fn a_capture_pasta_did_not_write_stops_the_run() {
    if let Some(why) = sandbox_skip() {
        eprintln!("SKIPPED: {why}");
        return;
    }
    let dir = tmpdir("unwritten");
    let real = ["/usr/bin/pasta", "/usr/sbin/pasta", "/bin/pasta"]
        .into_iter()
        .find(|p| Path::new(p).exists())
        .unwrap_or("pasta");
    let wrapper = dir.join("pasta-without-pcap");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nskip=0\nfor a do\n  shift\n  if [ \"$skip\" = 1 ]; then skip=0; continue; fi\n  if [ \"$a\" = --pcap ]; then skip=1; continue; fi\n  set -- \"$@\" \"$a\"\ndone\nexec {real} \"$@\"\n"
        ),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("{e}"));
    let (pcap, rep, marker) = (
        dir.join("run.pcap"),
        dir.join("report.json"),
        dir.join("ran"),
    );
    let out = Command::new(BIN)
        .args(["run", "--allow", "192.0.2.1:9/tcp", "--capture"])
        .arg(&pcap)
        .arg("--report")
        .arg(&rep)
        .arg("--")
        .arg("touch")
        .arg(&marker)
        .env("PLAYPEN_PASTA", &wrapper)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let report = read_report(&rep);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert_eq!(report["outcome"], "not_started", "{report}");
    assert!(
        report["message"]
            .as_str()
            .is_some_and(|m| m.contains("pasta did not write the packet capture")
                && m.contains("nothing was run")),
        "{report}"
    );
    assert!(!marker.exists(), "the command ran");
    assert!(
        report["capture"].is_null() && report["started_at"].is_null(),
        "{report}"
    );
    assert!(!pcap.exists(), "the unused capture file was left behind");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_report_says_when_the_command_started_and_ended() {
    if let Some(why) = sandbox_skip() {
        eprintln!("SKIPPED: {why}");
        return;
    }
    let dir = tmpdir("times");
    let rep = dir.join("report.json");
    let before = OffsetDateTime::now_utc();
    let out = Command::new(BIN)
        .args(["run", "--no-network", "--report"])
        .arg(&rep)
        .args(["--", "sleep", "2"])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let after = OffsetDateTime::now_utc();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let report = read_report(&rep);
    let at = |key: &str| {
        let s = report[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key}: {report}"));
        assert!(s.ends_with('Z'), "{s}");
        OffsetDateTime::parse(s, &Rfc3339).unwrap_or_else(|e| panic!("{s}: {e}"))
    };
    let (started, ended) = (at("started_at"), at("ended_at"));
    assert!(
        before <= started && started <= ended && ended <= after,
        "{report}"
    );
    let ran = (ended - started).as_seconds_f64();
    assert!((ran - 2.0).abs() < 1.0, "{ran} s for sleep 2");
    assert!(report["capture"].is_null(), "{report}");

    // Nothing ran: no times.
    let out = Command::new(BIN)
        .args([
            "run",
            "--allow",
            "192.0.2.1:1/tcp",
            "--until",
            "2000-01-01T00:00:00Z",
            "--report",
        ])
        .arg(&rep)
        .args(["--", "true"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.status.code(), Some(2));
    let report = read_report(&rep);
    assert_eq!(report["outcome"], "refused");
    assert!(
        report["started_at"].is_null() && report["ended_at"].is_null(),
        "{report}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Runs `playpen run` with a capture at `pcap` and a command that leaves a
/// marker if it runs. Returns the exit status and the report.
fn refused_run(dir: &Path, pcap: &Path, extra: &[&str]) -> (Option<i32>, serde_json::Value) {
    let rep = dir.join("report.json");
    let marker = dir.join("ran");
    let mut args = vec!["run", "--report", rep.to_str().unwrap_or(""), "--capture"];
    args.push(pcap.to_str().unwrap_or(""));
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", "touch", marker.to_str().unwrap_or("")]);
    let out = Command::new(BIN)
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(!marker.exists(), "the command ran: {}", text(&out.stderr));
    let report = read_report(&rep);
    assert_eq!(report["outcome"], "refused", "{report}");
    assert_eq!(report["startup_evidence"], "not_started", "{report}");
    assert!(
        report["capture"].is_null() && report["started_at"].is_null(),
        "{report}"
    );
    (out.status.code(), report)
}

#[test]
fn a_taken_name_a_link_and_an_unusable_directory_are_refused() {
    let dir = tmpdir("refusals");
    let allow = ["--allow", "192.0.2.1:9/tcp"];

    let existing = dir.join("existing.pcap");
    std::fs::write(&existing, "earlier capture").unwrap_or_else(|e| panic!("{e}"));
    let (code, r) = refused_run(&dir, &existing, &allow);
    assert_eq!(code, Some(2));
    assert!(
        r["message"]
            .as_str()
            .is_some_and(|m| m.contains("already exists")),
        "{r}"
    );
    assert_eq!(
        std::fs::read_to_string(&existing).unwrap_or_default(),
        "earlier capture"
    );

    let link = dir.join("link.pcap");
    let target = dir.join("elsewhere");
    std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|e| panic!("{e}"));
    let (code, r) = refused_run(&dir, &link, &allow);
    assert_eq!(code, Some(2));
    assert!(
        r["message"]
            .as_str()
            .is_some_and(|m| m.contains("symbolic link")),
        "{r}"
    );
    assert!(!target.exists());

    let locked = dir.join("locked");
    std::fs::create_dir(&locked).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500))
        .unwrap_or_else(|e| panic!("{e}"));
    let (code, r) = refused_run(&dir, &locked.join("run.pcap"), &allow);
    assert_eq!(code, Some(2));
    assert!(
        r["message"].as_str().is_some_and(
            |m| m.contains("cannot create the capture file") && m.contains("Permission denied")
        ),
        "{r}"
    );

    let shared = dir.join("shared");
    std::fs::create_dir(&shared).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775))
        .unwrap_or_else(|e| panic!("{e}"));
    let (code, r) = refused_run(&dir, &shared.join("run.pcap"), &allow);
    assert_eq!(code, Some(2));
    assert!(
        r["message"]
            .as_str()
            .is_some_and(|m| m.contains("can be written by its group or others")),
        "{r}"
    );
    assert!(!shared.join("run.pcap").exists());

    let (code, r) = refused_run(&dir, &dir.join("offline.pcap"), &["--no-network"]);
    assert_eq!(code, Some(2));
    assert!(
        r["message"]
            .as_str()
            .is_some_and(|m| m.contains("--capture and --no-network")),
        "{r}"
    );
    assert!(!dir.join("offline.pcap").exists());
    let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_plan_and_its_digest_include_the_capture() {
    let dir = tmpdir("plan");
    let pcap = dir.join("run.pcap");
    let plan = |capture: Option<&Path>| -> serde_json::Value {
        let mut c = Command::new(BIN);
        c.args(["plan", "--format", "json", "--allow", "192.0.2.1:443/tcp"]);
        if let Some(p) = capture {
            c.arg("--capture").arg(p);
        }
        let out = c
            .args(["--", "true"])
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        serde_json::from_slice(&out.stdout).unwrap_or_default()
    };
    let without = plan(None);
    let with = plan(Some(&pcap));
    assert!(without["plan"].get("capture").is_none(), "{without}");
    assert_eq!(with["plan"]["capture"], pcap.display().to_string());
    assert_ne!(with["digest"], without["digest"]);
    assert!(!pcap.exists(), "plan created the capture file");

    // A run with a capture the reviewed plan did not have is refused
    // before the file is made.
    let digest = without["digest"].as_str().unwrap_or("");
    let (code, r) = refused_run(
        &dir,
        &pcap,
        &["--allow", "192.0.2.1:443/tcp", "--expect-plan", digest],
    );
    assert_eq!(code, Some(2));
    assert!(
        r["message"]
            .as_str()
            .is_some_and(|m| m.contains("reviewed plan")),
        "{r}"
    );
    assert!(!pcap.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn compare_ignores_the_times_and_the_capture() {
    let dir = tmpdir("compare");
    let (a, b) = (dir.join("a.json"), dir.join("b.json"));
    let mut report = serde_json::json!({"playpen_version":"0.1.0", "outcome":"ran",
        "allowed":["192.0.2.1:80/tcp"], "network":"pasta", "hosts":[], "exposed":[],
        "socket_guard":"landlock", "display":false,
        "dropped":{"packets":0,"destinations_truncated":false,"destinations":[]},
        "lookups":{"names":[],"truncated":false},
        "started_at":"2026-11-22T10:00:00Z", "ended_at":"2026-11-22T10:00:02Z",
        "capture":{"file":"/w/a.pcap","bytes":24,"sha256":"00"}});
    std::fs::write(&a, report.to_string()).unwrap_or_else(|e| panic!("{e}"));
    report["started_at"] = "2026-11-23T09:00:00.5Z".into();
    report["ended_at"] = "2026-11-23T09:30:00Z".into();
    report["capture"] = serde_json::Value::Null;
    std::fs::write(&b, report.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let out = Command::new(BIN)
        .arg("compare")
        .args([&a, &b])
        .args(["--format", "json"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stdout));
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(result["policy"], "same");
    assert_eq!(result["evidence"], "complete");
    let _ = std::fs::remove_dir_all(&dir);
}
