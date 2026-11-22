//! Integration tests: run the built binary.
//!
//! Every network test uses addresses that exist only inside the sandbox
//! (documentation addresses added to the sandbox's own `lo` with the hidden
//! `--lo-addr` test aid) or the host's loopback. Nothing is sent to another
//! host, even if the filter were broken: packets to an address on the
//! sandbox's `lo` never reach pasta.

use std::io::Read as _;
use std::net::{TcpListener, UdpSocket};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

/// Why the sandbox cannot run here, if it cannot.
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

fn playpen(args: &[&str]) -> Command {
    let mut c = Command::new(BIN);
    c.args(args);
    c.stdin(Stdio::null());
    c
}

fn run(args: &[&str]) -> Output {
    playpen(args)
        .output()
        .unwrap_or_else(|e| panic!("cannot run playpen: {e}"))
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// The sandbox options shared by the reachability tests.
const LO: &[&str] = &[
    "--lo-addr",
    "192.0.2.1",
    "--lo-addr",
    "192.0.2.2",
    "--lo-addr",
    "2001:db8::1",
    "--lo-addr",
    "2001:db8::2",
];

/// Runs a reach probe inside a sandbox; returns (target, reached) pairs and
/// the playpen output.
fn reach(allow: &[&str], serve: &[&str], tries: &[&str]) -> (Vec<(String, bool)>, Output) {
    let mut args = vec!["run"];
    for a in allow {
        args.push("--allow");
        args.push(a);
    }
    args.extend_from_slice(LO);
    args.extend_from_slice(&["--", BIN, "probe", "reach"]);
    for s in serve {
        args.push("--serve");
        args.push(s);
    }
    for t in tries {
        args.push("--try");
        args.push(t);
    }
    let out = run(&args);
    (parse_reach(&text(&out.stdout)), out)
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

#[test]
fn tcp_allowed_reaches_other_port_and_address_blocked() {
    require_sandbox!();
    let (r, out) = reach(
        &["192.0.2.1:9101/tcp"],
        &[
            "192.0.2.1:9101/tcp",
            "192.0.2.1:9102/tcp",
            "192.0.2.2:9101/tcp",
        ],
        &[
            "192.0.2.1:9101/tcp",
            "192.0.2.1:9102/tcp",
            "192.0.2.2:9101/tcp",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(reached(&r, "192.0.2.1:9101/tcp"));
    assert!(!reached(&r, "192.0.2.1:9102/tcp"));
    assert!(!reached(&r, "192.0.2.2:9101/tcp"));
}

#[test]
fn udp_allowed_reaches_other_port_and_address_blocked() {
    require_sandbox!();
    let (r, out) = reach(
        &["192.0.2.1:9201/udp"],
        &[
            "192.0.2.1:9201/udp",
            "192.0.2.1:9202/udp",
            "192.0.2.2:9201/udp",
        ],
        &[
            "192.0.2.1:9201/udp",
            "192.0.2.1:9202/udp",
            "192.0.2.2:9201/udp",
            "192.0.2.1:9201/tcp",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(reached(&r, "192.0.2.1:9201/udp"));
    assert!(!reached(&r, "192.0.2.1:9202/udp"));
    assert!(!reached(&r, "192.0.2.2:9201/udp"));
    // The protocol is part of the approval.
    assert!(!reached(&r, "192.0.2.1:9201/tcp"));
}

#[test]
fn ipv6_allowed_reaches_others_blocked() {
    require_sandbox!();
    let (r, out) = reach(
        &["[2001:db8::1]:9301/tcp", "[2001:db8::1]:9302/udp"],
        &[
            "[2001:db8::1]:9301/tcp",
            "[2001:db8::1]:9303/tcp",
            "[2001:db8::2]:9301/tcp",
            "[2001:db8::1]:9302/udp",
            "[2001:db8::2]:9302/udp",
        ],
        &[
            "[2001:db8::1]:9301/tcp",
            "[2001:db8::1]:9303/tcp",
            "[2001:db8::2]:9301/tcp",
            "[2001:db8::1]:9302/udp",
            "[2001:db8::2]:9302/udp",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(reached(&r, "[2001:db8::1]:9301/tcp"));
    assert!(!reached(&r, "[2001:db8::1]:9303/tcp"));
    assert!(!reached(&r, "[2001:db8::2]:9301/tcp"));
    assert!(reached(&r, "[2001:db8::1]:9302/udp"));
    assert!(!reached(&r, "[2001:db8::2]:9302/udp"));
}

#[test]
fn ipv4_approval_does_not_open_ipv6_and_networks_work() {
    require_sandbox!();
    let (r, out) = reach(
        &["192.0.2.0/24:9401-9402/tcp"],
        &["192.0.2.2:9402/tcp", "[2001:db8::1]:9401/tcp"],
        &["192.0.2.2:9402/tcp", "[2001:db8::1]:9401/tcp"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(reached(&r, "192.0.2.2:9402/tcp"));
    assert!(!reached(&r, "[2001:db8::1]:9401/tcp"));
}

/// The network and broadcast addresses of a listed IPv4 network are not
/// hosts (hallpass refuses them too): dropped and counted, unless listed
/// on their own. The addresses exist only on the sandbox's `lo`.
#[test]
fn network_and_broadcast_addresses_of_a_listed_network_are_dropped() {
    require_sandbox!();
    let dir = tmpdir("edges");
    let report = dir.join("report.json");
    let targets = [
        "198.51.100.0:9411/tcp",
        "198.51.100.7:9411/tcp",
        "198.51.100.255:9411/tcp",
        "198.51.100.255:9412/udp",
        "203.0.113.255:9411/tcp",
        "203.0.113.255:9412/tcp",
    ];
    let mut args = vec![
        "run",
        "--allow",
        "198.51.100.0/24:9411/tcp",
        "--allow",
        "198.51.100.0/24:9412/udp",
        // Listed on its own, the last address of a network is a host.
        "--allow",
        "203.0.113.0/24:9411-9412/tcp",
        "--allow",
        "203.0.113.255:9411/tcp",
        "--report",
        report.to_str().unwrap_or(""),
    ];
    for a in [
        "198.51.100.0",
        "198.51.100.7",
        "198.51.100.255",
        "203.0.113.255",
    ] {
        args.extend_from_slice(&["--lo-addr", a]);
    }
    args.extend_from_slice(&["--", BIN, "probe", "reach"]);
    for t in targets {
        args.extend_from_slice(&["--serve", t]);
    }
    for t in targets {
        args.extend_from_slice(&["--try", t]);
    }
    let out = run(&args);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let r = parse_reach(&text(&out.stdout));
    assert!(reached(&r, "198.51.100.7:9411/tcp"));
    assert!(!reached(&r, "198.51.100.0:9411/tcp"));
    assert!(!reached(&r, "198.51.100.255:9411/tcp"));
    assert!(!reached(&r, "198.51.100.255:9412/udp"));
    assert!(reached(&r, "203.0.113.255:9411/tcp"));
    // Only on the ports of its own rule, not on the network's.
    assert!(!reached(&r, "203.0.113.255:9412/tcp"));
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap_or_default())
            .unwrap_or_default();
    let dropped: Vec<&str> = v["dropped"]["destinations"]
        .as_array()
        .map_or_default(|a| a.iter().filter_map(|d| d["address"].as_str()).collect());
    for a in ["198.51.100.0", "198.51.100.255", "203.0.113.255"] {
        assert!(dropped.contains(&a), "{a} not in {dropped:?}");
    }
    assert!(!dropped.contains(&"198.51.100.7"), "{dropped:?}");
    let _ = std::fs::remove_dir_all(&dir);

    // A name cannot be mapped to such an address either.
    let out = run(&[
        "run",
        "--allow",
        "198.51.100.0/24:9411/tcp",
        "--host",
        "all.example.test=198.51.100.255",
        "--",
        "true",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let err = text(&out.stderr);
    assert!(err.contains("broadcast address"), "{err}");
    assert!(err.contains("nothing was run"), "{err}");
}

#[test]
fn loopback_inside_the_sandbox_works() {
    require_sandbox!();
    let (r, out) = reach(
        &["192.0.2.1:9101/tcp"],
        &["127.0.0.1:9501/tcp", "[::1]:9501/tcp", "127.0.0.1:9502/udp"],
        &["127.0.0.1:9501/tcp", "[::1]:9501/tcp", "127.0.0.1:9502/udp"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(r.iter().all(|(_, ok)| *ok), "{r:?}");
}

#[test]
fn host_loopback_is_unreachable_by_default() {
    require_sandbox!();
    // Listeners on the host's loopback, outside the sandbox. pasta's default
    // automatic forwarding (which playpen turns off) skips the ephemeral
    // range, so these must be below 32768 for the test to mean anything.
    // Bind and keep the sockets in one step: probing for a free port and
    // binding it afterwards races with every other process on the machine.
    let base = 23_000 + u16::try_from(std::process::id() % 5000).unwrap_or(0);
    let (port, tcp4, udp4) = (base..base + 500)
        .find_map(|p| {
            let tcp = TcpListener::bind(("127.0.0.1", p)).ok()?;
            let udp = UdpSocket::bind(("127.0.0.1", p)).ok()?;
            Some((p, tcp, udp))
        })
        .unwrap_or_else(|| panic!("no free port near {base}"));
    let tcp6 = TcpListener::bind(("::1", port)).ok();
    tcp4.set_nonblocking(true).unwrap_or_else(|e| panic!("{e}"));
    udp4.set_nonblocking(true).unwrap_or_else(|e| panic!("{e}"));
    let mut tries = vec![
        format!("127.0.0.1:{port}/tcp"),
        format!("127.0.0.1:{port}/udp"),
    ];
    if let Some(l) = &tcp6 {
        let _ = l.set_nonblocking(true);
        tries.push(format!("[::1]:{port}/tcp"));
    }
    let tries_ref: Vec<&str> = tries.iter().map(String::as_str).collect();
    // A real (pasta) network, as in normal use.
    let (r, out) = reach(&["192.0.2.1:9101/tcp"], &[], &tries_ref);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    for t in &tries {
        assert!(!reached(&r, t), "{t} reached the host's loopback");
    }
    assert!(tcp4.accept().is_err(), "the host listener got a connection");
    let mut buf = [0u8; 64];
    assert!(
        udp4.recv_from(&mut buf).is_err(),
        "the host UDP socket got a datagram"
    );
    if let Some(l) = tcp6 {
        assert!(
            l.accept().is_err(),
            "the host IPv6 listener got a connection"
        );
    }
}

fn privs_json(extra: &[&str]) -> serde_json::Value {
    let mut args = vec!["run", "--allow", "192.0.2.1:9101/tcp"];
    args.extend_from_slice(LO);
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", BIN, "probe", "privs", "--nft", "/usr/bin/nft"]);
    let out = run(&args);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    serde_json::from_str(text(&out.stdout).trim())
        .unwrap_or_else(|e| panic!("{e}: {}", text(&out.stdout)))
}

fn assert_all_denied(v: &serde_json::Value) {
    for key in [
        "nft_flush_ruleset",
        "nft_add_table",
        "add_address",
        "add_link",
        "set_link_up",
        "raw_socket_v4",
        "raw_socket_v6",
        "packet_socket",
        "setns_net_of_pid1",
        "read_pid1_memory",
    ] {
        let val = v[key].as_str().unwrap_or("missing");
        assert!(val.starts_with("denied"), "{key}: {val}");
    }
    assert_eq!(v["cap_eff"], "0000000000000000");
    assert_eq!(v["cap_prm"], "0000000000000000");
    assert_eq!(v["no_new_privs"], "1");
    assert_eq!(v["uid"].as_u64(), Some(u64::from(nix_uid())));
}

fn nix_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(u32::MAX)
}

#[test]
fn command_cannot_change_rules_add_addresses_or_open_raw_sockets() {
    require_sandbox!();
    let v = privs_json(&[]);
    assert_all_denied(&v);
}

#[test]
fn rules_still_hold_after_the_command_tried_to_flush_them() {
    require_sandbox!();
    let mut args = vec!["run", "--allow", "192.0.2.1:9101/tcp"];
    args.extend_from_slice(LO);
    let script = format!(
        "nft flush ruleset 2>/dev/null; {BIN} probe reach --serve 192.0.2.2:9101/tcp --try 192.0.2.2:9101/tcp"
    );
    args.extend_from_slice(&["--", "sh", "-c", &script]);
    let out = run(&args);
    let r = parse_reach(&text(&out.stdout));
    assert!(!reached(&r, "192.0.2.2:9101/tcp"));
}

#[test]
fn children_and_grandchildren_are_equally_confined() {
    require_sandbox!();
    let mut args = vec!["run", "--allow", "192.0.2.1:9101/tcp"];
    args.extend_from_slice(LO);
    let inner = format!(
        "{BIN} probe reach --serve 192.0.2.1:9101/tcp --serve 192.0.2.2:9101/tcp --try 192.0.2.1:9101/tcp --try 192.0.2.2:9101/tcp; {BIN} probe privs --nft /usr/bin/nft"
    );
    let outer = format!("sh -c '{inner}' & wait");
    args.extend_from_slice(&["--", "sh", "-c", &outer]);
    let out = run(&args);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let r = parse_reach(&stdout);
    assert!(reached(&r, "192.0.2.1:9101/tcp"));
    assert!(!reached(&r, "192.0.2.2:9101/tcp"));
    let privs = stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v.get("cap_eff").is_some())
        .unwrap_or_else(|| panic!("no privs line: {stdout}"));
    assert_all_denied(&privs);
}

#[test]
fn background_processes_die_with_the_command() {
    require_sandbox!();
    let dir = tmpdir("orphan");
    let marker = dir.join("late");
    let _ = std::fs::remove_file(&marker);
    let script = format!("(sleep 2; touch {}) & exit 0", marker.display());
    let out = run(&["run", "--no-network", "--", "sh", "-c", &script]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        !marker.exists(),
        "a background process outlived the sandbox"
    );
}

#[test]
fn until_in_the_past_refuses_and_runs_nothing() {
    let dir = tmpdir("until-past");
    let marker = dir.join("ran");
    let _ = std::fs::remove_file(&marker);
    let report = dir.join("report.json");
    let out = run(&[
        "run",
        "--allow",
        "192.0.2.1:443/tcp",
        "--until",
        "2001-01-01T00:00:00Z",
        "--report",
        report.to_str().unwrap_or(""),
        "--",
        "touch",
        marker.to_str().unwrap_or(""),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("nothing was run"),
        "{}",
        text(&out.stderr)
    );
    assert!(!marker.exists());
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap_or_default())
            .unwrap_or_default();
    assert_eq!(json["outcome"], "refused");
}

fn rfc3339_in(secs: u64) -> String {
    let t = time::OffsetDateTime::now_utc() + Duration::from_secs(secs);
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[test]
fn until_shortly_ahead_stops_the_command() {
    require_sandbox!();
    let until = rfc3339_in(2);
    let dir = tmpdir("until-ahead");
    let report = dir.join("report.json");
    let started = Instant::now();
    let out = run(&[
        "run",
        "--no-network",
        "--until",
        &until,
        "--format",
        "json",
        "--report",
        report.to_str().unwrap_or(""),
        "--",
        "sleep",
        "30",
    ]);
    let took = started.elapsed();
    assert!(took < Duration::from_secs(8), "took {took:?}");
    assert!(took >= Duration::from_secs(1), "took {took:?}");
    assert_eq!(out.status.code(), Some(128 + 15), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("approval ended"),
        "{}",
        text(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap_or_default())
            .unwrap_or_default();
    assert_eq!(json["stopped_by_until"], true);
    assert_eq!(json["signal"], 15);
}

#[test]
fn until_kills_a_command_that_ignores_sigterm() {
    require_sandbox!();
    let until = rfc3339_in(1);
    let started = Instant::now();
    let out = run(&[
        "run",
        "--no-network",
        "--until",
        &until,
        "--",
        "sh",
        "-c",
        "trap '' TERM; while :; do sleep 0.2; done",
    ]);
    let took = started.elapsed();
    assert_eq!(out.status.code(), Some(128 + 9), "{}", text(&out.stderr));
    assert!(took < Duration::from_secs(10), "took {took:?}");
}

/// SIGSTOP sent to playpen itself cannot be caught, so playpen cannot
/// freeze the sandbox first as it does for Ctrl-Z. The sandbox's init
/// notices that playpen went silent and freezes the command, so it does not
/// run on past the end time while nothing enforces it; when playpen
/// continues, it stops the command as usual.
#[test]
fn sigstop_of_playpen_itself_freezes_the_command() {
    require_sandbox!();
    let dir = tmpdir("sigstop");
    let ticks = dir.join("ticks");
    let _ = std::fs::remove_file(&ticks);
    let until = rfc3339_in(4);
    let script = format!("while :; do echo t >> {}; sleep 0.1; done", ticks.display());
    let mut child = playpen(&[
        "run",
        "--no-network",
        "--until",
        &until,
        "--",
        "sh",
        "-c",
        &script,
    ])
    .stderr(Stdio::piped())
    .spawn()
    .unwrap_or_else(|e| panic!("{e}"));
    let pid = child.id().to_string();
    let kill = |sig: &str| {
        let st = Command::new("kill").args([sig, &pid]).status();
        assert!(st.is_ok_and(|s| s.success()), "kill {sig}");
    };
    let count = || std::fs::read_to_string(&ticks).map_or(0, |t| t.lines().count());
    let deadline = Instant::now() + Duration::from_secs(3);
    while count() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(count() > 0, "the command did not start");
    kill("-STOP");
    // Longer than the silence init tolerates, and past the end time.
    std::thread::sleep(Duration::from_secs(7));
    let frozen_at = count();
    std::thread::sleep(Duration::from_secs(1));
    let later = count();
    kill("-CONT");
    let status = child.wait().unwrap_or_else(|e| panic!("{e}"));
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    assert_eq!(
        later, frozen_at,
        "the command kept running while playpen was stopped: {err}"
    );
    assert!(err.contains("the approval ended at"), "{err}");
    assert!(err.contains("paused"), "{err}");
    assert_eq!(status.code(), Some(128 + 15), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// If playpen itself is killed outright, the sandbox goes with it: the
/// command does not run on with nobody watching the end time or the pass.
#[test]
fn killing_playpen_kills_the_sandbox() {
    require_sandbox!();
    let dir = tmpdir("killed");
    for extra in [&["--no-network"][..], &["--allow", "192.0.2.1:9/tcp"]] {
        let ticks = dir.join(format!("ticks-{}", extra.len()));
        let _ = std::fs::remove_file(&ticks);
        // In its own session, so nothing but playpen's death can stop it.
        let script = format!(
            "setsid sh -c 'while :; do echo t >> {0}; sleep 0.1; done' & while :; do echo t >> {0}; sleep 0.1; done",
            ticks.display()
        );
        let mut args = vec!["run"];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--", "sh", "-c", &script]);
        let mut child = playpen(&args)
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("{e}"));
        let count = || std::fs::read_to_string(&ticks).map_or(0, |t| t.lines().count());
        let deadline = Instant::now() + Duration::from_secs(5);
        while count() < 4 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(count() >= 4, "{extra:?}: the command did not start");
        child.kill().unwrap_or_else(|e| panic!("{e}"));
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(500));
        let after = count();
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(count(), after, "{extra:?}: the command outlived playpen");
        // A killed playpen cannot remove the directory of pasta's PID file.
        let base = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .unwrap_or_else(std::env::temp_dir);
        let mine = format!("playpen-{}-", child.id());
        for e in std::fs::read_dir(&base).into_iter().flatten().flatten() {
            if e.file_name().to_string_lossy().starts_with(&mine) {
                let _ = std::fs::remove_file(e.path().join("pasta.pid"));
                let _ = std::fs::remove_dir(e.path());
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn fake_tool(name: &str, script: &str) -> PathBuf {
    let dir = tmpdir(name);
    let path = dir.join("tool");
    std::fs::write(&path, script).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    path
}

fn assert_not_started_with(env: (&str, &Path), expect: &str) {
    assert_not_started_with_allow(env, expect, "192.0.2.1:443/tcp");
}

fn assert_not_started_with_allow(env: (&str, &Path), expect: &str, allow: &str) {
    let dir = tmpdir("not-started");
    let marker = dir.join(format!("ran-{}", expect.len()));
    let _ = std::fs::remove_file(&marker);
    let out = playpen(&[
        "run",
        "--allow",
        allow,
        "--",
        "touch",
        marker.to_str().unwrap_or(""),
    ])
    .env(env.0, env.1)
    .output()
    .unwrap_or_else(|e| panic!("{e}"));
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("nothing was run"), "{err}");
    assert!(err.contains(expect), "{err}");
    assert!(!marker.exists(), "the command ran");
}

#[test]
fn failing_nft_load_starts_nothing() {
    require_sandbox!();
    let nft = fake_tool(
        "nft-fail",
        "#!/bin/sh\ncat >/dev/null\necho 'simulated failure' >&2\nexit 1\n",
    );
    assert_not_started_with(("PLAYPEN_NFT", &nft), "nft refused the ruleset");
}

#[test]
fn nft_that_loads_nothing_is_caught_by_verification() {
    require_sandbox!();
    let nft = fake_tool(
        "nft-noop",
        "#!/bin/sh\ncat >/dev/null\necho '{\"nftables\": []}'\nexit 0\n",
    );
    assert_not_started_with(("PLAYPEN_NFT", &nft), "not the one playpen built");
}

#[test]
fn narrower_nft_readback_refuses_to_start_workload() {
    require_sandbox!();
    let nft = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .into_iter()
        .map(|dir| Path::new(dir).join("nft"))
        .find(|path| path.is_file())
        .expect("native nft");
    // The load is passed through unchanged. Change only an inclusive port
    // endpoint in the readback so it still carries the same number of rules.
    let adapter = fake_tool(
        "nft-narrower-readback",
        &format!(
            "#!/bin/sh\n\
        if [ \"$1\" = --json ]; then\n\
            output=$('{}' \"$@\") || exit \"$?\"\n\
            printf '%s\\n' \"$output\" | sed 's/8002/8001/g'\n\
        else\n\
            exec '{}' \"$@\"\n\
        fi\n",
            nft.display(),
            nft.display()
        ),
    );
    assert_not_started_with_allow(
        ("PLAYPEN_NFT", &adapter),
        "the loaded ruleset is not the one playpen built: output rule 6 differs",
        "192.0.2.1:8000-8002/tcp",
    );
}

#[test]
fn failing_pasta_starts_nothing() {
    require_sandbox!();
    let pasta = fake_tool(
        "pasta-fail",
        "#!/bin/sh\necho 'simulated pasta failure' >&2\nexit 1\n",
    );
    assert_not_started_with(("PLAYPEN_PASTA", &pasta), "pasta did not come up");
}

#[test]
fn missing_command_runs_nothing() {
    require_sandbox!();
    let out = run(&[
        "run",
        "--no-network",
        "--",
        "/nonexistent/playpen-test-command",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("nothing was run"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn host_names_resolve_to_the_approved_address() {
    require_sandbox!();
    let out = run(&[
        "run",
        "--allow",
        "192.0.2.10:443/tcp",
        "--host",
        "svc.example.test=192.0.2.10",
        "--",
        "sh",
        "-c",
        &format!(
            "{BIN} probe resolve svc.example.test; {BIN} probe resolve other.example.test; cat /etc/resolv.conf"
        ),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let lines: Vec<serde_json::Value> = stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    assert_eq!(lines[0]["addresses"], serde_json::json!(["192.0.2.10"]));
    assert_eq!(lines[1]["addresses"], serde_json::json!([]));
    assert!(!stdout.contains("nameserver"));
}

#[test]
fn host_files_on_the_host_are_untouched() {
    require_sandbox!();
    let before = std::fs::read("/etc/hosts").unwrap_or_default();
    let out = run(&[
        "run",
        "--allow",
        "192.0.2.10:443/tcp",
        "--host",
        "svc.example.test=192.0.2.10",
        "--",
        "true",
    ]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(std::fs::read("/etc/hosts").unwrap_or_default(), before);
}

#[test]
fn dropped_packets_are_reported() {
    require_sandbox!();
    let dir = tmpdir("drops");
    let report = dir.join("report.json");
    let mut args = vec![
        "run",
        "--allow",
        "192.0.2.1:9101/tcp",
        "--report",
        report.to_str().unwrap_or(""),
    ];
    args.extend_from_slice(LO);
    args.extend_from_slice(&[
        "--",
        BIN,
        "probe",
        "reach",
        "--try",
        "192.0.2.2:9601/tcp",
        "--try",
        "192.0.2.2:9602/udp",
    ]);
    let out = run(&args);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let err = text(&out.stderr);
    assert!(err.contains("WARNING"), "{err}");
    assert!(err.contains("192.0.2.2 tcp port 9601"), "{err}");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap_or_default())
            .unwrap_or_default();
    assert_eq!(json["outcome"], "ran");
    assert!(
        json["dropped"]["packets"].as_u64().unwrap_or(0) >= 2,
        "{json}"
    );
    let dests = json["dropped"]["destinations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        dests
            .iter()
            .any(|d| d["address"] == "192.0.2.2" && d["port"] == 9601 && d["protocol"] == "tcp")
    );
    assert!(
        dests
            .iter()
            .any(|d| d["address"] == "192.0.2.2" && d["port"] == 9602 && d["protocol"] == "udp")
    );
}

#[test]
fn a_quiet_command_reports_no_drops() {
    require_sandbox!();
    let out = run(&["run", "--allow", "192.0.2.1:9101/tcp", "--", "true"]);
    assert_eq!(out.status.code(), Some(0));
    let err = text(&out.stderr);
    assert!(
        err.contains("no packets to unapproved destinations"),
        "{err}"
    );
    assert!(
        err.contains("allowing only 192.0.2.1:9101/tcp with no time limit"),
        "{err}"
    );
}

#[test]
fn exit_status_passes_through_and_report_tells_it_from_refusal() {
    require_sandbox!();
    let dir = tmpdir("exit");
    let report = dir.join("report.json");
    let out = run(&[
        "run",
        "--no-network",
        "--report",
        report.to_str().unwrap_or(""),
        "--",
        "sh",
        "-c",
        "exit 2",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report).unwrap_or_default())
            .unwrap_or_default();
    assert_eq!(json["outcome"], "ran");
    assert_eq!(json["exit_code"], 2);
    let out = run(&["run", "--no-network", "--", "sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn death_by_signal_is_reported() {
    require_sandbox!();
    let out = run(&["run", "--no-network", "--", "sh", "-c", "kill -KILL $$"]);
    assert_eq!(out.status.code(), Some(128 + 9));
    assert!(text(&out.stderr).contains("killed by signal 9"));
}

#[test]
fn signals_are_forwarded_to_the_command() {
    require_sandbox!();
    let mut child = playpen(&[
        "run",
        "--no-network",
        "--",
        "sh",
        "-c",
        "trap 'echo got-term; exit 42' TERM; echo ready; while :; do sleep 0.1; done",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap_or_else(|e| panic!("{e}"));
    let mut stdout = child.stdout.take().unwrap_or_else(|| panic!("no stdout"));
    let mut first = [0u8; 6];
    stdout
        .read_exact(&mut first)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(&first, b"ready\n");
    let pid = child.id().to_string();
    let killed = Command::new("kill").args(["-TERM", &pid]).status();
    assert!(killed.is_ok_and(|s| s.success()));
    let status = child.wait().unwrap_or_else(|e| panic!("{e}"));
    let mut rest = String::new();
    let _ = stdout.read_to_string(&mut rest);
    assert!(rest.contains("got-term"), "{rest}");
    assert_eq!(status.code(), Some(42));
}

/// The pid of the one child of `parent`, from `/proc`.
fn only_child(parent: u32) -> Option<u32> {
    let mut found = std::fs::read_dir("/proc")
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()))
        .filter(|pid| {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            // After the command name: the state letter, then the parent.
            stat.rsplit_once(") ")
                .and_then(|(_, tail)| tail.split(' ').nth(1)?.parse().ok())
                == Some(parent)
        });
    let first = found.next()?;
    found.next().is_none().then_some(first)
}

/// How a test sends SIGUSR1 to a running playpen.
#[derive(Clone, Copy, Debug)]
enum SendTo {
    /// To playpen alone.
    Supervisor,
    /// To playpen's whole process group, the command included.
    Group,
    /// To every playpen process one by one (as `killall playpen` does),
    /// not to the command.
    EachPlaypen,
}

fn spawn_headless_signal_workload(extra: &[&str], workload: &[&str]) -> std::process::Child {
    use std::os::unix::process::CommandExt as _;

    let mut args = vec!["run", "--no-network"];
    args.extend_from_slice(extra);
    args.push("--");
    args.extend_from_slice(workload);
    let mut command = playpen(&args);
    command.stdout(Stdio::piped()).stderr(Stdio::inherit());
    // SAFETY: setsid is async-signal-safe. Run it after fork to guarantee a
    // private process group and detach from any terminal inherited from Cargo.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().expect("start a headless local sandbox")
}

fn usr1_deliveries(extra: &[&str], how: SendTo, workload: &[&str]) -> Vec<usize> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    use std::io::BufRead as _;
    use std::sync::mpsc;

    const SENT: usize = 4;
    const QUIET: Duration = Duration::from_millis(200);
    let mut child = spawn_headless_signal_workload(extra, workload);
    let pid = i32::try_from(child.id()).expect("Linux PID");
    let (tx, rx) = mpsc::channel();
    let stdout = child.stdout.take().expect("piped sandbox stdout");
    let reader = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if matches!(line.as_str(), "ready" | "usr1") && tx.send(line).is_err() {
                break;
            }
        }
    });
    let collect = || -> Result<Vec<usize>, String> {
        let ready = rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        if ready != "ready" {
            return Err(format!("unexpected readiness event: {ready}"));
        }
        let targets = match how {
            SendTo::Supervisor => vec![pid],
            SendTo::Group => vec![-pid],
            SendTo::EachPlaypen => {
                // P, C, S and I, each the only child of the one before.
                let mut helpers = vec![pid];
                for _ in 0..3 {
                    let last = helpers[helpers.len() - 1];
                    let next = only_child(u32::try_from(last).map_err(|e| e.to_string())?)
                        .ok_or_else(|| format!("no child of {last}"))?;
                    helpers.push(i32::try_from(next).map_err(|e| e.to_string())?);
                }
                helpers
            }
        };
        let mut batches = Vec::with_capacity(SENT);
        for _ in 0..SENT {
            for &target in &targets {
                kill(Pid::from_raw(target), Signal::SIGUSR1).map_err(|e| e.to_string())?;
            }
            // Wait for the first receipt, then observe a quiet interval before
            // sending again. Ordinary signals can coalesce when queued at once.
            let first = rx
                .recv_timeout(Duration::from_secs(2))
                .map_err(|e| e.to_string())?;
            if first != "usr1" {
                return Err(format!("unexpected signal event: {first}"));
            }
            let mut count = 1;
            loop {
                match rx.recv_timeout(QUIET) {
                    Ok(event) if event == "usr1" => count += 1,
                    Ok(event) => return Err(format!("unexpected signal event: {event}")),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(e) => return Err(e.to_string()),
                }
            }
            batches.push(count);
        }
        Ok(batches)
    };
    let deliveries = collect();
    let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().expect("check sandbox exit") {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("stop stuck sandbox");
            let _ = child.wait();
            panic!("signal receiver did not exit after SIGTERM ({how:?}, {extra:?})");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    reader.join().expect("collect signal events");
    let late: Vec<_> = rx.try_iter().collect();
    assert!(
        late.is_empty(),
        "late signal receipts: {late:?} ({how:?}, {extra:?})"
    );
    assert!(
        status.success(),
        "receiver exit {status} ({how:?}, {extra:?})"
    );
    deliveries.unwrap_or_else(|err| panic!("signal receiver: {err} ({how:?}, {extra:?})"))
}

#[test]
fn a_signal_for_playpen_reaches_the_command_once() {
    require_sandbox!();
    let mut observations = Vec::new();
    for extra in [&[][..], &["--new-session"][..]] {
        for how in [SendTo::Supervisor, SendTo::EachPlaypen, SendTo::Group] {
            observations.push((
                extra,
                how,
                usr1_deliveries(extra, how, &[BIN, "probe", "signals"]),
            ));
        }
    }
    for (extra, how, deliveries) in &observations {
        assert_eq!(
            deliveries,
            &[1, 1, 1, 1],
            "{how:?} in {extra:?}; all observations: {observations:?}"
        );
    }
}

#[test]
fn a_headless_forwarded_signal_reaches_a_background_descendant_once() {
    require_sandbox!();
    // The background probe is the only process that emits receipts. Its
    // parent shell traps USR1 without relaying it. TERM arranges a clean
    // shutdown of the probe even on versions with leader-only forwarding.
    let workload = [
        "sh",
        "-c",
        r#"
trap ':' USR1
trap 'kill -TERM "$member" 2>/dev/null || :; wait "$member"; exit 0' TERM
"$1" probe signals &
member=$!
while kill -0 "$member" 2>/dev/null; do wait "$member" || :; done
"#,
        "signal-descendant",
        BIN,
    ];
    let deliveries = usr1_deliveries(&[], SendTo::Supervisor, &workload);
    assert_eq!(deliveries, &[1, 1, 1, 1]);
}

/// A process inside that signals PID 1 (the sandbox's init) reaches the
/// command, as a container's init would pass it on.
#[test]
fn a_signal_sent_to_pid_1_inside_reaches_the_command() {
    require_sandbox!();
    let out = run(&[
        "run",
        "--no-network",
        "--",
        "sh",
        "-c",
        "trap 'exit 43' TERM; kill -TERM 1; sleep 2; exit 1",
    ]);
    assert_eq!(out.status.code(), Some(43), "{}", text(&out.stderr));
}

#[test]
fn no_network_has_only_loopback() {
    require_sandbox!();
    // pasta is not needed for --no-network.
    let out = playpen(&[
        "run",
        "--no-network",
        "--lo-addr",
        "192.0.2.1",
        "--",
        BIN,
        "probe",
        "reach",
        "--serve",
        "127.0.0.1:9701/tcp",
        "--serve",
        "192.0.2.1:9701/tcp",
        "--try",
        "127.0.0.1:9701/tcp",
        "--try",
        "192.0.2.1:9701/tcp",
    ])
    .env("PLAYPEN_PASTA", "/nonexistent/pasta")
    .output()
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let r = parse_reach(&text(&out.stdout));
    assert!(reached(&r, "127.0.0.1:9701/tcp"));
    assert!(!reached(&r, "192.0.2.1:9701/tcp"));
    let ifaces = run(&["run", "--no-network", "--", "cat", "/proc/net/dev"]);
    let list = text(&ifaces.stdout);
    assert!(list.contains("lo:"));
    assert_eq!(list.lines().count(), 3, "{list}");
}

#[test]
fn host_sockets_are_hidden() {
    require_sandbox!();
    let dir = tmpdir("hide");
    let secret = dir.join("secret.txt");
    std::fs::write(&secret, "host data").unwrap_or_else(|e| panic!("{e}"));
    let out = run(&[
        "run",
        "--no-network",
        "--hide",
        secret.to_str().unwrap_or(""),
        "--",
        "cat",
        secret.to_str().unwrap_or(""),
    ]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(text(&out.stdout), "");
    let bus = format!("/run/user/{}/bus", nix_uid());
    if Path::new(&bus).exists() {
        let out = run(&["run", "--no-network", "--", "test", "-S", &bus]);
        assert_eq!(
            out.status.code(),
            Some(1),
            "the session bus is still a socket inside"
        );
    }
}

#[test]
fn explicit_missing_and_dangling_hide_paths_are_reported_on_stderr() {
    require_sandbox!();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = tmpdir("hide-diagnostic").join(nonce.to_string());
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    let missing = dir.join("missing");
    let dangling = dir.join("dangling");
    let existing = dir.join("existing");
    std::fs::write(&existing, "host data").unwrap_or_else(|e| panic!("{e}"));
    std::os::unix::fs::symlink(dir.join("absent-target"), &dangling)
        .unwrap_or_else(|e| panic!("{e}"));

    let mut sandbox_available = true;
    for path in [&missing, &dangling] {
        let path = path.to_str().unwrap_or("");
        let out = run(&[
            "run",
            "--no-network",
            "--hide",
            path,
            "--",
            "printf",
            "usable stdout",
        ]);
        assert!(
            text(&out.stderr).contains("NOTE: --hide path"),
            "{}",
            text(&out.stderr)
        );
        assert!(text(&out.stderr).contains("nothing was hidden there"));
        if out.status.code() != Some(0) {
            assert!(
                text(&out.stderr).contains("nothing was run"),
                "{}",
                text(&out.stderr)
            );
            sandbox_available = false;
            break;
        }
        assert_eq!(text(&out.stdout), "usable stdout");
    }

    let path = existing.to_str().unwrap_or("");
    let out = run(&["run", "--no-network", "--hide", path, "--", "cat", path]);
    assert!(
        !text(&out.stderr).contains("NOTE: --hide path"),
        "{}",
        text(&out.stderr)
    );
    if out.status.code() != Some(0) {
        assert!(
            text(&out.stderr).contains("nothing was run"),
            "{}",
            text(&out.stderr)
        );
        sandbox_available = false;
    }
    if !sandbox_available {
        eprintln!("SKIPPED: host refused sandbox setup before hide/stdout behavior could run");
        return;
    }
    assert_eq!(text(&out.stdout), "");
}

#[test]
fn refusals_exit_2_and_run_nothing() {
    let cases: &[&[&str]] = &[
        &["run", "--", "true"],
        &["run", "--allow", "example.test:443/tcp", "--", "true"],
        &["run", "--allow", "192.0.2.01:443/tcp", "--", "true"],
        &["run", "--allow", "192.0.2.1/24:443/tcp", "--", "true"],
        &["run", "--allow", "0.0.0.0:443/tcp", "--", "true"],
        &["run", "--allow", "224.0.0.1:443/udp", "--", "true"],
        &["run", "--allow", "255.255.255.255:443/udp", "--", "true"],
        &[
            "run",
            "--allow",
            "192.0.2.1:443/tcp",
            "--no-network",
            "--",
            "true",
        ],
        &[
            "run",
            "--allow",
            "192.0.2.1:443/tcp",
            "--host",
            "a.test=198.51.100.1",
            "--",
            "true",
        ],
        &[
            "run",
            "--allow",
            "192.0.2.1:443/tcp",
            "--until",
            "2099-01-01T00:00:00",
            "--",
            "true",
        ],
        &[
            "run",
            "--allow",
            "192.0.2.1:443/tcp; flush ruleset",
            "--",
            "true",
        ],
    ];
    for args in cases {
        let out = run(args);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{args:?}: {}",
            text(&out.stderr)
        );
        let err = text(&out.stderr);
        assert!(err.contains("refused"), "{args:?}: {err}");
        assert!(err.contains("nothing was run"), "{args:?}: {err}");
    }
    let out = run(&["run", "--", "true"]);
    assert!(text(&out.stderr).contains("almost always a mistake"));
}

#[test]
fn rules_prints_the_ruleset_and_refuses_hostile_specs() {
    let out = run(&[
        "rules",
        "--allow",
        "192.0.2.1:443/tcp",
        "--allow",
        "[2001:db8::/32]:53/udp",
    ]);
    assert_eq!(out.status.code(), Some(0));
    let t = text(&out.stdout);
    assert!(t.contains("ip daddr 192.0.2.1 tcp dport 443 accept"));
    assert!(t.contains("ip6 daddr 2001:db8::/32 udp dport 53 accept"));
    assert!(t.contains("policy drop"));
    let out = run(&["rules", "--allow", "192.0.2.1:443/tcp", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert!(v["ruleset"].as_str().unwrap_or("").contains("policy drop"));
    let out = run(&["rules", "--allow", "192.0.2.1:443/tcp } ; flush ruleset"]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, b"");
}

#[test]
fn doctor_passes_here() {
    require_sandbox!();
    let out = run(&["doctor", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(v["ok"], true, "{}", text(&out.stdout));
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn startup_evidence_guides_retry_after_refusal_and_child_exit() {
    require_sandbox!();
    for (command, outcome, evidence, code) in [
        (
            "/nonexistent/playpen-test-command",
            "not_started",
            "not_started",
            1,
        ),
        ("/bin/true", "ran", "exec_and_exit", 0),
        ("/bin/sh", "ran", "exec_and_exit", 2),
    ] {
        let report = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("startup-evidence-{}.json", std::process::id()));
        let mut cmd = Command::new(BIN);
        cmd.args(["run", "--no-network", "--report"])
            .arg(&report)
            .args(["--", command]);
        if command == "/bin/sh" {
            cmd.args(["-c", "exit 2"]);
        }
        assert_eq!(cmd.output().expect("run").status.code(), Some(code));
        let r: serde_json::Value =
            serde_json::from_slice(&std::fs::read(report).expect("report")).expect("JSON");
        assert_eq!(r["outcome"], outcome);
        assert_eq!(r["startup_evidence"], evidence);
    }
}

#[test]
fn fail_on_drop_changes_wrapper_status_only_when_requested() {
    require_sandbox!();
    let dir = tmpdir("fail-on-drop");
    for enabled in [false, true] {
        let report = dir.join(if enabled {
            "assert.json"
        } else {
            "default.json"
        });
        let mut args = vec![
            "run",
            "--allow",
            "192.0.2.1:9101/tcp",
            "--report",
            report.to_str().unwrap_or(""),
        ];
        if enabled {
            args.push("--fail-on-drop");
        }
        args.extend_from_slice(LO);
        args.extend_from_slice(&[
            "--",
            BIN,
            "probe",
            "reach",
            "--serve",
            "192.0.2.1:9101/tcp",
            "--serve",
            "192.0.2.1:9102/tcp",
            "--try",
            "192.0.2.1:9101/tcp",
            "--try",
            "192.0.2.1:9102/tcp",
        ]);
        let out = run(&args);
        assert_eq!(
            out.status.code(),
            Some(i32::from(enabled)),
            "{}",
            text(&out.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(report).unwrap_or_default())
                .unwrap_or_default();
        assert_eq!(json["exit_code"], 0);
        assert_eq!(json["playpen_exit_status"], i32::from(enabled));
        assert!(
            json["dropped"]["destinations"]
                .as_array()
                .is_some_and(|d| d.iter().any(|x| x["address"] == "192.0.2.1"
                    && x["port"] == 9102
                    && x["protocol"] == "tcp"))
        );
        if enabled {
            assert_eq!(json["drop_assertion"], "violated");
        } else {
            assert!(json.get("drop_assertion").is_none());
        }
    }
}

#[test]
fn shareable_report_omits_private_refusal_inputs() {
    let dir = tmpdir("shareable-refusal");
    let report = dir.join("summary.json");
    let out = run(&[
        "run",
        "--allow",
        "private-invalid",
        "--host",
        "private-host=192.0.2.1",
        "--expose",
        "/private-path",
        "--report",
        report.to_str().unwrap_or(""),
        "--shareable-report",
        "--",
        "private-command",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let artifact = std::fs::read_to_string(report).unwrap_or_default();
    assert!(!artifact.contains("private-"), "{artifact}");
    let json: serde_json::Value = serde_json::from_str(&artifact).unwrap_or_default();
    assert_eq!(json["outcome"], "refused");
    assert!(json["dropped_packets"].is_null());
}

#[test]
fn compare_reports_uses_endpoints_and_requires_complete_evidence() {
    let dir = tmpdir("compare");
    let old = dir.join("old.json");
    let new = dir.join("new.json");
    let base = serde_json::json!({"playpen_version":"0.1.0", "outcome":"ran", "allowed":["192.0.2.1:80/tcp"], "network":"pasta", "hosts":[], "exposed":[], "socket_guard":"landlock", "display":false, "dropped":{"packets":1,"destinations_truncated":false,"destinations":[{"address":"192.0.2.2","protocol":"tcp","port":80,"packets":1}]}});
    let save = |path: &Path, v: &serde_json::Value| {
        std::fs::write(path, v.to_string()).unwrap_or_else(|e| panic!("{e}"));
    };
    save(&old, &base);
    let mut changed = base;
    changed["dropped"]["packets"] = 2.into();
    changed["dropped"]["destinations"][0]["packets"] = 2.into();
    save(&new, &changed);
    let args = [
        "compare",
        old.to_str().unwrap_or(""),
        new.to_str().unwrap_or(""),
        "--format",
        "json",
    ];
    assert_eq!(run(&args).status.code(), Some(0));
    changed["dropped"]["destinations"][0]["address"] = "192.0.2.3".into();
    save(&new, &changed);
    let out = run(&args);
    assert_eq!(out.status.code(), Some(1));
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(result["new_denials"][0]["address"], "192.0.2.3");
    changed["allowed"] = serde_json::json!(["192.0.2.4:80/tcp"]);
    changed["dropped"]["destinations_truncated"] = true.into();
    save(&new, &changed);
    let out = run(&args);
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(result["policy"], "changed");
    assert_eq!(result["evidence"], "incomplete");
    assert_eq!(result["no_longer_observed"], serde_json::json!([]));
    save(&old, &serde_json::json!({"schema":"playpen-shareable-v1"}));
    assert_eq!(run(&args).status.code(), Some(2));
}

#[test]
fn grant_use_reports_first_match_without_changing_admissions() {
    require_sandbox!();
    let dir = tmpdir("grant-use");
    let report_path = dir.join("report.json");
    let policy = [
        "--allow",
        "192.0.2.1:9101/tcp",
        "--allow",
        "192.0.2.1:9102/tcp",
        "--allow",
        "192.0.2.1:9101/tcp",
        "--allow",
        "192.0.2.0/30:9101-9102/tcp",
    ];
    let workload = [
        "--",
        BIN,
        "probe",
        "reach",
        "--serve",
        "192.0.2.1:9101/tcp",
        "--try",
        "192.0.2.1:9101/tcp",
        "--try",
        "192.0.2.1:9103/tcp",
    ];
    let run_report = |include: bool| {
        let mut args = vec![
            "run",
            "--report",
            report_path.to_str().expect("UTF-8 test directory"),
        ];
        if include {
            args.push("--report-grant-use");
        }
        args.extend_from_slice(&policy);
        args.extend_from_slice(LO);
        args.extend_from_slice(&workload);
        let out = run(&args);
        assert!(out.status.success(), "{}", text(&out.stderr));
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&report_path).expect("read report"))
                .expect("report JSON");
        (parse_reach(&text(&out.stdout)), report)
    };
    let (baseline, quiet) = run_report(false);
    let (observed, report) = run_report(true);
    assert_eq!(baseline, observed);
    assert!(reached(&observed, "192.0.2.1:9101/tcp"));
    assert!(!reached(&observed, "192.0.2.1:9103/tcp"));
    assert_eq!(report["dropped"]["packets"], quiet["dropped"]["packets"]);
    assert!(report["dropped"]["packets"].as_u64().is_some_and(|p| p > 0));
    assert!(quiet.get("grant_use").is_none());
    let grants = report["grant_use"]["grants"]
        .as_array()
        .expect("grant observations");
    assert_eq!(grants.len(), 4);
    assert_eq!(grants[0]["id"], "grant_1");
    assert_eq!(grants[0]["rule"], "192.0.2.1:9101/tcp");
    assert!(grants[0]["label"].is_null());
    assert_eq!(grants[0]["state"], "observed");
    assert!(grants[0]["packets"].as_u64().is_some_and(|p| p > 0));
    assert_eq!(grants[1]["state"], "no_observed_match");
    assert_eq!(grants[1]["packets"], 0);
    for ambiguous in &grants[2..] {
        assert_eq!(ambiguous["state"], "shadowed_or_ambiguous");
        assert_eq!(ambiguous["packets"], 0);
    }
}

#[test]
fn missing_grant_use_counters_are_independent_of_drop_evidence() {
    require_sandbox!();
    let nft = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .into_iter()
        .map(|dir| Path::new(dir).join("nft"))
        .find(|path| path.is_file())
        .expect("native nft");
    let dir = tmpdir("grant-counter-missing");
    let state = dir.join("read");
    let report = dir.join("report.json");
    let tool = fake_tool(
        "nft-grant-counter-missing",
        &format!(
            "#!/bin/sh\n\
        if [ \"$1\" != --json ]; then exec '{}' \"$@\"; fi\n\
        output=$('{}' \"$@\") || exit \"$?\"\n\
        if [ -f '{}' ]; then\n\
            printf '%s\\n' \"$output\" | sed 's/\"grant_1\"/\"unavailable\"/g'\n\
        else\n\
            touch '{}' || exit \"$?\"\n\
            printf '%s\\n' \"$output\"\n\
        fi\n",
            nft.display(),
            nft.display(),
            state.display(),
            state.display()
        ),
    );
    let out = playpen(&[
        "run",
        "--allow",
        "192.0.2.1:9101/tcp",
        "--allow",
        "192.0.2.1:9102/tcp",
        "--report-grant-use",
        "--report",
        report.to_str().expect("UTF-8 test directory"),
        "--",
        "/usr/bin/true",
    ])
    .env("PLAYPEN_NFT", tool)
    .output()
    .expect("run local workload");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).expect("read report")).expect("report JSON");
    assert_eq!(report["grant_use"]["grants"][0]["state"], "unavailable");
    assert!(report["grant_use"]["grants"][0]["packets"].is_null());
    assert_eq!(
        report["grant_use"]["grants"][1]["state"],
        "no_observed_match"
    );
    assert_eq!(report["grant_use"]["grants"][1]["packets"], 0);
    assert_eq!(report["dropped"]["packets"], 0);
}

#[test]
fn no_network_grant_use_is_empty() {
    require_sandbox!();
    let report = tmpdir("grant-no-network").join("report.json");
    let out = run(&[
        "run",
        "--no-network",
        "--report-grant-use",
        "--report",
        report.to_str().expect("UTF-8 test directory"),
        "--",
        "/usr/bin/true",
    ]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).expect("read report")).expect("report JSON");
    assert_eq!(
        report["grant_use"],
        serde_json::json!({"grants":[],"truncated":false})
    );
}

#[test]
fn policy_test_matches_loopback_fixture_and_catches_wrong_expectation() {
    require_sandbox!();
    let dir = tmpdir("policy-test");
    let cases = dir.join("cases.json");
    std::fs::write(
        &cases,
        r#"[{"name":"wrong","address":"192.0.2.1","protocol":"tcp","port":9102,"expect":"allow"}]"#,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let out = run(&[
        "policy-test",
        cases.to_str().unwrap_or(""),
        "--allow",
        "192.0.2.1:9101/tcp",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stdout).contains("wrong: expected allow, got deny"));
    let (observed, _) = reach(
        &["192.0.2.1:9101/tcp"],
        &["192.0.2.1:9102/tcp"],
        &["192.0.2.1:9102/tcp"],
    );
    assert!(!reached(&observed, "192.0.2.1:9102/tcp"));
}

#[test]
fn policy_test_covers_edges_overlaps_ipv6_and_protocols() {
    let dir = tmpdir("policy-matrix");
    let cases = dir.join("cases.json");
    std::fs::write(&cases, r#"[{"address":"192.0.2.0","protocol":"tcp","port":80,"expect":"deny"},{"address":"192.0.2.255","protocol":"tcp","port":80,"expect":"deny"},{"address":"192.0.2.1","protocol":"udp","port":80,"expect":"deny"},{"address":"192.0.2.128","protocol":"tcp","port":80,"expect":"deny"},{"address":"192.0.2.0","protocol":"tcp","port":81,"expect":"allow"},{"address":"198.51.100.0","protocol":"tcp","port":80,"expect":"allow"},{"address":"198.51.100.1","protocol":"tcp","port":80,"expect":"allow"},{"address":"2001:db8::1","protocol":"udp","port":53,"expect":"allow"}]"#).unwrap_or_else(|e| panic!("{e}"));
    let out = run(&[
        "policy-test",
        cases.to_str().unwrap_or(""),
        "--allow",
        "192.0.2.0/24:80/tcp",
        "--allow",
        "192.0.2.128/25:80/tcp",
        "--allow",
        "192.0.2.0:81/tcp",
        "--allow",
        "198.51.100.0/31:80/tcp",
        "--allow",
        "[2001:db8::/120]:53/udp",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{} {}",
        text(&out.stdout),
        text(&out.stderr)
    );
}

#[test]
fn policy_mismatch_names_the_grant_that_actually_matched() {
    let cases = tmpdir("mismatch-reason").join("cases.json");
    std::fs::write(
        &cases,
        r#"[{"address":"192.0.2.0","port":80,"protocol":"tcp","expect":"deny"}]"#,
    )
    .expect("cases");
    let out = run(&[
        "policy-test",
        cases.to_str().expect("path"),
        "--allow",
        "192.0.2.0/24:80/tcp",
        "--allow",
        "192.0.2.0:80/tcp",
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stdout).contains("granted by 192.0.2.0:80/tcp"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn published_reviewed_offline_workflow_and_report_contract() {
    require_sandbox!();
    let dir = tmpdir("published-workflow");
    let report_path = dir.join("report.json");
    let plan = run(&[
        "plan",
        "--format",
        "json",
        "--no-network",
        "--",
        "printf",
        "hello",
    ]);
    assert_eq!(plan.status.code(), Some(0), "{}", text(&plan.stderr));
    let preview: serde_json::Value = serde_json::from_slice(&plan.stdout).unwrap_or_default();
    let digest = preview["digest"].as_str().unwrap_or("");
    assert!(digest.starts_with("sha256:"));
    assert_eq!(preview["plan"]["network"], "none");
    let run_out = run(&[
        "run",
        "--expect-plan",
        digest,
        "--no-network",
        "--report",
        report_path.to_str().unwrap_or(""),
        "--",
        "printf",
        "hello",
    ]);
    assert_eq!(run_out.status.code(), Some(0), "{}", text(&run_out.stderr));
    assert_eq!(run_out.stdout, b"hello");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).unwrap_or_default())
            .unwrap_or_default();
    assert_eq!(report["outcome"], "ran");
    assert_eq!(report["startup_evidence"], "exec_and_exit");
    assert_eq!(report["exit_code"], 0);
    assert_eq!(report["playpen_exit_status"], 0);
    assert_eq!(report["dropped"]["packets"], 0);
    assert_eq!(report["dropped"]["destinations_truncated"], false);
    let refused = run(&[
        "run",
        "--expect-plan",
        digest,
        "--no-network",
        "--report",
        report_path.to_str().unwrap_or(""),
        "--",
        "printf",
        "changed",
    ]);
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(refused.stdout, [] as [u8; 0]);
    let refusal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).unwrap_or_default())
            .unwrap_or_default();
    assert_eq!(refusal["outcome"], "refused");
    assert_eq!(refusal["startup_evidence"], "not_started");
    assert_eq!(refusal["playpen_exit_status"], 2);
    assert!(refusal["dropped"].is_null());
    let before = dir.join("baseline.json");
    let after = dir.join("incomplete.json");
    std::fs::write(&before, report.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let mut incomplete = report;
    incomplete["dropped"] = serde_json::Value::Null;
    std::fs::write(&after, incomplete.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let compared = run(&[
        "compare",
        before.to_str().unwrap_or(""),
        after.to_str().unwrap_or(""),
        "--format",
        "json",
    ]);
    assert_eq!(compared.status.code(), Some(2));
    let comparison: serde_json::Value =
        serde_json::from_slice(&compared.stdout).unwrap_or_default();
    assert_eq!(comparison["policy"], "same");
    assert_eq!(comparison["evidence"], "incomplete");
}

#[test]
fn doctor_offline_mode_does_not_require_pasta() {
    require_sandbox!();
    let offline = playpen(&["doctor", "--mode", "offline", "--format", "json"])
        .env("PLAYPEN_PASTA", "/nonexistent/playpen-test-pasta")
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let offline_json: serde_json::Value =
        serde_json::from_slice(&offline.stdout).unwrap_or_default();
    assert_eq!(offline.status.code(), Some(0), "{}", text(&offline.stdout));
    assert_eq!(offline_json["capability"]["mode"], "offline");
    assert_eq!(offline_json["capability"]["status"], "available");
    assert!(offline_json["probes"].as_array().is_some_and(|probes| {
        probes
            .iter()
            .all(|probe| probe["status"] == "executed" && probe["ok"] == true)
    }));
    assert!(!text(&offline.stdout).contains("pasta"));

    let egress = playpen(&["doctor", "--mode", "egress", "--format", "json"])
        .env("PLAYPEN_PASTA", "/nonexistent/playpen-test-pasta")
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let egress_json: serde_json::Value = serde_json::from_slice(&egress.stdout).unwrap_or_default();
    assert_eq!(egress.status.code(), Some(1), "{}", text(&egress.stdout));
    assert_eq!(egress_json["capability"]["mode"], "egress");
    assert_eq!(egress_json["capability"]["status"], "unavailable");
    assert!(egress_json["probes"].as_array().is_some_and(|probes| {
        probes
            .iter()
            .all(|probe| probe["status"] == "untested" && probe["ok"].is_null())
    }));
}

#[test]
fn doctor_missing_nft_makes_both_modes_unavailable_and_probes_untested() {
    require_sandbox!();
    for mode in ["offline", "egress"] {
        let out = playpen(&["doctor", "--mode", mode, "--format", "json"])
            .env("PLAYPEN_NFT", "/nonexistent/playpen-test-nft")
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
        assert_eq!(out.status.code(), Some(1), "{mode}: {}", text(&out.stdout));
        assert_eq!(json["capability"]["mode"], mode);
        assert_eq!(json["capability"]["status"], "unavailable");
        assert!(json["probes"].as_array().is_some_and(|probes| {
            probes
                .iter()
                .all(|probe| probe["status"] == "untested" && probe["ok"].is_null())
        }));
        assert!(json["checks"].as_array().is_some_and(|checks| {
            checks
                .iter()
                .any(|check| check["name"] == "nft" && check["ok"] == false)
        }));
    }
}

#[test]
fn json_run_uses_one_report_stream_and_preserves_child_exit_status() {
    require_sandbox!();
    let payload = "printf 'child-stdout'; printf 'child-stderr' >&2; exit 7";
    let result = run(&["run", "--json", "--no-network", "--", "sh", "-c", payload]);
    assert_eq!(result.status.code(), Some(7), "{}", text(&result.stderr));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).expect("one report");
    assert_eq!(report["exit_code"], 7);
    assert_eq!(report["startup_evidence"], "exec_and_exit");
    assert!(text(&result.stderr).contains("child-stdoutchild-stderr"));

    let file = tmpdir("json-routing").join("report.json");
    let output = run(&[
        "--format=json",
        "run",
        "--no-network",
        "--report",
        file.to_str().expect("path"),
        "--",
        "sh",
        "-c",
        payload,
    ]);
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"child-stdout");
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(file).expect("report")).expect("JSON");
    assert_eq!(saved["exit_code"], 7);
    assert!(saved["advice"].is_array());
}
