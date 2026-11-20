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
use std::time::{Duration, Instant};

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

fn fake_tool(name: &str, script: &str) -> PathBuf {
    let dir = tmpdir(name);
    let path = dir.join("tool");
    std::fs::write(&path, script).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    path
}

fn assert_not_started_with(env: (&str, &Path), expect: &str) {
    let dir = tmpdir("not-started");
    let marker = dir.join(format!("ran-{}", expect.len()));
    let _ = std::fs::remove_file(&marker);
    let out = playpen(&[
        "run",
        "--allow",
        "192.0.2.1:443/tcp",
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
        "#!/bin/sh\necho 'simulated failure' >&2\nexit 1\n",
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

/// Starts a signal counter in a sandbox in its own process group, sends it
/// SIGUSR1 `SENT` times, and returns how many arrived.
fn usr1_deliveries(extra: &[&str], how: SendTo) -> u64 {
    use std::io::BufRead as _;
    use std::os::unix::process::CommandExt as _;
    const SENT: u32 = 4;
    let kill = |target: &str, sig: &str| {
        let st = Command::new("kill").args([sig, "--", target]).status();
        assert!(st.is_ok_and(|s| s.success()), "kill {sig} {target}");
    };
    let mut args = vec!["run", "--no-network"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", BIN, "probe", "signals"]);
    let mut child = playpen(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap_or_else(|e| panic!("{e}"));
    let pid = child.id();
    let mut stdout =
        std::io::BufReader::new(child.stdout.take().unwrap_or_else(|| panic!("no stdout")));
    let mut line = String::new();
    let _ = stdout.read_line(&mut line);
    assert_eq!(line, "ready\n");
    // playpen and its three helpers (C, S and I in sandbox.rs), each the
    // only child of the one before; the command is I's child.
    let mut helpers = vec![pid];
    for _ in 0..3 {
        let last = helpers.last().copied().unwrap_or(pid);
        helpers.push(only_child(last).unwrap_or_else(|| panic!("no child of {last}")));
    }
    for _ in 0..SENT {
        match how {
            SendTo::Supervisor => kill(&pid.to_string(), "-USR1"),
            SendTo::Group => kill(&format!("-{pid}"), "-USR1"),
            SendTo::EachPlaypen => {
                for p in &helpers {
                    kill(&p.to_string(), "-USR1");
                }
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    kill(&pid.to_string(), "-TERM");
    let mut rest = String::new();
    let _ = stdout.read_to_string(&mut rest);
    let _ = child.wait();
    let v: serde_json::Value = serde_json::from_str(rest.trim()).unwrap_or_default();
    v["usr1"]
        .as_u64()
        .unwrap_or_else(|| panic!("no count in {rest:?} ({how:?})"))
}

/// A signal for playpen reaches the command once, however it was sent:
/// to playpen alone, or to each of its processes. Sent to the whole
/// process group, the command also gets its own copy from the kernel when
/// it is in that group (bn-1w3: playpen cannot tell that it did), so there
/// it arrives twice, never more; in a new session, once.
#[test]
fn a_signal_for_playpen_reaches_the_command_once() {
    require_sandbox!();
    assert_eq!(usr1_deliveries(&[], SendTo::Supervisor), 4);
    assert_eq!(usr1_deliveries(&[], SendTo::EachPlaypen), 4);
    let group = usr1_deliveries(&[], SendTo::Group);
    assert!((4..=8).contains(&group), "{group} deliveries of 4 signals");
    for how in [SendTo::Supervisor, SendTo::EachPlaypen, SendTo::Group] {
        assert_eq!(usr1_deliveries(&["--new-session"], how), 4, "{how:?}");
    }
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
            "192.0.2.1:443/tcp",
            "--format",
            "json",
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
