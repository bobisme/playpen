//! End-to-end tests that a packet to another host reaches the firewall, so
//! that it is counted and refused like any other, where the sandbox would
//! otherwise have no route for it (see `src/routes.rs`).
//!
//! Under `--no-network` the sandbox routes everything into `discard0`, a
//! `dummy` interface that frees what is sent to it; the firewall refuses
//! each packet before it gets there. The destinations are documentation
//! addresses, so nothing could leave even if the filter were wrong.
//!
//! With pasta, the tests build a throwaway network namespace that plays
//! "the host" (`unshare --user --map-root-user --net`, as in `gateway.rs`)
//! with a default route for one address family only, or no IPv6 at all.
//! Its interfaces are `dummy` interfaces, which discard what is sent to
//! them, so nothing can leave the machine.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_playpen");
/// The port of the fake host's listener.
const PORT: &str = "9561";

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

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
        .join(format!("routes-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
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

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_default()).unwrap_or_default()
}

/// `playpen run ARGS` with a report; the output and the report.
fn run(dir: &Path, args: &[&str]) -> (Output, Value) {
    let report = dir.join("report.json");
    let _ = std::fs::remove_file(&report);
    let out = Command::new(BIN)
        .arg("run")
        .arg("--report")
        .arg(&report)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let r = read_json(&report);
    (out, r)
}

/// Whether the report lists `address protocol port` as dropped.
fn dropped(r: &Value, address: &str, protocol: &str, port: u16) -> bool {
    r["dropped"]["destinations"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|d| {
            d["address"] == address
                && d["protocol"] == protocol
                && d["port"].as_u64() == Some(u64::from(port))
                && d["packets"].as_u64() >= Some(1)
        })
}

/// The evaluation's "sneaky build" (it phoned home over TCP and UDP, then
/// reported success) passed `--fail-on-drop` under `--no-network`: with
/// only `lo` its packets failed at routing and were never counted. Now it
/// fails the check, and the report names both destinations.
#[test]
fn a_build_that_phones_home_fails_the_ci_check_without_a_network() {
    require!(false);
    let dir = tmpdir("sneaky");
    let script = format!(
        "{BIN} probe reach --try 203.0.113.50:80/tcp --try 203.0.113.50:8125/udp; {BIN} probe resolve telemetry.vendor.example; echo build ok; exit 0"
    );
    let (out, r) = run(
        &dir,
        &["--no-network", "--fail-on-drop", "--", "sh", "-c", &script],
    );
    let err = text(&out.stderr);
    let context = format!("{err}\n{}\n{r}", text(&out.stdout));
    assert!(text(&out.stdout).contains("build ok"), "{context}");
    assert_eq!(out.status.code(), Some(1), "{context}");
    assert_eq!(r["exit_code"], 0, "{context}");
    assert_eq!(r["drop_assertion"], "violated", "{context}");
    assert_eq!(r["dropped"]["packets"], 2, "{context}");
    assert!(dropped(&r, "203.0.113.50", "tcp", 80), "{context}");
    assert!(dropped(&r, "203.0.113.50", "udp", 8125), "{context}");
    assert!(r["uncounted"].is_null(), "{context}");
    assert_eq!(
        err.lines().next(),
        Some("playpen: no network, loopback only, with no time limit; everything else is dropped"),
        "{context}"
    );
    assert!(
        err.contains(
            "playpen: exiting with status 1: --fail-on-drop and 2 packet(s) to unapproved destinations were dropped"
        ),
        "{context}"
    );
    // Refused at once, as with a network: "No route to host" for IPv4 TCP,
    // "Operation not permitted" for UDP.
    let stdout = text(&out.stdout);
    assert!(stdout.contains("No route to host"), "{context}");
    assert!(stdout.contains("Operation not permitted"), "{context}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--on-drop stop` under `--no-network` stops the command at its first
/// attempt to reach another host, within one reading (2 s) of it.
#[test]
fn on_drop_stop_stops_at_the_first_attempt_without_a_network() {
    require!(false);
    let dir = tmpdir("stop");
    let script = format!("{BIN} probe reach --try 203.0.113.50:80/tcp; sleep 30; echo not stopped");
    let started = Instant::now();
    let (out, r) = run(
        &dir,
        &[
            "--no-network",
            "--on-drop",
            "stop",
            "--",
            "sh",
            "-c",
            &script,
        ],
    );
    let took = started.elapsed();
    let context = format!("{}\n{r}", text(&out.stderr));
    assert!(took < Duration::from_secs(12), "took {took:?}; {context}");
    assert!(!text(&out.stdout).contains("not stopped"), "{context}");
    assert_eq!(r["stopped_by_drop"], true, "{context}");
    assert_eq!(
        r["egress_cut"]["tripped_by"],
        json!([{"address": "203.0.113.50", "protocol": "tcp", "port": 80, "packets": 1}]),
        "{context}"
    );
    assert_ne!(out.status.code(), Some(0), "{context}");
    assert!(
        text(&out.stderr).contains(
            "playpen: a packet to an unapproved destination was dropped: 203.0.113.50 tcp port 80 (--on-drop stop); the firewall now refuses all traffic but loopback; sending SIGTERM"
        ),
        "{context}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--live-drops` under `--no-network` names each destination while the
/// command runs, over IPv4 and IPv6.
#[test]
fn live_drops_name_each_destination_without_a_network() {
    require!(false);
    let dir = tmpdir("live");
    let script = format!(
        "{BIN} probe reach --try 203.0.113.50:80/tcp --try [2001:db8::50]:8125/udp; sleep 3"
    );
    let (out, r) = run(
        &dir,
        &["--no-network", "--live-drops", "--", "sh", "-c", &script],
    );
    let err = text(&out.stderr);
    let context = format!("{err}\n{r}");
    assert_eq!(out.status.code(), Some(0), "{context}");
    for line in [
        "playpen: dropped: 203.0.113.50 tcp port 80 (not approved)",
        "playpen: dropped: 2001:db8::50 udp port 8125 (not approved)",
    ] {
        assert!(err.lines().any(|l| l == line), "{line}: {context}");
    }
    assert!(dropped(&r, "2001:db8::50", "udp", 8125), "{context}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The offline sandbox: `lo` and `discard0`, both default routes into
/// `discard0`, the command cannot remove them, and loopback still works.
/// An idle run counts nothing: the kernel's own reports when `discard0`
/// comes up meet the uncounted drop rule.
#[test]
fn the_offline_sandbox_routes_everything_into_the_discard_interface() {
    require!(false);
    let dir = tmpdir("discard");
    let script = format!(
        "{BIN} probe interfaces; {BIN} probe privs --nft /usr/bin/nft; {BIN} probe reach --serve 127.0.0.1:9563/tcp --try 127.0.0.1:9563/tcp --serve [::1]:9563/udp --try [::1]:9563/udp; sleep 3"
    );
    let (out, r) = run(
        &dir,
        &["--no-network", "--fail-on-drop", "--", "sh", "-c", &script],
    );
    let stdout = text(&out.stdout);
    let context = format!("{stdout}\n{}\n{r}", text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{context}");
    let lines: Vec<Value> = stdout
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let find = |key: &str| {
        lines
            .iter()
            .find(|v| v.get(key).is_some())
            .cloned()
            .unwrap_or_else(|| panic!("no {key}: {context}"))
    };
    let interfaces = find("interfaces");
    assert_eq!(
        interfaces["interfaces"],
        json!(["lo", "discard0"]),
        "{context}"
    );
    assert_eq!(
        interfaces["default_routes"],
        json!({"ipv4": ["discard0"], "ipv6": ["discard0"]}),
        "{context}"
    );
    let privs = find("cap_eff");
    for key in ["add_address", "add_link", "add_route", "delete_route"] {
        assert_eq!(
            privs[key], "denied: EPERM: Operation not permitted",
            "{key}: {context}"
        );
    }
    for target in ["127.0.0.1:9563/tcp", "[::1]:9563/udp"] {
        assert!(
            lines
                .iter()
                .any(|v| v["target"] == target && v["reached"] == true),
            "{target}: {context}"
        );
    }
    assert_eq!(r["drop_assertion"], "pass", "{context}");
    assert_eq!(r["dropped"]["packets"], 0, "{context}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `compare` cannot call evidence complete when a report says packets
/// failed at routing before the firewall could count them.
#[test]
fn compare_calls_an_uncounted_report_incomplete() {
    let dir = tmpdir("compare");
    let (a, b) = (dir.join("a.json"), dir.join("b.json"));
    let mut report = json!({"playpen_version":"0.1.0", "outcome":"ran",
        "allowed":[], "network":"none", "hosts":[], "exposed":[],
        "socket_guard":"landlock", "display":false, "uncounted": null,
        "dropped":{"packets":0,"destinations_truncated":false,"destinations":[]},
        "lookups":{"names":[],"truncated":false}});
    std::fs::write(&a, report.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let compare = |b: &Path| {
        let out = Command::new(BIN)
            .arg("compare")
            .args([&a, b])
            .args(["--format", "json"])
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
        (out.status.code(), v)
    };
    std::fs::write(&b, report.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let (code, v) = compare(&b);
    assert_eq!((code, &v["evidence"]), (Some(0), &json!("complete")), "{v}");
    report["uncounted"] =
        "IPv4 and IPv6 packets to other hosts fail at routing and are not counted (why)".into();
    std::fs::write(&b, report.to_string()).unwrap_or_else(|e| panic!("{e}"));
    let (code, v) = compare(&b);
    assert_eq!(
        (code, &v["evidence"]),
        (Some(2), &json!("incomplete")),
        "{v}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The fake host: runs as mapped root in a fresh network namespace, sets up
/// `lo` and `dummy0` as `$1` says, a second dummy interface with
/// 198.51.100.7 and a listener on it, then runs playpen as the caller's uid
/// again.
///
/// - `ula`: IPv4 with a default route; IPv6 only a unique local network
///   with no default route (the host of the evaluation).
/// - `v4only`: IPv4 with a default route, no IPv6 address at all.
/// - `v6route`: IPv6 with a default route; IPv4 only a network with no
///   default route.
const OUTER: &str = r#"#!/bin/sh
set -e
MODE="$1"; BIN="$2"; PORT="$3"; LOG="$4"; U="$5"; G="$6"; shift 6
ip link set lo up
ip link add dummy0 type dummy
case "$MODE" in
ula)
  ip addr add 192.0.2.10/24 dev dummy0
  ip -6 addr add fd00:db8::10/64 dev dummy0 nodad
  ip link set dummy0 up
  ip route add default via 192.0.2.1 ;;
v4only)
  ip addr add 192.0.2.10/24 dev dummy0
  ip link set dummy0 up
  ip route add default via 192.0.2.1 ;;
v6route)
  ip addr add 192.0.2.10/24 dev dummy0
  ip -6 addr add 2001:db8::10/64 dev dummy0 nodad
  ip link set dummy0 up
  ip -6 route add default via 2001:db8::1 dev dummy0 ;;
esac
ip link add svc0 type dummy
ip addr add 198.51.100.7/32 dev svc0
ip link set svc0 up
"$BIN" probe listen "0.0.0.0:$PORT/tcp" --ms 20000 >"$LOG" &
L=$!
n=0
until grep -q listening "$LOG"; do n=$((n+1)); [ $n -lt 200 ] || exit 3; sleep 0.02; done
set +e
unshare --user --map-user="$U" --map-group="$G" "$@"
rc=$?
sleep 0.3
kill $L
exit $rc
"#;

/// Inside the sandbox: show the routes, then try the targets.
const INNER: &str = r#"#!/bin/sh
bin="$1"; shift
"$bin" probe interfaces
for target do shift; set -- "$@" --try "$target"; done
exec "$bin" probe reach "$@"
"#;

struct FakeHost {
    inside: String,
    stderr: String,
    listener: String,
    report: Value,
}

impl FakeHost {
    /// The default routes the sandbox had.
    fn routes(&self) -> Value {
        self.inside
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find_map(|v| v.get("default_routes").cloned())
            .unwrap_or_default()
    }

    /// The probe's result for `target`.
    fn tried(&self, target: &str) -> Value {
        self.inside
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|v| v["target"] == target)
            .unwrap_or_else(|| panic!("no result for {target}: {}", self.context()))
    }

    fn context(&self) -> String {
        format!(
            "inside {}\nstderr {}\nlistener {}\nreport {}",
            self.inside, self.stderr, self.listener, self.report
        )
    }
}

/// Runs playpen in a fake host of `mode` with `allow` approved and has the
/// probe inside try each of `targets`.
fn run_in_fake_host(mode: &str, allow: &[&str], targets: &[&str]) -> FakeHost {
    let dir = tmpdir(&format!("host-{mode}"));
    let outer = write_script(&dir, "outer.sh", OUTER);
    let inner = write_script(&dir, "inner.sh", INNER);
    let log = dir.join("listener");
    let rep = dir.join("report.json");
    let uid = nix::unistd::getuid().to_string();
    let gid = nix::unistd::getgid().to_string();
    let mut cmd = Command::new("unshare");
    cmd.args(["--user", "--map-root-user", "--net", "sh"])
        .arg(&outer)
        .args([mode, BIN, PORT])
        .arg(&log)
        .args([&uid, &gid])
        .args([BIN, "run"]);
    for a in allow {
        cmd.args(["--allow", a]);
    }
    cmd.arg("--report")
        .arg(&rep)
        .args(["--", "sh"])
        .arg(&inner)
        .arg(BIN)
        .args(targets);
    let out = cmd.output().unwrap_or_else(|e| panic!("{e}"));
    let host = FakeHost {
        inside: text(&out.stdout),
        stderr: text(&out.stderr),
        listener: std::fs::read_to_string(&log).unwrap_or_default(),
        report: read_json(&rep),
    };
    let _ = std::fs::remove_dir_all(&dir);
    host
}

/// On a host with no IPv6 default route, pasta copies none, and an IPv6
/// attempt used to fail at routing, uncounted. playpen adds a default
/// route into pasta's interface, so the attempt is refused and counted.
/// The approved IPv4 destination is reached as before.
#[test]
fn an_ipv6_attempt_is_counted_where_the_host_has_no_ipv6_default_route() {
    require!(true);
    let approved = format!("198.51.100.7:{PORT}/tcp");
    let tcp6 = format!("[2001:db8:5::7]:{PORT}/tcp");
    let udp6 = "[2001:db8:5::7]:9/udp";
    let h = run_in_fake_host("ula", &[&approved], &[&approved, &tcp6, udp6]);
    let context = h.context();
    // pasta copied the IPv4 default route; playpen added the IPv6 one.
    assert_eq!(
        h.routes(),
        json!({"ipv4": ["dummy0"], "ipv6": ["dummy0"]}),
        "{context}"
    );
    assert_eq!(h.tried(&approved)["reached"], true, "{context}");
    assert!(h.listener.contains("accepted\":\""), "{context}");
    assert_eq!(h.tried(&tcp6)["reached"], false, "{context}");
    assert_eq!(
        h.tried(&tcp6)["error"],
        "Permission denied (os error 13)",
        "{context}"
    );
    assert_eq!(
        h.tried(udp6)["error"],
        "Operation not permitted (os error 1)",
        "{context}"
    );
    assert!(
        dropped(&h.report, "2001:db8:5::7", "tcp", 9561),
        "{context}"
    );
    assert!(dropped(&h.report, "2001:db8:5::7", "udp", 9), "{context}");
    assert!(h.report["uncounted"].is_null(), "{context}");
    assert!(!h.stderr.contains("NOTE"), "{context}");

    // Approved, the IPv6 destination goes to pasta, which cannot reach it
    // from the fake host either: not reached, nothing dropped.
    let h = run_in_fake_host("ula", &[&tcp6], &[&tcp6]);
    let context = h.context();
    assert_eq!(h.tried(&tcp6)["reached"], false, "{context}");
    assert_eq!(h.report["dropped"]["packets"], 0, "{context}");
}

/// The same for IPv4 on a host with an IPv6 default route only, and for
/// IPv6 on a host with no IPv6 at all.
#[test]
fn an_attempt_is_counted_in_the_family_the_host_cannot_route() {
    require!(true);
    let tcp4 = format!("203.0.113.50:{PORT}/tcp");
    let tcp6 = format!("[2001:db8:5::7]:{PORT}/tcp");
    for mode in ["v6route", "v4only"] {
        let h = run_in_fake_host(mode, &["192.0.2.99:9/tcp"], &[&tcp4, &tcp6]);
        let context = format!("{mode}: {}", h.context());
        let routes = h.routes();
        assert!(
            routes["ipv4"].as_array().is_some_and(|a| !a.is_empty())
                && routes["ipv6"].as_array().is_some_and(|a| !a.is_empty()),
            "{context}"
        );
        assert!(dropped(&h.report, "203.0.113.50", "tcp", 9561), "{context}");
        assert!(
            dropped(&h.report, "2001:db8:5::7", "tcp", 9561),
            "{context}"
        );
        assert!(h.report["uncounted"].is_null(), "{context}");
        assert!(!h.listener.contains("accepted\":\""), "{context}");
    }
}
