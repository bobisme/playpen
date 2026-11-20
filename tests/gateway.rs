//! End-to-end test of pasta's gateway mapping (`--map-host-loopback
//! none`), without the real network.
//!
//! By default pasta makes the gateway address inside the namespace refer
//! to the host's loopback, which would let the command reach every service
//! on the host's 127.0.0.1 through an approval of the gateway. playpen
//! turns that off. To test it end to end, the test builds a throwaway
//! network namespace (`unshare --user --map-root-user --net`) that plays
//! "the host": its only interface besides `lo` is a `dummy` interface, which
//! discards every packet sent to it, with gateway 192.0.2.1 (a
//! documentation address). playpen runs inside it as the caller's own uid,
//! and pasta copies that fake host's configuration. So nothing can leave
//! the machine even if the filter or the mapping were wrong: the worst
//! case is a packet into the dummy interface.
//!
//! A listener on the fake host's wildcard address shows whether a
//! connection to the gateway arrived at "the host".
//!
//! The same is done for IPv6: the dummy interface also has `2001:db8::10/64`
//! with gateway `2001:db8::1`, and a second listener waits on `[::]`.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");
const PORT: &str = "9555";
/// The port of the IPv6 listener (the IPv4 one must not answer for it).
const PORT6: &str = "9556";

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn tmpdir() -> PathBuf {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("gateway-{}", std::process::id()));
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

/// The fake host: runs as mapped root in a fresh network namespace, sets up
/// `lo` and the dummy interface, starts the listener, then runs playpen as
/// the caller's uid again.
const OUTER: &str = r#"#!/bin/sh
set -e
BIN="$1"; PORT="$2"; LOG="$3"; U="$4"; G="$5"; PORT6="$6"; shift 6
ip link set lo up
ip link add dummy0 type dummy
ip addr add 192.0.2.10/24 dev dummy0
ip -6 addr add 2001:db8::10/64 dev dummy0 nodad
ip link set dummy0 up
ip route add default via 192.0.2.1
ip -6 route add default via 2001:db8::1 dev dummy0
"$BIN" probe listen "0.0.0.0:$PORT/tcp" --ms 20000 >"$LOG" &
L=$!
"$BIN" probe listen "[::]:$PORT6/tcp" --ms 20000 >"$LOG.v6" &
L6=$!
n=0
until grep -q listening "$LOG" && grep -q listening "$LOG.v6"; do n=$((n+1)); [ $n -lt 200 ] || exit 3; sleep 0.02; done
set +e
unshare --user --map-user="$U" --map-group="$G" "$@"
rc=$?
# Let the listeners log a connection that is still in their backlog.
sleep 0.3
kill $L $L6
exit $rc
"#;

/// Inside the sandbox: show pasta's configuration, then try the gateway.
const INNER: &str = r#"#!/bin/sh
cat /proc/net/route /proc/net/ipv6_route
exec "$1" probe reach --try "192.0.2.1:$2/tcp" --try "[2001:db8::1]:$3/tcp"
"#;

/// A pasta that drops `--map-host-loopback none`, as if playpen forgot it.
fn fake_pasta(dir: &Path) -> PathBuf {
    let real = pasta().unwrap_or_default();
    let body = format!(
        "#!/bin/sh\nskip=0\nfor a do\n  shift\n  if [ \"$skip\" = 1 ]; then skip=0; continue; fi\n  if [ \"$a\" = \"--map-host-loopback\" ]; then skip=1; continue; fi\n  set -- \"$@\" \"$a\"\ndone\nexec {} \"$@\"\n",
        real.display()
    );
    write_script(dir, "pasta-maps-loopback", &body)
}

struct Outcome {
    /// What the sandbox printed (route table and probe result).
    inside: String,
    stderr: String,
    /// What the fake host's listener printed.
    listener: String,
    /// What the fake host's IPv6 listener printed.
    listener6: String,
    report: serde_json::Value,
}

fn run_in_fake_host(name: &str, allow: &[&str], pasta: Option<&Path>) -> Outcome {
    let dir = tmpdir();
    let outer = write_script(&dir, "outer.sh", OUTER);
    let inner = write_script(&dir, "inner.sh", INNER);
    let log = dir.join(format!("{name}.listener"));
    let rep = dir.join(format!("{name}.report.json"));
    let _ = std::fs::remove_file(&rep);
    let uid = nix::unistd::getuid().to_string();
    let gid = nix::unistd::getgid().to_string();
    let mut cmd = Command::new("unshare");
    cmd.args(["--user", "--map-root-user", "--net", "sh"])
        .arg(&outer)
        .args([BIN, PORT])
        .arg(&log)
        .args([&uid, &gid])
        .args([PORT6, BIN, "run"]);
    for a in allow {
        cmd.args(["--allow", a]);
    }
    cmd.arg("--report")
        .arg(&rep)
        .args(["--", "sh"])
        .arg(&inner)
        .args([BIN, PORT, PORT6]);
    if let Some(p) = pasta {
        cmd.env("PLAYPEN_PASTA", p);
    }
    let out = cmd.output().unwrap_or_else(|e| panic!("{e}"));
    Outcome {
        inside: text(&out.stdout),
        stderr: text(&out.stderr),
        listener: std::fs::read_to_string(&log).unwrap_or_default(),
        listener6: std::fs::read_to_string(dir.join(format!("{name}.listener.v6")))
            .unwrap_or_default(),
        report: serde_json::from_str(&std::fs::read_to_string(&rep).unwrap_or_default())
            .unwrap_or_default(),
    }
}

/// Whether the probe inside reached `target`.
fn reached(o: &Outcome, target: &str) -> bool {
    o.inside
        .lines()
        .find(|l| l.contains(&format!("\"target\":\"{target}\"")))
        .unwrap_or_else(|| panic!("no result for {target}: {} {}", o.inside, o.stderr))
        .contains("\"reached\":true")
}

#[test]
fn the_gateway_is_not_the_host_loopback() {
    if let Some(why) = skip_reason() {
        eprintln!("SKIPPED: {why}");
        return;
    }
    let gw4 = format!("192.0.2.1:{PORT}/tcp");
    let gw6 = format!("[2001:db8::1]:{PORT6}/tcp");
    let allow = [gw4.as_str(), gw6.as_str()];

    // 1. As playpen runs pasta. pasta set the gateways up as 192.0.2.1
    //    (C0000201, stored little-endian in /proc/net/route) and
    //    2001:db8::1 (the default route in /proc/net/ipv6_route).
    let o = run_in_fake_host("real", &allow, None);
    assert!(
        o.inside.contains("010200C0"),
        "pasta did not configure gateway 192.0.2.1: {} {}",
        o.inside,
        o.stderr
    );
    assert!(
        o.inside
            .lines()
            .any(|l| l.starts_with("00000000000000000000000000000000 00 ")
                && l.contains(" 20010db8000000000000000000000001 ")),
        "pasta did not configure gateway 2001:db8::1: {} {}",
        o.inside,
        o.stderr
    );
    assert!(!reached(&o, &gw4), "the gateway was reached: {}", o.inside);
    assert!(
        !reached(&o, &gw6),
        "the IPv6 gateway was reached: {}",
        o.inside
    );
    assert!(
        !o.listener.contains("accepted\":\""),
        "the fake host's listener got a connection: {}",
        o.listener
    );
    assert!(
        o.listener6.contains("listening") && !o.listener6.contains("accepted\":\""),
        "the fake host's IPv6 listener got a connection: {}",
        o.listener6
    );

    // 2. The same with a pasta that maps the gateway to the host's
    //    loopback: the connections now arrive at the fake host's
    //    listeners. This shows the checks above would catch the mapping.
    let dir = tmpdir();
    let o = run_in_fake_host("mapped", &allow, Some(&fake_pasta(&dir)));
    assert!(
        reached(&o, &gw4) && reached(&o, &gw6),
        "control failed: {} {}",
        o.inside,
        o.stderr
    );
    assert!(
        o.listener.contains("accepted\":\"127.0.0.1"),
        "control failed: {}",
        o.listener
    );
    assert!(
        o.listener6.contains("accepted\":\"[::1]"),
        "IPv6 control failed: {}",
        o.listener6
    );

    // 3. Not approved: dropped and counted by the ruleset, so it does not
    //    even reach pasta.
    let other = format!("192.0.2.99:{PORT}/tcp");
    let o = run_in_fake_host("unapproved", &[&other], None);
    assert!(!reached(&o, &gw4) && !reached(&o, &gw6), "{}", o.inside);
    // Rejected at once: "No route to host" for IPv4, "Permission denied"
    // for IPv6 (how the kernel reports ICMPv6 administratively prohibited).
    assert!(o.inside.contains("No route to host"), "{}", o.inside);
    assert!(o.inside.contains("Permission denied"), "{}", o.inside);
    assert!(!o.listener.contains("accepted\":\""), "{}", o.listener);
    assert!(!o.listener6.contains("accepted\":\""), "{}", o.listener6);
    let dests = o.report["dropped"]["destinations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for (address, port) in [("192.0.2.1", PORT), ("2001:db8::1", PORT6)] {
        assert!(
            dests.iter().any(|d| d["address"] == address
                && d["protocol"] == "tcp"
                && d["port"].as_u64() == port.parse().ok()),
            "{address}: {}",
            o.report
        );
    }
}
