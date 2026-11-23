//! `run --report-contacts` and `playpen suggest`.
//!
//! The acceptance test builds the throwaway host of `tests/capture.rs`: a
//! user and network namespace whose only way out is a `dummy` interface
//! (it discards everything sent to it), with two service addresses on a
//! second dummy interface that pasta does not copy into the sandbox. A
//! listener on each address and port logs what it accepts. Nothing can
//! leave the machine, even if the filter were wrong.
//!
//! The other tests use the sandbox's own loopback addresses (`--lo-addr`),
//! as `tests/run.rs` does.

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_playpen");
const CAUTION: &str = "One quiet run does not show that a later run needs less.";

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A fresh directory only the caller can write to.
fn tmpdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("contacts-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("{e}"));
    dir
}

fn path(p: &Path) -> &str {
    p.to_str()
        .unwrap_or_else(|| panic!("{} is not UTF-8", p.display()))
}

fn tool(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.exists())
}

/// Why the sandbox cannot run here, if it cannot.
fn sandbox_skip() -> Option<String> {
    let max = std::fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap_or_default();
    if max.trim().is_empty() || max.trim() == "0" {
        return Some("user namespaces are not available".into());
    }
    ["nft", "pasta"]
        .into_iter()
        .find(|t| tool(t).is_none())
        .map(|t| format!("{t} is not installed"))
}

/// Why the fake host cannot be built here, if it cannot.
fn fake_host_skip() -> Option<String> {
    if let Some(why) = sandbox_skip() {
        return Some(why);
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

macro_rules! require {
    ($skip:expr) => {
        if let Some(why) = $skip {
            eprintln!("SKIPPED: {why}");
            return;
        }
    };
}

fn playpen(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env_remove("FORMAT")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("cannot run playpen: {e}"))
}

fn read_report(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap_or_default()).unwrap_or_default()
}

fn write_json(path: &Path, v: &Value) {
    std::fs::write(path, v.to_string()).unwrap_or_else(|e| panic!("{e}"));
}

/// The `(target, reached)` lines of `probe reach`, and the error of each
/// target that was not reached.
fn reach_results(stdout: &str) -> Vec<(String, bool, String)> {
    stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v.get("target").is_some())
        .map(|v| {
            (
                v["target"].as_str().unwrap_or("").to_owned(),
                v["reached"].as_bool().unwrap_or(true),
                v["error"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect()
}

fn reached(results: &[(String, bool, String)], target: &str) -> bool {
    results
        .iter()
        .find(|(t, _, _)| t == target)
        .map_or_else(|| panic!("no result for {target} in {results:?}"), |r| r.1)
}

/// The report's contacted destinations as `ADDR PROTO PORT` and their
/// packets.
fn contacted(report: &Value) -> Vec<(String, u64)> {
    report["contacted"]["destinations"]
        .as_array()
        .unwrap_or_else(|| panic!("no contacted destinations in {report}"))
        .iter()
        .map(|d| {
            (
                format!(
                    "{} {} {}",
                    d["address"].as_str().unwrap_or("?"),
                    d["protocol"].as_str().unwrap_or("?"),
                    d["port"]
                ),
                d["packets"].as_u64().unwrap_or(0),
            )
        })
        .collect()
}

fn names(contacts: &[(String, u64)]) -> Vec<&str> {
    contacts.iter().map(|(n, _)| n.as_str()).collect()
}

/// The fake host: runs as mapped root in a fresh network namespace, sets up
/// the dummy interfaces, starts a TCP listener on each of 198.51.100.7 and
/// 198.51.100.9, ports 9557 and 9558, each logging to `DIR/listen-A-P.log`,
/// then runs playpen as the caller's uid again.
const OUTER: &str = r#"#!/bin/sh
set -e
BIN="$1"; DIR="$2"; U="$3"; G="$4"; shift 4
ip link set lo up
ip link add dummy0 type dummy
ip addr add 192.0.2.10/24 dev dummy0
ip link set dummy0 up
ip route add default via 192.0.2.1
ip link add fixture0 type dummy
ip addr add 198.51.100.7/32 dev fixture0
ip addr add 198.51.100.9/32 dev fixture0
ip link set fixture0 up
PIDS=
for a in 7 9; do
  for p in 9557 9558; do
    "$BIN" probe listen "198.51.100.$a:$p/tcp" --ms 30000 >"$DIR/listen-$a-$p.log" &
    PIDS="$PIDS $!"
  done
done
for a in 7 9; do
  for p in 9557 9558; do
    n=0
    until grep -q listening "$DIR/listen-$a-$p.log"; do
      n=$((n+1)); [ $n -lt 200 ] || exit 3; sleep 0.02
    done
  done
done
set +e
unshare --user --map-user="$U" --map-group="$G" "$@"
rc=$?
# A listener looks for a connection every 20 ms: give it the time to log
# the last ones.
sleep 0.5
kill $PIDS
exit $rc
"#;

/// Runs `playpen ARGS` in a fresh fake host whose listeners log to `dir`.
fn in_fake_host(dir: &Path, args: &[&str]) -> Output {
    let outer = dir.join("outer.sh");
    std::fs::write(&outer, OUTER).unwrap_or_else(|e| panic!("{e}"));
    Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "sh"])
        .arg(&outer)
        .arg(BIN)
        .arg(dir)
        .arg(nix::unistd::getuid().to_string())
        .arg(nix::unistd::getgid().to_string())
        .arg(BIN)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{e}"))
}

/// How many connections the fake host's listener on `addr`:`port` took.
fn accepted(dir: &Path, addr: u8, port: u16) -> usize {
    std::fs::read_to_string(dir.join(format!("listen-{addr}-{port}.log")))
        .unwrap_or_default()
        .lines()
        .filter(|l| l.contains("\"accepted\""))
        .count()
}

/// `probe reach` trying each of `targets`, after `--`.
fn reach_args<'a>(targets: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["--", BIN, "probe", "reach"];
    for t in targets {
        args.extend(["--try", t]);
    }
    args
}

/// The three destinations the acceptance test contacts, and the fourth
/// that the wide grant admits too.
const THREE: [&str; 3] = [
    "198.51.100.7:9557/tcp",
    "198.51.100.7:9558/tcp",
    "198.51.100.9:9557/tcp",
];
const FOURTH: &str = "198.51.100.9:9558/tcp";

/// The wide run of the acceptance test in a fake host whose listeners log
/// to `dir`. Returns the contacted destinations it reported.
fn wide_run(dir: &Path, report_path: &Path) -> Vec<(String, u64)> {
    let mut args = vec![
        "run",
        "--allow",
        "198.51.100.0/24:9550-9560/tcp",
        "--host",
        "app.example.test=198.51.100.7",
        "--host",
        "idle.example.test=198.51.100.20",
        "--report-contacts",
        "--report",
        path(report_path),
    ];
    args.extend(reach_args(&THREE));
    let out = in_fake_host(dir, &args);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("; contacted destinations recorded"),
        "{stderr}"
    );
    assert!(
        stderr.contains("playpen: the command contacted 3 approved destination(s); the report lists them in contacted\n"),
        "{stderr}"
    );
    let results = reach_results(&text(&out.stdout));
    for t in THREE {
        assert!(reached(&results, t), "{t}: {results:?}");
    }
    let report = read_report(report_path);
    assert_eq!(report["outcome"], "ran", "{report}");
    assert_eq!(report["contacted"]["truncated"], false, "{report}");
    assert!(report["contacted_error"].is_null(), "{report}");
    let listed = contacted(&report);
    assert_eq!(
        names(&listed),
        [
            "198.51.100.7 tcp 9557",
            "198.51.100.7 tcp 9558",
            "198.51.100.9 tcp 9557"
        ],
        "{report}"
    );
    // One connection each: one flow start each.
    assert!(listed.iter().all(|(_, p)| *p == 1), "{listed:?}");
    for (a, p) in [(7, 9557), (7, 9558), (9, 9557)] {
        assert_eq!(accepted(dir, a, p), 1, "198.51.100.{a}:{p}");
    }
    assert_eq!(accepted(dir, 9, 9558), 0);
    listed
}

/// The narrow run of the acceptance test: `suggested` as it is, trying all
/// four destinations. Returns the contacted destinations it reported.
fn narrow_run(dir: &Path, report_path: &Path, suggested: &str) -> Vec<(String, u64)> {
    let mut args = vec!["run"];
    args.extend(suggested.split_whitespace());
    args.extend(["--report-contacts", "--report", path(report_path)]);
    let mut all = THREE.to_vec();
    all.push(FOURTH);
    args.extend(reach_args(&all));
    let out = in_fake_host(dir, &args);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let results = reach_results(&text(&out.stdout));
    for t in THREE {
        assert!(reached(&results, t), "{t}: {results:?}");
    }
    assert!(!reached(&results, FOURTH), "{results:?}");
    let report = read_report(report_path);
    assert_eq!(report["allowed"], json!(THREE));
    assert_eq!(report["hosts"], json!(["app.example.test=198.51.100.7"]));
    assert_eq!(
        report["dropped"]["destinations"],
        json!([{"address": "198.51.100.9", "protocol": "tcp", "port": 9558, "packets": 1}]),
        "{report}"
    );
    for (a, p) in [(7, 9557), (7, 9558), (9, 9557)] {
        assert_eq!(accepted(dir, a, p), 1, "198.51.100.{a}:{p}");
    }
    assert_eq!(accepted(dir, 9, 9558), 0);
    contacted(&report)
}

/// The bone's acceptance: a /24 grant over a port range, three contacted
/// destinations. The report lists exactly those; `suggest` turns them into
/// options; a run with those options admits the same three and drops a
/// fourth destination that the wide grant admitted.
#[test]
fn suggested_options_admit_the_same_requests_and_drop_a_fourth() {
    require!(fake_host_skip());
    let wide = tmpdir("wide");
    let wide_report = wide.join("report.json");
    let listed = wide_run(&wide, &wide_report);

    let out = playpen(&["suggest", path(&wide_report)]);
    let suggested = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        suggested,
        "--allow 198.51.100.7:9557/tcp\n--allow 198.51.100.7:9558/tcp\n--allow 198.51.100.9:9557/tcp\n--host app.example.test=198.51.100.7\n"
    );
    assert!(text(&out.stderr).contains(CAUTION), "{}", text(&out.stderr));

    let narrow = tmpdir("narrow");
    let again = narrow_run(&narrow, &narrow.join("report.json"), &suggested);
    assert_eq!(names(&again), names(&listed));
    let _ = std::fs::remove_dir_all(&wide);
    let _ = std::fs::remove_dir_all(&narrow);
}

/// More destinations than a set holds: the record says it is truncated,
/// `suggest` refuses, and every approved packet still passes.
#[test]
fn past_1024_destinations_the_record_is_truncated_and_nothing_is_dropped() {
    require!(sandbox_skip());
    let dir = tmpdir("overflow");
    let report_path = dir.join("report.json");
    let targets: Vec<String> = (2000..3100).map(|p| format!("192.0.2.1:{p}/tcp")).collect();
    let mut args = vec![
        "run",
        "--allow",
        "192.0.2.1:2000-3099/tcp",
        "--lo-addr",
        "192.0.2.1",
        "--report-contacts",
        "--report",
        path(&report_path),
        "--",
        BIN,
        "probe",
        "reach",
    ];
    for t in &targets {
        args.extend(["--try", t.as_str()]);
    }
    let out = playpen(&args);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let results = reach_results(&text(&out.stdout));
    assert_eq!(results.len(), targets.len());
    // Nothing listens: each connection is refused by the address itself,
    // not by the firewall, the 1025th and later ones too.
    let errors: BTreeSet<&str> = results.iter().map(|r| r.2.as_str()).collect();
    assert_eq!(
        errors,
        BTreeSet::from(["Connection refused (os error 111)"]),
        "{results:?}"
    );
    let report = read_report(&report_path);
    assert_eq!(report["dropped"]["packets"], 0, "{report}");
    assert_eq!(report["contacted"]["truncated"], true, "{report}");
    let listed = contacted(&report);
    assert_eq!(listed.len(), 1024);
    let ports: BTreeSet<&str> = names(&listed).into_iter().collect();
    assert_eq!(ports.len(), 1024);
    assert!(
        text(&out.stderr).contains("(the list is incomplete or inconsistent)"),
        "{}",
        text(&out.stderr)
    );

    let out = playpen(&["suggest", path(&report_path)]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, b"");
    assert!(
        text(&out.stderr).contains("truncated"),
        "{}",
        text(&out.stderr)
    );
    let out = playpen(&["--format", "json", "suggest", path(&report_path)]);
    assert_eq!(out.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&out.stderr).unwrap_or_default();
    assert_eq!(error["error"]["type"], "incomplete-record", "{error}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A run with grants in both families and `--report-grant-use`, with or
/// without `--report-contacts`: the reach results, the report and stderr.
fn both_families(report_path: &Path, contacts: bool) -> (Vec<(String, bool)>, Value, String) {
    let mut args = vec![
        "run",
        "--allow",
        "192.0.2.0/24:9100-9200/tcp",
        "--allow",
        "[2001:db8::/64]:9100-9200/udp",
        "--lo-addr",
        "192.0.2.1",
        "--lo-addr",
        "192.0.2.2",
        "--lo-addr",
        "2001:db8::1",
        "--report-grant-use",
        "--report",
        path(report_path),
    ];
    if contacts {
        args.push("--report-contacts");
    }
    args.extend([
        "--",
        BIN,
        "probe",
        "reach",
        "--serve",
        "192.0.2.1:9101/tcp",
        "--serve",
        "[2001:db8::1]:9105/udp",
        "--try",
        "192.0.2.1:9101/tcp",
        "--try",
        "192.0.2.1:9101/tcp",
        "--try",
        "192.0.2.2:9150/tcp",
        "--try",
        "192.0.2.1:9300/tcp",
        "--try",
        "[2001:db8::1]:9105/udp",
        "--try",
        "[2001:db8::1]:9105/udp",
        "--try",
        "[2001:db8::1]:9106/udp",
    ]);
    let out = playpen(&args);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let results: Vec<(String, bool)> = reach_results(&text(&out.stdout))
        .into_iter()
        .map(|(t, r, _)| (t, r))
        .collect();
    (results, read_report(report_path), text(&out.stderr))
}

/// Both families, beside `--report-grant-use`: what is admitted, dropped
/// and counted per grant is the same with and without the record.
#[test]
fn contacts_count_flow_starts_beside_grant_use_in_both_families() {
    require!(sandbox_skip());
    let dir = tmpdir("both");
    let report_path = dir.join("report.json");
    let (plain, plain_report, plain_stderr) = both_families(&report_path, false);
    let (recorded, report, stderr) = both_families(&report_path, true);
    assert_eq!(plain, recorded);
    assert!(plain_report.get("contacted").is_none(), "{plain_report}");
    assert!(
        plain_report.get("contacted_error").is_none(),
        "{plain_report}"
    );
    assert!(!plain_stderr.contains("contacted"), "{plain_stderr}");
    assert_eq!(report["dropped"], plain_report["dropped"]);
    assert_eq!(report["grant_use"], plain_report["grant_use"]);
    assert_eq!(report["grant_use"]["grants"][0]["packets"], 3, "{report}");
    assert_eq!(report["grant_use"]["grants"][1]["packets"], 3, "{report}");
    assert!(
        stderr.contains("; contacted destinations recorded"),
        "{stderr}"
    );
    assert!(
        stderr.contains("the command contacted 4 approved destination(s)"),
        "{stderr}"
    );
    // Two connections, two flows; a refused connection is a flow start
    // too; two datagrams from two sockets, two flows. The dropped port is
    // not here.
    assert_eq!(
        contacted(&report),
        [
            ("192.0.2.1 tcp 9101".to_owned(), 2),
            ("192.0.2.2 tcp 9150".to_owned(), 1),
            ("2001:db8::1 udp 9105".to_owned(), 2),
            ("2001:db8::1 udp 9106".to_owned(), 1),
        ],
        "{report}"
    );
    assert_eq!(report["contacted"]["truncated"], false);

    let out = playpen(&["--format", "json", "suggest", path(&report_path)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let s: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(s["source"], "allow");
    assert_eq!(
        s["allow"],
        json!([
            "192.0.2.1:9101/tcp",
            "192.0.2.2:9150/tcp",
            "[2001:db8::1]:9105/udp",
            "[2001:db8::1]:9106/udp"
        ])
    );
    assert_eq!(s["no_network"], false);
    assert!(
        s["advice"][0]["message"]
            .as_str()
            .is_some_and(|m| m.contains(CAUTION)),
        "{s}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn without_network_nothing_is_contacted_and_suggest_says_so() {
    require!(sandbox_skip());
    let dir = tmpdir("no-network");
    let report_path = dir.join("report.json");
    let out = playpen(&[
        "run",
        "--no-network",
        "--report-contacts",
        "--report",
        path(&report_path),
        "--",
        "/usr/bin/true",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let report = read_report(&report_path);
    assert_eq!(
        report["contacted"],
        json!({"destinations": [], "truncated": false})
    );
    let out = playpen(&["suggest", path(&report_path)]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), "--no-network\n");
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("--no-network admits the same traffic"),
        "{stderr}"
    );
    assert!(stderr.contains(CAUTION), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A teardown listing without the record: the report says why, and
/// `suggest` refuses.
#[test]
fn an_unreadable_record_is_null_with_its_error_and_suggest_refuses() {
    require!(sandbox_skip());
    let Some(nft) = tool("nft") else { return };
    let dir = tmpdir("unreadable");
    let state = dir.join("read");
    let report_path = dir.join("report.json");
    let wrapper = dir.join("nft");
    // The second JSON listing is the teardown's: rename the counter there.
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" != --json ]; then exec '{nft}' \"$@\"; fi\n\
             output=$('{nft}' \"$@\") || exit \"$?\"\n\
             if [ -f '{state}' ]; then\n\
                 printf '%s\\n' \"$output\" | sed 's/\"name\": \"contacted\", \"table\"/\"name\": \"renamed\", \"table\"/'\n\
             else\n\
                 touch '{state}' || exit \"$?\"\n\
                 printf '%s\\n' \"$output\"\n\
             fi\n",
            nft = nft.display(),
            state = state.display(),
        ),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("{e}"));
    let out = Command::new(BIN)
        .args([
            "run",
            "--allow",
            "192.0.2.1:9101/tcp",
            "--report-contacts",
            "--report",
            path(&report_path),
            "--",
            "/usr/bin/true",
        ])
        .env("PLAYPEN_NFT", &wrapper)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let report = read_report(&report_path);
    assert!(report["contacted"].is_null(), "{report}");
    assert!(report.get("contacted").is_some(), "{report}");
    assert_eq!(
        report["contacted_error"], "nft JSON has no \"contacted\" counter",
        "{report}"
    );
    assert!(
        stderr.contains("could not read the contacted destinations: nft JSON has no"),
        "{stderr}"
    );
    // The drops are read from the same listing and are not affected.
    assert_eq!(report["dropped"]["packets"], 0, "{report}");
    let out = playpen(&["suggest", path(&report_path)]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("unavailable"),
        "{}",
        text(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_option_needs_a_full_report_and_is_in_the_plan() {
    let dir = tmpdir("usage");
    let marker = dir.join("ran");
    let report = dir.join("report.json");
    for args in [
        &[
            "run",
            "--allow",
            "192.0.2.1:443/tcp",
            "--report-contacts",
            "--shareable-report",
            "--report",
            path(&report),
            "--",
            "touch",
            path(&marker),
        ][..],
        &[
            "run",
            "--allow",
            "192.0.2.1:443/tcp",
            "--report-contacts",
            "--",
            "touch",
            path(&marker),
        ][..],
    ] {
        let out = playpen(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(!report.exists() && !marker.exists(), "{args:?}");
    }
    let out = playpen(&[
        "--format",
        "json",
        "run",
        "--allow",
        "192.0.2.1:443/tcp",
        "--report-contacts",
        "--shareable-report",
        "--",
        "true",
    ]);
    assert_eq!(out.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&out.stderr).unwrap_or_default();
    assert_eq!(error["error"]["type"], "invalid-arguments", "{error}");

    let plan = |extra: &[&str]| {
        let mut args = vec!["--format", "json", "plan", "--allow", "192.0.2.1:443/tcp"];
        args.extend_from_slice(extra);
        args.extend(["--", "true"]);
        let out = playpen(&args);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        serde_json::from_slice::<Value>(&out.stdout).unwrap_or_default()
    };
    let without = plan(&[]);
    let with = plan(&["--report-contacts"]);
    assert!(
        without["plan"].get("report_contacts").is_none(),
        "{without}"
    );
    assert_eq!(with["plan"]["report_contacts"], true, "{with}");
    assert_ne!(with["digest"], without["digest"]);
    let mut stripped = with["plan"].clone();
    stripped
        .as_object_mut()
        .map(|o| o.remove("report_contacts"));
    assert_eq!(stripped, without["plan"]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A hand-written report, as a full run would write it.
fn hand_written() -> Value {
    json!({
        "playpen_version": "0.1.0",
        "outcome": "ran",
        "network": "pasta",
        "allowed": ["192.0.2.0/24:443/tcp"],
        "hosts": ["api.example.test=192.0.2.7 (pass: web)"],
        "pass": null,
        "dropped": {"packets": 0, "destinations": [], "destinations_truncated": false},
        "lookups": {"names": [], "truncated": false},
        "contacted": {"destinations": [
            {"address": "192.0.2.7", "protocol": "tcp", "port": 443, "packets": 1}
        ], "truncated": false},
        "contacted_error": null
    })
}

#[test]
fn suggest_reads_the_report_as_data_and_refuses_what_it_cannot_narrow() {
    let dir = tmpdir("suggest");
    let file = dir.join("report.json");
    let suggest = |v: &Value| {
        write_json(&file, v);
        playpen(&["suggest", path(&file)])
    };

    let out = suggest(&hand_written());
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "--allow 192.0.2.7:443/tcp\n--host api.example.test=192.0.2.7\n"
    );

    // Under a pass: destinations, not options.
    let mut pass = hand_written();
    pass["pass"] = json!({"file": "/p.toml", "id": "x"});
    let out = suggest(&pass);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "192.0.2.7:443/tcp\n--host api.example.test=192.0.2.7\n"
    );
    assert!(text(&out.stderr).contains("--allow cannot be added beside --pass"));
    write_json(&file, &pass);
    let out = playpen(&["--format", "json", "suggest", path(&file)]);
    let s: Value = serde_json::from_slice(&out.stdout).unwrap_or_default();
    assert_eq!(s["source"], "pass", "{s}");
    assert_eq!(s["allow"], json!(["192.0.2.7:443/tcp"]));
    assert_eq!(s["advice"][1]["type"], "pass", "{s}");

    let mut wider = hand_written();
    wider["contacted"]["destinations"][0]["port"] = 444.into();
    let mut not_started = hand_written();
    not_started["outcome"] = "not_started".into();
    let mut without = hand_written();
    without.as_object_mut().map(|o| o.remove("contacted"));
    let mut shareable = hand_written();
    shareable["playpen_version"] = Value::Null;
    shareable["schema"] = "playpen-shareable-v1".into();
    for (v, said) in [
        (wider, "not admitted by the run's grants"),
        (not_started, "not \"ran\""),
        (without, "--report-contacts"),
        (shareable, "unsupported or reduced report schema"),
    ] {
        let out = suggest(&v);
        assert_eq!(out.status.code(), Some(2), "{v}");
        assert_eq!(out.stdout, b"", "{v}");
        assert!(text(&out.stderr).contains(said), "{}", text(&out.stderr));
    }
    std::fs::write(&file, "not json").unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(playpen(&["suggest", path(&file)]).status.code(), Some(2));
    let out = playpen(&["suggest", path(&dir.join("missing.json"))]);
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
