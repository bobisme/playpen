//! Integration tests for `--pass-broker`: the command reads the pass and
//! spends from its ledger through the broker's socket, and can change none
//! of the files.
//!
//! Every test uses a temporary `XDG_STATE_HOME`, so the witness is written
//! there and never in the real `~/.local/state/hallpass`. The destination is
//! a documentation address on the sandbox's own `lo` (`--lo-addr`); nothing
//! is sent anywhere. The guest is a short Python program that speaks the
//! protocol and prints each reply as one JSON line.

#![allow(
    clippy::disallowed_macros,
    reason = "test code may print with the std macros"
)]

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
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
    for tool in ["nft", "pasta", "python3"] {
        let found = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
            .iter()
            .any(|d| Path::new(d).join(tool).exists());
        if !found {
            return Some(format!("{tool} is not installed"));
        }
    }
    if !playpen::landlock::resolve_unix_supported() {
        return Some("Landlock ABI 9 is not available".into());
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

fn stamp(t: OffsetDateTime) -> String {
    t.replace_nanosecond(0)
        .unwrap_or(t)
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn hours(h: i64) -> String {
    stamp(OffsetDateTime::now_utc() + time::Duration::hours(h))
}

/// A pass with destination `web` (192.0.2.1:9101/tcp) and the ceiling
/// `calls`.
fn pass_text(revoked: bool, ports: &str, calls: u64) -> String {
    format!(
        "format = 1\nid = \"broker-pass-1\"\nname = \"Practice range\"\n\n[approval]\nowner = \"Pat Owner, Example Corp\"\nreference = \"email of 2026-11-18\"\noperator = \"Sam Tester\"\nvalid_from = {}\nvalid_until = {}\nrevoked = {revoked}\n\n[[destination]]\nlabel = \"web\"\naddress = \"192.0.2.1\"\nprotocol = \"tcp\"\nports = {ports}\n\n[ceilings]\ncalls = {calls}\n",
        hours(-1),
        hours(1),
    )
}

/// Writes `contents` to `path` with mode 0600, as a new file renamed over
/// the old one.
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

/// One test's files: `DIR/pass/test.pass.toml` (a directory of its own,
/// so playpen hides it), the state home `DIR/state` and room for markers.
struct Fixture {
    dir: PathBuf,
    pass: PathBuf,
    state_home: PathBuf,
}

impl Fixture {
    fn new(name: &str, calls: u64) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("broker-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let own = dir.join("pass");
        std::fs::create_dir_all(&own).unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("{e}"));
        let pass = own.join("test.pass.toml");
        write_pass(&pass, &pass_text(false, "9101", calls));
        let state_home = dir.join("state");
        std::fs::create_dir_all(&state_home).unwrap_or_else(|e| panic!("{e}"));
        Self {
            dir,
            pass,
            state_home,
        }
    }

    fn state(&self) -> PathBuf {
        self.state_home.join("hallpass")
    }

    fn s(p: &Path) -> String {
        p.to_str().unwrap_or("").to_owned()
    }

    /// `playpen run --pass PASS --pass-broker EXTRA -- python3 -I -c SCRIPT ARGS`.
    fn command(&self, extra: &[&str], script: &str, args: &[&str]) -> Command {
        let mut cmd = Command::new(BIN);
        cmd.arg("run")
            .arg("--pass")
            .arg(&self.pass)
            .arg("--pass-broker")
            .args(["--lo-addr", "192.0.2.1"])
            .args(extra)
            .args(["--", "python3", "-I", "-c", script])
            .args(args)
            .env("XDG_STATE_HOME", &self.state_home)
            .stdin(Stdio::null());
        cmd
    }

    fn run(&self, extra: &[&str], script: &str, args: &[&str]) -> Output {
        self.command(extra, script, args)
            .output()
            .unwrap_or_else(|e| panic!("cannot run playpen: {e}"))
    }

    /// The ledger as hallpass verifies it on the host, with the witness.
    fn verified(&self) -> hallpass::LedgerView {
        let loaded = hallpass::load(&self.pass).unwrap_or_else(|e| panic!("{e}"));
        hallpass::read_ledger(&loaded, &hallpass::StateDir::new(self.state()))
            .unwrap_or_else(|e| panic!("the host ledger does not verify: {e}"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The guest's helpers: `ask(f, request)` sends one line and returns the
/// reply; `say(x)` prints one JSON line.
const PRELUDE: &str = r#"
import json, os, socket, sys, time
P = os.environ["PLAYPEN_PASS_BROKER"]
def conn():
    s = socket.socket(socket.AF_UNIX)
    s.connect(P)
    return s, s.makefile("rw")
def ask(f, req):
    f.write(json.dumps(req) + "\n"); f.flush()
    return json.loads(f.readline())
def say(x):
    print(json.dumps(x), flush=True)
"#;

fn script(body: &str) -> String {
    format!("{PRELUDE}\n{body}")
}

fn lines(out: &Output) -> Vec<Value> {
    text(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn by_tag<'a>(replies: &'a [Value], tag: &str) -> &'a Value {
    replies
        .iter()
        .find(|v| v["tag"] == tag)
        .unwrap_or_else(|| panic!("no reply tagged {tag} in {replies:?}"))
}

/// The guest of the persistence test: every operation once, each reply
/// tagged.
const PERSIST_PY: &str = r#"
s, f = conn()
for tag, req in [
    ("hello", {"op": "hello", "id": 7}),
    ("pass", {"op": "pass"}),
    ("block", {"op": "block-spend", "counter": "calls", "n": 2, "to": "192.0.2.1:9101/tcp"}),
    ("ref", {"op": "referenced-spend", "charges": [{"counter": "calls", "n": 1}],
             "to": ["192.0.2.1:9101/tcp"], "caller_ref": "job-1", "require_new_ref": True,
             "record_target": True}),
    ("dup", {"op": "referenced-spend", "charges": [{"counter": "calls", "amount": 1}],
             "caller_ref": "job-1", "require_new_ref": True}),
    ("dry", {"op": "block-spend", "counter": "calls", "dry_run": True}),
    ("batch", {"op": "spend-batch", "counter": "calls",
               "units": [{"caller_ref": "u-1", "to": "192.0.2.1:9101/tcp"}, {"caller_ref": "u-2"}]}),
    ("big", {"op": "spend-batch", "counter": "calls",
             "units": [{"caller_ref": "v-%d" % i} for i in range(6)]}),
    ("wrongto", {"op": "block-spend", "counter": "calls", "to": "192.0.2.9:9101/tcp"}),
    ("receipt", {"op": "receipt", "caller_ref": "u-1"}),
    ("ledger", {"op": "verified-ledger"}),
]:
    r = ask(f, req)
    r["tag"] = tag
    say(r)
say({"tag": "env", "path": P})
"#;

/// The command reads the pass through the broker; block, referenced and
/// batch spends persist in the host's ledger and witness; receipt and
/// verified-ledger agree with what hallpass reads on the host.
#[test]
fn the_command_reads_the_pass_and_its_spends_persist_in_the_host_ledger_and_witness() {
    require_sandbox!();
    let fx = Fixture::new("persist", 10);
    let report = fx.dir.join("report.json");
    let out = fx.run(
        &["--report", report.to_str().unwrap_or("")],
        &script(PERSIST_PY),
        &[],
    );
    let err = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    let r = lines(&out);

    let hello = by_tag(&r, "hello");
    assert_eq!(hello["result"], "ok", "{hello}");
    assert_eq!(hello["id"], 7);
    assert_eq!(hello["protocol"], "pass-broker-v1");
    assert_eq!(
        hello["hallpass_revision"],
        "7c06ea837ab6aa98858dc18e4be1fbaf6f3e85ff"
    );
    for op in [
        "hello",
        "pass",
        "watch",
        "block-spend",
        "referenced-spend",
        "spend-batch",
        "receipt",
        "verified-ledger",
    ] {
        assert!(
            hello["capabilities"]
                .as_array()
                .is_some_and(|c| c.iter().any(|x| x == op)),
            "{op}: {hello}"
        );
    }
    assert_eq!(hello["file"], Fixture::s(&fx.pass));

    let bytes = std::fs::read(&fx.pass).unwrap_or_default();
    let pass = by_tag(&r, "pass");
    assert_eq!(pass["text"].as_str().map(str::as_bytes), Some(&bytes[..]));
    assert_eq!(
        pass["digest"],
        hallpass::Digest::of(&bytes).to_string(),
        "{pass}"
    );
    assert_eq!(pass["state"], "valid");
    assert_eq!(pass["window"]["state"], "valid");
    assert_eq!(pass["withdrawn"], Value::Null);

    assert_spends(&fx, &r);
    assert_host(&fx, &r, &out, &report);
}

/// The spend replies of the persistence test.
fn assert_spends(fx: &Fixture, r: &[Value]) {
    let block = by_tag(r, "block");
    assert_eq!(block["result"], "allowed", "{block}");
    assert_eq!(block["command"], "spend");
    assert_eq!(block["seq"], 1);
    assert_eq!(block["spent"], 2);
    assert_eq!(block["label"], "web");
    let reference = by_tag(r, "ref");
    assert_eq!(reference["result"], "allowed", "{reference}");
    assert_eq!(reference["receipt"]["caller_ref"], "job-1");
    assert_eq!(reference["receipt"]["targets"][0]["label"], "web");
    let dup = by_tag(r, "dup");
    assert_eq!(dup["result"], "refused", "{dup}");
    assert_eq!(dup["refusal"]["code"], "duplicate-reference", "{dup}");
    let dry = by_tag(r, "dry");
    assert_eq!(dry["result"], "would-allow", "{dry}");
    assert_eq!(dry["seq"], Value::Null);

    let batch = by_tag(r, "batch");
    assert_eq!(batch["result"], "allowed", "{batch}");
    assert_eq!(batch["committed"], 2);
    assert_eq!(batch["units"][0]["caller_ref"], "u-1");
    assert_eq!(batch["units"][0]["receipt"]["targets"][0]["label"], "web");
    let seqs: Vec<u64> = batch["units"].as_array().map_or_else(Vec::new, |u| {
        u.iter().filter_map(|x| x["seq"].as_u64()).collect()
    });
    assert_eq!(seqs, [3, 4], "{batch}");
    // 5 spent, 5 left: six units do not fit, and none is recorded.
    let big = by_tag(r, "big");
    assert_eq!(big["result"], "refused", "{big}");
    assert_eq!(big["refusal"]["code"], "ceiling-reached");
    assert_eq!(big["committed"], 0);
    assert_eq!(big["requested"], 6);
    assert_eq!(big["spent_before"], 5);
    assert_eq!(big["spent"], 5);
    assert_eq!(big["projected_spent"], 11);
    assert_eq!(big["refused_unit"], 6);
    assert_eq!(big["units"], serde_json::json!([]));
    let wrong = by_tag(r, "wrongto");
    assert_eq!(wrong["result"], "refused", "{wrong}");
    assert_eq!(wrong["refusal"]["code"], "address-not-listed", "{wrong}");

    let receipt = by_tag(r, "receipt");
    assert_eq!(receipt["result"], "found", "{receipt}");
    assert_eq!(receipt["witness"], "matches");
    let ledger = by_tag(r, "ledger");
    assert_eq!(ledger["result"], "ok", "{ledger}");
    assert_eq!(ledger["verified"], true);
    assert_eq!(ledger["witness"], "matches");
    assert_eq!(ledger["totals"][0]["spent"], 5);
    assert_eq!(
        ledger["ledger"],
        format!("{}.ledger", Fixture::s(&fx.pass)),
        "{ledger}"
    );
}

/// The ledger, the witness, the socket and the report on the host after
/// the persistence test.
fn assert_host(fx: &Fixture, r: &[Value], out: &Output, report: &Path) {
    let err = text(&out.stderr);
    // No reply names the /proc paths the broker reads through.
    assert!(!text(&out.stdout).contains("/proc/self/fd"), "{r:?}");

    // On the host: the same ledger, verified against the same witness.
    let view = fx.verified();
    assert_eq!(view.witness.as_str(), "matches");
    assert_eq!(view.tally.spent("calls"), 5);
    let loaded = hallpass::load(&fx.pass).unwrap_or_else(|e| panic!("{e}"));
    for reference in ["job-1", "u-1", "u-2"] {
        let found = hallpass::evidence::lookup_receipt(
            &loaded,
            &hallpass::StateDir::new(fx.state()),
            reference,
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(found.result, "found", "{reference}");
    }
    assert!(fx.state().join("broker-pass-1.witness").is_file());

    // The socket the command was given is the one the start line named,
    // and it is gone with its directory after the run.
    let socket = by_tag(r, "env")["path"].as_str().unwrap_or("").to_owned();
    assert!(
        err.contains(&format!("pass broker: {socket} (pass-broker-v1")),
        "{err}"
    );
    assert!(err.contains("hallpass state directory: "), "{err}");
    assert!(!Path::new(&socket).exists(), "{socket} is still there");
    assert!(
        !Path::new(&socket).parent().is_some_and(Path::exists),
        "{socket}"
    );
    let rep: Value = serde_json::from_str(&std::fs::read_to_string(report).unwrap_or_default())
        .unwrap_or_default();
    let b = &rep["pass"]["broker"];
    assert_eq!(b["protocol"], "pass-broker-v1", "{rep}");
    assert_eq!(b["socket"], socket.as_str());
    assert_eq!(b["state_directory"], Fixture::s(&fx.state()));
    assert_eq!(b["state_directory_view"], "hidden");
    assert_eq!(b["activity"]["recorded"], 3, "{b}");
    assert_eq!(b["activity"]["refused"], 3, "{b}");
    assert_eq!(rep["exposed"], serde_json::json!([]), "{rep}");
}

/// Requests can name no file, unknown or malformed requests and lines that
/// are too long get error replies, a client that sends nothing blocks no
/// other, and no more than the limit of connections is served at once.
#[test]
fn the_protocol_refuses_what_it_does_not_take_and_bounds_its_clients() {
    require_sandbox!();
    let fx = Fixture::new("protocol", 10);
    let body = r#"
idle, _ = conn()
idle.sendall(b'{"op": "hel')
s, f = conn()
for tag, req in [
    ("file", {"op": "pass", "file": "/etc/passwd"}),
    ("state", {"op": "block-spend", "counter": "calls", "state_dir": "/tmp/x"}),
    ("ledgerpath", {"op": "verified-ledger", "ledger": "/tmp/x.ledger"}),
    ("unknown", {"op": "spend", "charges": []}),
    ("noop", {"id": 3}),
    ("badtimeout", {"op": "receipt", "caller_ref": "x", "lock_timeout_ms": 600000}),
    ("both", {"op": "referenced-spend", "charges": [{"counter": "calls", "n": 1, "amount": 1}]}),
]:
    r = ask(f, req); r["tag"] = tag; say(r)
f.write("this is not json\n"); f.flush()
r = json.loads(f.readline()); r["tag"] = "notjson"; say(r)
big, bf = conn()
big.sendall(b'{"op":"hello","pad":"' + b"x" * (1 << 20) + b'"}\n')
r = json.loads(bf.readline()); r["tag"] = "long"; say(r)
say({"tag": "after-long", "eof": bf.readline() == ""})
held = []
for i in range(70):
    c, cf = conn()
    held.append((c, cf))
import select
time.sleep(1)
replies = []
for c, cf in held:
    ready, _, _ = select.select([c], [], [], 0)
    replies.append(json.loads(cf.readline()) if ready else None)
refused = [r for r in replies if r and r["error"]["code"] == "too-many-connections"]
say({"tag": "limit", "refused": len(refused), "silent": sum(1 for r in replies if r is None)})
r = ask(f, {"op": "hello"}); r["tag"] = "still"; say(r)
"#;
    let out = fx.run(&[], &script(body), &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let r = lines(&out);
    for tag in [
        "file",
        "state",
        "ledgerpath",
        "noop",
        "badtimeout",
        "both",
        "notjson",
    ] {
        let v = by_tag(&r, tag);
        assert_eq!(v["result"], "error", "{tag}: {v}");
        assert_eq!(v["error"]["code"], "usage", "{tag}: {v}");
        assert_eq!(v["error"]["recording"], "not-recorded", "{tag}: {v}");
    }
    assert!(
        by_tag(&r, "file")["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("unknown field `file`")),
        "{r:?}"
    );
    assert_eq!(by_tag(&r, "unknown")["error"]["code"], "unknown-op");
    assert_eq!(by_tag(&r, "long")["error"]["code"], "line-too-long");
    assert_eq!(by_tag(&r, "after-long")["eof"], true);
    // 64 at once, the first two of this script's included: 64 - 2 of the
    // 70 are served (and silent), the other 8 refused.
    let limit = by_tag(&r, "limit");
    assert_eq!(limit["refused"], 8, "{limit}");
    assert_eq!(limit["silent"], 62, "{limit}");
    assert_eq!(by_tag(&r, "still")["result"], "ok");
    assert_eq!(fx.verified().tally.spent("calls"), 0);
}

/// The guest of the tamper test: every way to change the pass, the ledger
/// and the witness, then a spend, then a move of the state directory.
const TAMPER_PY: &str = r#"
import errno
pass_, ledger, witness, state, state_home, scratch = sys.argv[1:7]
results = {}
def attempt(name, fn):
    try:
        fn()
        results[name] = "done"
    except OSError as e:
        results[name] = errno.errorcode.get(e.errno, str(e.errno))
def write(path, data=b"x"):
    with open(path, "r+b") as fh:
        fh.truncate(0); fh.write(data)
def read(path):
    with open(path, "rb") as fh:
        return fh.read()
for name, path in [("pass", pass_), ("ledger", ledger), ("witness", witness)]:
    attempt(name + ":write", lambda p=path: write(p))
    attempt(name + ":unlink", lambda p=path: os.unlink(p))
    attempt(name + ":rename", lambda p=path: os.rename(p, p + ".moved"))
    attempt(name + ":replace", lambda p=path: os.rename(scratch, p))
    attempt(name + ":link", lambda p=path: os.link(p, os.path.join(os.path.dirname(scratch), "linked-" + os.path.basename(p))))
    try:
        results[name + ":read"] = len(read(path))
    except OSError as e:
        results[name + ":read"] = errno.errorcode.get(e.errno, "?")
attempt("state:create", lambda: open(os.path.join(state, "new.witness"), "xb").close())
attempt("state:rename", lambda: os.rename(state, state + ".moved"))
attempt("state:rmdir", lambda: os.rmdir(state))
attempt("passdir:create", lambda: open(os.path.join(os.path.dirname(pass_), "new"), "xb").close())
attempt("passdir:rename", lambda: os.rename(os.path.dirname(pass_), os.path.dirname(pass_) + ".moved"))
results["state:list"] = os.listdir(state) if os.path.isdir(state) else None
s, f = conn()
results["spend"] = ask(f, {"op": "referenced-spend", "charges": [{"counter": "calls", "n": 1}], "caller_ref": "inside-1"})["result"]
results["ledger"] = ask(f, {"op": "verified-ledger"})
# No directory on the way to the state directory or the pass's directory
# can be renamed, removed, replaced or unmounted: a forged witness at the
# usual path is never what host tools find.
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
def umount(path, flags):
    if libc.umount2(path.encode(), flags) != 0:
        raise OSError(ctypes.get_errno(), "umount2")
forged = os.path.join(os.path.dirname(scratch), "forged")
os.makedirs(os.path.join(forged, "hallpass"), exist_ok=True)
open(os.path.join(forged, "hallpass", "broker-pass-1.witness"), "w").close()
dirs = set()
for start in (state, os.path.dirname(pass_)):
    d = start
    while d != "/":
        dirs.add(d)
        d = os.path.dirname(d)
for d in sorted(dirs):
    attempt("anc:rename:" + d, lambda d=d: os.rename(d, d + ".moved"))
    attempt("anc:rmdir:" + d, lambda d=d: os.rmdir(d))
    attempt("anc:umount:" + d, lambda d=d: umount(d, 0))
    attempt("anc:detach:" + d, lambda d=d: umount(d, 2))
attempt("forge:replace", lambda: os.rename(forged, state_home))
results["dirs"] = len(dirs)
r = ask(f, {"op": "block-spend", "counter": "calls"})
results["last"] = r["result"]
say(results)
"#;

/// From inside, every way to change the pass, the ledger or the witness,
/// or to write in the state directory, fails; a moved state directory stops
/// the broker's spends; on the host the ledger and the witness verify and
/// hold exactly the broker's spends.
#[test]
fn the_command_cannot_replace_the_pass_roll_back_the_ledger_or_remove_the_witness() {
    require_sandbox!();
    for view in ["hidden", "read_only"] {
        let fx = Fixture::new(&format!("tamper-{view}"), 10);
        if view == "read_only" {
            // Another file in the pass's directory: playpen makes it
            // read-only instead of hiding it.
            std::fs::write(fx.pass.with_file_name("notes.txt"), "x")
                .unwrap_or_else(|e| panic!("{e}"));
        }
        // A spend on the host first, so the ledger and the witness exist.
        let loaded = hallpass::load(&fx.pass).unwrap_or_else(|e| panic!("{e}"));
        let request = hallpass::SpendRequest::new("calls", 1);
        let first = hallpass::spend_in(
            &fx.pass,
            &request,
            OffsetDateTime::now_utc(),
            &hallpass::StateDir::new(fx.state()),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(first.seq, Some(1));
        drop(loaded);
        let ledger = PathBuf::from(format!("{}.ledger", Fixture::s(&fx.pass)));
        let witness = fx.state().join("broker-pass-1.witness");
        let before = (
            std::fs::read(&fx.pass).unwrap_or_default(),
            std::fs::read(&ledger).unwrap_or_default(),
            std::fs::read(&witness).unwrap_or_default(),
        );
        let scratch = fx.dir.join("scratch");
        std::fs::write(&scratch, pass_text(false, "[9101, 9102]", 1000))
            .unwrap_or_else(|e| panic!("{e}"));
        let out = fx.run(
            &["--pass-recheck-ms", "100"],
            &script(TAMPER_PY),
            &[
                &Fixture::s(&fx.pass),
                &Fixture::s(&ledger),
                &Fixture::s(&witness),
                &Fixture::s(&fx.state()),
                &Fixture::s(&fx.state_home),
                &Fixture::s(&scratch),
            ],
        );
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{view}: {err}");
        let r = lines(&out);
        let res = r
            .first()
            .unwrap_or_else(|| panic!("{view}: no result: {err}"));
        eprintln!("{view}: {res}");
        assert_untouched(view, res, &fx, &ledger, &witness, &before);
    }
}

/// What the tamper test's guest found, and the host's files after it.
fn assert_untouched(
    view: &str,
    res: &Value,
    fx: &Fixture,
    ledger: &Path,
    witness: &Path,
    before: &(Vec<u8>, Vec<u8>, Vec<u8>),
) {
    {
        for (key, value) in res.as_object().into_iter().flatten() {
            let Some(what) = value.as_str() else { continue };
            if key.ends_with(":read") || key == "spend" || key == "ledger" {
                continue;
            }
            assert_ne!(what, "done", "{view}: {key} succeeded: {res}");
        }
        // Inside, the pass and the ledger read as nothing: /dev/null, or
        // not there at all.
        for key in ["pass:read", "ledger:read", "witness:read"] {
            assert!(
                res[key] == 0 || res[key].is_string(),
                "{view}: {key}: {res}"
            );
        }
        assert!(
            res["state:list"].is_null() || res["state:list"] == serde_json::json!([]),
            "{view}: {res}"
        );
        assert_eq!(res["spend"], "allowed", "{view}: {res}");
        assert_eq!(res["ledger"]["witness"], "matches", "{view}: {res}");
        assert_eq!(res["last"], "allowed", "{view}: {res}");
        // The test's own directories are the caller's: only the mounts keep
        // them in place.
        for dir in [&fx.dir, &fx.state_home, &fx.state(), &fx.dir.join("pass")] {
            let d = Fixture::s(dir);
            for (op, want) in [
                ("rename", "EBUSY"),
                ("rmdir", "EBUSY"),
                ("umount", "EPERM"),
                ("detach", "EPERM"),
            ] {
                assert_eq!(res[format!("anc:{op}:{d}")], want, "{view}: {op} {d}");
            }
        }
        assert_eq!(res["forge:replace"], "EBUSY", "{view}: {res}");
        assert!(res["dirs"].as_u64() > Some(3), "{view}: {res}");
        // On the host: the pass is the same, the ledger only grew by the
        // broker's spend, and both verify against the witness.
        assert_eq!(std::fs::read(&fx.pass).unwrap_or_default(), before.0);
        let after = std::fs::read(ledger).unwrap_or_default();
        assert!(
            after.starts_with(&before.1),
            "{view}: the ledger was rewritten"
        );
        assert_ne!(std::fs::read(witness).unwrap_or_default(), before.2);
        let ledger_view = fx.verified();
        assert_eq!(ledger_view.witness.as_str(), "matches", "{view}");
        assert_eq!(ledger_view.tally.spent("calls"), 3, "{view}");
    }
}

/// When the state directory is moved anyway (from the host: the command
/// cannot), the broker refuses spends and playpen stops the run; the report
/// says where the directory playpen holds is now.
#[test]
fn a_state_directory_moved_on_the_host_stops_the_run_and_says_where_it_is() {
    require_sandbox!();
    let fx = Fixture::new("statemoved", 1000);
    let ready = fx.dir.join("ready");
    let report = fx.dir.join("report.json");
    let body = r#"
import signal
signal.signal(signal.SIGTERM, signal.SIG_IGN)
s, f = conn()
say({"tag": "before", "reply": ask(f, {"op": "block-spend", "counter": "calls"})})
open(sys.argv[1], "w").close()
for i in range(400):
    r = ask(f, {"op": "block-spend", "counter": "calls"})
    if r["result"] != "allowed":
        say({"tag": "after", "reply": r})
        break
    time.sleep(0.02)
time.sleep(30)
"#;
    let mut child = Guard::spawn(
        fx.command(
            &["--pass-recheck-ms", "100", "--report", &Fixture::s(&report)],
            &script(body),
            &[&Fixture::s(&ready)],
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let start = Instant::now();
    while !ready.exists() {
        assert!(start.elapsed() < Duration::from_secs(60), "never ready");
        std::thread::sleep(Duration::from_millis(20));
    }
    let moved = fx.dir.join("state.moved");
    std::fs::rename(&fx.state_home, &moved).unwrap_or_else(|e| panic!("{e}"));
    let out = child.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
    let err = text(&out.stderr);
    let r = lines(&out);
    assert_eq!(by_tag(&r, "before")["reply"]["result"], "allowed", "{err}");
    let after = &by_tag(&r, "after")["reply"];
    assert_eq!(after["result"], "refused", "{after}");
    assert_eq!(after["refusal"]["code"], "state-moved", "{after}");
    let now_at = format!(
        "the directory playpen holds is now at {}",
        Fixture::s(&moved.join("hallpass"))
    );
    assert!(err.contains(&now_at), "{err}");
    let rep: Value = serde_json::from_str(&std::fs::read_to_string(&report).unwrap_or_default())
        .unwrap_or_default();
    assert_eq!(rep["stopped_by_pass"], true, "{rep}");
    let why = rep["stop_reason"].as_str().unwrap_or("");
    assert!(why.contains("the hallpass state directory"), "{why}");
    assert!(why.contains(&now_at), "{why}");
    // Put back, the witness at the usual path is the real one.
    std::fs::rename(&moved, &fx.state_home).unwrap_or_else(|e| panic!("{e}"));
    let view = fx.verified();
    assert_eq!(view.witness.as_str(), "matches");
    assert!(view.tally.spent("calls") >= 1);
}

/// Several guest processes spending at once: the ledger total is exactly
/// the number of allowed spends, and never above the ceiling.
#[test]
fn concurrent_guest_spends_add_up_exactly_and_stop_at_the_ceiling() {
    require_sandbox!();
    let fx = Fixture::new("concurrent", 25);
    let body = r#"
workers, each = 8, 6
pids = []
r, w = os.pipe()
for i in range(workers):
    pid = os.fork()
    if pid == 0:
        os.close(r)
        s, f = conn()
        out = []
        for j in range(each):
            if j % 2:
                req = {"op": "block-spend", "counter": "calls", "n": 1}
            else:
                req = {"op": "referenced-spend", "charges": [{"counter": "calls", "n": 1}],
                       "caller_ref": "w%d-%d" % (i, j), "require_new_ref": True}
            rep = ask(f, req)
            out.append([rep["result"], rep.get("seq"), (rep.get("refusal") or {}).get("code")])
        os.write(w, (json.dumps(out) + "\n").encode())
        os._exit(0)
    pids.append(pid)
os.close(w)
for pid in pids:
    os.waitpid(pid, 0)
data = b""
while True:
    chunk = os.read(r, 65536)
    if not chunk:
        break
    data += chunk
results = [x for line in data.decode().splitlines() for x in json.loads(line)]
s, f = conn()
say({"results": results, "ledger": ask(f, {"op": "verified-ledger"})})
"#;
    let out = fx.run(&[], &script(body), &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let r = lines(&out);
    let res = &r[0]["results"];
    let all = res.as_array().map_or(&[][..], Vec::as_slice);
    assert_eq!(all.len(), 48, "{res}");
    let allowed: Vec<u64> = all
        .iter()
        .filter(|x| x[0] == "allowed")
        .filter_map(|x| x[1].as_u64())
        .collect();
    let refused = all.iter().filter(|x| x[0] == "refused").count();
    assert_eq!(allowed.len(), 25, "{res}");
    assert_eq!(refused, 23, "{res}");
    assert!(
        all.iter()
            .filter(|x| x[0] == "refused")
            .all(|x| x[2] == "ceiling-reached"),
        "{res}"
    );
    let mut seqs = allowed;
    seqs.sort_unstable();
    assert_eq!(seqs, (1..=25).collect::<Vec<u64>>(), "every seq once");
    assert_eq!(r[0]["ledger"]["totals"][0]["spent"], 25);
    let view = fx.verified();
    assert_eq!(view.tally.spent("calls"), 25);
    assert_eq!(view.witness.as_str(), "matches");
}

/// A detached command (its own session, no terminal) keeps spending
/// through the broker across many re-reads; a host revocation reaches it
/// as a watch event with the new digest and state, and its next spend is
/// refused, before playpen stops the run.
#[test]
fn a_detached_command_spends_across_rechecks_and_sees_a_revocation() {
    require_sandbox!();
    let fx = Fixture::new("detached", 1000);
    let ready = fx.dir.join("ready");
    let body = r#"
import signal
signal.signal(signal.SIGTERM, signal.SIG_IGN)
ready = sys.argv[1]
w, wf = conn()
first = ask(wf, {"op": "watch"})
say({"tag": "watch", "first": first})
s, f = conn()
spent = 0
for i in range(30):
    r = ask(f, {"op": "referenced-spend", "charges": [{"counter": "calls", "n": 1}],
                "caller_ref": "loop-%d" % i, "require_new_ref": True})
    if r["result"] == "allowed":
        spent += 1
    time.sleep(0.05)
say({"tag": "loop", "spent": spent})
open(ready, "w").close()
events = []
while True:
    line = wf.readline()
    if not line:
        break
    ev = json.loads(line)
    events.append(ev)
    if ev["event"] in ("revoked", "stopping"):
        break
say({"tag": "events", "events": events})
r = ask(f, {"op": "block-spend", "counter": "calls"})
say({"tag": "after", "reply": r})
p = ask(f, {"op": "pass"})
say({"tag": "pass", "reply": p})
"#;
    let mut child = Guard::spawn(
        fx.command(
            &["--new-session", "--pass-recheck-ms", "100"],
            &script(body),
            &[&Fixture::s(&ready)],
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let start = Instant::now();
    while !ready.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the command never got through its spends"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let revoked = pass_text(true, "9101", 1000);
    write_pass(&fx.pass, &revoked);
    let out = child.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
    let err = text(&out.stderr);
    let r = lines(&out);
    assert_eq!(by_tag(&r, "watch")["first"]["event"], "current", "{err}");
    assert_eq!(by_tag(&r, "loop")["spent"], 30, "{r:?} {err}");
    let events = by_tag(&r, "events")["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let ev = events
        .iter()
        .find(|e| e["event"] == "revoked")
        .unwrap_or_else(|| panic!("no revoked event: {events:?} {err}"));
    assert_eq!(ev["state"], "revoked");
    assert_eq!(
        ev["digest"],
        hallpass::Digest::of(revoked.as_bytes()).to_string()
    );
    assert_eq!(ev["text"], revoked.as_str());
    let after = &by_tag(&r, "after")["reply"];
    assert_eq!(after["result"], "refused", "{after}");
    assert_eq!(after["refusal"]["code"], "revoked", "{after}");
    let pass = &by_tag(&r, "pass")["reply"];
    assert_eq!(pass["state"], "revoked", "{pass}");
    assert_eq!(pass["withdrawn"]["code"], "revoked", "{pass}");
    assert!(err.contains("revoked"), "{err}");
    let view = fx.verified();
    assert_eq!(view.tally.spent("calls"), 30);
    assert_eq!(view.witness.as_str(), "matches");
}

/// A host edit that narrows a destination in use is a `narrowed` event,
/// and the broker refuses the next spend.
#[test]
fn a_narrowed_pass_is_an_event_and_a_refused_spend() {
    require_sandbox!();
    let fx = Fixture::new("narrowed", 1000);
    write_pass(&fx.pass, &pass_text(false, "[9101, 9102]", 1000));
    let ready = fx.dir.join("ready");
    let body = r#"
import signal
signal.signal(signal.SIGTERM, signal.SIG_IGN)
w, wf = conn()
ask(wf, {"op": "watch"})
s, f = conn()
say({"tag": "before", "reply": ask(f, {"op": "block-spend", "counter": "calls"})})
open(sys.argv[1], "w").close()
events = []
while True:
    ev = json.loads(wf.readline())
    events.append(ev)
    if ev["event"] in ("narrowed", "stopping"):
        break
say({"tag": "events", "events": events})
say({"tag": "after", "reply": ask(f, {"op": "block-spend", "counter": "calls"})})
"#;
    let mut child = Guard::spawn(
        fx.command(
            &["--pass-recheck-ms", "100"],
            &script(body),
            &[&Fixture::s(&ready)],
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped()),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let start = Instant::now();
    while !ready.exists() {
        assert!(start.elapsed() < Duration::from_secs(60), "never ready");
        std::thread::sleep(Duration::from_millis(20));
    }
    write_pass(&fx.pass, &pass_text(false, "9101", 1000));
    let out = child.wait_with_output().unwrap_or_else(|e| panic!("{e}"));
    let err = text(&out.stderr);
    let r = lines(&out);
    assert_eq!(by_tag(&r, "before")["reply"]["result"], "allowed", "{err}");
    let events = by_tag(&r, "events")["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let ev = events
        .iter()
        .find(|e| e["event"] == "narrowed")
        .unwrap_or_else(|| panic!("no narrowed event: {events:?} {err}"));
    assert_eq!(ev["state"], "valid");
    assert!(
        ev["message"]
            .as_str()
            .is_some_and(|m| m.contains("destination `web`")),
        "{ev}"
    );
    let after = &by_tag(&r, "after")["reply"];
    assert_eq!(after["result"], "refused", "{after}");
    assert!(
        after["refusal"]["code"] == "narrowed" || after["refusal"]["code"] == "stopping",
        "{after}"
    );
    assert_eq!(after["source"], "broker");
    assert!(err.contains("destination `web`"), "{err}");
    assert_eq!(fx.verified().tally.spent("calls"), 1);
}

/// `plan` names the broker only when it is given; it needs `--pass` and
/// cannot be combined with `--pass-dir-writable`.
#[test]
fn the_plan_has_the_broker_key_only_when_given() {
    let fx = Fixture::new("plan", 10);
    let plan = |extra: &[&str]| {
        let out = Command::new(BIN)
            .args(["plan", "--format", "json", "--pass"])
            .arg(&fx.pass)
            .args(extra)
            .args(["--", "true"])
            .env("XDG_STATE_HOME", &fx.state_home)
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        serde_json::from_slice::<Value>(&out.stdout).unwrap_or_default()
    };
    let without = plan(&[]);
    assert!(without["plan"].get("pass_broker").is_none(), "{without}");
    let with = plan(&["--pass-broker"]);
    let b = &with["plan"]["pass_broker"];
    assert_eq!(b["protocol"], "pass-broker-v1", "{with}");
    assert_eq!(
        b["hallpass_revision"],
        "7c06ea837ab6aa98858dc18e4be1fbaf6f3e85ff"
    );
    assert_eq!(b["state_directory"], Fixture::s(&fx.state()));
    assert_ne!(with["digest"], without["digest"]);
    // Planning creates nothing.
    assert!(!fx.state().exists());
    for args in [
        &["run", "--pass-broker", "--no-network", "--", "true"][..],
        &["plan", "--pass-broker", "--no-network", "--", "true"][..],
    ] {
        let out = Command::new(BIN)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(text(&out.stderr).contains("--pass <FILE>"), "{args:?}");
    }
    let out = Command::new(BIN)
        .args(["run", "--pass"])
        .arg(&fx.pass)
        .args(["--pass-broker", "--pass-dir-writable", "--", "true"])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.status.code(), Some(2));
    assert!(
        text(&out.stderr).contains("cannot be used with"),
        "{}",
        text(&out.stderr)
    );
}
