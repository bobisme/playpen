//! End-to-end tests for VM sockets (`AF_VSOCK`): the sandbox's network
//! namespace has VSOCK mode `local`, so the command's VM sockets reach only
//! the sandbox's own, and playpen does not run a command whose namespace
//! did not get that mode (docs/DESIGN.md, "VM sockets (`AF_VSOCK`)").
//!
//! The VM-socket side runs `tests/socket_families.py`, with a Python whose
//! `socket` module has `AF_VSOCK`. Nothing leaves the machine: the
//! listener is the test's own, reached over the loopback transport (CID 1).
//!
//! Like every playpen run, these load the `vsock` module where it is not
//! loaded: creating an `AF_VSOCK` socket makes the kernel load it, and with it
//! the transports its `net-pf-40` alias names, `vsock_loopback` among them
//! (measured on 7.2.8). They skip where VM sockets cannot be created, where
//! the kernel has no VSOCK namespace mode, and where the loopback transport
//! does not connect even outside the sandbox.

#![allow(
    clippy::disallowed_macros,
    reason = "test code may print with the std macros"
)]

mod common;

use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::Guard;
use playpen::vsock::Host;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");
const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/socket_families.py");
/// `VMADDR_PORT_ANY`: the listener takes a port the kernel picks.
const ANY_PORT: &str = "4294967295";
/// The start-line clause of a sandbox in VSOCK mode `local`.
const LOCAL_CLAUSE: &str = "VM sockets (AF_VSOCK): only the sandbox's own (VSOCK mode local)";

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A Python 3 whose `socket` module has `AF_VSOCK` (some builds lack it).
fn python() -> Option<&'static str> {
    ["/usr/bin/python3", "python3"].into_iter().find(|p| {
        Command::new(p)
            .args(["-I", "-c", "import socket; socket.AF_VSOCK"])
            .stdin(Stdio::null())
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

/// Why these tests cannot run here, if they cannot; else the Python to use.
///
/// Loads `vsock` where it is not loaded, as `playpen run` would.
fn requirements() -> Result<&'static str, String> {
    let max = std::fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap_or_default();
    if max.trim().is_empty() || max.trim() == "0" {
        return Err("user namespaces are not available".into());
    }
    if playpen::tools::nft().is_none() {
        return Err("nft is not installed".into());
    }
    match playpen::vsock::prepare() {
        Host::Modes => {}
        Host::Unavailable => {
            return Err(
                "this kernel cannot create VM sockets (AF_VSOCK), and vsock cannot be loaded"
                    .into(),
            );
        }
        Host::NoModes => {
            return Err(
                "this kernel has VM sockets but no VSOCK namespace mode (Linux before 7.0)".into(),
            );
        }
    }
    python().ok_or_else(|| "no python3 with socket.AF_VSOCK".into())
}

macro_rules! require_vsock {
    () => {
        match requirements() {
            Ok(python) => python,
            Err(why) => {
                eprintln!("SKIPPED: {why}");
                return;
            }
        }
    };
}

/// `playpen run ARGS -- PYTHON -I socket_families.py PROBE...`.
fn sandbox(args: &[&str], python: &str, probe: &[&str]) -> Output {
    Command::new(BIN)
        .arg("run")
        .args(args)
        .args(["--", python, "-I", SCRIPT])
        .args(probe)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("cannot run playpen: {e}"))
}

/// A fresh path for a report.
fn report_path(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("vsock-{name}-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

fn read_report(path: &Path) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let _ = std::fs::remove_file(path);
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn the_sandbox_reads_vsock_mode_local() {
    let python = require_vsock!();
    let mut modes: Vec<(&str, Vec<&str>)> = vec![("offline", vec!["--no-network"])];
    if playpen::tools::pasta().is_some() {
        // A documentation address: nothing is sent anywhere.
        modes.push(("egress", vec!["--allow", "192.0.2.1:9/tcp"]));
    } else {
        eprintln!("pasta is not installed: only --no-network is checked");
    }
    for (name, args) in modes {
        let report = report_path(name);
        let report_arg = report.display().to_string();
        let mut run_args = args.clone();
        run_args.extend(["--report", &report_arg]);
        let out = sandbox(&run_args, python, &["vsock-mode"]);
        let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{name}: {stdout}{stderr}");
        // What the command itself reads in its namespace.
        assert!(
            stdout.lines().any(|l| l == "ns_mode=local"),
            "{name}: {stdout}"
        );
        assert!(
            stdout.lines().any(|l| l == "child_ns_mode=local"),
            "{name}: {stdout}"
        );
        assert!(
            stderr
                .lines()
                .any(|l| l == format!("playpen:   {LOCAL_CLAUSE}")),
            "{name}: {stderr}"
        );
        assert_eq!(read_report(&report)["vsock"], "local", "{name}");
    }
}

#[test]
fn a_vsock_listener_of_the_caller_is_not_reachable_from_inside() {
    let python = require_vsock!();
    // Two connections at most: the one from outside, and the one from
    // inside if it got through. The guard stops it either way.
    let mut listener = Guard::spawn(
        Command::new(python)
            .args(["-I", SCRIPT, "vsock-listen", ANY_PORT])
            .args(["--count", "2", "--timeout", "60"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()),
    )
    .unwrap_or_else(|e| panic!("cannot start the listener: {e}"));
    let stdout = listener
        .stdout
        .take()
        .unwrap_or_else(|| panic!("no stdout of the listener"));
    let mut lines = BufReader::new(stdout).lines();
    let first = lines.next().and_then(Result::ok).unwrap_or_default();
    let Some(port) = first.strip_prefix("listening port=").map(str::to_owned) else {
        panic!("the listener did not start: {first:?}");
    };

    // Outside the sandbox the listener is reachable over the loopback
    // transport; without that the test inside would prove nothing.
    let outside = Command::new(python)
        .args(["-I", SCRIPT, "vsock-connect", "1", &port])
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("cannot run {python}: {e}"));
    let outside = text(&outside.stdout);
    if !outside.starts_with("connected reply=pong") {
        eprintln!(
            "SKIPPED: the loopback transport (vsock_loopback) did not connect outside the sandbox: {outside}"
        );
        return;
    }
    let accepted = lines.next().and_then(Result::ok).unwrap_or_default();
    assert!(accepted.starts_with("accepted cid=1 "), "{accepted}");

    // Without VSOCK mode local this connects too ("connected reply=pong").
    let out = sandbox(&["--no-network"], python, &["vsock-connect", "1", &port]);
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{stdout}{stderr}");
    assert_eq!(stdout.trim(), "error ECONNRESET", "{stderr}");
}

/// The run stops when the sandbox's namespace did not get VSOCK mode
/// `local`.
///
/// The kernel gives an unprivileged caller no way to have playpen's write
/// refused, so `socket_families.py with-mode` runs playpen in a user and
/// mount namespace of its own in which a tmpfs over `/proc/sys` makes
/// `/proc/sys/net/vsock/ns_mode` read the given text, in the sandbox's
/// network namespace too. With `local` the same fake gets past this check,
/// and the run stops later, where the sandbox mounts its own `/proc` (the
/// tmpfs over `/proc/sys` keeps the kernel from allowing that): so it is
/// the mode that stops the run with `global`.
#[test]
fn a_sandbox_that_did_not_get_vsock_mode_local_is_not_run() {
    let python = require_vsock!();
    let marker = report_path("marker");
    let touch = format!("touch {}", marker.display());
    let run_with = |mode: &str| {
        Command::new(python)
            .args(["-I", SCRIPT, "with-mode", mode, BIN, "run", "--no-network"])
            .args(["--format", "json", "--", "sh", "-c", &touch])
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("cannot run {python}: {e}"))
    };
    let out = run_with("global");
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    if stdout.starts_with("error ") {
        eprintln!("SKIPPED: cannot fake /proc/sys/net/vsock here: {stdout}");
        return;
    }
    assert_eq!(out.status.code(), Some(1), "{stdout}{stderr}");
    let report: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}{stderr}"));
    assert_eq!(report["vsock"], "global", "{report}");
    assert_eq!(report["outcome"], "not_started", "{report}");
    assert_eq!(report["startup_evidence"], "not_started", "{report}");
    let message = report["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("did not get VSOCK mode local") && message.ends_with("nothing was run"),
        "{message}"
    );
    assert!(!stderr.contains(LOCAL_CLAUSE), "{stderr}");
    assert!(!marker.exists(), "the command ran");

    let out = run_with("local");
    let (stdout, stderr) = (text(&out.stdout), text(&out.stderr));
    let report: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}{stderr}"));
    assert_eq!(report["vsock"], "local", "{report}");
    let message = report["message"].as_str().unwrap_or_default();
    assert!(message.contains("/proc"), "{message}");
    assert!(!message.contains("VSOCK"), "{message}");
    assert!(stderr.contains(LOCAL_CLAUSE), "{stderr}");
    let _ = std::fs::remove_file(&marker);
}
