//! playpen never panics, and keeps its exit status, when stdout or stderr
//! cannot be written.

#![allow(
    clippy::disallowed_macros,
    reason = "test code may print with the std macros"
)]

use std::io::Read as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod common;

use common::Guard;

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

fn playpen(args: &[&str]) -> Command {
    let mut c = Command::new(BIN);
    c.args(args);
    c.stdin(Stdio::null());
    c
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// A pipe end that nobody reads: writing to it gives `EPIPE`.
fn closed_pipe() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap_or_else(|e| panic!("cannot make a pipe: {e}"));
    drop(reader);
    Stdio::from(writer)
}

/// Fails when the stderr text shows a panic.
fn assert_no_panic(stderr: &str) {
    assert!(!stderr.contains("panicked"), "playpen panicked: {stderr}");
    assert!(
        !stderr.contains("failed printing"),
        "playpen failed printing: {stderr}"
    );
}

#[test]
fn a_listing_whose_reader_left_does_not_panic() {
    // The reader closed before playpen wrote, so the write gives EPIPE.
    let out = playpen(&["rules", "--allow", "192.0.2.1:443/tcp", "--format", "json"])
        .stdout(closed_pipe())
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("cannot run playpen: {e}"));
    assert_no_panic(&String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

#[test]
fn a_listing_read_for_one_byte_does_not_panic() {
    let mut child = Guard::spawn(
        playpen(&["rules", "--allow", "192.0.2.1:443/tcp", "--format", "json"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap_or_else(|e| panic!("cannot run playpen: {e}"));
    let mut stdout = child.stdout.take().unwrap_or_else(|| panic!("no stdout"));
    let mut byte = [0_u8; 1];
    stdout
        .read_exact(&mut byte)
        .unwrap_or_else(|e| panic!("no output: {e}"));
    drop(stdout);
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("cannot wait: {e}"));
    assert_no_panic(&String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{out:?}");
}

#[test]
fn a_run_whose_stderr_reader_left_still_writes_its_report() {
    if let Some(why) = skip_reason() {
        eprintln!("SKIPPED: {why}");
        return;
    }
    let dir = tmpdir("stdio-stderr");
    let report = dir.join("report.json");
    let _ = std::fs::remove_file(&report);
    let path = report.display().to_string();
    let out = playpen(&["run", "--no-network", "--report", &path, "--", "true"])
        .stdout(Stdio::piped())
        .stderr(closed_pipe())
        .output()
        .unwrap_or_else(|e| panic!("cannot run playpen: {e}"));
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let text = std::fs::read_to_string(&report).unwrap_or_else(|e| panic!("no report: {e}"));
    let json: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("report is not JSON: {e}"));
    assert_eq!(json["playpen_exit_status"], 0, "{text}");
}

/// The exit status of `run --no-network --format json -- true` with the
/// stdout that `setup` gives it, and its stderr text.
fn run_with_stdout(stdout: Stdio, close_fd: bool) -> (Option<i32>, String) {
    let mut cmd = playpen(&["run", "--no-network", "--format", "json", "--", "true"]);
    cmd.stdout(stdout).stderr(Stdio::piped());
    if close_fd {
        // SAFETY: close is async-signal-safe and nothing else runs in the
        // closure.
        unsafe {
            cmd.pre_exec(|| {
                libc::close(1);
                Ok(())
            });
        }
    }
    let out: Output = cmd
        .output()
        .unwrap_or_else(|e| panic!("cannot run playpen: {e}"));
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_report_to_a_closed_stdout_is_lost_without_changing_the_status() {
    if let Some(why) = skip_reason() {
        eprintln!("SKIPPED: {why}");
        return;
    }
    let (baseline, _) = run_with_stdout(Stdio::null(), false);
    assert_eq!(baseline, Some(0));
    let (status, stderr) = run_with_stdout(closed_pipe(), false);
    assert_no_panic(&stderr);
    assert_eq!(status, baseline, "{stderr}");
    assert!(stderr.contains("the report was not written"), "{stderr}");
    let (status, stderr) = run_with_stdout(Stdio::null(), true);
    assert_no_panic(&stderr);
    assert_eq!(status, baseline, "{stderr}");
}
