use std::fs::File;
use std::io::{BufRead as _, BufReader, Read as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use nix::fcntl::OFlag;
use nix::unistd::{pipe2, write};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

fn stream_command(args: &[&str], full: bool) -> (std::process::Output, File) {
    let (r, w) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).expect("pipe");
    if full {
        let buf = [0_u8; libc::PIPE_BUF];
        while write(&w, &buf).is_ok() {}
    }
    let raw = w.as_raw_fd();
    let mut cmd = Command::new(BIN);
    cmd.args(["run", "--events-fd", "42"]).args(args);
    // SAFETY: dup2 and fcntl are async-signal-safe. w remains live until spawn.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 42) < 0 || libc::fcntl(42, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().expect("CLI");
    drop(w);
    (out, File::from(r))
}

#[test]
fn event_refusal_is_private_and_terminal() {
    let (out, r) = stream_command(&["--allow", "INVALID_PRIVATE", "--", "true"], false);
    let mut data = String::new();
    BufReader::new(r)
        .read_to_string(&mut data)
        .expect("complete stream");
    let record: Value = serde_json::from_str(&data).expect("single record");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(record["event"], "terminal");
    assert_eq!(record["details"]["outcome"], "refused");
    assert!(!data.contains("INVALID_PRIVATE"));
}

#[test]
fn events_separate_child_status_and_survive_a_full_pipe() {
    let args = [
        "--no-network",
        "--",
        "sh",
        "-c",
        "test ! -e /proc/self/fd/42 || exit 77; printf child; printf diagnostic >&2; exit 2",
    ];
    let (out, r) = stream_command(&args, false);
    assert_eq!(out.stdout, b"child");
    assert!(String::from_utf8_lossy(&out.stderr).contains("diagnostic"));
    assert_eq!(out.status.code(), Some(2));
    let mut reader = BufReader::with_capacity(3, r);
    let mut records = Vec::new();
    let mut line = String::new();
    while reader.read_line(&mut line).expect("pipe") > 0 {
        records.push(serde_json::from_str::<Value>(&line).expect("complete JSON line"));
        line.clear();
    }
    assert_eq!(records.len(), 3);
    for (i, name) in ["validated", "starting", "terminal"].iter().enumerate() {
        assert_eq!(records[i]["event"], *name);
        assert_eq!(records[i]["seq"], i + 1);
    }
    assert_eq!(records[2]["details"]["child_exit"], 2);
    assert_eq!(records[2]["details"]["outcome"], "ran");
    let (full, _) = stream_command(&args, true);
    assert_eq!(full.stdout, b"child");
    assert_eq!(full.status.code(), Some(2));
}

#[test]
fn a_regular_file_is_refused_with_the_workaround() {
    let path = std::env::temp_dir().join(format!("playpen-events-{}.jsonl", std::process::id()));
    let file = File::create(&path).expect("file");
    let raw = file.as_raw_fd();
    let mut cmd = Command::new(BIN);
    cmd.args(["run", "--events-fd", "42", "--no-network", "--", "true"]);
    // SAFETY: dup2 and fcntl are async-signal-safe. file remains live until spawn.
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(raw, 42) < 0 || libc::fcntl(42, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().expect("CLI");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("requires the write end of a pipe"), "{err}");
    assert!(err.contains("42> >(cat > events.jsonl)"), "{err}");
    assert!(err.contains("nothing was run"), "{err}");
    assert_eq!(std::fs::metadata(&path).expect("stat").len(), 0);
    let _ = std::fs::remove_file(&path);
}
