//! Helpers the integration tests share. A test file includes them with
//! `mod common;`.
//!
//! Each test file is its own crate and uses only part of this module.
#![allow(
    dead_code,
    reason = "every test crate includes the whole module and uses part of it"
)]
#![allow(
    clippy::disallowed_macros,
    reason = "test code may print with the std macros"
)]

use std::io;
use std::ops::{Deref, DerefMut};
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command, Output};
use std::time::{Duration, Instant};

/// A child process that runs in a session of its own and is killed, with
/// everything it started on the host, and reaped when the guard is dropped.
///
/// A test that spawns a `playpen run` which does not end by itself holds one
/// of these, so a panic before the test's own kill does not leave the run
/// behind. The guard dereferences to the [`Child`].
///
/// Killing the child alone is not enough: the processes playpen starts on
/// the host stay in its session, but once the child is gone nothing else
/// stops them. The command inside the sandbox may make sessions of its own,
/// but only inside the sandbox's PID namespace, which ends with the
/// sandbox's init.
pub struct Guard {
    /// The child; `None` once [`Guard::wait_with_output`] consumed it.
    child: Option<Child>,
    /// The child's PID, which is also its session.
    sid: i32,
    /// The start time of the session leader, to tell it from a later
    /// process that got the same PID.
    started: Option<u64>,
}

impl Guard {
    /// Starts `command` as the leader of a new session.
    ///
    /// # Errors
    ///
    /// Whatever [`Command::spawn`] returns.
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        // SAFETY: setsid is async-signal-safe, and nothing else runs in the
        // closure.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        let sid = i32::try_from(child.id()).map_err(io::Error::other)?;
        Ok(Self {
            started: start_time(sid),
            child: Some(child),
            sid,
        })
    }

    /// Waits for the child and collects its output, as
    /// [`Child::wait_with_output`] does, but keeps the guard, so that what
    /// the child left behind is still killed when the guard is dropped.
    ///
    /// # Errors
    ///
    /// Whatever [`Child::wait_with_output`] returns.
    ///
    /// # Panics
    ///
    /// When the output was already collected.
    pub fn wait_with_output(&mut self) -> io::Result<Output> {
        self.child
            .take()
            .expect("the output of the child was already collected")
            .wait_with_output()
    }
}

impl Deref for Guard {
    type Target = Child;

    fn deref(&self) -> &Child {
        self.child
            .as_ref()
            .expect("the output of the child was already collected")
    }
}

impl DerefMut for Guard {
    fn deref_mut(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("the output of the child was already collected")
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Unreaped, the leader keeps its PID, and so the session number,
        // from being reused while the session is emptied.
        if let Some(child) = &mut self.child {
            let _ = child.kill();
        }
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let left = self.left();
            if left.is_empty() {
                break;
            }
            if Instant::now() >= end {
                eprintln!("processes of the test's child are still there: {left:?}");
                break;
            }
            for pid in left {
                // SAFETY: kill takes plain integers; the PIDs are positive.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if let Some(child) = &mut self.child {
            let _ = child.wait();
        }
    }
}

impl Guard {
    /// The processes still in the child's session, and their descendants.
    fn left(&self) -> Vec<i32> {
        // A leader that is there with another start time is a process that
        // got the PID after the session ended.
        if std::fs::metadata(format!("/proc/{}", self.sid)).is_ok()
            && start_time(self.sid) != self.started
        {
            return Vec::new();
        }
        session_and_descendants(self.sid)
    }
}

/// The start time of process `pid` in clock ticks since boot, if it exists.
fn start_time(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // After the name, field 3 (the state) is first; the start time is field 22.
    stat.rsplit_once(") ")?.1.split(' ').nth(19)?.parse().ok()
}

/// The processes in session `sid`, without its leader `sid`, and their
/// descendants. A process whose parent has died is still in the session;
/// one that made a session of its own is found by its parent.
fn session_and_descendants(sid: i32) -> Vec<i32> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    // (pid, parent, session) of every process.
    let all: Vec<(i32, i32, i32)> = dir
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(|pid| {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // After the name: state, parent, process group, session.
            let mut fields = stat.rsplit_once(") ")?.1.split(' ');
            let parent = fields.nth(1)?.parse().ok()?;
            let session = fields.nth(1)?.parse().ok()?;
            Some((pid, parent, session))
        })
        .collect();
    // Not by the leader's PID as a parent: once the leader is reaped, that
    // PID can belong to an unrelated process.
    let mut found: Vec<i32> = all
        .iter()
        .filter(|&&(pid, _, session)| session == sid && pid != sid)
        .map(|&(pid, _, _)| pid)
        .collect();
    loop {
        let more: Vec<i32> = all
            .iter()
            .filter(|&&(pid, parent, _)| {
                pid != sid && found.contains(&parent) && !found.contains(&pid)
            })
            .map(|&(pid, _, _)| pid)
            .collect();
        if more.is_empty() {
            return found;
        }
        found.extend(more);
    }
}
