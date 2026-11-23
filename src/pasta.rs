//! Starting and stopping `pasta` for the sandbox's network namespace.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

use crate::capture::Capture;

/// Options that turn off everything in pasta that would reach the host or
/// accept traffic from outside, apart from plain outbound forwarding.
pub const OPTIONS: &[&str] = &[
    "--config-net",
    "--quiet",
    // No inbound port forwarding from the host into the namespace.
    "--tcp-ports",
    "none",
    "--udp-ports",
    "none",
    // No forwarding from the namespace's loopback to the host's ports
    // (pasta's default "auto" would make host loopback services appear on
    // 127.0.0.1 inside).
    "--tcp-ns",
    "none",
    "--udp-ns",
    "none",
    // Do not map the gateway (or any address) to the host's loopback.
    "--map-host-loopback",
    "none",
    // No DNS: no resolver addresses, no search list, no DNS forwarding.
    "--dns",
    "none",
    "--search",
    "none",
    "--no-dhcp",
    "--no-dhcpv6",
    "--no-ra",
];

/// With a capture, how long [`Pasta::stop`] waits for pasta to exit by
/// itself. pasta looks once a second whether the namespace's process is
/// gone.
const SELF_EXIT_WAIT: Duration = Duration::from_secs(2);

/// With a capture, how long playpen waits for pasta to exit after SIGTERM.
const TERM_WAIT: Duration = Duration::from_secs(1);

/// The full argument list for attaching to `target`'s namespaces, with
/// `--pcap NAME` when there is a capture.
#[must_use]
pub fn args(pid_file: &Path, target: Pid, pcap: Option<&OsStr>) -> Vec<OsString> {
    let mut v: Vec<OsString> = OPTIONS.iter().map(OsString::from).collect();
    v.push("--pid".into());
    v.push(pid_file.into());
    if let Some(name) = pcap {
        v.push("--pcap".into());
        v.push(name.into());
    }
    v.push(target.to_string().into());
    v
}

/// A running pasta.
#[derive(Debug)]
pub struct Pasta {
    pid: Option<Pid>,
    dir: PathBuf,
    /// Whether it writes a capture, which must be complete when it stops.
    capture: bool,
}

/// Starts pasta attached to `target`'s user and network namespaces and
/// waits until it has configured the namespace (pasta forks to the
/// background only after that).
///
/// With a capture, pasta starts in the capture's directory and opens the
/// file by its bare name; it does that, and writes the pcap header, before
/// it forks to the background.
///
/// # Errors
/// When pasta cannot run or exits with an error, or did not write the
/// capture.
pub fn start(pasta: &Path, target: Pid, capture: Option<&Capture>) -> Result<Pasta, String> {
    let dir = crate::sandbox::private_dir()?;
    // Absolute, as pasta may start in the capture's directory.
    let pid_file =
        std::path::absolute(dir.join("pasta.pid")).unwrap_or_else(|_| dir.join("pasta.pid"));
    let mut command = Command::new(pasta);
    command
        .args(args(&pid_file, target, capture.map(Capture::name)))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(c) = capture {
        command.current_dir(c.pasta_dir());
    }
    let out = command.output();
    let cleanup = |dir: &Path| {
        let _ = fs::remove_file(dir.join("pasta.pid"));
        let _ = fs::remove_dir(dir);
    };
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            cleanup(&dir);
            return Err(format!("cannot run {}: {e}", pasta.display()));
        }
    };
    if !out.status.success() {
        cleanup(&dir);
        return Err(format!(
            "pasta did not come up ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let pid = fs::read_to_string(&pid_file)
        .ok()
        .and_then(|t| t.trim().parse::<i32>().ok())
        .map(Pid::from_raw);
    let running = Pasta {
        pid,
        dir,
        capture: capture.is_some(),
    };
    if let Some(c) = capture
        && let Err(e) = c.check_written()
    {
        // Dropping `running` stops pasta.
        let said = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        return Err(if said.is_empty() {
            e
        } else {
            format!("{e}: {said}")
        });
    }
    Ok(running)
}

impl Pasta {
    /// Stops pasta if it is still running and removes its files. Called
    /// once the namespace's process has been reaped; pasta then exits on
    /// its own within a second.
    ///
    /// With a capture, playpen waits for that (up to [`SELF_EXIT_WAIT`])
    /// and returns only once pasta has exited, so the file is complete.
    /// pasta writes each packet as it goes, with two writes (record header,
    /// then frame), and exits on its own between packets. Its SIGTERM
    /// handler can run between the two writes and leave the last record
    /// cut, so SIGTERM comes only after the wait.
    pub fn stop(self) {
        if self.capture
            && let Some(pid) = self.pid
        {
            wait_gone(pid, SELF_EXIT_WAIT);
        }
        drop(self);
    }
}

/// On every way out of the run, an early error included.
impl Drop for Pasta {
    fn drop(&mut self) {
        if let Some(pid) = self.pid
            && is_pasta(pid)
        {
            let _ = kill(pid, Signal::SIGTERM);
            if self.capture {
                wait_gone(pid, TERM_WAIT);
            }
        }
        let _ = fs::remove_file(self.dir.join("pasta.pid"));
        let _ = fs::remove_dir(&self.dir);
    }
}

/// Whether `pid` is a live (not zombie) pasta process.
fn is_pasta(pid: Pid) -> bool {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    // "PID (COMM) STATE ...": COMM may itself contain parentheses.
    let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
        return false;
    };
    let comm = stat.get(open + 1..close).unwrap_or_default();
    let state = stat.get(close + 1..).unwrap_or_default().trim_start();
    (comm.starts_with("pasta") || comm.starts_with("passt"))
        && !state.starts_with('Z')
        && !state.starts_with('X')
}

/// Waits up to `limit` for `pid` to stop being a live pasta. Returns
/// whether it has.
fn wait_gone(pid: Pid, limit: Duration) -> bool {
    let end = Instant::now() + limit;
    loop {
        if !is_pasta(pid) {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_loopback_and_dns_are_off() {
        let a = args(Path::new("/x/pid"), Pid::from_raw(42), None);
        let pair = |k: &str, v: &str| a.windows(2).any(|w| w[0] == k && w[1] == v);
        assert!(pair("--map-host-loopback", "none"));
        assert!(pair("--tcp-ns", "none"));
        assert!(pair("--udp-ns", "none"));
        assert!(pair("--tcp-ports", "none"));
        assert!(pair("--udp-ports", "none"));
        assert!(pair("--dns", "none"));
        assert!(!a.iter().any(|s| s == "--dns-forward"));
        assert!(!a.iter().any(|s| s == "--pcap"));
        assert_eq!(a.last().and_then(|s| s.to_str()), Some("42"));
    }

    #[test]
    fn a_capture_is_a_bare_name_before_the_pid() {
        let a = args(
            Path::new("/x/pid"),
            Pid::from_raw(42),
            Some(OsStr::new("run.pcap")),
        );
        let n = a.len();
        assert_eq!(a[n - 3], "--pcap");
        assert_eq!(a[n - 2], "run.pcap");
        assert_eq!(a[n - 1], "42");
    }

    #[test]
    fn this_process_is_not_pasta() {
        assert!(!is_pasta(nix::unistd::getpid()));
        assert!(wait_gone(nix::unistd::getpid(), Duration::ZERO));
    }
}
