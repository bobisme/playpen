//! Starting and stopping `pasta` for the sandbox's network namespace.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

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

/// The full argument list for attaching to `target`'s namespaces.
#[must_use]
pub fn args(pid_file: &Path, target: Pid) -> Vec<String> {
    let mut v: Vec<String> = OPTIONS.iter().map(|s| (*s).to_owned()).collect();
    v.push("--pid".into());
    v.push(pid_file.display().to_string());
    v.push(target.to_string());
    v
}

/// A running pasta.
#[derive(Debug)]
pub struct Pasta {
    pid: Option<Pid>,
    dir: PathBuf,
}

/// Starts pasta attached to `target`'s user and network namespaces and
/// waits until it has configured the namespace (pasta forks to the
/// background only after that).
///
/// # Errors
/// When pasta cannot run or exits with an error.
pub fn start(pasta: &Path, target: Pid) -> Result<Pasta, String> {
    let dir = crate::sandbox::private_dir()?;
    let pid_file = dir.join("pasta.pid");
    let out = Command::new(pasta)
        .args(args(&pid_file, target))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
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
    Ok(Pasta { pid, dir })
}

impl Pasta {
    /// Stops pasta if it is still running and removes its files. pasta
    /// also exits on its own once the namespace is gone.
    pub fn stop(self) {
        if let Some(pid) = self.pid {
            let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            if comm.starts_with("pasta") || comm.starts_with("passt") {
                let _ = kill(pid, Signal::SIGTERM);
            }
        }
        let _ = fs::remove_file(self.dir.join("pasta.pid"));
        let _ = fs::remove_dir(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_loopback_and_dns_are_off() {
        let a = args(Path::new("/x/pid"), Pid::from_raw(42));
        let pair = |k: &str, v: &str| a.windows(2).any(|w| w[0] == k && w[1] == v);
        assert!(pair("--map-host-loopback", "none"));
        assert!(pair("--tcp-ns", "none"));
        assert!(pair("--udp-ns", "none"));
        assert!(pair("--tcp-ports", "none"));
        assert!(pair("--udp-ports", "none"));
        assert!(pair("--dns", "none"));
        assert!(!a.iter().any(|s| s == "--dns-forward"));
        assert_eq!(a.last().map(String::as_str), Some("42"));
    }
}
