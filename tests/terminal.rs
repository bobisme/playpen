//! Integration tests for what the command inherits from the caller:
//! descriptors, standard input/output/error that are sockets, and the
//! terminal (interactive use, driven through a pseudo-terminal).
//!
//! Every sandbox here uses `--no-network`; the only sockets are on the
//! host's loopback or Unix socket pairs.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

fn skip_reason() -> Option<String> {
    let max = std::fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap_or_default();
    if max.trim().is_empty() || max.trim() == "0" {
        return Some("user namespaces are not available".into());
    }
    let nft = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .iter()
        .any(|d| Path::new(d).join("nft").exists());
    if !nft {
        return Some("nft is not installed".into());
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

// ------------------------------------------------ inherited descriptors

/// Runs `cmd` with `extra` open, without close-on-exec, on descriptors
/// 50, 51, ...
fn with_fds(cmd: &mut Command, extra: &[i32]) -> Output {
    let extra = extra.to_vec();
    // SAFETY: dup2 is async-signal-safe and touches only descriptors the
    // parent opened for this purpose; no allocation happens in the hook.
    unsafe {
        cmd.pre_exec(move || {
            for (i, fd) in extra.iter().enumerate() {
                let target = 50 + i32::try_from(i).unwrap_or(0);
                if libc::dup2(*fd, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    cmd.stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{e}"))
}

/// The descriptor numbers `probe fds` printed, without the one it used to
/// list them.
fn listed_fds(stdout: &str) -> Vec<i64> {
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_default();
    v["fds"].as_array().map_or_else(Vec::new, |a| {
        a.iter()
            .filter(|e| !e["target"].as_str().unwrap_or("").ends_with("/fd"))
            .filter_map(|e| e["fd"].as_i64())
            .collect()
    })
}

#[test]
fn inherited_descriptors_do_not_reach_the_command() {
    require_sandbox!();
    let file = File::open(env!("CARGO_MANIFEST_DIR").to_owned() + "/Cargo.toml")
        .unwrap_or_else(|e| panic!("{e}"));
    let (unix_a, _unix_b) = UnixStream::pair().unwrap_or_else(|e| panic!("{e}"));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let tcp = TcpStream::connect(listener.local_addr().unwrap_or_else(|e| panic!("{e}")))
        .unwrap_or_else(|e| panic!("{e}"));
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let (pipe_r, _pipe_w) = nix::unistd::pipe().unwrap_or_else(|e| panic!("{e}"));
    let extra = [
        file.as_raw_fd(),
        unix_a.as_raw_fd(),
        tcp.as_raw_fd(),
        udp.as_raw_fd(),
        listener.as_raw_fd(),
        pipe_r.as_raw_fd(),
    ];
    // Without playpen the probe sees them: the test itself works.
    let direct = with_fds(Command::new(BIN).args(["probe", "fds"]), &extra);
    let seen = listed_fds(&text(&direct.stdout));
    for n in 50..56 {
        assert!(seen.contains(&n), "fd {n} not inherited directly: {seen:?}");
    }
    let inside = with_fds(
        Command::new(BIN).args(["run", "--no-network", "--", BIN, "probe", "fds"]),
        &extra,
    );
    assert_eq!(inside.status.code(), Some(0), "{}", text(&inside.stderr));
    let seen = listed_fds(&text(&inside.stdout));
    assert_eq!(seen, vec![0, 1, 2], "{}", text(&inside.stdout));
}

// ------------------------------------------- stdio that is a socket

fn run_with_stdout(stdout: OwnedFd, stdin: Stdio) -> Output {
    Command::new(BIN)
        .args(["run", "--no-network", "--", "echo", "hi"])
        .stdin(stdin)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn stdio_sockets_that_reach_the_host_network_are_refused() {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let connected_udp = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    connected_udp
        .connect(udp.local_addr().unwrap_or_else(|e| panic!("{e}")))
        .unwrap_or_else(|e| panic!("{e}"));
    let unconnected_tcp = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Inet,
        nix::sys::socket::SockType::Stream,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        None,
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let listening = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let cases: Vec<(OwnedFd, &str)> = vec![
        (OwnedFd::from(udp), "datagram"),
        (OwnedFd::from(connected_udp), "datagram"),
        (unconnected_tcp, "unconnected TCP"),
        (OwnedFd::from(listening), "listening TCP"),
    ];
    for (fd, expect) in cases {
        let out = run_with_stdout(fd, Stdio::null());
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{expect}: {err}");
        assert!(err.contains("standard output is"), "{err}");
        assert!(err.contains(expect), "{expect}: {err}");
        assert!(err.contains("nothing was run"), "{err}");
    }
    // The same check covers standard input.
    let udp_in = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let out = Command::new(BIN)
        .args(["run", "--no-network", "--", "true"])
        .stdin(Stdio::from(OwnedFd::from(udp_in)))
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("standard input is"));
}

#[test]
fn connected_tcp_and_unix_stdio_work() {
    require_sandbox!();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let client = TcpStream::connect(listener.local_addr().unwrap_or_else(|e| panic!("{e}")))
        .unwrap_or_else(|e| panic!("{e}"));
    let (mut server, _) = listener.accept().unwrap_or_else(|e| panic!("{e}"));
    let out = run_with_stdout(OwnedFd::from(client), Stdio::null());
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let mut got = String::new();
    server
        .read_to_string(&mut got)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, "hi\n");

    let (a, mut b) = UnixStream::pair().unwrap_or_else(|e| panic!("{e}"));
    let out = run_with_stdout(OwnedFd::from(a), Stdio::null());
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let mut got = String::new();
    b.read_to_string(&mut got).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, "hi\n");
}

// ------------------------------------------------- pseudo-terminal

/// A host `bash -i` on a pseudo-terminal the test drives, as an operator
/// at a terminal would.
struct Pty {
    master: File,
    child: Child,
    seen: Vec<u8>,
    /// Bytes of `seen` already matched by `expect`.
    at: usize,
}

impl Pty {
    fn shell() -> Option<Self> {
        if !Path::new("/usr/bin/bash").exists() && !Path::new("/bin/bash").exists() {
            return None;
        }
        let mut master: libc::c_int = -1;
        let mut slave: libc::c_int = -1;
        let size = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty writes two descriptors into the locals and reads
        // the window size; a null name and termios are allowed.
        let rc = unsafe {
            libc::openpty(
                &raw mut master,
                &raw mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &raw const size,
            )
        };
        assert_eq!(rc, 0, "openpty failed");
        // SAFETY: both descriptors were just returned by openpty and are
        // owned by nothing else.
        let (master, slave) = unsafe { (File::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        let clone = |fd: &OwnedFd| Stdio::from(fd.try_clone().unwrap_or_else(|e| panic!("{e}")));
        let mut cmd = Command::new("bash");
        cmd.args(["--norc", "--noprofile", "-i"])
            .env("PS1", "$ ")
            .env("TERM", "dumb")
            .env("P", BIN)
            .stdin(clone(&slave))
            .stdout(clone(&slave))
            .stderr(clone(&slave));
        // SAFETY: setsid and ioctl are async-signal-safe; the hook makes
        // the pseudo-terminal the shell's controlling terminal.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap_or_else(|e| panic!("{e}"));
        drop(slave);
        let mut pty = Self {
            master,
            child,
            seen: Vec::new(),
            at: 0,
        };
        pty.expect("$ ");
        Some(pty)
    }

    fn send(&mut self, s: &str) {
        self.master
            .write_all(s.as_bytes())
            .unwrap_or_else(|e| panic!("{e}"));
    }

    /// Reads whatever arrives within `d`.
    fn read_for(&mut self, d: Duration) {
        let end = Instant::now() + d;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            let ms = u16::try_from(left.as_millis().min(1000)).unwrap_or(1000);
            let mut fds = [nix::poll::PollFd::new(
                std::os::fd::AsFd::as_fd(&self.master),
                nix::poll::PollFlags::POLLIN,
            )];
            if nix::poll::poll(&mut fds, nix::poll::PollTimeout::from(ms)).unwrap_or(0) > 0 {
                let mut buf = [0u8; 4096];
                match self.master.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => self.seen.extend_from_slice(&buf[..n]),
                }
            }
        }
    }

    /// Waits up to 10 s for `needle` after the last match; returns what
    /// came before it.
    fn expect(&mut self, needle: &str) -> String {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let rest = text(&self.seen[self.at..]);
            if let Some(pos) = rest.find(needle) {
                self.at += rest[..pos].len() + needle.len();
                return rest[..pos].to_owned();
            }
            assert!(
                Instant::now() < end,
                "timed out waiting for {needle:?}; terminal shows: {rest:?}"
            );
            self.read_for(Duration::from_millis(100));
        }
    }

    /// Everything after the last match, read for `d`.
    fn quiet_for(&mut self, d: Duration) -> String {
        self.read_for(d);
        let rest = text(&self.seen[self.at..]);
        self.at = self.seen.len();
        rest
    }

    fn set_size(&self, rows: u16, cols: u16) {
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ reads one winsize struct from a live local.
        let rc = unsafe { libc::ioctl(self.master.as_raw_fd(), libc::TIOCSWINSZ, &raw const size) };
        assert_eq!(rc, 0, "TIOCSWINSZ failed");
    }

    /// The exit status of the last command, as the outer shell saw it.
    fn status(&mut self) -> String {
        // Split so the echoed command line does not match.
        self.send("echo \"r\"\"c=$?\"\n");
        self.expect("rc=");
        self.expect("\n").trim().to_owned()
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

macro_rules! require_pty {
    ($pty:ident) => {
        require_sandbox!();
        let Some(mut $pty) = Pty::shell() else {
            eprintln!("SKIPPED: bash is not installed");
            return;
        };
    };
}

#[test]
fn ctrl_c_reaches_the_command() {
    require_pty!(t);
    t.send("$P run --no-network -- sh -c 'echo st\"\"arted; sleep 30'\n");
    t.expect("started");
    t.send("\x03");
    assert_eq!(t.status(), "130");
}

#[test]
fn ctrl_z_stops_the_whole_sandbox_and_fg_resumes_it() {
    require_pty!(t);
    // The loop runs in its own session, so the terminal's SIGTSTP never
    // reaches it: only playpen's freeze can stop it.
    t.send(
        "$P run --no-network -- sh -c 'setsid sh -c \"while :; do echo t\\\"\\\"ick; sleep 0.1; done\" & wait'\n",
    );
    t.expect("tick");
    t.send("\x1a");
    t.expect("Stopped");
    // Let a tick that was already on its way arrive, then nothing more.
    let _ = t.quiet_for(Duration::from_millis(300));
    let while_stopped = t.quiet_for(Duration::from_millis(700));
    assert!(
        !while_stopped.contains("tick"),
        "the command kept running while playpen was stopped: {while_stopped:?}"
    );
    t.send("fg\n");
    t.expect("tick");
    t.send("\x03");
    assert_eq!(t.status(), "130");
}

#[test]
fn a_terminal_resize_reaches_the_command() {
    require_pty!(t);
    t.send(
        "$P run --no-network -- sh -c 'trap \"stty size\" WINCH; echo re\"\"ady; while :; do sleep 0.1; done'\n",
    );
    t.expect("ready");
    t.set_size(40, 100);
    t.expect("40 100");
    t.send("\x03");
    assert_eq!(t.status(), "130");
}

#[test]
fn the_command_reads_from_the_terminal() {
    require_pty!(t);
    t.send("$P run --no-network -- sh -c 'read x; echo \"got-$x\"'\n");
    // Wait for the sandbox to be up before typing.
    t.expect("host Unix sockets");
    t.send("hello\n");
    t.expect("got-hello");
    assert_eq!(t.status(), "0");
}

#[test]
fn job_control_works_in_a_shell_inside() {
    require_pty!(t);
    t.send("$P run --no-network -- bash --norc --noprofile -i\n");
    t.expect("host Unix sockets");
    t.expect("$ ");
    t.send("sleep 30\n");
    t.read_for(Duration::from_millis(300));
    t.send("\x1a");
    t.expect("Stopped");
    t.expect("$ ");
    t.send("fg\n");
    t.expect("sleep 30");
    t.send("\x03");
    t.expect("$ ");
    t.send("echo in-$((40+2))\n");
    t.expect("in-42");
    t.send("exit\n");
    t.expect("command exited with status 0");
    assert_eq!(t.status(), "0");
}

#[test]
fn the_command_cannot_type_into_the_terminal() {
    require_pty!(t);
    for extra in ["", "--new-session "] {
        t.send(&format!("$P run --no-network {extra}-- $P probe tty\n"));
        let line = t.expect("\"tiocsti\"");
        let rest = t.expect("}");
        assert!(rest.contains("denied"), "{extra}: {line}{rest}");
        if extra.is_empty() {
            // The terminal stays the command's controlling terminal.
            assert!(line.contains("\"dev_tty\":\"ALLOWED\""), "{line}");
        } else {
            assert!(line.contains("\"dev_tty\":\"denied"), "{line}");
        }
        assert_eq!(t.status(), "0");
    }
}

#[test]
fn in_a_new_session_ctrl_c_ctrl_z_resize_and_input_still_work() {
    require_pty!(t);
    t.send(
        "$P run --no-network --new-session -- sh -c 'trap \"stty size\" WINCH; read x; echo \"got-$x\"; echo t\"\"ick; while :; do sleep 0.1; done'\n",
    );
    t.expect("own session");
    t.send("hello\n");
    t.expect("got-hello");
    t.expect("tick");
    // The terminal signals playpen's process group, not the command's
    // session: playpen passes the resize on.
    t.set_size(30, 90);
    t.expect("30 90");
    t.send("\x1a");
    t.expect("Stopped");
    t.send("fg\n");
    t.read_for(Duration::from_millis(300));
    t.send("\x03");
    assert_eq!(t.status(), "130");
}
