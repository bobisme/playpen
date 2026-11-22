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
/// 500, 501, ... (well above anything the test process itself has open,
/// also with other tests running in parallel: a source descriptor that was
/// itself in the target range would be overwritten or keep its
/// close-on-exec flag).
fn with_fds(cmd: &mut Command, extra: &[i32]) -> Output {
    let extra = extra.to_vec();
    // SAFETY: dup2 is async-signal-safe and touches only descriptors the
    // parent opened for this purpose; no allocation happens in the hook.
    unsafe {
        cmd.pre_exec(move || {
            for (i, fd) in extra.iter().enumerate() {
                let target = 500 + i32::try_from(i).unwrap_or(0);
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
    for n in 500..506 {
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
    let peer = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    let connected_tcp = TcpStream::connect(peer.local_addr().unwrap_or_else(|e| panic!("{e}")))
        .unwrap_or_else(|e| panic!("{e}"));
    let cases: Vec<(OwnedFd, &str)> = vec![
        (OwnedFd::from(udp), "datagram"),
        (OwnedFd::from(connected_udp), "datagram"),
        (unconnected_tcp, "unconnected TCP"),
        (OwnedFd::from(listening), "listening TCP"),
        (OwnedFd::from(connected_tcp), "connected TCP"),
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
fn connected_unix_stdio_works() {
    require_sandbox!();
    let (a, mut b) = UnixStream::pair().unwrap_or_else(|e| panic!("{e}"));
    let out = run_with_stdout(OwnedFd::from(a), Stdio::null());
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let mut got = String::new();
    b.read_to_string(&mut got).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got, "hi\n");
}

/// Runs `probe stdout-reconnect TARGET` in a sandbox with `stdout` as its
/// standard output; returns playpen's exit status and standard error.
fn reconnect_stdout(extra: &[&str], stdout: OwnedFd, target: &str) -> (Option<i32>, String) {
    let out = Command::new(BIN)
        .args(["run", "--no-network"])
        .args(extra)
        .args(["--", BIN, "probe", "stdout-reconnect", target])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::piped())
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    (out.status.code(), text(&out.stderr))
}

/// A socket on standard output was made in the host's network namespace.
/// The command must not be able to point it at another address: a
/// connected TCP socket can be dissolved (`connect` with `AF_UNSPEC`) and
/// connected again to any address the host can reach, past the filter.
#[test]
fn a_tcp_socket_on_stdout_cannot_be_pointed_elsewhere() {
    require_sandbox!();
    let peer = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    // A second service on the host's loopback, which no sandbox reaches.
    let other = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    other
        .set_nonblocking(true)
        .unwrap_or_else(|e| panic!("{e}"));
    let target = format!(
        "{}/tcp",
        other.local_addr().unwrap_or_else(|e| panic!("{e}"))
    );
    let client = TcpStream::connect(peer.local_addr().unwrap_or_else(|e| panic!("{e}")))
        .unwrap_or_else(|e| panic!("{e}"));
    let (code, err) = reconnect_stdout(&[], OwnedFd::from(client), &target);
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        other.accept().is_err(),
        "the command connected its standard output to another host service: {err}"
    );
    assert!(!err.contains("\"connected\":\"ALLOWED\""), "{err}");
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("standard output is"), "{err}");
    assert!(err.contains("nothing was run"), "{err}");
}

/// A Unix socket on standard output that is not connected yet belongs to
/// the host's network namespace too, and with it the host's abstract
/// sockets (a display server, a session bus). The command must not be able
/// to connect it to one: Landlock's scope refuses that; without Landlock
/// such a socket is not let in.
#[test]
fn a_unix_socket_on_stdout_cannot_reach_host_abstract_sockets() {
    use nix::sys::socket::{
        AddressFamily, Backlog, SockFlag, SockType, UnixAddr, bind, listen, socket,
    };
    require_sandbox!();
    let unix = |ty| {
        socket(
            AddressFamily::Unix,
            ty,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )
        .unwrap_or_else(|e| panic!("{e}"))
    };
    let name = format!("playpen-test-stdout-{}", std::process::id());
    let target = format!("@{name}");
    let addr = UnixAddr::new_abstract(name.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    let mut modes: Vec<&[&str]> = vec![&["--without-landlock"]];
    if playpen::landlock::resolve_unix_supported() {
        modes.push(&[]);
    }
    for ty in [SockType::Datagram, SockType::Stream] {
        // A "host daemon" on an abstract address.
        let daemon = unix(ty);
        bind(daemon.as_raw_fd(), &addr).unwrap_or_else(|e| panic!("{e}"));
        if ty == SockType::Stream {
            listen(&daemon, Backlog::new(4).unwrap_or(Backlog::MAXCONN))
                .unwrap_or_else(|e| panic!("{e}"));
        }
        for mode in &modes {
            let (code, err) = reconnect_stdout(mode, unix(ty), &target);
            let arrived = if ty == SockType::Stream {
                nix::sys::socket::accept(&daemon).is_ok()
            } else {
                let mut buf = [0u8; 32];
                nix::sys::socket::recv(
                    daemon.as_raw_fd(),
                    &mut buf,
                    nix::sys::socket::MsgFlags::empty(),
                )
                .is_ok()
            };
            assert!(
                !arrived,
                "{ty:?} {mode:?}: the command reached a host abstract socket: {err}"
            );
            assert!(
                !err.contains("\"connected\":\"ALLOWED\""),
                "{ty:?} {mode:?}: {err}"
            );
            if mode.is_empty() {
                // Let in; Landlock refuses the connection.
                assert_eq!(code, Some(0), "{ty:?}: {err}");
            } else {
                assert_eq!(code, Some(2), "{ty:?}: {err}");
                assert!(err.contains("standard output is"), "{err}");
                assert!(err.contains("nothing was run"), "{err}");
            }
        }
    }
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

#[test]
fn background_and_foreground_resume_a_sandbox_pipeline() {
    require_pty!(t);
    t.send("$P run --no-network -- sh -c 'while :; do echo p\"\"ulse; sleep 0.1; done' | cat\n");
    t.expect("pulse");
    t.send("\x1a");
    t.expect("Stopped");
    let _ = t.quiet_for(Duration::from_millis(300));
    assert!(!t.quiet_for(Duration::from_millis(500)).contains("pulse"));
    t.send("bg\n");
    t.expect("pulse");
    t.send("fg\n");
    t.expect("| cat");
    t.expect("pulse");
    t.send("\x03");
    assert_eq!(t.status(), "130");
    t.send("echo p\"\"ipeline-finished\n");
    t.expect("pipeline-finished");
}

#[test]
fn nested_interactive_pipeline_can_stop_background_foreground_and_interrupt() {
    if playpen::sandbox::tiocsti_allowed() {
        eprintln!(
            "SKIPPED: automatic new-session mode has no controlling terminal for nested job control"
        );
        return;
    }
    require_pty!(t);
    t.send("$P run --no-network -- bash --norc --noprofile -i\n");
    t.expect("host Unix sockets");
    t.expect("$ ");
    t.send("while :; do echo n\"\"ested-pulse; sleep 0.1; done | cat\n");
    t.expect("nested-pulse");
    t.send("\x1a");
    t.expect("Stopped");
    t.expect("$ ");
    let _ = t.quiet_for(Duration::from_millis(300));
    assert!(
        !t.quiet_for(Duration::from_millis(500))
            .contains("nested-pulse")
    );
    t.send("bg\n");
    t.expect("nested-pulse");
    t.send("fg\n");
    t.expect("| cat");
    t.expect("nested-pulse");
    t.send("\x03");
    t.expect("$ ");
    t.send("echo n\"\"ested-alive\n");
    t.expect("nested-alive");
    t.send("exit\n");
    t.expect("command exited with status 0");
    assert_eq!(t.status(), "0");
}

#[test]
fn foreground_pipeline_host_stage_can_read_terminal_input() {
    require_pty!(t);
    t.send("bash -c 'echo host-\"\"ready >/dev/tty; IFS= read -r word; printf \"host-read:%s\\n\" \"$word\"' | $P run --no-network -- cat\n");
    t.expect("host-ready");
    t.send("pipeline-input\n");
    t.expect("host-read:pipeline-input");
    assert_eq!(t.status(), "0");
}

#[test]
fn redirected_workload_can_use_its_controlling_terminal() {
    if playpen::sandbox::tiocsti_allowed() {
        eprintln!("SKIPPED: automatic new-session mode has no controlling terminal");
        return;
    }
    require_pty!(t);
    t.send("$P run --no-network -- sh -c 'echo tty-\"\"ready >/dev/tty; IFS= read -r word </dev/tty; printf \"tty-read:%s\\n\" \"$word\" >/dev/tty' </dev/null >/dev/null 2>&1\n");
    t.expect("tty-ready");
    t.send("terminal-input\n");
    t.expect("tty-read:terminal-input");
    assert_eq!(t.status(), "0");
}
