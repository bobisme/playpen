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
    // Close-on-exec like the others: only the copies `with_fds` makes are
    // for the child, and no child of another test may keep these.
    let (pipe_r, _pipe_w) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).unwrap_or_else(|e| panic!("{e}"));
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
        let (master, slave) = Self::pair();
        let mut cmd = Command::new("bash");
        cmd.args(["--norc", "--noprofile", "-i"])
            .env("PS1", "$ ")
            .env("TERM", "dumb")
            .env("P", BIN);
        let mut pty = Self::spawn(master, &slave, &mut cmd);
        drop(slave);
        pty.expect("$ ");
        Some(pty)
    }

    /// A new pseudo-terminal of 24 rows and 80 columns: (master, slave).
    ///
    /// Both ends are opened close-on-exec in the same call that makes
    /// them. Tests run in parallel threads, and a child another test
    /// starts between an open and a later `FD_CLOEXEC` would keep this
    /// terminal's master. A process that holds the master of its own
    /// terminal never sees it hang up: that kept `playpen run` trees of
    /// failed tests alive for days.
    fn pair() -> (File, OwnedFd) {
        // SAFETY: open takes a NUL-terminated path; the result is checked.
        let master = unsafe {
            libc::open(
                c"/dev/ptmx".as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        assert!(
            master >= 0,
            "open /dev/ptmx: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: the descriptor was just opened and is owned by nothing else.
        let master = unsafe { File::from_raw_fd(master) };
        // SAFETY: grantpt and unlockpt take a live master descriptor.
        let unlocked = unsafe {
            libc::grantpt(master.as_raw_fd()) == 0 && libc::unlockpt(master.as_raw_fd()) == 0
        };
        assert!(
            unlocked,
            "unlock the PTY: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: TIOCGPTPEER opens the slave of a live master with the
        // given flags and returns a new descriptor; the result is checked.
        let slave = unsafe {
            libc::ioctl(
                master.as_raw_fd(),
                libc::TIOCGPTPEER,
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        assert!(
            slave >= 0,
            "open the PTY slave: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: the descriptor was just opened and is owned by nothing else.
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };
        let size = libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ reads one winsize struct from a live local.
        let rc = unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &raw const size) };
        assert_eq!(rc, 0, "TIOCSWINSZ failed");
        (master, slave)
    }

    fn spawn(master: File, slave: &OwnedFd, cmd: &mut Command) -> Self {
        let clone = |fd: &OwnedFd| Stdio::from(fd.try_clone().expect("duplicate PTY slave"));
        cmd.stdin(clone(slave))
            .stdout(clone(slave))
            .stderr(clone(slave));
        // SAFETY: setsid, ioctl and signal are async-signal-safe; the hook
        // makes the pseudo-terminal the shell's controlling terminal.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // As a terminal emulator starts its shell. A test binary
                // started as a background job of a script inherits SIGINT
                // and SIGQUIT ignored, and the shell would pass that on to
                // every command: Ctrl-C would then stop nothing.
                for sig in [
                    libc::SIGHUP,
                    libc::SIGINT,
                    libc::SIGQUIT,
                    libc::SIGTSTP,
                    libc::SIGTTIN,
                    libc::SIGTTOU,
                ] {
                    if libc::signal(sig, libc::SIG_DFL) == libc::SIG_ERR {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap_or_else(|e| panic!("{e}"));
        Self {
            master,
            child,
            seen: Vec::new(),
            at: 0,
        }
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
                "timed out waiting for {needle:?}; terminal shows: {rest:?}; before that: {:?}",
                text(&self.seen[..self.at])
            );
            self.read_for(Duration::from_millis(100));
        }
    }

    /// Waits up to 10 s for each of `needles` after the last match, in any
    /// order, and continues after the one that came last. Output that
    /// reaches the terminal by two routes, such as the private terminal
    /// relay and a pipe through `cat`, can arrive either way round.
    fn expect_each(&mut self, needles: &[&str]) {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let rest = text(&self.seen[self.at..]);
            let ends: Option<Vec<usize>> = needles
                .iter()
                .map(|needle| rest.find(needle).map(|pos| pos + needle.len()))
                .collect();
            if let Some(last) = ends.and_then(|ends| ends.into_iter().max()) {
                self.at += last;
                return;
            }
            assert!(
                Instant::now() < end,
                "timed out waiting for each of {needles:?}; terminal shows: {rest:?}; before that: {:?}",
                text(&self.seen[..self.at])
            );
            self.read_for(Duration::from_millis(100));
        }
    }

    /// Waits up to 10 s until the terminal passes Ctrl-C and Ctrl-Z on as
    /// bytes (`ISIG` is off) instead of signalling its foreground job.
    /// Reading meanwhile keeps the output flowing.
    fn expect_keys_as_bytes(&mut self) {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            // SAFETY: tcgetattr fills the struct on success, which is
            // checked; on the master it reads the slave's settings.
            let isig = unsafe {
                let mut settings = std::mem::MaybeUninit::<libc::termios>::uninit();
                assert_eq!(
                    libc::tcgetattr(self.master.as_raw_fd(), settings.as_mut_ptr()),
                    0,
                    "tcgetattr on the PTY master"
                );
                settings.assume_init().c_lflag & libc::ISIG != 0
            };
            if !isig {
                return;
            }
            assert!(
                Instant::now() < end,
                "the terminal still turns control keys into signals; terminal shows: {:?}",
                text(&self.seen[self.at..])
            );
            self.read_for(Duration::from_millis(10));
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

/// When a test ends, passed or failed (a timed-out `expect` panics), its
/// shell and everything the shell started are killed and gone before the
/// test returns.
///
/// Killing the shell alone is not enough: the shell gives each job a
/// process group of its own, and once the shell is gone a stopped or
/// background `playpen run` gets no hangup signal from the terminal.
/// Everything playpen starts on the host stays in the shell's session; the
/// command may make a session of its own, but only inside the sandbox's PID
/// namespace, which ends with the sandbox's init.
impl Drop for Pty {
    fn drop(&mut self) {
        let Ok(shell) = i32::try_from(self.child.id()) else {
            return;
        };
        // Unreaped, the shell keeps its PID, and so the session number,
        // from being reused while the session is emptied.
        let _ = self.child.kill();
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let left = session_and_descendants(shell);
            if left.is_empty() {
                break;
            }
            if Instant::now() >= end {
                eprintln!("processes of the test's terminal are still there: {left:?}");
                break;
            }
            for pid in left {
                // SAFETY: kill takes plain integers; the PIDs are positive.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.wait();
    }
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

#[test]
fn attached_and_new_session_pid_and_group_signals_have_one_delivery() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    require_pty!(t);
    for (option, whole_group) in [
        ("--new-session", false),
        ("--new-session", true),
        ("", false),
        ("", true),
    ] {
        t.send(&format!(
            "$P run --no-network {option} -- $P probe signals\n"
        ));
        t.expect("ready");
        // SAFETY: master is the live master fd for this test's private PTY.
        let pgid = unsafe { libc::tcgetpgrp(t.master.as_raw_fd()) };
        assert!(pgid > 1 && pgid != i32::try_from(t.child.id()).expect("shell PID"));
        let target = Pid::from_raw(if whole_group { -pgid } else { pgid });
        for _ in 0..4 {
            kill(target, Signal::SIGUSR1).expect("signal the foreground test job");
            t.expect("usr1");
            let late = t.quiet_for(Duration::from_millis(200));
            assert!(
                !late.contains("usr1"),
                "duplicate receipt for option={option:?}, whole_group={whole_group}: {late:?}"
            );
        }
        kill(Pid::from_raw(pgid), Signal::SIGTERM).expect("finish the counter");
        t.expect(r#"{"usr1":4}"#);
        assert_eq!(t.status(), "0");
    }
}

/// The processes named `playpen` in this session, as (PID, process group),
/// in ascending PID order: the supervisor first.
fn playpen_processes(session: u32) -> Vec<(i32, i32)> {
    let mut found: Vec<(i32, i32)> = std::fs::read_dir("/proc")
        .expect("list /proc")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<i32>().ok())
        .filter_map(|pid| {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let (head, tail) = stat.rsplit_once(") ")?;
            let mut fields = tail.split(' ');
            // After the name: state, parent, process group, session.
            let group: i32 = fields.nth(2)?.parse().ok()?;
            let in_session = fields.next()?.parse() == Ok(session);
            (in_session && head.split_once('(')?.1 == "playpen").then_some((pid, group))
        })
        .collect();
    found.sort_unstable();
    found
}

/// A link to the binary under another name, so that a sender choosing
/// processes named `playpen` does not choose the workload.
fn renamed_probe(tag: &str) -> std::path::PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("directory for the renamed probe");
    let link = dir.join("sigcount");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(BIN, &link).expect("link the probe");
    link
}

/// `killall playpen` reaches every playpen process and not the command, in
/// ascending PID order; `kill $(pidof playpen)` in descending order. Both
/// include the witness in the supervisor's process group, and neither is a
/// signal for the group: the command gets it from playpen, once.
#[test]
fn attached_signal_for_each_playpen_process_has_one_delivery() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    require_pty!(t);
    let probe = renamed_probe("each-playpen");
    for descending in [false, true] {
        t.send(&format!(
            "$P run --no-network -- {} probe signals\n",
            probe.display()
        ));
        t.expect("ready");
        let mut helpers = playpen_processes(t.child.id());
        // P, C, the DNS stub, S, I and the witness; the last two after
        // the others.
        assert_eq!(helpers.len(), 6, "playpen processes: {helpers:?}");
        let supervisor = helpers[0].0;
        let in_group = helpers.iter().filter(|h| h.1 == helpers[0].1).count();
        assert_eq!(in_group, 5, "init leaves the group: {helpers:?}");
        if descending {
            helpers.reverse();
        }
        for _ in 0..4 {
            for &(pid, _) in &helpers {
                kill(Pid::from_raw(pid), Signal::SIGUSR1).expect("signal a playpen process");
            }
            t.expect("usr1");
            let late = t.quiet_for(Duration::from_millis(200));
            assert!(
                !late.contains("usr1"),
                "duplicate receipt, descending={descending}: {late:?}"
            );
        }
        kill(Pid::from_raw(supervisor), Signal::SIGTERM).expect("finish the counter");
        t.expect(r#"{"usr1":4}"#);
        assert_eq!(t.status(), "0");
    }
    let _ = std::fs::remove_dir_all(probe.parent().expect("probe directory"));
}

/// A shell with job control inside puts itself in a process group of its
/// own. A signal for playpen's group then reaches the witness and not the
/// shell, so playpen still has to pass it on.
#[test]
fn attached_group_signal_reaches_a_shell_that_left_the_group() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    if playpen::sandbox::tiocsti_allowed() {
        eprintln!("SKIPPED: automatic new-session mode has no nested job control");
        return;
    }
    require_pty!(t);
    t.send("$P run --no-network -- bash --norc --noprofile -i\n");
    t.expect("host Unix sockets");
    t.expect("$ ");
    t.send("trap 'echo got-us\"\"r1' USR1\n");
    t.expect("$ ");
    let group = playpen_processes(t.child.id())[0].1;
    // SAFETY: master is the live master fd for this test's private PTY.
    let foreground = unsafe { libc::tcgetpgrp(t.master.as_raw_fd()) };
    assert_ne!(foreground, group, "the inner shell took the terminal");
    for _ in 0..3 {
        kill(Pid::from_raw(-group), Signal::SIGUSR1).expect("signal playpen's group");
        // bash runs the trap when it next reads a line.
        t.read_for(Duration::from_millis(150));
        t.send("\n");
        t.expect("got-usr1");
        let late = t.quiet_for(Duration::from_millis(200));
        assert!(!late.contains("got-usr1"), "duplicate receipt: {late:?}");
    }
    t.send("exit\n");
    t.expect("command exited with status 0");
    assert_eq!(t.status(), "0");
}

/// `kill 0` inside reaches the command's whole process group, which is the
/// caller's: the command, playpen and its witness. Init is not in it, and
/// playpen sees a signal for the group; neither passes it on.
#[test]
fn attached_group_signal_from_inside_has_one_delivery() {
    require_pty!(t);
    t.send(concat!(
        "$P run --no-network -- sh -c '(trap \"\" USR1; sleep 0.5; kill -USR1 0; sleep 0.5; ",
        "kill -USR1 0; sleep 0.5; kill -TERM 0) & exec \"$0\" probe signals' $P\n"
    ));
    t.expect("ready");
    for _ in 0..2 {
        t.expect("usr1");
        let late = t.quiet_for(Duration::from_millis(200));
        assert!(!late.contains("usr1"), "duplicate receipt: {late:?}");
    }
    t.expect(r#"{"usr1":2}"#);
    assert_eq!(t.status(), "0");
}

#[test]
fn private_tty_opens_a_controlling_terminal_and_preserves_redirected_stdout() {
    require_pty!(t);
    t.send("output=$(mktemp); before=$(stty -g)\n");
    t.expect("$ ");
    t.send(
        r#"$P run --no-network --private-tty -- sh -c 'test ! -t 1 || exit 41; printf "tty-%s\n" private >/dev/tty || exit 42; IFS= read -r value </dev/tty || exit 43; printf "file-%s\n" "$value"' >"$output"
"#,
    );
    t.expect("tty-private\r\n");
    t.send("redirected\n");
    t.expect("$ ");
    assert_eq!(t.status(), "0");
    t.expect("$ ");
    t.send(
        r#"if test "$(cat "$output")" = "file-"redirected && test "$(stty -g)" = "$before"; then echo restored-"and-separated"; fi; rm -f "$output"
"#,
    );
    t.expect("restored-and-separated\r\n");
}

#[test]
fn private_tty_delivers_each_supervisor_and_group_signal_once() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::{Pid, getpgid};

    require_pty!(t);
    t.send(
        r#"sh -c 'echo pt"y-pid=$$"; exec "$1" run --no-network --private-tty -- "$1" probe signals' wrapper "$P"
"#,
    );
    t.expect("pty-pid=");
    let pid: i32 = t.expect("\n").trim().parse().expect("wrapper PID");
    let wrapper = Pid::from_raw(pid);
    assert_eq!(
        getpgid(Some(wrapper)).expect("wrapper process group"),
        wrapper
    );
    t.expect("ready\r\n");
    for target in [wrapper, Pid::from_raw(-pid)] {
        for _ in 0..4 {
            kill(target, Signal::SIGUSR1).expect("signal private test job");
            assert!(!t.expect("usr1\r\n").contains("command exited"));
            let additional = t.quiet_for(Duration::from_millis(200));
            assert!(
                !additional.contains("usr1"),
                "duplicate receipt for {target:?}: {additional:?}"
            );
        }
    }
    kill(wrapper, Signal::SIGTERM).expect("finish counted probe");
    t.expect(r#"{"usr1":8}"#);
    t.expect("$ ");
    assert_eq!(t.status(), "0");
}

#[test]
fn private_tty_outer_stop_freezes_detached_descendant_until_fg() {
    require_pty!(t);
    // The detached descendant is outside the private terminal's session.
    // Its redirected stderr bypasses the relay, so an idle master alone
    // cannot make a live writer look frozen.
    let pulse = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("private-tty-freeze-{}", std::process::id()));
    let shell_path = pulse.to_string_lossy().replace('\'', "'\\''");
    let pulse_count = || {
        std::fs::metadata(&pulse)
            .expect("redirected pulse file")
            .len()
    };
    t.send(&format!(
        r#"$P run --no-network --private-tty -- sh -c 'trap "kill -STOP $$" TSTP; setsid sh -c "while :; do echo private-\"tick\"; printf . >&2; sleep 0.1; done" & while :; do if IFS= read -r value </dev/tty && test "$value" = quit; then exit 0; fi; done' 2>'{shell_path}'
"#,
    ));
    t.expect("private-tick\r\n");
    t.send("\x1a");
    t.expect("Stopped");
    t.expect("$ ");
    let _ = t.quiet_for(Duration::from_millis(250));
    let frozen = pulse_count();
    assert!(frozen > 0, "the redirected writer never started");
    let _ = t.quiet_for(Duration::from_millis(400));
    assert_eq!(pulse_count(), frozen, "detached writer kept running");
    t.send("fg\n");
    t.expect("private-tick\r\n");
    let _ = t.quiet_for(Duration::from_millis(200));
    assert!(pulse_count() > frozen, "detached writer failed to resume");
    t.send("quit\n");
    t.expect("$ ");
    assert_eq!(t.status(), "0");
    std::fs::remove_file(pulse).expect("remove redirected pulse file");
}

#[test]
fn private_tty_inner_bash_controls_a_pipeline() {
    require_pty!(t);
    t.send("$P run --no-network --private-tty -- bash --norc --noprofile -i\n");
    t.expect("host Unix sockets");
    t.expect("$ ");
    t.send("sleep 30 | sh -c 'echo pipe-\"ready\"; cat'\n");
    t.expect("pipe-ready\r\n");
    t.send("\x1a");
    t.expect("Stopped");
    t.expect("$ ");
    t.send("bg\n");
    t.expect("$ ");
    assert_eq!(t.status(), "0");
    t.expect("$ ");
    t.send("if test -n \"$(jobs -pr)\"; then echo pipeline-\"running\"; fi\n");
    t.expect("pipeline-running\r\n");
    t.expect("$ ");
    t.send("fg\n");
    t.expect("sleep 30");
    t.send("\x03");
    t.expect("$ ");
    assert_eq!(t.status(), "130");
    t.expect("$ ");
    t.send("echo inner-\"still-live\"; exit 0\n");
    t.expect("inner-still-live\r\n");
    t.expect("command exited with status 0");
    t.expect("$ ");
    assert_eq!(t.status(), "0");
}

#[test]
fn private_tty_resizes_and_restores_the_outer_terminal_after_interrupt() {
    require_pty!(t);
    t.send("before=$(stty -g)\n");
    t.expect("$ ");
    t.send(
        r#"$P run --no-network --private-tty -- sh -c 'trap "stty size </dev/tty" WINCH; printf "resize-%s\n" ready; while :; do sleep 0.1; done'
"#,
    );
    t.expect("resize-ready\r\n");
    t.set_size(41, 103);
    t.expect("41 103\r\n");
    t.send("\x03");
    t.expect("$ ");
    assert_eq!(t.status(), "130");
    t.expect("$ ");
    t.send("if test \"$(stty -g)\" = \"$before\"; then echo tty-\"restored\"; fi\n");
    t.expect("tty-restored\r\n");
}

#[test]
fn private_tty_refuses_a_session_without_controlling_terminal() {
    require_sandbox!();
    let mut command = Command::new(BIN);
    command
        .args([
            "run",
            "--no-network",
            "--private-tty",
            "--",
            "echo",
            "unexpected-marker",
        ])
        .stdin(Stdio::null());
    // SAFETY: setsid is async-signal-safe and guarantees no controlling tty,
    // even if the integration suite itself was launched from a terminal.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command
        .output()
        .expect("launch playpen without a controlling tty");
    let err = text(&out.stderr);
    assert!(matches!(out.status.code(), Some(1 | 2)), "{err}");
    assert!(
        err.contains("terminal") && err.contains("nothing was run"),
        "{err}"
    );
    assert!(out.stdout.is_empty(), "{}", text(&out.stdout));
}

#[test]
fn private_tty_inner_job_control_keeps_the_outer_output_pipeline_running() {
    require_pty!(t);
    t.send("set -o pipefail\n");
    t.expect("$ ");
    t.send("$P run --private-tty --no-network -- env 'PS1=private-test> ' bash --norc --noprofile -i | cat\n");
    t.expect("host Unix sockets");
    t.expect("private-test> ");
    t.send("sleep 30 | sh -c 'echo nested-\"pipeline-ready\"; cat'\n");
    t.expect("nested-pipeline-ready");
    // The relay looks at the private terminal every 20 ms. Until it has
    // seen the nested job there, Ctrl-Z would stop the outer cat as well.
    t.expect_keys_as_bytes();
    t.send("\x1a");
    let stopped = t.expect("Stopped");
    assert!(!stopped.contains("command exited"), "{stopped:?}");
    t.expect("private-test> ");
    t.send("bg\n");
    t.expect("private-test> ");
    t.send("echo bg-\"status=$?\" >&2\n");
    t.expect("bg-status=0\r\n");
    t.expect("private-test> ");
    t.send("if test -n \"$(jobs -pr)\"; then echo nested-\"job-running\" >&2; fi\n");
    t.expect("nested-job-running\r\n");
    t.expect("private-test> ");
    t.send("fg\n");
    // Bash prints the fg command line on stdout. Do not wait for that
    // line, since a stopped cat would hide the final output witness too.
    // Wait instead until the relay passes Ctrl-C to the nested job.
    t.expect_keys_as_bytes();
    t.send("\x03");
    t.expect("private-test> ");
    t.send("echo fg-\"status=$?\" >&2\n");
    t.expect("fg-status=130\r\n");
    t.expect("private-test> ");
    // This marker originates on the inner shell's stdout, which reaches
    // the host only through the outer pipeline's cat. The next prompt
    // comes through the relay, and can be shown before the marker.
    t.send("echo through-\"outer-cat\"\n");
    t.expect_each(&["through-outer-cat", "private-test> "]);
    t.send("exit 0\n");
    t.expect("command exited with status 0");
    t.expect("$ ");
    assert_eq!(t.status(), "0");
    t.expect("$ ");
    t.send("if test -z \"$(jobs -sp)\"; then echo outer-\"jobs-clear\"; fi\n");
    t.expect("outer-jobs-clear\r\n");
}

#[test]
fn private_tty_drains_the_last_output_before_reporting_exit() {
    require_pty!(t);
    t.send("$P run --private-tty --no-network -- sh -c 'printf \"BE%sGIN\\n\" -; head -c 98304 /dev/zero | tr \"\\000\" x; printf \"FIN%sISH\\n\" -; exit 23'\n");
    t.expect("BE-GIN\r\n");
    let payload = t.expect("FIN-ISH\r\n");
    assert_eq!(payload.len(), 98_304, "wrong final PTY byte count");
    assert!(payload.bytes().all(|byte| byte == b'x'));
    t.expect("command exited with status 23");
    t.expect("$ ");
    assert_eq!(t.status(), "23");
}

#[test]
fn private_tty_signals_foreground_pipeline_after_its_leader_exits() {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    require_pty!(t);
    t.send("sh -c 'echo wrap\"per=$$\"; exec \"$1\" run --no-network --private-tty -- bash --norc --noprofile -i' wrapper \"$P\"\n");
    t.expect("wrapper=");
    let wrapper = Pid::from_raw(t.expect("\n").trim().parse().expect("wrapper PID"));
    t.expect("host Unix sockets");
    t.expect("$ ");
    // Bash reaps the first pipeline stage while the second still owns the tty.
    // The surviving stage acknowledges readiness only once the leader is gone.
    t.send(r#"true | sh -c 'read -r pid comm state ppid pgid rest < /proc/self/stat; while test -d /proc/$pgid; do sleep 0.02; done; trap "echo signal-\"received\"; exit 0" USR1; echo leader-"gone"; while :; do read -r input </dev/tty; done'
"#);
    t.expect("leader-gone\r\n");
    kill(wrapper, Signal::SIGUSR1).expect("signal wrapper");
    t.expect("signal-received\r\n");
    t.expect("$ ");
    t.send("exit 0\n");
    t.expect("command exited with status 0");
    t.expect("$ ");
    assert_eq!(t.status(), "0");
}

#[test]
fn private_tty_restores_mode_when_session_leader_is_killed() {
    require_sandbox!();
    assert_private_tty_restored_after_leader_kill(false);
}

#[test]
fn private_tty_restores_mode_after_leader_kill_with_redirected_stdin() {
    require_sandbox!();
    assert_private_tty_restored_after_leader_kill(true);
}

fn assert_private_tty_restored_after_leader_kill(redirected_stdin: bool) {
    use std::os::unix::process::ExitStatusExt as _;

    // Retain the slave in the test process, outside Playpen's session, so
    // the terminal settings remain observable after its leader dies.
    let (master, slave) = Pty::pair();
    let mode = || {
        // SAFETY: the retained slave is live and tcgetattr initializes the
        // struct on success. Compare the public fields, not struct padding.
        let mut settings = std::mem::MaybeUninit::<libc::termios>::uninit();
        unsafe {
            assert_eq!(libc::tcgetattr(slave.as_raw_fd(), settings.as_mut_ptr()), 0);
            let settings = settings.assume_init();
            (
                [
                    settings.c_iflag,
                    settings.c_oflag,
                    settings.c_cflag,
                    settings.c_lflag,
                ],
                settings.c_line,
                settings.c_cc,
                [
                    libc::cfgetispeed(&raw const settings),
                    libc::cfgetospeed(&raw const settings),
                ],
            )
        }
    };
    let before = mode();
    let mut cmd = if redirected_stdin {
        // The fixture gives the shell a controlling terminal. It keeps
        // the same session-leader PID when it execs Playpen with a null fd 0.
        let mut shell = Command::new("sh");
        shell.args(["-c", "exec \"$@\" </dev/null", "session-leader", BIN]);
        shell
    } else {
        Command::new(BIN)
    };
    cmd.args([
        "run",
        "--no-network",
        "--private-tty",
        "--",
        "sh",
        "-c",
        "echo kill-test-ready; exec sleep 30",
    ]);
    let mut t = Pty::spawn(master, &slave, &mut cmd);
    t.expect("kill-test-ready");
    let ready_deadline = Instant::now() + Duration::from_secs(2);
    while mode() == before {
        assert!(
            Instant::now() < ready_deadline,
            "the relay never entered raw mode"
        );
        t.read_for(Duration::from_millis(20));
    }

    t.child.kill().expect("send SIGKILL to the session leader");
    let wait_deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = t.child.try_wait().expect("wait for session leader") {
            break status;
        }
        assert!(
            Instant::now() < wait_deadline,
            "session leader did not exit"
        );
        t.read_for(Duration::from_millis(20));
    };
    assert_eq!(status.signal(), Some(libc::SIGKILL));

    let restore_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let actual = mode();
        if actual == before {
            break;
        }
        assert!(
            Instant::now() < restore_deadline,
            "terminal mode left changed after leader SIGKILL: before {before:?}, after {actual:?}"
        );
        t.read_for(Duration::from_millis(20));
    }
}

#[test]
fn private_tty_separates_keyboard_input_when_all_stdio_are_redirected() {
    require_pty!(t);
    t.send(
        r#"scratch=$(mktemp -d); printf '%s\n' file-line >"$scratch/input"
"#,
    );
    t.expect("$ ");
    t.send(
        r#"$P run --no-network --private-tty -- sh -c 'test ! -t 0 && test ! -t 1 && test ! -t 2 || exit 41; IFS= read -r data || exit 42; printf "keyboard-%s\n" ready >/dev/tty || exit 43; IFS= read -r key </dev/tty || exit 44; if IFS= read -r extra; then exit 45; fi; printf "file-stdout:%s/%s\n" "$data" "$key"; printf "file-stderr:%s/%s\n" "$data" "$key" >&2' <"$scratch/input" >"$scratch/output" 2>"$scratch/error"
"#,
    );
    t.expect("keyboard-ready\r\n");
    t.send("keyboard-line\n");
    let tail = t.expect("$ ");
    assert!(
        !tail.contains("file-stdout:") && !tail.contains("file-stderr:"),
        "{tail}"
    );
    assert_eq!(t.status(), "0");
    t.expect("$ ");
    t.send(
        r#"if test "$(cat "$scratch/output")" = 'file-stdout:file-line/keyboard-line' && grep -Fxq 'file-stderr:file-line/keyboard-line' "$scratch/error"; then echo redirected-"stdio-confirmed"; fi; rm -f "$scratch/input" "$scratch/output" "$scratch/error"; rmdir "$scratch"
"#,
    );
    t.expect("redirected-stdio-confirmed\r\n");
}

#[test]
fn private_tty_keeps_piped_stdin_separate_from_dev_tty_keyboard_input() {
    require_pty!(t);
    t.send("set -o pipefail\n");
    t.expect("$ ");
    t.send(
        r#"printf '%s\n' pipe-first pipe-last | $P run --no-network --private-tty -- sh -c 'test ! -t 0 || exit 41; IFS= read -r first || exit 42; printf "pipe-keyboard-%s\n" ready >/dev/tty || exit 43; IFS= read -r key </dev/tty || exit 44; IFS= read -r last || exit 45; if IFS= read -r extra; then exit 46; fi; printf "channels:%s/%s/%s\n" "$first" "$key" "$last"'
"#,
    );
    t.expect("pipe-keyboard-ready\r\n");
    t.send("keyboard-line\n");
    t.expect("channels:pipe-first/keyboard-line/pipe-last\r\n");
    t.expect("$ ");
    assert_eq!(t.status(), "0");
}

/// A command that sends to a denied address and sleeps past a reading of
/// the drop counter, run at the terminal with `--events-fd` (so the counter
/// is read while it runs) and `mode`. Without `--live-drops` the terminal
/// shows no new line, while the events stream gets the `denied` record;
/// with it, the line is shown before the command ends.
fn live_lines_only_when_asked(t: &mut Pty, mode: &str) {
    t.send("events=$(mktemp)\n");
    t.expect("$ ");
    for live in [false, true] {
        let flag = if live { " --live-drops" } else { "" };
        t.send(&format!(
            "$P run --no-network --lo-addr 192.0.2.2 --events-fd 3{mode}{flag} -- sh -c '\"$P\" probe reach --try 192.0.2.2:9602/udp >/dev/null; sleep 3; echo fin\"\"ished' 3> >(cat >\"$events\")\n"
        ));
        let during = t.expect("finished");
        let at_end = t.expect("$ ");
        let case = format!("{mode}{flag}: {during:?} {at_end:?}");
        assert_eq!(
            during.contains("playpen: dropped: 192.0.2.2 udp port 9602 (not approved)"),
            live,
            "{case}"
        );
        assert_eq!(during.contains("playpen: dropped:"), live, "{case}");
        assert!(!at_end.contains("playpen: dropped:"), "{case}");
        assert!(at_end.contains("WARNING: 1 packet(s)"), "{case}");
        assert_eq!(t.status(), "0", "{case}");
        t.expect("$ ");
        t.send("sleep 0.3; echo \"den\"\"ied=$(grep -c '\"event\":\"denied\"' \"$events\")\"\n");
        t.expect("denied=");
        assert_eq!(t.expect("\n").trim(), "1", "{case}");
        t.expect("$ ");
    }
    t.send("rm -f \"$events\"\n");
    t.expect("$ ");
}

#[test]
fn without_live_drops_an_attached_terminal_sees_no_new_lines() {
    require_pty!(t);
    live_lines_only_when_asked(&mut t, "");
}

#[test]
fn without_live_drops_a_private_terminal_sees_no_new_lines() {
    require_pty!(t);
    live_lines_only_when_asked(&mut t, " --private-tty");
}
