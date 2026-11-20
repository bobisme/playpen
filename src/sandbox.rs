//! The namespace mechanism: build the sandbox, run the command in it, tear
//! it down and read the drop counters.
//!
//! Process tree (each arrow is a `fork`):
//!
//! ```text
//! playpen (P, host namespaces)
//!  └─ C   new user + network namespace, mapped root inside; loads the
//!     │   ruleset, later reads the counters. Never runs user code.
//!     └─ S   unshares a PID namespace, waits for its init.
//!        └─ I   PID 1 of the new PID namespace, in a private mount
//!           │   namespace: mounts /proc, the resolver files, hides host
//!           │   daemon sockets; forwards signals, reaps orphans.
//!           └─ X   nested user namespace mapped back to the caller's own
//!                  uid/gid, no capabilities, no_new_privs; execs the command.
//! ```
//!
//! `pasta` is started by P after C reports the ruleset is loaded and
//! verified, and attaches to C's namespaces. Until that moment the network
//! namespace has nothing but `lo`, so there is no window in which traffic
//! could leave unfiltered.
//!
//! Children report to P over one pipe with one line per event; P talks to C
//! over another pipe (the byte `g` means "go", end of file means "abort").
//! After "go" the same pipe reaches I: `f` asks it to freeze (SIGSTOP)
//! every process in the sandbox, `t` to thaw the ones it froze. P sends
//! them when it is suspended (Ctrl-Z) and continued, so the command never
//! runs while P, which enforces the end time and re-reads the pass, is
//! stopped. The signals P passes on to the command travel on this pipe
//! too, one byte each (see [`signal_byte`]): I is in P's process group, so
//! a signal sent to the group, or to every playpen process, reaches I as
//! well, and I could not tell that copy from one P sent it with `kill`.
//! P also sends `b` every second. When I hears nothing from P for
//! [`SILENCE_LIMIT`] (P was stopped with SIGSTOP, which it cannot catch,
//! or is stuck), I freezes the sandbox by itself until P is heard again.

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::mount::{MsFlags, mount};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sched::{CloneFlags, unshare};
use nix::sys::prctl;
use nix::sys::signal::{SigSet, SigmaskHow, Signal, kill, sigprocmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Gid, Pid, Uid, getgid, getpid, getppid, getuid, pipe2, read};

use crate::approval::Approval;
use crate::pass::{PassWatch, Recheck};
use crate::resolver::{self, HostEntry};
use crate::ruleset::{self, DropSummary};

/// How long the command gets between SIGTERM and SIGKILL when the approval
/// ends.
pub const GRACE: Duration = Duration::from_secs(3);

/// Signals P and I pass on to the command.
const FORWARDED: [Signal; 7] = [
    Signal::SIGINT,
    Signal::SIGTERM,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGUSR1,
    Signal::SIGUSR2,
    Signal::SIGWINCH,
];

/// `si_code` of signals the kernel generated itself, for example a terminal's
/// Ctrl-C. Those already reach every process in the foreground process
/// group, the command included, so they are not forwarded a second time.
const SI_KERNEL: i32 = 0x80;

/// Everything the sandbox needs to know. Built and checked by the CLI.
#[derive(Debug, Clone)]
pub struct Plan {
    /// What is approved.
    pub approval: Approval,
    /// `--host` entries.
    pub hosts: Vec<HostEntry>,
    /// Whether to attach pasta (false for `--no-network`).
    pub network: bool,
    /// Addresses to add to `lo` before the ruleset loads (test aid).
    pub lo_addrs: Vec<IpAddr>,
    /// Extra paths to hide from the command (`--hide`).
    pub hide: Vec<PathBuf>,
    /// Host paths brought back in deliberately (`--expose`, `--display`):
    /// bound into place over the mount layer and let through Landlock.
    /// Canonical, existing paths.
    pub exposed: Vec<PathBuf>,
    /// Refuse connections to host Unix sockets with Landlock (false for
    /// `--without-landlock`, which also walks `/run`, `/tmp` and `/var/tmp`
    /// for sockets to cover).
    pub landlock: bool,
    /// Run the command in a new session without a controlling terminal
    /// (`--new-session`, or automatically where `TIOCSTI` is allowed), so
    /// it cannot push input into the caller's terminal.
    pub new_session: bool,
    /// The command and its arguments.
    pub command: Vec<OsString>,
    /// The `nft` binary.
    pub nft: PathBuf,
    /// The `pasta` binary.
    pub pasta: PathBuf,
    /// With `--pass`: the pass file to re-read while the command runs. A
    /// re-read can stop the run, never change the rules.
    pub watch: Option<PassWatch>,
}

/// How the command ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandStatus {
    /// Exited with this code.
    Exited(i32),
    /// Killed by this signal number.
    Signaled(i32),
}

/// The result of a run in which the command was started.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// How the command ended.
    pub status: CommandStatus,
    /// True when playpen stopped the command because the approval ended.
    pub stopped_by_until: bool,
    /// Why playpen stopped the command after re-reading the pass, if it did.
    pub stopped_by_pass: Option<String>,
    /// The drop counters, or why they could not be read.
    pub drops: Result<DropSummary, String>,
}

/// Why the command did not run, or what went wrong after it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// The sandbox could not be built; the command was never started.
    NotStarted(String),
    /// Something failed after the command had started.
    Failed(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStarted(m) => write!(f, "{m}; nothing was run"),
            Self::Failed(m) => f.write_str(m),
        }
    }
}

/// Things P reports while the command runs.
pub trait Events {
    /// The sandbox is ready and the command is about to start.
    fn starting(&mut self);
    /// The approval ended; the command is being stopped.
    fn until_reached(&mut self);
    /// A re-read of the pass found an edit that changes nothing in use.
    fn pass_edited(&mut self, message: &str);
    /// A re-read of the pass withdrew the approval; the command is being
    /// stopped for this reason.
    fn pass_withdrawn(&mut self, reason: &str);
}

/// Number of threads in this process, from `/proc/self/status`.
///
/// # Errors
/// When the file cannot be read.
pub fn thread_count() -> Result<u32, String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("cannot read /proc/self/status: {e}"))?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Threads:"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| "no Threads: line in /proc/self/status".to_owned())
}

/// Marks every inherited descriptor above stderr close-on-exec, so the
/// command gets stdin, stdout and stderr and nothing else (an inherited
/// socket could belong to the host's network namespace).
fn cloexec_inherited_fds() -> Result<(), String> {
    let entries =
        fs::read_dir("/proc/self/fd").map_err(|e| format!("cannot list /proc/self/fd: {e}"))?;
    let fds: Vec<i32> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
        .filter(|&fd| fd > 2)
        .collect();
    for fd in fds {
        // SAFETY: `fd` came from /proc/self/fd a moment ago; nothing in this
        // single-threaded process closes descriptors in between, and we only
        // set a flag on it through a borrowed handle that does not outlive
        // this statement. The directory handle used for the listing is
        // already closed; if `fd` was that one, fcntl fails with EBADF, which
        // we ignore.
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
        let _ = fcntl(borrowed, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC));
    }
    Ok(())
}

fn write_line(fd: &OwnedFd, line: &str) {
    let mut bytes = line.replace('\n', " ").into_bytes();
    bytes.push(b'\n');
    let mut rest = &bytes[..];
    while !rest.is_empty() {
        match nix::unistd::write(fd, rest) {
            Ok(n) => rest = &rest[n..],
            Err(Errno::EINTR) => {}
            Err(_) => return,
        }
    }
}

fn send_byte(fd: &OwnedFd, b: u8) {
    loop {
        match nix::unistd::write(fd, &[b]) {
            Err(Errno::EINTR) => {}
            _ => return,
        }
    }
}

fn write_file(path: &str, contents: &str) -> Result<(), String> {
    fs::write(path, contents).map_err(|e| format!("cannot write {path}: {e}"))
}

fn exit_now(code: i32) -> ! {
    std::process::exit(code)
}

/// Forks. The caller must be single-threaded.
fn fork_checked() -> Result<ForkResult, String> {
    // SAFETY: playpen never starts threads, and P checks that the process
    // is single-threaded before the first fork (`run` refuses otherwise),
    // so every process in the tree is single-threaded when it forks. In a
    // single-threaded process there is no lock another thread could hold
    // across the fork, so the child may allocate and run ordinary Rust code.
    unsafe { nix::unistd::fork() }.map_err(|e| format!("fork failed: {e}"))
}

/// Signals P, C, S and I block and read from a signalfd (I) or leave
/// pending (C, S). Job-control signals are included so that only the
/// command can be stopped by the terminal: P handles SIGTSTP itself (see
/// the module comment), and never stops for terminal input or output.
fn blocked_set() -> SigSet {
    let mut set = SigSet::empty();
    for s in FORWARDED {
        set.add(s);
    }
    for s in [
        Signal::SIGCHLD,
        Signal::SIGTSTP,
        Signal::SIGCONT,
        Signal::SIGTTIN,
        Signal::SIGTTOU,
    ] {
        set.add(s);
    }
    set
}

/// Refuses standard input, output or error that is a socket through which
/// the command could reach the network outside the filter.
///
/// They come from the caller, so they belong to the host's network
/// namespace. Allowed: anything that is not a socket; Unix sockets (a connection or
/// send to another one is refused by Landlock); connected TCP (it reaches
/// only its peer, which the caller chose). Refused: datagram sockets (UDP
/// can send to any address even when connected), unconnected or listening
/// stream sockets, and every other address family.
///
/// # Errors
/// With a message saying which descriptor and what to do.
pub fn check_stdio() -> Result<(), String> {
    use nix::sys::socket::{SockaddrLike as _, SockaddrStorage, getpeername, getsockname};
    use nix::sys::socket::{getsockopt, sockopt};
    use std::os::fd::AsRawFd as _;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let fds = [
        ("standard input", stdin.as_fd()),
        ("standard output", stdout.as_fd()),
        ("standard error", stderr.as_fd()),
    ];
    for (name, fd) in fds {
        let Ok(st) = nix::sys::stat::fstat(fd) else {
            continue;
        };
        if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
            continue;
        }
        let raw = fd.as_raw_fd();
        let family = getsockname::<SockaddrStorage>(raw)
            .ok()
            .and_then(|a| a.family());
        let what = match family {
            Some(AddressFamily::Unix) => continue,
            Some(AddressFamily::Inet | AddressFamily::Inet6) => {
                let ty = getsockopt(&fd, sockopt::SockType).ok();
                let listening = getsockopt(&fd, sockopt::AcceptConn).unwrap_or(true);
                let connected = getpeername::<SockaddrStorage>(raw).is_ok();
                match ty {
                    Some(SockType::Stream) if connected && !listening => continue,
                    Some(SockType::Stream) if listening => {
                        "a listening TCP socket, through which anyone could connect to the command"
                    }
                    Some(SockType::Stream) => {
                        "an unconnected TCP socket, which the command could connect to any address"
                    }
                    _ => {
                        "a datagram or raw IP socket, through which the command could send to any address"
                    }
                }
            }
            _ => "a socket of a kind playpen does not let through (not Unix, not TCP)",
        };
        return Err(format!(
            "{name} is {what}, outside the filter: it belongs to the host's network. Give the command a pipe, a file or a terminal instead (for example add `| cat`)"
        ));
    }
    Ok(())
}

/// Byte P sends I: stop every process in the sandbox.
const FREEZE: u8 = b'f';
/// Byte P sends I: continue the processes it stopped.
const THAW: u8 = b't';
/// Byte P sends C: build the PID namespace and start the command.
const GO: u8 = b'g';
/// Byte P sends I every [`BEAT_INTERVAL`] while the command runs: P is
/// running, so the end time and the pass are being watched.
const BEAT: u8 = b'b';

/// How often P tells I that it is running.
const BEAT_INTERVAL: Duration = Duration::from_secs(1);

/// How long I lets the command run without a sign of P before it freezes
/// the sandbox.
///
/// P is silent when it is stopped (SIGSTOP cannot be caught,
/// so P cannot ask for the freeze as it does for Ctrl-Z) or stuck; nothing
/// then enforces the end time or re-reads the pass. Several intervals, so
/// a busy machine does not freeze the command by mistake.
pub const SILENCE_LIMIT: Duration = Duration::from_secs(5);

/// The byte P sends I to have it pass `sig` on to the command: 1 to 7, the
/// signal's place in [`FORWARDED`]. `None` for any other signal.
fn signal_byte(sig: Signal) -> Option<u8> {
    let at = FORWARDED.iter().position(|s| *s == sig)?;
    u8::try_from(at + 1).ok()
}

/// The signal a byte from P stands for, if it is one of [`signal_byte`]'s.
fn byte_signal(byte: u8) -> Option<Signal> {
    FORWARDED.get(usize::from(byte).checked_sub(1)?).copied()
}

/// P asks I to pass `sig` on to the command.
fn pass_on(down_w: &OwnedFd, sig: Signal) {
    if let Some(b) = signal_byte(sig) {
        send_byte(down_w, b);
    }
}

/// True when this kernel lets an unprivileged process push input into its
/// controlling terminal with `TIOCSTI`.
///
/// That is when `dev.tty.legacy_tiocsti` is not 0, or the setting does not
/// exist because the kernel predates it.
#[must_use]
pub fn tiocsti_allowed() -> bool {
    fs::read_to_string("/proc/sys/dev/tty/legacy_tiocsti").map_or(true, |v| v.trim() != "0")
}

/// Runs the plan. Returns when the command and the sandbox are gone.
///
/// # Errors
/// [`RunError::NotStarted`] when anything fails before the command starts
/// (the message says why, and, where `AppArmor` restricts user namespaces,
/// what the operator can do about it); [`RunError::Failed`] for trouble
/// afterwards.
pub fn run(plan: &Plan, events: &mut dyn Events) -> Result<RunResult, RunError> {
    run_sandbox(plan, events).map_err(|e| match e {
        RunError::NotStarted(m) => {
            RunError::NotStarted(with_apparmor_hint(m, apparmor_restricts()))
        }
        other @ RunError::Failed(_) => other,
    })
}

/// True when `kernel.apparmor_restrict_unprivileged_userns` is 1.
#[must_use]
pub fn apparmor_restricts() -> bool {
    fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .is_ok_and(|v| v.trim() == "1")
}

/// Adds what to do on systems where `AppArmor` restricts unprivileged user
/// namespaces.
///
/// There the namespace is created but holds no capabilities, so the first
/// privileged step inside fails with a bare "permission denied".
#[must_use]
pub fn with_apparmor_hint(message: String, restricted: bool) -> String {
    if !restricted {
        return message;
    }
    format!(
        "{message}. This system restricts unprivileged user namespaces with AppArmor (kernel.apparmor_restrict_unprivileged_userns = 1), which is the likely cause. An administrator can allow playpen with an AppArmor profile for its binary that grants `userns,` (an example is in docs/DESIGN.md, section \"AppArmor\"), or set kernel.apparmor_restrict_unprivileged_userns to 0 for the whole machine; `playpen doctor` shows the setting"
    )
}

fn run_sandbox(plan: &Plan, events: &mut dyn Events) -> Result<RunResult, RunError> {
    let not_started = RunError::NotStarted;
    match thread_count() {
        Ok(1) => {}
        Ok(n) => {
            return Err(not_started(format!(
                "playpen must be single-threaded to create a user namespace, but has {n} threads"
            )));
        }
        Err(e) => return Err(not_started(e)),
    }
    if getuid().is_root() {
        return Err(not_started(
            "playpen is meant to run as an ordinary user, not root; run it without sudo".to_owned(),
        ));
    }
    if plan.landlock && !crate::landlock::resolve_unix_supported() {
        return Err(not_started(landlock_missing()));
    }
    cloexec_inherited_fds().map_err(not_started)?;
    let mask = blocked_set();
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&mask), None)
        .map_err(|e| not_started(format!("cannot block signals: {e}")))?;
    let sigfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .map_err(|e| not_started(format!("cannot create signalfd: {e}")))?;
    let (up_r, up_w) = pipe2(OFlag::O_CLOEXEC).map_err(|e| not_started(format!("pipe: {e}")))?;
    let (down_r, down_w) =
        pipe2(OFlag::O_CLOEXEC).map_err(|e| not_started(format!("pipe: {e}")))?;
    let ids = Ids {
        uid: getuid(),
        gid: getgid(),
        parent: getpid(),
    };
    let ruleset_text = ruleset::render(&plan.approval.rules);
    let files = SandboxFiles::build(plan);

    match fork_checked().map_err(not_started)? {
        ForkResult::Child => {
            drop(up_r);
            drop(down_w);
            drop(sigfd);
            let code = match stage_c(plan, &ids, &ruleset_text, &files, &up_w, &down_r) {
                Ok(()) => 0,
                Err(msg) => {
                    write_line(&up_w, &format!("fail {msg}"));
                    1
                }
            };
            exit_now(code);
        }
        ForkResult::Parent { child } => {
            drop(up_w);
            drop(down_r);
            parent(plan, child, &sigfd, &up_r, down_w, events)
        }
    }
}

/// Why the run cannot start when Landlock cannot refuse Unix socket
/// connections.
#[must_use]
pub fn landlock_missing() -> String {
    let have = crate::landlock::abi().map_or_else(
        || "Landlock is not enabled in this kernel".to_owned(),
        |v| format!("this kernel has Landlock ABI {v}"),
    );
    format!(
        "playpen needs Landlock ABI {} or later to keep the command away from host Unix sockets (a host daemon reached through one can open connections for it), and {have}. Use a newer kernel (with landlock in its lsm= list), or run with --without-landlock to rely on hiding by mounts only: sockets under /run, /tmp, /var/tmp and the runtime directory are then hidden, sockets elsewhere (for example in the home directory) stay reachable",
        crate::landlock::RESOLVE_UNIX_ABI
    )
}

struct Ids {
    uid: Uid,
    gid: Gid,
    parent: Pid,
}

/// Generated contents bound over host files inside the sandbox.
#[derive(Debug, Clone)]
struct SandboxFiles {
    hosts: String,
    resolv: String,
    nsswitch: Option<String>,
    /// Directories replaced by fresh private ones.
    covers: Vec<crate::sockets::Cover>,
    /// `--hide`.
    hide: Vec<PathBuf>,
    /// `--expose` and `--display`.
    exposed: Vec<PathBuf>,
    /// Walk `/run`, `/tmp` and `/var/tmp` and cover every socket found
    /// (`--without-landlock`).
    walk: bool,
}

impl SandboxFiles {
    fn build(plan: &Plan) -> Self {
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|h| h.trim().to_owned());
        let nsswitch = fs::read_to_string("/etc/nsswitch.conf")
            .ok()
            .map(|t| resolver::nsswitch_conf(&t));
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        Self {
            hosts: resolver::hosts_file(&plan.hosts, hostname.as_deref()),
            resolv: resolver::resolv_conf(),
            nsswitch,
            covers: crate::sockets::covers(getuid(), runtime_dir.as_deref()),
            hide: plan.hide.clone(),
            exposed: plan.exposed.clone(),
            walk: !plan.landlock,
        }
    }
}

// ---------------------------------------------------------------- P ----

struct ParentState {
    buf: Vec<u8>,
    failure: Option<String>,
    init: Option<Pid>,
    started: bool,
    status: Option<CommandStatus>,
    drops: Option<Result<DropSummary, String>>,
    ready: bool,
    eof: bool,
}

impl ParentState {
    fn handle_line(&mut self, line: &str) {
        let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
        match word {
            "ready" => self.ready = true,
            "fail" => {
                if self.failure.is_none() {
                    self.failure = Some(rest.to_owned());
                }
            }
            "init" => self.init = rest.parse::<i32>().ok().map(Pid::from_raw),
            "started" => self.started = true,
            "exit" => self.status = rest.parse().ok().map(CommandStatus::Exited),
            "signal" => self.status = rest.parse().ok().map(CommandStatus::Signaled),
            "drops" => {
                self.drops = Some(
                    serde_json::from_str::<DropSummaryWire>(rest)
                        .map(DropSummaryWire::into_summary)
                        .map_err(|e| format!("bad counter report: {e}")),
                );
            }
            "dropserr" => self.drops = Some(Err(rest.to_owned())),
            _ => {}
        }
    }

    /// Reads what is available on `fd` and handles complete lines.
    fn pump(&mut self, fd: &OwnedFd) {
        let mut chunk = [0u8; 8192];
        match read(fd, &mut chunk) {
            Ok(0) => self.eof = true,
            Ok(n) => {
                self.buf.extend_from_slice(&chunk[..n]);
                while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                    let line: Vec<u8> = self.buf.drain(..=pos).collect();
                    let text = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
                    self.handle_line(&text);
                }
            }
            Err(Errno::EINTR | Errno::EAGAIN) => {}
            Err(_) => self.eof = true,
        }
    }
}

/// The JSON form of [`DropSummary`] passed from C to P.
#[derive(serde::Deserialize)]
struct DropSummaryWire {
    packets: u64,
    destinations: Vec<DroppedWire>,
    destinations_truncated: bool,
}

#[derive(serde::Deserialize)]
struct DroppedWire {
    address: String,
    protocol: String,
    port: Option<u16>,
    packets: u64,
}

impl DropSummaryWire {
    fn into_summary(self) -> DropSummary {
        DropSummary {
            packets: self.packets,
            destinations_truncated: self.destinations_truncated,
            destinations: self
                .destinations
                .into_iter()
                .map(|d| ruleset::DroppedDest {
                    address: d.address,
                    protocol: d.protocol,
                    port: d.port,
                    packets: d.packets,
                })
                .collect(),
        }
    }
}

/// Waits until `fd` has data or `deadline` passes. Returns false on timeout.
fn wait_readable(fd: &OwnedFd, deadline: Instant) -> bool {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        let ms = u16::try_from(left.as_millis().min(10_000)).unwrap_or(10_000);
        let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(ms.max(1))) {
            Ok(0) | Err(Errno::EINTR) => {}
            Ok(_) | Err(_) => return true,
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one event loop; splitting it would scatter its state"
)]
fn parent(
    plan: &Plan,
    child: Pid,
    sigfd: &SignalFd,
    up_r: &OwnedFd,
    down_w: OwnedFd,
    events: &mut dyn Events,
) -> Result<RunResult, RunError> {
    let mut st = ParentState {
        buf: Vec::new(),
        failure: None,
        init: None,
        started: false,
        status: None,
        drops: None,
        ready: false,
        eof: false,
    };
    // Phase 1: C builds the namespaces and loads the ruleset.
    let setup_deadline = Instant::now() + Duration::from_secs(30);
    while !st.ready && st.failure.is_none() && !st.eof {
        if !wait_readable(up_r, setup_deadline) {
            st.failure = Some("the namespace setup did not finish within 30 seconds".into());
            break;
        }
        st.pump(up_r);
    }
    if !st.ready {
        let _ = kill(child, Signal::SIGKILL);
        let _ = waitpid(child, None);
        let why = st
            .failure
            .unwrap_or_else(|| "the namespace setup ended without saying why".into());
        return Err(RunError::NotStarted(why));
    }

    // Phase 2: connectivity.
    let mut pasta = None;
    if plan.network {
        match crate::pasta::start(&plan.pasta, child) {
            Ok(p) => pasta = Some(p),
            Err(e) => {
                drop(down_w);
                let _ = waitpid(child, None);
                return Err(RunError::NotStarted(e));
            }
        }
    }
    let wall_deadline = plan.approval.ends_at.map(|end| {
        let left = end.at() - time::OffsetDateTime::now_utc();
        Instant::now() + left.try_into().unwrap_or(Duration::ZERO)
    });
    let mut watch = plan.watch.clone();
    let mut withdrawn = None;
    if let Some(d) = wall_deadline
        && d <= Instant::now()
    {
        withdrawn = Some("the approval ended while the sandbox was being built".to_owned());
    } else if let Some(w) = watch.as_mut() {
        match w.recheck(time::OffsetDateTime::now_utc()) {
            Recheck::Unchanged => {}
            Recheck::Edited(m) => events.pass_edited(&m),
            Recheck::Stop(why) => {
                withdrawn = Some(format!("while the sandbox was being built, {why}"));
            }
        }
    }
    if let Some(why) = withdrawn {
        drop(down_w);
        let _ = waitpid(child, None);
        if let Some(p) = pasta {
            p.stop();
        }
        return Err(RunError::NotStarted(why));
    }
    events.starting();
    send_byte(&down_w, GO);

    // Phase 3: the command runs.
    let mut term_sent_at: Option<Instant> = None;
    let mut killed = false;
    let mut stopped_by_pass: Option<String> = None;
    let mut next_recheck = watch.as_ref().map(|w| Instant::now() + w.interval);
    let mut next_beat = Instant::now();
    while !st.eof {
        let now = Instant::now();
        // Tell I that P is running and looking at the clock and the pass.
        if now >= next_beat {
            send_byte(&down_w, BEAT);
            next_beat = now + BEAT_INTERVAL;
        }
        let mut wake = next_beat;
        if let (Some(w), Some(due)) = (watch.as_mut(), next_recheck)
            && term_sent_at.is_none()
        {
            if now >= due {
                match w.recheck(time::OffsetDateTime::now_utc()) {
                    Recheck::Unchanged => {}
                    Recheck::Edited(m) => events.pass_edited(&m),
                    Recheck::Stop(why) => {
                        events.pass_withdrawn(&why);
                        stopped_by_pass = Some(why);
                        term_sent_at = Some(now);
                        stop_command(st.init, child, &down_w);
                    }
                }
                next_recheck = Some(Instant::now() + w.interval);
            }
            if let Some(due) = next_recheck {
                wake = wake.min(due);
            }
        }
        if let Some(d) = wall_deadline
            && term_sent_at.is_none()
        {
            if now >= d {
                events.until_reached();
                term_sent_at = Some(now);
                stop_command(st.init, child, &down_w);
            } else {
                wake = wake.min(d);
            }
        }
        if let Some(t) = term_sent_at
            && !killed
        {
            if now >= t + GRACE {
                killed = true;
                let _ = kill(st.init.unwrap_or(child), Signal::SIGKILL);
            } else {
                wake = wake.min(t + GRACE);
            }
        }
        let ms = u16::try_from(
            wake.saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, 10_000),
        )
        .unwrap_or(10_000);
        let mut fds = [
            PollFd::new(up_r.as_fd(), PollFlags::POLLIN),
            PollFd::new(sigfd.as_fd(), PollFlags::POLLIN),
        ];
        match poll(&mut fds, PollTimeout::from(ms)) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => {
                return Err(RunError::Failed(format!("poll failed: {e}")));
            }
        }
        let up_ready = fds[0].revents().is_some_and(|r| !r.is_empty());
        let sig_ready = fds[1].revents().is_some_and(|r| !r.is_empty());
        if up_ready {
            st.pump(up_r);
        }
        if sig_ready {
            while let Ok(Some(info)) = sigfd.read_signal() {
                let Ok(sig) = Signal::try_from(i32::try_from(info.ssi_signo).unwrap_or(0)) else {
                    continue;
                };
                match sig {
                    Signal::SIGCHLD | Signal::SIGTTIN | Signal::SIGTTOU => {}
                    // Signals are read only after "go"; I reads the bytes
                    // once its loop runs, even if they come before that.
                    Signal::SIGTSTP => suspend(&down_w),
                    Signal::SIGCONT => send_byte(&down_w, THAW),
                    // The terminal sent it to its foreground process group,
                    // which holds the command, or, in a new session, I
                    // (which passes it on).
                    _ if info.ssi_code == SI_KERNEL => {}
                    _ => pass_on(&down_w, sig),
                }
            }
        }
    }
    drop(down_w);
    let _ = waitpid(child, None);
    if let Some(p) = pasta {
        p.stop();
    }
    if !st.started {
        let why = st
            .failure
            .unwrap_or_else(|| "the sandbox ended before the command started".into());
        return Err(RunError::NotStarted(why));
    }
    let status = match st.status {
        Some(s) => s,
        None if killed => CommandStatus::Signaled(Signal::SIGKILL as i32),
        None => {
            return Err(RunError::Failed(
                "the sandbox ended without reporting the command's exit status".into(),
            ));
        }
    };
    Ok(RunResult {
        status,
        stopped_by_until: term_sent_at.is_some() && stopped_by_pass.is_none(),
        stopped_by_pass,
        drops: st
            .drops
            .unwrap_or_else(|| Err("the drop counters were not reported".into())),
    })
}

/// Ctrl-Z (or SIGTSTP from anyone): have I stop every process in the
/// sandbox, then stop P itself, so the shell sees playpen as stopped. When
/// P is continued, it reads SIGCONT and has I continue them.
fn suspend(down_w: &OwnedFd) {
    send_byte(down_w, FREEZE);
    let _ = kill(getpid(), Signal::SIGSTOP);
}

/// First step of stopping the command: ask the sandbox's init to pass
/// SIGTERM on to it; SIGKILL to C if there is no init yet.
fn stop_command(init: Option<Pid>, child: Pid, down_w: &OwnedFd) {
    if init.is_some() {
        pass_on(down_w, Signal::SIGTERM);
    } else {
        let _ = kill(child, Signal::SIGKILL);
    }
}

// ---------------------------------------------------------------- C ----

fn die_with_parent(parent: Pid) -> Result<(), String> {
    prctl::set_pdeathsig(Signal::SIGKILL).map_err(|e| format!("PR_SET_PDEATHSIG: {e}"))?;
    if getppid() != parent {
        return Err("playpen exited during setup".into());
    }
    Ok(())
}

fn stage_c(
    plan: &Plan,
    ids: &Ids,
    ruleset_text: &str,
    files: &SandboxFiles,
    up_w: &OwnedFd,
    down_r: &OwnedFd,
) -> Result<(), String> {
    die_with_parent(ids.parent)?;
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET).map_err(|e| {
        format!(
            "cannot create a user and network namespace ({e}); run `playpen doctor` to see what is missing"
        )
    })?;
    write_file("/proc/self/setgroups", "deny")?;
    write_file("/proc/self/uid_map", &format!("0 {} 1", ids.uid))?;
    write_file("/proc/self/gid_map", &format!("0 {} 1", ids.gid))?;
    crate::netlink::set_link_up(crate::netlink::LO_INDEX)
        .map_err(|e| format!("cannot bring lo up inside the namespace: {e}"))?;
    for addr in &plan.lo_addrs {
        crate::netlink::add_address(crate::netlink::LO_INDEX, *addr)
            .map_err(|e| format!("cannot add {addr} to lo: {e}"))?;
    }
    load_ruleset(&plan.nft, ruleset_text)?;
    verify_ruleset(&plan.nft, plan.approval.rules.len())?;
    write_line(up_w, "ready");

    let mut go = [0u8; 1];
    match read(down_r, &mut go) {
        Ok(1) if go[0] == GO => {}
        _ => exit_now(0),
    }
    // This process holds every capability over the network namespace. It
    // stayed dumpable only so pasta (same user, outside) could open its
    // /proc/PID/ns entries; pasta is attached now and no command exists
    // yet. From here on nothing running as the same user may ptrace it or
    // open its /proc entries, and every child inherits that.
    prctl::set_dumpable(false).map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;

    match fork_checked()? {
        ForkResult::Child => {
            let code = match stage_s(plan, files, up_w, down_r) {
                Ok(()) => 0,
                Err(msg) => {
                    write_line(up_w, &format!("fail {msg}"));
                    1
                }
            };
            exit_now(code);
        }
        ForkResult::Parent { child } => {
            let _ = waitpid(child, None);
        }
    }
    match read_counters(&plan.nft) {
        Ok(summary) => {
            let json = serde_json::to_string(&summary).unwrap_or_default();
            write_line(up_w, &format!("drops {json}"));
        }
        Err(e) => write_line(up_w, &format!("dropserr {e}")),
    }
    Ok(())
}

fn nft_command(nft: &Path) -> Command {
    let mut cmd = Command::new(nft);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn load_ruleset(nft: &Path, text: &str) -> Result<(), String> {
    let mut child = nft_command(nft)
        .args(["-f", "-"])
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", nft.display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(text.as_bytes())
            .map_err(|e| format!("cannot send the ruleset to nft: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("nft did not finish: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "nft refused the ruleset ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

fn list_table(nft: &Path) -> Result<String, String> {
    let out = nft_command(nft)
        .stdin(Stdio::null())
        .args(["--json", "list", "table", "inet", ruleset::TABLE])
        .output()
        .map_err(|e| format!("cannot run {}: {e}", nft.display()))?;
    if !out.status.success() {
        return Err(format!(
            "nft could not list the table ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|_| "nft printed non-UTF-8 output".into())
}

fn verify_ruleset(nft: &Path, allow_count: usize) -> Result<(), String> {
    let json = list_table(nft).map_err(|e| format!("cannot verify the ruleset: {e}"))?;
    ruleset::verify_loaded(&json, allow_count)
        .map_err(|e| format!("the loaded ruleset is not the one playpen built: {e}"))
}

fn read_counters(nft: &Path) -> Result<DropSummary, String> {
    let json = list_table(nft)?;
    ruleset::parse_counters(&json)
}

// ---------------------------------------------------------------- S ----

fn stage_s(
    plan: &Plan,
    files: &SandboxFiles,
    up_w: &OwnedFd,
    down_r: &OwnedFd,
) -> Result<(), String> {
    prctl::set_pdeathsig(Signal::SIGKILL).map_err(|e| format!("PR_SET_PDEATHSIG: {e}"))?;
    unshare(CloneFlags::CLONE_NEWPID).map_err(|e| format!("cannot create a PID namespace: {e}"))?;
    match fork_checked()? {
        ForkResult::Child => {
            let code = match stage_i(plan, files, up_w, down_r) {
                Ok(code) => code,
                Err(msg) => {
                    write_line(up_w, &format!("fail {msg}"));
                    1
                }
            };
            exit_now(code);
        }
        ForkResult::Parent { child } => {
            write_line(up_w, &format!("init {child}"));
            let _ = waitpid(child, None);
            Ok(())
        }
    }
}

// ---------------------------------------------------------------- I ----

fn stage_i(
    plan: &Plan,
    files: &SandboxFiles,
    up_w: &OwnedFd,
    down_r: &OwnedFd,
) -> Result<i32, String> {
    prctl::set_pdeathsig(Signal::SIGKILL).map_err(|e| format!("PR_SET_PDEATHSIG: {e}"))?;
    // A private IPC namespace: System V shared memory, semaphores and
    // message queues, and POSIX message queues, of host processes are not
    // reachable from inside.
    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWIPC)
        .map_err(|e| format!("cannot create a mount and IPC namespace: {e}"))?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| format!("cannot make mounts private: {e}"))?;
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| format!("cannot mount /proc for the new PID namespace: {e}"))?;
    setup_files(plan, files)?;

    let (err_r, err_w) = pipe2(OFlag::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
    let sigfd = SignalFd::with_flags(
        &blocked_set(),
        SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK,
    )
    .map_err(|e| format!("cannot create signalfd: {e}"))?;
    let child = match fork_checked()? {
        ForkResult::Child => {
            drop(err_r);
            drop(sigfd);
            let msg = match stage_x(plan) {
                Ok(never) => match never {},
                Err(msg) => msg,
            };
            write_line(&err_w, &msg);
            exit_now(127);
        }
        ForkResult::Parent { child } => child,
    };
    drop(err_w);
    let mut msg = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match read(&err_r, &mut chunk) {
            Ok(0) => break,
            Ok(n) => msg.extend_from_slice(&chunk[..n]),
            Err(Errno::EINTR) => {}
            Err(_) => break,
        }
    }
    if !msg.is_empty() {
        let _ = waitpid(child, None);
        return Err(String::from_utf8_lossy(&msg).trim().to_owned());
    }
    write_line(up_w, "started");
    // In its own session the command leads its own process group, and
    // the terminal no longer signals it: send what P passes on to the whole
    // group, as the terminal would.
    let target = if plan.new_session {
        Pid::from_raw(-child.as_raw())
    } else {
        child
    };
    init_loop(child, target, plan.new_session, &sigfd, up_w, down_r)
}

/// I's work while the command runs: pass the signals P names on to
/// `target`, freeze and thaw on P's request, reap orphans, and report how
/// the command ended.
///
/// Of the signals I receives itself, two kinds are passed on: those a
/// process inside the sandbox sent to PID 1, and, with `from_terminal`,
/// those the kernel sent (the terminal signals I's process group, no
/// longer the command's). A signal from a process outside (sent to the
/// process group, or to every playpen process) is not: P received it too
/// and passes it on through the pipe, and passing on both would deliver it
/// twice.
fn init_loop(
    child: Pid,
    target: Pid,
    from_terminal: bool,
    sigfd: &SignalFd,
    up_w: &OwnedFd,
    down_r: &OwnedFd,
) -> Result<i32, String> {
    let mut frozen: Vec<Pid> = Vec::new();
    let mut p_open = true;
    // When P was last heard, whether P asked for the freeze in force
    // (Ctrl-Z), and whether I froze the sandbox because P went silent.
    let mut heard = Instant::now();
    let mut asked = false;
    let mut silent = false;
    loop {
        let mut fds = vec![PollFd::new(sigfd.as_fd(), PollFlags::POLLIN)];
        if p_open {
            fds.push(PollFd::new(down_r.as_fd(), PollFlags::POLLIN));
        }
        // Wake when P has been silent too long; while frozen for that,
        // every interval, to stop whatever a pass of the freeze missed.
        // Not after Ctrl-Z: P asked for that freeze before it stopped.
        let watching = p_open && !asked;
        let timeout = if watching {
            let left = if silent {
                BEAT_INTERVAL
            } else {
                (heard + SILENCE_LIMIT).saturating_duration_since(Instant::now())
            };
            PollTimeout::from(u16::try_from(left.as_millis() + 1).unwrap_or(u16::MAX))
        } else {
            PollTimeout::NONE
        };
        match poll(&mut fds, timeout) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => return Err(format!("poll failed: {e}")),
        }
        let from_p = p_open && fds[1].revents().is_some_and(|r| !r.is_empty());
        drop(fds);
        if from_p {
            let mut b = [0u8; 16];
            match read(down_r, &mut b) {
                Ok(0) | Err(Errno::EBADF) => p_open = false,
                Ok(n) => {
                    // Any byte shows that P runs. The sandbox I froze for
                    // P's silence continues, unless P itself asked for a
                    // freeze that still holds.
                    heard = Instant::now();
                    if silent {
                        silent = false;
                        if !asked {
                            thaw(&mut frozen);
                        }
                    }
                    for &byte in &b[..n] {
                        match byte {
                            FREEZE => {
                                asked = true;
                                freeze(&mut frozen);
                            }
                            THAW => {
                                asked = false;
                                thaw(&mut frozen);
                            }
                            _ => {
                                if let Some(sig) = byte_signal(byte) {
                                    let _ = kill(target, sig);
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
        if p_open && !asked && heard.elapsed() >= SILENCE_LIMIT {
            if !silent {
                silent = true;
                eprintln!(
                    "playpen: playpen itself has been stopped or stuck for {} s, so nothing enforces the end time or re-reads the pass; the command is paused until playpen continues (`fg`, or `kill -CONT` its process)",
                    SILENCE_LIMIT.as_secs()
                );
            }
            freeze(&mut frozen);
        }
        let info = match sigfd.read_signal() {
            Ok(Some(info)) => info,
            Ok(None) | Err(Errno::EINTR | Errno::EAGAIN) => continue,
            Err(e) => return Err(format!("signalfd read failed: {e}")),
        };
        let Ok(sig) = Signal::try_from(i32::try_from(info.ssi_signo).unwrap_or(0)) else {
            continue;
        };
        if sig != Signal::SIGCHLD {
            // Job-control signals are P's business (freeze and thaw).
            // A sender outside this PID namespace shows as pid 0.
            let from_kernel = info.ssi_code == SI_KERNEL;
            let from_inside = !from_kernel && info.ssi_pid != 0;
            if FORWARDED.contains(&sig) && (from_inside || (from_terminal && from_kernel)) {
                let _ = kill(target, sig);
            }
            continue;
        }
        if reap(child, up_w) {
            return Ok(0);
        }
    }
}

/// Reaps every process that has ended. True when the command was among
/// them; how it ended is then reported to P.
fn reap(child: Pid, up_w: &OwnedFd) -> bool {
    loop {
        match waitpid(None::<Pid>, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, code)) if pid == child => {
                write_line(up_w, &format!("exit {code}"));
                return true;
            }
            Ok(WaitStatus::Signaled(pid, s, _)) if pid == child => {
                write_line(up_w, &format!("signal {}", s as i32));
                return true;
            }
            Ok(WaitStatus::StillAlive) | Err(_) => return false,
            Ok(_) => {}
        }
    }
}

/// The processes in this PID namespace other than init, with their state
/// letter from `/proc/PID/stat`.
fn sandbox_processes() -> Vec<(Pid, char)> {
    let Ok(dir) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    dir.filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()))
        .filter(|&pid| pid > 1)
        .filter_map(|pid| {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            // The state follows the command name, which is in parentheses
            // and may itself contain ") ".
            let state = stat.rsplit_once(") ")?.1.chars().next()?;
            Some((Pid::from_raw(pid), state))
        })
        .collect()
}

/// Stops (SIGSTOP) every process in the sandbox that is not stopped
/// already, and remembers them. Processes stopped before (for example a job
/// a shell inside suspended) are left alone, so a later thaw does not
/// resume them. Repeated until a pass finds nothing new, so a child forked
/// during the pass is caught too.
fn freeze(frozen: &mut Vec<Pid>) {
    for _ in 0..20 {
        let mut new = false;
        for (pid, state) in sandbox_processes() {
            if frozen.contains(&pid) || matches!(state, 'T' | 't' | 'Z' | 'X') {
                continue;
            }
            if kill(pid, Signal::SIGSTOP).is_ok() {
                frozen.push(pid);
                new = true;
            }
        }
        if !new {
            break;
        }
    }
}

/// Continues the processes [`freeze`] stopped.
fn thaw(frozen: &mut Vec<Pid>) {
    for pid in frozen.drain(..) {
        let _ = kill(pid, Signal::SIGCONT);
    }
}

/// Where generated files are written before they are bound into place: a
/// tmpfs mounted over `/tmp` for a moment and detached again afterwards
/// (the bind mounts keep the files alive). A memfd cannot be used: the
/// kernel refuses to bind from its internal mount.
const STAGING: &str = "/tmp";

/// Binds `contents` read-only over `target`.
fn bind_contents(target: &str, name: &str, contents: &str) -> Result<(), String> {
    let source = format!("{STAGING}/{name}");
    fs::write(&source, contents).map_err(|e| format!("cannot write {source}: {e}"))?;
    mount(
        Some(source.as_str()),
        target,
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| format!("cannot bind the generated file over {target}: {e}"))?;
    mount(
        None::<&str>,
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|e| format!("cannot make {target} read-only: {e}"))?;
    Ok(())
}

fn hide_path(path: &Path) -> Result<(), String> {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    // Follow a symlink to what it names; hide that.
    let meta = if meta.file_type().is_symlink() {
        match fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        }
    } else {
        meta
    };
    let result = if meta.is_dir() {
        mount(
            Some("tmpfs"),
            path,
            Some("tmpfs"),
            MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            Some("size=4k,mode=0555"),
        )
    } else {
        mount(
            Some("/dev/null"),
            path,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
    };
    result.map_err(|e| format!("cannot hide {} from the command: {e}", path.display()))
}

/// Mounts a fresh, empty, writable tmpfs over `cover.path` with the host
/// directory's mode, and creates its child directory if it has one.
fn cover_dir(cover: &crate::sockets::Cover) -> Result<(), String> {
    let opts = format!("mode={:o}", cover.mode);
    mount(
        Some("tmpfs"),
        &cover.path,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(opts.as_str()),
    )
    .map_err(|e| {
        format!(
            "cannot replace {} with a private directory: {e}",
            cover.path.display()
        )
    })?;
    if let Some(child) = &cover.child {
        let dir = cover.path.join(child);
        crate::sockets::mkdir_all(&dir)?;
        fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(|e| format!("cannot set the mode of {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// An exposed host path, held open from before the mount layer so it can
/// be bound back over it.
struct Held {
    path: PathBuf,
    fd: OwnedFd,
    dir: bool,
}

fn hold(path: &Path) -> Result<Held, String> {
    let fd = nix::fcntl::open(
        path,
        OFlag::O_PATH | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .map_err(|e| format!("cannot open the exposed path {}: {e}", path.display()))?;
    let dir = nix::sys::stat::fstat(&fd)
        .map(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR)
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    Ok(Held {
        path: path.to_path_buf(),
        fd,
        dir,
    })
}

/// Binds an exposed path back into place if the mount layer hid it (the
/// path no longer names the same object).
fn restore(held: &Held) -> Result<(), String> {
    use std::os::fd::AsRawFd as _;
    let orig = nix::sys::stat::fstat(&held.fd)
        .map_err(|e| format!("cannot stat {}: {e}", held.path.display()))?;
    if let Ok(now) = nix::sys::stat::stat(&held.path)
        && now.st_dev == orig.st_dev
        && now.st_ino == orig.st_ino
    {
        return Ok(());
    }
    if fs::symlink_metadata(&held.path).is_err() {
        if let Some(parent) = held.path.parent() {
            crate::sockets::mkdir_all(parent)?;
        }
        let made = if held.dir {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&held.path)
                .map_err(|e| e.to_string())
        } else {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&held.path)
                .map(drop)
                .map_err(|e| e.to_string())
        };
        made.map_err(|e| {
            format!(
                "cannot create a mount point for {}: {e}",
                held.path.display()
            )
        })?;
    }
    let source = format!("/proc/self/fd/{}", held.fd.as_raw_fd());
    mount(
        Some(source.as_str()),
        &held.path,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| format!("cannot expose {}: {e}", held.path.display()))
}

/// Finds the sockets to cover for `--without-landlock`.
fn walk_targets(files: &SandboxFiles) -> Result<Vec<PathBuf>, String> {
    let mut roots: Vec<PathBuf> = crate::sockets::WALK_ROOTS
        .iter()
        .filter_map(|r| fs::canonicalize(r).ok())
        .collect();
    roots.sort();
    roots.dedup();
    let mut skip: Vec<PathBuf> = files.covers.iter().map(|c| c.path.clone()).collect();
    skip.extend(files.exposed.iter().cloned());
    crate::sockets::find_sockets(&roots, &skip, crate::sockets::WALK_LIMIT)
}

fn setup_files(plan: &Plan, files: &SandboxFiles) -> Result<(), String> {
    // Everything that must be looked at in the host's view of the tree is
    // done first, before any of the mounts below change it.
    let held: Vec<Held> = files
        .exposed
        .iter()
        .map(|p| hold(p))
        .collect::<Result<_, _>>()?;
    let walked = if files.walk {
        walk_targets(files)?
    } else {
        Vec::new()
    };
    let mqueue = Path::new("/dev/mqueue").is_dir();

    stage_resolver_files(plan, files)?;
    for cover in &files.covers {
        cover_dir(cover)?;
    }
    if mqueue {
        // The fresh IPC namespace's own message queues; the host's queues
        // were reachable through the host's mqueue mount.
        mount(
            Some("mqueue"),
            "/dev/mqueue",
            Some("mqueue"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|e| format!("cannot mount a private /dev/mqueue: {e}"))?;
    }
    for sock in &walked {
        match mount(
            Some("/dev/null"),
            sock,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        ) {
            // Removed on the host since the walk: nothing left to cover.
            Ok(()) | Err(Errno::ENOENT) => {}
            Err(e) => return Err(format!("cannot cover the socket {}: {e}", sock.display())),
        }
    }
    for h in &held {
        restore(h)?;
    }
    for path in &files.hide {
        hide_path(path)?;
    }
    Ok(())
}

fn stage_resolver_files(plan: &Plan, files: &SandboxFiles) -> Result<(), String> {
    mount(
        Some("tmpfs"),
        STAGING,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("size=64k,mode=0700"),
    )
    .map_err(|e| format!("cannot mount a staging tmpfs on {STAGING}: {e}"))?;
    let result = bind_resolver_files(plan, files);
    nix::mount::umount2(STAGING, nix::mount::MntFlags::MNT_DETACH)
        .map_err(|e| format!("cannot remove the staging tmpfs from {STAGING}: {e}"))?;
    result
}

fn bind_resolver_files(plan: &Plan, files: &SandboxFiles) -> Result<(), String> {
    if Path::new("/etc/hosts").exists() {
        bind_contents("/etc/hosts", "hosts", &files.hosts)?;
    } else if !plan.hosts.is_empty() {
        return Err("--host needs /etc/hosts to exist on this system to bind over it".into());
    }
    if fs::metadata("/etc/resolv.conf").is_ok() {
        bind_contents("/etc/resolv.conf", "resolv.conf", &files.resolv)?;
    }
    if let Some(ns) = &files.nsswitch {
        bind_contents("/etc/nsswitch.conf", "nsswitch.conf", ns)?;
    }
    Ok(())
}

// ---------------------------------------------------------------- X ----

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

fn clear_capabilities() -> Result<(), String> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capset(2) reads one header and, for version 3, exactly two
    // data structs. Both are `repr(C)` with the kernel's layout
    // (`__user_cap_header_struct`, `__user_cap_data_struct`), live on the
    // stack for the whole call, and the kernel writes only to the header
    // (its version field) — which is why it is passed as a mutable pointer.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("capset: {}", Errno::last()))
    }
}

/// Checks that this process has no capabilities left and cannot open raw
/// sockets in the network namespace.
fn verify_dropped(uid: Uid, gid: Gid) -> Result<(), String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("cannot read /proc/self/status: {e}"))?;
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let value = status
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map(str::trim)
            .ok_or_else(|| format!("no {key} line in /proc/self/status"))?;
        if value.bytes().any(|b| b != b'0') {
            return Err(format!("{key} is {value}, not empty"));
        }
    }
    let nnp = status
        .lines()
        .find_map(|l| l.strip_prefix("NoNewPrivs:"))
        .map(str::trim);
    if nnp != Some("1") {
        return Err("no_new_privs is not set".into());
    }
    if getuid() != uid || getgid() != gid {
        return Err(format!(
            "running as uid {} gid {}, expected {uid} {gid}",
            getuid(),
            getgid()
        ));
    }
    for (family, ty, what) in [
        (AddressFamily::Inet, SockType::Raw, "a raw IPv4 socket"),
        (AddressFamily::Inet6, SockType::Raw, "a raw IPv6 socket"),
        (AddressFamily::Packet, SockType::Raw, "a packet socket"),
    ] {
        let proto = if family == AddressFamily::Packet {
            None
        } else {
            Some(SockProtocol::Icmp)
        };
        match socket(family, ty, SockFlag::SOCK_CLOEXEC, proto) {
            Err(Errno::EPERM | Errno::EACCES) => {}
            Ok(_) => return Err(format!("could still open {what}")),
            Err(e) => return Err(format!("opening {what} failed with {e}, expected EPERM")),
        }
    }
    if crate::netlink::set_link_up(crate::netlink::LO_INDEX) != Err(Errno::EPERM) {
        return Err("could still change interfaces through netlink".into());
    }
    Ok(())
}

fn stage_x(plan: &Plan) -> Result<std::convert::Infallible, String> {
    // Outer namespace ids of the caller: 0 inside the outer namespace maps
    // to the caller's uid/gid on the host. Read them from the outer map.
    let uid_map = fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    let gid_map = fs::read_to_string("/proc/self/gid_map").unwrap_or_default();
    let user_outer = outer_id(&uid_map).ok_or("cannot read the outer uid map")?;
    let group_outer = outer_id(&gid_map).ok_or("cannot read the outer gid map")?;
    unshare(CloneFlags::CLONE_NEWUSER)
        .map_err(|e| format!("cannot create the nested user namespace: {e}"))?;
    // Our /proc entries belong to root while non-dumpable; this process is
    // in the nested namespace now and holds nothing over the network
    // namespace, so it may be dumpable again (exec would reset it anyway).
    prctl::set_dumpable(true).map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    write_file("/proc/self/setgroups", "deny")?;
    write_file("/proc/self/uid_map", &format!("{user_outer} 0 1"))?;
    write_file("/proc/self/gid_map", &format!("{group_outer} 0 1"))?;
    let uid = Uid::from_raw(user_outer);
    let gid = Gid::from_raw(group_outer);
    nix::unistd::setresgid(gid, gid, gid).map_err(|e| format!("setresgid: {e}"))?;
    nix::unistd::setresuid(uid, uid, uid).map_err(|e| format!("setresuid: {e}"))?;
    clear_capabilities()?;
    prctl::set_no_new_privs().map_err(|e| format!("PR_SET_NO_NEW_PRIVS: {e}"))?;
    verify_dropped(uid, gid)
        .map_err(|e| format!("the privilege drop could not be verified: {e}"))?;
    if plan.landlock {
        crate::landlock::restrict(&plan.exposed)
            .map_err(|e| format!("cannot restrict Unix socket connections with Landlock: {e}"))?;
    }
    if plan.new_session {
        // No controlling terminal: TIOCSTI needs the terminal to be the
        // caller's controlling terminal, and /dev/tty cannot be opened.
        nix::unistd::setsid().map_err(|e| format!("cannot start a new session: {e}"))?;
    }
    sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)
        .map_err(|e| format!("cannot unblock signals: {e}"))?;
    let (program, args) = plan.command.split_first().ok_or("no command was given")?;
    let err = Command::new(program).args(args).exec();
    Err(format!(
        "cannot run {}: {err}",
        Path::new(program).display()
    ))
}

/// The host id that id 0 of the outer namespace maps to, from a map that
/// reads `0 <host> 1`.
fn outer_id(map: &str) -> Option<u32> {
    let mut words = map.split_whitespace();
    let inside = words.next()?;
    let outside = words.next()?;
    let count = words.next()?;
    if inside != "0" || count != "1" {
        return None;
    }
    outside.parse().ok()
}

/// Creates a private directory for pasta's PID file.
///
/// # Errors
/// When the directory cannot be created.
pub fn private_dir() -> Result<PathBuf, String> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let dir = base.join(format!("playpen-{}-{nanos}", std::process::id()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outer_id_reads_single_mappings() {
        assert_eq!(outer_id("         0       1000          1\n"), Some(1000));
        assert_eq!(outer_id("0 0 4294967295"), None);
        assert_eq!(outer_id("1000 0 1"), None);
        assert_eq!(outer_id(""), None);
    }

    #[test]
    fn apparmor_hint_only_where_apparmor_restricts() {
        assert_eq!(
            with_apparmor_hint("cannot mount".into(), false),
            "cannot mount"
        );
        let m = with_apparmor_hint("cannot mount".into(), true);
        assert!(m.starts_with("cannot mount. "), "{m}");
        assert!(m.contains("userns,"), "{m}");
        assert!(m.contains("apparmor_restrict_unprivileged_userns"), "{m}");
        assert!(m.contains("docs/DESIGN.md"), "{m}");
    }

    #[test]
    fn signal_bytes_round_trip_and_do_not_collide() {
        for sig in FORWARDED {
            let b = signal_byte(sig);
            assert_eq!(b.and_then(byte_signal), Some(sig));
            assert!(b.is_some_and(|b| ![FREEZE, THAW, GO].contains(&b)));
        }
        assert_eq!(signal_byte(Signal::SIGKILL), None);
        for b in [0, 8, FREEZE, THAW, GO] {
            assert_eq!(byte_signal(b), None);
        }
    }

    #[test]
    fn parent_state_parses_lines() {
        let mut st = ParentState {
            buf: Vec::new(),
            failure: None,
            init: None,
            started: false,
            status: None,
            drops: None,
            ready: false,
            eof: false,
        };
        st.handle_line("ready");
        st.handle_line("init 4321");
        st.handle_line("started");
        st.handle_line("exit 7");
        st.handle_line(r#"drops {"packets":2,"destinations":[],"destinations_truncated":true}"#);
        assert!(st.ready && st.started);
        assert_eq!(st.init, Some(Pid::from_raw(4321)));
        assert_eq!(st.status, Some(CommandStatus::Exited(7)));
        assert!(matches!(st.drops, Some(Ok(DropSummary { packets: 2, .. }))));
        st.handle_line("signal 15");
        assert_eq!(st.status, Some(CommandStatus::Signaled(15)));
    }
}
