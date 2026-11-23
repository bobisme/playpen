//! The namespace mechanism: build the sandbox, run the command in it, tear
//! it down and read the drop counters.
//!
//! Process tree (each arrow is a `fork`):
//!
//! ```text
//! playpen (P, host namespaces)
//!  └─ C   new user + network namespace, mapped root inside; loads the
//!     │   ruleset, later reads the counters. Never runs user code.
//!     ├─ D   the DNS stub on 127.0.0.1 port 53 (see `dns_stub`); binds,
//!     │      then drops every capability and, with Landlock, confines
//!     │      itself to its descriptors; answers `--host` names only.
//!     └─ S   unshares a PID namespace, waits for its init.
//!        └─ I   PID 1 of the new PID namespace, in a private mount
//!           │   namespace: mounts /proc, the resolver files, hides host
//!           │   daemon sockets; forwards signals, reaps orphans.
//!           └─ X   nested user namespace mapped back to the caller's own
//!                  uid/gid, no capabilities, no_new_privs; execs the command.
//!  └─ W   only when the command shares the caller's terminal job: stays
//!         in P's process group and reports the signals it is sent.
//! ```
//!
//! `pasta` is started by P after C reports the ruleset is loaded and
//! verified, and attaches to C's namespaces. Until that moment the network
//! namespace has nothing but `lo`, so there is no window in which traffic
//! could leave unfiltered. Under `--no-network` C adds the discard
//! interface after the ruleset instead, and with pasta C adds the default
//! routes pasta did not, before the command exists (see
//! [`crate::routes`]); either failure is reported as `uncounted WHY`.
//!
//! Children report to P over one pipe with one line per event; P talks to C
//! over another pipe (the byte `g` means "go", end of file means "abort").
//! After "go" the same pipe reaches I: `f` asks it to freeze (SIGSTOP)
//! every process in the sandbox, `t` to thaw the ones it froze. P sends
//! them when it is suspended (Ctrl-Z) and continued, so the command never
//! runs while P, which enforces the end time and re-reads the pass, is
//! stopped. The signals P passes on to the command travel on this pipe
//! too, one byte each (see [`signal_byte`]). This distinguishes forwarded
//! signals from copies received by helpers in the caller's process group.
//! When the command shares that group, a signal sent to the whole group has
//! reached the command already; [`Witness`] says how P tells.
//! P also sends `b` every second. When I hears nothing from P for
//! [`SILENCE_LIMIT`] (P was stopped with SIGSTOP, which it cannot catch,
//! or is stuck), I freezes the sandbox by itself until P is heard again.
//!
//! P has a third pipe, to C alone (I never sees it). When P decides to stop
//! the command because the approval ended or the pass withdrew it, it sends
//! [`CUT`] there. C adds the one element of the ruleset's `cut` set, which
//! refuses every packet that is not loopback, and answers `cut` on the
//! report pipe. Only then does P print the notice and send SIGTERM (see
//! [`Cut`]). From the approval's end time the ruleset refuses the same
//! traffic by itself, whatever P does.
//!
//! With [`Plan::watch_drops`], C also reads the drop counter every
//! [`live_drops::INTERVAL`] while the command runs and sends each new
//! dropped destination on the report pipe as `denied JSON`; P passes it on
//! ([`Events::denied`]).
//!
//! With [`Plan::on_drop`] the ruleset closes all egress by itself at the
//! first packet it drops (see [`crate::tripwire`]). The first reading that
//! finds the drop counter above zero also sends `tripped JSON`. P reports
//! it ([`Events::tripped`]), and with [`OnDrop::Stop`] stops the command as
//! at the end time: [`CUT`] (the element is there already, so nothing
//! changes), the notice, SIGTERM, the grace, SIGKILL.

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::net::IpAddr;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::mount::{MsFlags, mount};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::pty::{Winsize, openpty};
use nix::sched::{CloneFlags, unshare};
use nix::sys::prctl;
use nix::sys::signal::{SigSet, SigmaskHow, Signal, kill, sigprocmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};
use nix::sys::termios::tcgetattr;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{
    ForkResult, Gid, Pid, Uid, getgid, getpgrp, getpid, getppid, getuid, pipe2, read,
};

use crate::approval::Approval;
use crate::live_drops::{self, LiveDrops};
use crate::pass::{PassWatch, Recheck};
use crate::resolver::{self, HostEntry};
use crate::ruleset::{self, DropSummary, Instrumentation};
use crate::tripwire::OnDrop;

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
/// Ctrl-C. In attached mode the terminal already signals its foreground job.
const SI_KERNEL: i32 = 0x80;

/// `si_code` of a signal sent with `kill(2)`, the only call that can address
/// a whole process group.
const SI_USER: i32 = 0;

/// How long a signal I received from outside its PID namespace counts
/// against a group send, from the moment P read I's report.
const CONTROL_WINDOW: Duration = Duration::from_millis(500);

/// How long P waits for W or I to answer [`SYNC`]. Without an answer P
/// passes the signal on, as it did before there was a witness.
const SYNC_LIMIT: Duration = Duration::from_secs(1);

/// Everything the sandbox needs to know. Built and checked by the CLI.
#[derive(Debug, Clone)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent settings of one run, each from its own option"
)]
pub struct Plan {
    /// Optional private loopback HTTP response for offline runs.
    pub fixture: Option<crate::fixture::Fixture>,
    /// What is approved.
    pub approval: Approval,
    /// `--host` entries.
    pub hosts: Vec<HostEntry>,
    /// Whether to attach pasta (false for `--no-network`).
    pub network: bool,
    /// Number of grants instrumented for first-match packet counts.
    pub grant_counters: usize,
    /// Record the destinations the command contacts through a grant
    /// (`--report-contacts`).
    pub report_contacts: bool,
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
    /// With `--capture`: the file pasta writes its packet capture to.
    pub capture: Option<std::sync::Arc<crate::capture::Capture>>,
    /// With `--pass`: the pass file to re-read while the command runs. A
    /// re-read can stop the run, never change the rules.
    pub watch: Option<PassWatch>,
    /// With `--events-fd`, `--live-drops` or `--on-drop`: C reads the drop
    /// counter every [`crate::live_drops::INTERVAL`] while the command
    /// runs, and P reports each new dropped destination
    /// ([`Events::denied`]).
    pub watch_drops: bool,
    /// With `--on-drop`: the ruleset closes all egress at the first packet
    /// it drops, and needs [`Plan::watch_drops`] for P to learn of it.
    pub on_drop: Option<OnDrop>,
}

impl Plan {
    fn grant_counter_count(&self) -> usize {
        self.grant_counters
            .min(self.approval.rules().len())
            .min(crate::grant_use::LIMIT)
    }

    /// What the ruleset of this run holds beyond the approval: P renders
    /// it, and C verifies it and reads its counters at teardown.
    fn instrumentation(&self) -> Instrumentation {
        Instrumentation {
            grant_counters: self.grant_counter_count(),
            record_contacts: self.report_contacts,
            tripwire: self.on_drop.is_some(),
        }
    }
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
    /// Observed per-grant packet counts in instrumentation order.
    pub grant_packets: Vec<Option<u64>>,
    /// The names the command looked up, or why they could not be read.
    pub lookups: Result<crate::dns_stub::Lookups, String>,
    /// Packets the time rule or the cut refused on their way out; `None`
    /// when the counters could not be read.
    pub refused_after_end: Option<u64>,
    /// With `--report-contacts`: the destinations the command contacted
    /// through a grant, or why they could not be read. `None` without it.
    pub contacts: Option<Result<crate::contacts::Contacted, String>>,
    /// With `--on-drop`: the destinations a reading found when the cut
    /// tripped, if a reading did.
    pub tripped_by: Option<Vec<ruleset::DroppedDest>>,
    /// True when playpen stopped the command because the cut tripped
    /// (`--on-drop stop`).
    pub stopped_by_drop: bool,
    /// Packets the cut alone refused on their way out; `None` when the
    /// counter could not be read.
    pub cut_packets: Option<u64>,
    /// Why packets to other hosts may have failed at routing, before the
    /// ruleset could count them; `None` when every address family had a
    /// route (see [`crate::routes`]).
    pub uncounted: Option<String>,
}

/// Whether egress was closed in the firewall when playpen began to stop
/// the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cut {
    /// The ruleset refuses every packet that is not loopback, in both
    /// directions, from before the notice and SIGTERM on. Also when the
    /// sandbox was gone already, so nothing in it could send.
    Closed,
    /// The setup process could not add the cut, or did not confirm it
    /// within [`CUT_LIMIT`]; the text says which. The sandbox is killed at
    /// once instead, without the grace.
    Failed(String),
}

/// Why the command did not run, or what went wrong after it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// The sandbox could not be built; the command was never started.
    NotStarted(String),
    /// Execution may have occurred, and the supervisor lacks complete evidence.
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
    /// Close any supervisor-only event writer in the freshly forked setup child.
    fn in_setup_child(&mut self) {}
    /// Validate any caller-supplied scope pin immediately before releasing the child.
    ///
    /// # Errors
    /// A changed or withdrawn scope prevents launch.
    fn before_start(&mut self) -> Result<(), String> {
        Ok(())
    }
    /// The sandbox is ready and the command is about to start.
    fn starting(&mut self);
    /// The command was released ("go" was sent) at `at`.
    fn released(&mut self, _at: time::OffsetDateTime) {}
    /// P learned at `at` that the command had ended: from init's report of
    /// its exit status, or from the end of the sandbox when none came.
    fn ended(&mut self, _at: time::OffsetDateTime) {}
    /// The approval ended; egress is closed as `cut` says, and the command
    /// is being stopped.
    fn until_reached(&mut self, cut: &Cut);
    /// Approved addresses that turned out to be the sandbox's own: pasta
    /// gave them to its interface, so connections to them stay inside.
    fn own_addresses(&mut self, _addresses: &[IpAddr]) {}
    /// Packets to other hosts fail at routing in this sandbox and are not
    /// counted, for the reason given (see [`crate::routes`]). Said once,
    /// after [`Events::starting`].
    fn uncounted(&mut self, _why: &str) {}
    /// A re-read of the pass found an edit that changes nothing in use.
    fn pass_edited(&mut self, message: &str);
    /// A re-read of the pass withdrew the approval; egress is closed as
    /// `cut` says, and the command is being stopped for this reason.
    fn pass_withdrawn(&mut self, reason: &str, cut: &Cut);
    /// With [`Plan::watch_drops`]: a reading while the command ran found
    /// packets dropped to `dest`, a destination not reported before.
    /// `packets` is the count at that reading.
    fn denied(&mut self, _dest: &ruleset::DroppedDest) {}
    /// With [`Plan::watch_drops`]: the drop counter could not be read while
    /// the command ran, for the reason given. Said once; later readings are
    /// still tried.
    fn denied_unreadable(&mut self, _why: &str) {}
    /// With [`Plan::on_drop`]: a reading found that a dropped packet has
    /// closed all egress, sent to one of `tripped_by` (empty when the
    /// reading could not list them). With `stopping`, the command is being
    /// stopped and egress is closed as it says; without, the command keeps
    /// running. Said once, and not when the command is being stopped
    /// already or has ended.
    fn tripped(&mut self, _tripped_by: &[ruleset::DroppedDest], _stopping: Option<&Cut>) {}
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

pub(crate) fn write_line(fd: &OwnedFd, line: &str) {
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
pub(crate) fn fork_checked() -> Result<ForkResult, String> {
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
/// namespace, and stay there whatever the command does with them. Allowed:
/// anything that is not a socket, and Unix sockets (connecting one, or
/// sending by address, to a socket of the host is refused by Landlock, for
/// pathname and abstract addresses alike). Refused: every IP socket.
/// A UDP socket can send to any address even when connected; a TCP socket
/// can be connected to any address, and a connected one too, because
/// `connect` with `AF_UNSPEC` dissolves the connection first. Every other
/// address family is refused as well.
///
/// Without Landlock (`landlock` false) nothing refuses those connections,
/// and the host's abstract sockets, which the sandbox's own network
/// namespace does not have, are reachable through a socket made outside.
/// Then a Unix socket is let in only if it cannot be pointed anywhere: a
/// connected stream or sequenced-packet socket, or a listening one.
///
/// # Errors
/// With a message saying which descriptor and what to do.
pub fn check_stdio(landlock: bool) -> Result<(), String> {
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
        let ty = getsockopt(&fd, sockopt::SockType).ok();
        let listening = getsockopt(&fd, sockopt::AcceptConn).unwrap_or(false);
        let connected = getpeername::<SockaddrStorage>(raw).is_ok();
        let what = match family {
            Some(AddressFamily::Unix) => {
                let fixed = listening
                    || (connected && matches!(ty, Some(SockType::Stream | SockType::SeqPacket)));
                if landlock || fixed {
                    continue;
                }
                "a Unix socket that is not a connected stream, which (with --without-landlock) the command could connect to any Unix socket of the host, abstract ones included"
            }
            Some(AddressFamily::Inet | AddressFamily::Inet6) => match ty {
                Some(SockType::Stream) if listening => {
                    "a listening TCP socket, through which anyone could connect to the command"
                }
                Some(SockType::Stream) if connected => {
                    "a connected TCP socket, which the command could disconnect and connect again to any address"
                }
                Some(SockType::Stream) => {
                    "an unconnected TCP socket, which the command could connect to any address"
                }
                _ => {
                    "a datagram or raw IP socket, through which the command could send to any address"
                }
            },
            _ => "a socket of a kind playpen does not let through (not a Unix socket)",
        };
        return Err(format!(
            "{name} is {what}, outside the filter: it belongs to the host's network. Give the command a pipe, a file or a terminal instead (for example add `| cat`, or `< /dev/null`)"
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

/// P asks I to decide whether a keyboard stop belongs to an inner job or to
/// the whole playpen invocation.
const PRIVATE_TSTP: u8 = b'z';

/// Byte P sends W and I: report every signal received so far, then answer.
const SYNC: u8 = b'q';

/// Byte W answers [`SYNC`] with, after its reports.
const SYNCED: u8 = b'k';

/// Added to a [`signal_byte`] when P's whole process group was sent the
/// signal: I passes it on only if the command has left that group.
const GROUP_SENT: u8 = 0x10;

/// Byte P sends C on their own pipe: close all egress in the firewall now,
/// and answer `cut` (or `cuterr WHY`) on the report pipe.
const CUT: u8 = b'x';

/// How long P waits for C to confirm [`CUT`]. Adding the element takes
/// milliseconds; without an answer in this time P kills the sandbox
/// instead of giving the command the grace (see [`Cut::Failed`]).
pub const CUT_LIMIT: Duration = Duration::from_secs(2);

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

/// The place of a [`signal_byte`] in [`FORWARDED`].
fn byte_index(byte: u8) -> Option<usize> {
    usize::from(byte)
        .checked_sub(1)
        .filter(|at| *at < FORWARDED.len())
}

/// The signal a byte from P stands for when it carries [`GROUP_SENT`].
fn byte_group_signal(byte: u8) -> Option<Signal> {
    (byte & 0xf0 == GROUP_SENT)
        .then(|| byte_signal(byte & 0x0f))
        .flatten()
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
    run_with_output(plan, events, false, false)
}

/// Reserve stdout for the final report when requested by the CLI.
pub(crate) fn run_with_output(
    plan: &Plan,
    events: &mut dyn Events,
    stdout_report: bool,
    private_terminal_requested: bool,
) -> Result<RunResult, RunError> {
    run_sandbox(plan, events, stdout_report, private_terminal_requested).map_err(|e| match e {
        RunError::NotStarted(m) => {
            RunError::NotStarted(with_apparmor_hint(m, apparmor_restricts()))
        }
        other @ RunError::Failed(_) => other,
    })
}

/// Resources for the opt-in private terminal. The relay owns the master side;
/// the slave stays open in P so it can be inherited through sandbox setup and
/// closed only after I has reported the command's exit.
struct PrivateTerminal {
    relay: crate::terminal_relay::Relay,
    slave: Option<OwnedFd>,
    monitor: Option<OwnedFd>,
    streams: [bool; 3],
}

#[derive(Clone, Copy)]
struct PrivateTtyFds {
    slave: RawFd,
    master: RawFd,
}

impl PrivateTerminal {
    fn prepare(stdout_report: bool) -> Result<Self, String> {
        // Open /dev/tty independently of stdio: an explicit private tty owns
        // keyboard input even when every standard stream is redirected. This
        // open-file description also survives session-leader death.
        let raw_tty = unsafe {
            libc::open(
                c"/dev/tty".as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw_tty < 0 {
            return Err(format!(
                "--private-tty needs a controlling terminal: {}",
                Errno::last()
            ));
        }
        let host_tty = unsafe { OwnedFd::from_raw_fd(raw_tty) };
        let host_group = getpgrp();
        let foreground = unsafe { libc::tcgetpgrp(host_tty.as_raw_fd()) };
        if foreground < 0 || foreground != host_group.as_raw() {
            return Err(
                "--private-tty needs to run in the caller terminal's foreground process group"
                    .into(),
            );
        }
        let host_session = unsafe { libc::tcgetsid(host_tty.as_raw_fd()) };
        if host_session < 0 || unsafe { libc::getsid(0) } != host_session {
            return Err("--private-tty needs the caller's controlling terminal".into());
        }

        let mut streams = [false; 3];
        for (index, fd) in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]
            .into_iter()
            .enumerate()
        {
            if unsafe { libc::isatty(fd) } != 1 {
                continue;
            }
            if unsafe { libc::tcgetsid(fd) } != host_session
                || unsafe { libc::tcgetpgrp(fd) } != host_group.as_raw()
            {
                return Err(format!(
                    "--private-tty cannot preserve terminal-connected standard {} on a different terminal",
                    ["input", "output", "error"][index]
                ));
            }
            streams[index] = true;
        }
        // `run --json` moves stdout to stderr in C before exec. Match that
        // final descriptor layout so a redirected stderr stays redirected.
        if stdout_report {
            streams[1] = streams[2];
        }

        let termios = tcgetattr(host_tty.as_fd())
            .map_err(|e| format!("cannot read terminal settings: {e}"))?;
        let mut winsize = std::mem::MaybeUninit::<Winsize>::zeroed();
        // SAFETY: TIOCGWINSZ writes one `winsize` value to this valid buffer.
        if unsafe {
            libc::ioctl(
                host_tty.as_raw_fd(),
                libc::TIOCGWINSZ as libc::c_ulong,
                winsize.as_mut_ptr(),
            )
        } < 0
        {
            return Err(format!("cannot read terminal size: {}", Errno::last()));
        }
        // SAFETY: ioctl succeeded and initialized the complete winsize value.
        let winsize = unsafe { winsize.assume_init() };
        let pair = openpty(Some(&winsize), Some(&termios))
            .map_err(|e| format!("cannot create a private terminal: {e}"))?;
        let slave = pair.slave;
        // I needs its own-namespace view of the private foreground group.
        let monitor_raw = unsafe { libc::fcntl(pair.master.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if monitor_raw < 0 {
            return Err(format!(
                "cannot retain private terminal monitor: {}",
                Errno::last()
            ));
        }
        // SAFETY: fcntl duplicated the live master descriptor into a new fd.
        let monitor = unsafe { OwnedFd::from_raw_fd(monitor_raw) };
        // Keep the descriptor through fork, but never let it leak past exec.
        fcntl(slave.as_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|e| format!("cannot protect private terminal descriptor: {e}"))?;
        fcntl(monitor.as_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|e| format!("cannot protect private terminal monitor: {e}"))?;
        // SAFETY: run_sandbox verified this process is single-threaded before
        // creating the relay helper.
        let relay = unsafe { crate::terminal_relay::Relay::start(pair.master, host_tty) }
            .map_err(|e| format!("cannot start the private terminal relay: {e}"))?;
        Ok(Self {
            relay,
            slave: Some(slave),
            monitor: Some(monitor),
            streams,
        })
    }

    fn fds(&self) -> Option<PrivateTtyFds> {
        Some(PrivateTtyFds {
            slave: self.slave.as_ref()?.as_raw_fd(),
            master: self.monitor.as_ref()?.as_raw_fd(),
        })
    }

    fn stop(mut self) -> std::io::Result<()> {
        self.slave.take();
        self.monitor.take();
        self.relay.stop()
    }
}

impl Drop for PrivateTerminal {
    fn drop(&mut self) {
        self.slave.take();
        self.monitor.take();
        let _ = self.relay.stop();
    }
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

fn run_sandbox(
    plan: &Plan,
    events: &mut dyn Events,
    stdout_report: bool,
    private_terminal_requested: bool,
) -> Result<RunResult, RunError> {
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
    let private_tty = if private_terminal_requested {
        Some(PrivateTerminal::prepare(stdout_report).map_err(not_started)?)
    } else {
        None
    };
    let private_fds = private_tty.as_ref().and_then(PrivateTerminal::fds);
    let tty_streams = private_tty.as_ref().map_or([false; 3], |tty| tty.streams);
    let (up_r, up_w) = pipe2(OFlag::O_CLOEXEC).map_err(|e| not_started(format!("pipe: {e}")))?;
    let (down_r, down_w) =
        pipe2(OFlag::O_CLOEXEC).map_err(|e| not_started(format!("pipe: {e}")))?;
    // P to C alone: I reads the down pipe after "go", so a byte for C there
    // could be read by I instead.
    let (control_r, control_w) =
        pipe2(OFlag::O_CLOEXEC).map_err(|e| not_started(format!("pipe: {e}")))?;
    let ids = Ids {
        uid: getuid(),
        gid: getgid(),
        parent: getpid(),
    };
    let job =
        JobControl::for_run(plan.new_session, private_terminal_requested).map_err(not_started)?;
    let ruleset_text = ruleset::render_instrumented(&plan.approval, plan.instrumentation());
    let files = SandboxFiles::build(plan);

    match fork_checked().map_err(not_started)? {
        ForkResult::Child => {
            events.in_setup_child();
            drop(up_r);
            drop(down_w);
            drop(control_w);
            drop(sigfd);
            if stdout_report && let Err(e) = nix::unistd::dup2_stdout(std::io::stderr()) {
                write_line(
                    &up_w,
                    &format!("fail cannot route workload stdout to stderr: {e}"),
                );
                exit_now(1);
            }
            let code = match stage_c(
                plan,
                &ids,
                &ruleset_text,
                &files,
                &up_w,
                &down_r,
                control_r,
                job,
                private_fds,
                tty_streams,
            ) {
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
            drop(control_r);
            let channels = Channels {
                up_r,
                down_w,
                control_w,
            };
            parent(plan, child, &sigfd, channels, events, job, private_tty)
        }
    }
}

/// P's ends of its pipes to the sandbox.
struct Channels {
    /// Lines from C, S and I.
    up_r: OwnedFd,
    /// Bytes to C ("go") and after that to I.
    down_w: OwnedFd,
    /// Bytes to C alone ([`CUT`]).
    control_w: OwnedFd,
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

#[derive(Default)]
struct ParentState {
    buf: Vec<u8>,
    failure: Option<String>,
    status_error: Option<String>,
    private_tstp: Option<bool>,
    init: Option<Pid>,
    started: bool,
    status: Option<CommandStatus>,
    /// When the exit status was read.
    ended_at: Option<time::OffsetDateTime>,
    drops: Option<Result<DropSummary, String>>,
    grant_packets: Vec<Option<u64>>,
    lookups: Option<Result<crate::dns_stub::Lookups, String>>,
    ready: bool,
    eof: bool,
    /// Approved addresses C found on the sandbox's own interfaces.
    own: Vec<IpAddr>,
    /// [`SYNC`] bytes sent to I, and how many it has answered.
    asked: u64,
    synced: u64,
    /// When P read I's report of a signal from outside its PID namespace,
    /// by place in [`FORWARDED`].
    outside: [Option<Instant>; FORWARDED.len()],
    /// C's answer to [`CUT`]: done, or why not.
    cut: Option<Result<(), String>>,
    /// Packets refused after the approval ended, from C's last reading.
    refused_after_end: Option<u64>,
    /// New dropped destinations from C's readings while the command runs,
    /// not yet reported.
    denied: Vec<ruleset::DroppedDest>,
    /// Why C could not read the drop counter while the command ran, not yet
    /// reported.
    denied_error: Option<String>,
    /// The contacted destinations C read at teardown, or why it could not.
    contacts: Option<Result<crate::contacts::Contacted, String>>,
    /// With `--on-drop`: the destinations C sent when it found the cut
    /// tripped.
    tripped: Option<Vec<ruleset::DroppedDest>>,
    /// The same, until P has acted on the trip.
    trip_pending: Option<Vec<ruleset::DroppedDest>>,
    /// The `cut` counter, read by C at teardown.
    cut_packets: Option<u64>,
    /// Why packets to other hosts fail at routing, from C.
    uncounted: Option<String>,
    /// The reasons C gave that [`Events::uncounted`] has not been told yet.
    uncounted_unsaid: Option<String>,
}

impl ParentState {
    fn handle_line(&mut self, line: &str) {
        let (word, rest) = line.split_once(' ').unwrap_or((line, ""));
        match word {
            "ready" => self.ready = true,
            "denied" => {
                if let Ok(d) = serde_json::from_str::<DroppedWire>(rest) {
                    self.denied.push(d.into_dest());
                }
            }
            "deniederr" => self.denied_error = Some(rest.to_owned()),
            "tripped" if self.tripped.is_none() => {
                let list: Vec<_> = serde_json::from_str::<Vec<DroppedWire>>(rest)
                    .unwrap_or_default()
                    .into_iter()
                    .map(DroppedWire::into_dest)
                    .collect();
                self.tripped = Some(list.clone());
                self.trip_pending = Some(list);
            }
            "cut" => self.cut = Some(Ok(())),
            "cuterr" => self.cut = Some(Err(rest.to_owned())),
            "afterend" => self.refused_after_end = rest.parse().ok(),
            "cutcount" => self.cut_packets = rest.parse().ok(),
            "fail" => {
                if self.failure.is_none() {
                    self.failure = Some(rest.to_owned());
                }
            }
            "init" => self.init = rest.parse::<i32>().ok().map(Pid::from_raw),
            "statuserr" => self.status_error = Some(rest.to_owned()),
            "private-tstp" => self.private_tstp = Some(rest == "outer"),
            "own" => self.own = rest.split(' ').filter_map(|a| a.parse().ok()).collect(),
            "uncounted" => {
                let join = |before: Option<String>| {
                    before.map_or_else(|| rest.to_owned(), |b| format!("{b}; {rest}"))
                };
                self.uncounted = Some(join(self.uncounted.take()));
                self.uncounted_unsaid = Some(join(self.uncounted_unsaid.take()));
            }
            "synced" => self.synced += 1,
            "outside" => {
                if let Some(at) = rest.parse().ok().and_then(byte_index) {
                    self.outside[at] = Some(Instant::now());
                }
            }
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
            "grants" => self.grant_packets = serde_json::from_str(rest).unwrap_or_default(),
            "lookups" => {
                self.lookups = Some(
                    serde_json::from_str::<crate::dns_stub::Lookups>(rest)
                        .map(crate::dns_stub::Lookups::sanitized)
                        .map_err(|e| format!("bad lookup report at column {}", e.column())),
                );
            }
            "lookupserr" => self.lookups = Some(Err(rest.to_owned())),
            "contacts" => {
                self.contacts = Some(
                    serde_json::from_str(rest)
                        .map_err(|e| format!("bad report of contacted destinations: {e}")),
                );
            }
            "contactserr" => self.contacts = Some(Err(rest.to_owned())),
            _ => {}
        }
    }

    fn receive(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=pos).collect();
            self.handle_line(&String::from_utf8_lossy(&line[..pos]));
            if self.status.is_some() && self.ended_at.is_none() {
                self.ended_at = Some(time::OffsetDateTime::now_utc());
            }
        }
    }

    /// After GO, only an explicit pre-exec diagnostic proves refusal.
    fn launch_result(&self) -> Result<(), RunError> {
        if let Some(msg) = &self.status_error {
            return Err(RunError::Failed(msg.clone()));
        }
        match (&self.failure, self.started) {
            (None, true) => Ok(()),
            (Some(msg), false) => Err(RunError::NotStarted(msg.clone())),
            _ => Err(RunError::Failed(
                "the supervisor lost reliable startup evidence; the command may have executed"
                    .into(),
            )),
        }
    }

    /// Reads what is available on `fd` and handles complete lines.
    fn pump(&mut self, fd: &OwnedFd) {
        let mut chunk = [0u8; 8192];
        match read(fd, &mut chunk) {
            Ok(0) => self.eof = true,
            Ok(n) => self.receive(&chunk[..n]),
            Err(Errno::EINTR | Errno::EAGAIN) => {}
            Err(_) => self.eof = true,
        }
    }

    /// Passes on C's reports that packets to other hosts are not counted,
    /// each once.
    fn report_uncounted(&mut self, events: &mut dyn Events) {
        if let Some(why) = self.uncounted_unsaid.take() {
            events.uncounted(&why);
        }
    }

    /// Passes on what C's readings found while the command ran: each new
    /// dropped destination, and the first failure.
    fn report_denied(&mut self, events: &mut dyn Events) {
        for dest in std::mem::take(&mut self.denied) {
            events.denied(&dest);
        }
        if let Some(why) = self.denied_error.take() {
            events.denied_unreadable(&why);
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
                .map(DroppedWire::into_dest)
                .collect(),
        }
    }
}

impl DroppedWire {
    fn into_dest(self) -> ruleset::DroppedDest {
        ruleset::DroppedDest {
            address: self.address,
            protocol: self.protocol,
            port: self.port,
            packets: self.packets,
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

/// Asks C to close all egress in the firewall ([`CUT`]) and waits up to
/// [`CUT_LIMIT`] for its answer. Lines that arrive meanwhile are handled
/// as usual.
fn cut_egress(st: &mut ParentState, up_r: &OwnedFd, control_w: &OwnedFd) -> Cut {
    st.cut = None;
    send_byte(control_w, CUT);
    let deadline = Instant::now() + CUT_LIMIT;
    loop {
        match &st.cut {
            Some(Ok(())) => return Cut::Closed,
            Some(Err(why)) => return Cut::Failed(why.clone()),
            None => {}
        }
        // C has ended, and with it everything in the sandbox: nothing is
        // left that could send.
        if st.eof {
            return Cut::Closed;
        }
        if !wait_readable(up_r, deadline) {
            return Cut::Failed(format!(
                "the sandbox did not confirm the cut within {} s",
                CUT_LIMIT.as_secs()
            ));
        }
        st.pump(up_r);
    }
}

/// After the cut: SIGTERM and the grace when egress is closed, SIGKILL at
/// once when it may not be.
fn stop_after_cut(
    cut: &Cut,
    init: Option<Pid>,
    child: Pid,
    down_w: &OwnedFd,
    shutdown: &mut Shutdown,
) {
    shutdown.request(Instant::now());
    match cut {
        Cut::Closed => stop_command(init, child, down_w),
        Cut::Failed(_) => {
            let _ = kill(init.unwrap_or(child), Signal::SIGKILL);
            shutdown.killed = true;
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
    channels: Channels,
    events: &mut dyn Events,
    job: JobControl,
    mut private_tty: Option<PrivateTerminal>,
) -> Result<RunResult, RunError> {
    let Channels {
        up_r,
        down_w,
        control_w,
    } = channels;
    let up_r = &up_r;
    let deadline = plan.approval.ends_at.map(|end| {
        let left = end.at() - time::OffsetDateTime::now_utc();
        Deadline {
            monotonic: Instant::now() + left.try_into().unwrap_or(Duration::ZERO),
            wall: end.at(),
        }
    });
    let mut st = ParentState::default();
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
        match crate::pasta::start(&plan.pasta, child, plan.capture.as_deref()) {
            Ok(p) => pasta = Some(p),
            Err(e) => {
                drop(down_w);
                let _ = waitpid(child, None);
                return Err(RunError::NotStarted(e));
            }
        }
    }
    let mut watch = plan.watch.clone();
    let mut withdrawn = None;
    if let Some(d) = deadline
        && d.passed(Instant::now(), time::OffsetDateTime::now_utc())
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
    let withdrawn = withdrawn
        .or_else(|| events.before_start().err())
        .or_else(|| {
            deadline
                .filter(|d| d.passed(Instant::now(), time::OffsetDateTime::now_utc()))
                .map(|_| "the approval ended during the final launch check".to_owned())
        });
    if let Some(why) = withdrawn {
        drop(down_w);
        let _ = waitpid(child, None);
        if let Some(p) = pasta {
            p.stop();
        }
        return Err(RunError::NotStarted(why));
    }
    events.starting();
    // Under --no-network C has said it before "ready".
    st.report_uncounted(events);
    send_byte(&down_w, GO);
    events.released(time::OffsetDateTime::now_utc());

    // Phase 3: the command runs.
    let mut shutdown = Shutdown::default();
    let mut stopped_by_pass: Option<String> = None;
    let mut stopped_by_drop = false;
    let mut terminal_failure: Option<String> = None;
    let mut next_recheck = watch.as_ref().map(|w| Instant::now() + w.interval);
    let mut next_beat = Instant::now();
    let mut witness: Option<Witness> = None;
    let mut witness_due = job == JobControl::CallerTerminal;
    while !st.eof {
        let now = Instant::now();
        // W must be newer than I: see `Witness`.
        if witness_due && let Some(init) = st.init {
            witness_due = false;
            witness = Witness::start(init);
        }
        if let Some(tty) = private_tty.as_mut()
            && terminal_failure.is_none()
            && let Err(e) = tty.relay.check()
        {
            terminal_failure = Some(format!("private terminal relay failed: {e}"));
            shutdown.request(now);
            stop_command(st.init, child, &down_w);
        }
        // Tell I that P is running and looking at the clock and the pass.
        if now >= next_beat {
            send_byte(&down_w, BEAT);
            next_beat = now + BEAT_INTERVAL;
        }
        let mut wake = next_beat;
        // The end time is checked before the pass is read again: when both
        // are due (playpen was stopped across the end), the end time wins.
        if let Some(d) = deadline
            && shutdown.started.is_none()
        {
            if d.passed(now, time::OffsetDateTime::now_utc()) {
                // The time rule refuses this traffic from the end second on;
                // the cut also covers a monotonic deadline that comes first.
                let cut = cut_egress(&mut st, up_r, &control_w);
                events.until_reached(&cut);
                stop_after_cut(&cut, st.init, child, &down_w, &mut shutdown);
            } else {
                wake = wake.min(d.monotonic);
            }
        }
        if let (Some(w), Some(due)) = (watch.as_mut(), next_recheck)
            && shutdown.started.is_none()
        {
            if now >= due {
                match w.recheck(time::OffsetDateTime::now_utc()) {
                    Recheck::Unchanged => {}
                    Recheck::Edited(m) => events.pass_edited(&m),
                    Recheck::Stop(why) => {
                        // Egress is closed before anything is said or sent.
                        let cut = cut_egress(&mut st, up_r, &control_w);
                        events.pass_withdrawn(&why, &cut);
                        stopped_by_pass = Some(why);
                        stop_after_cut(&cut, st.init, child, &down_w, &mut shutdown);
                    }
                }
                next_recheck = Some(Instant::now() + w.interval);
            }
            if let Some(due) = next_recheck {
                wake = wake.min(due);
            }
        }
        if shutdown.take_kill(now) {
            let _ = kill(st.init.unwrap_or(child), Signal::SIGKILL);
        } else if let Some(due) = shutdown.kill_at() {
            wake = wake.min(due);
        }
        let ms = u16::try_from(
            wake.saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, 10_000),
        )
        .unwrap_or(10_000);
        let up_ready = {
            let mut fds = vec![
                PollFd::new(up_r.as_fd(), PollFlags::POLLIN),
                PollFd::new(sigfd.as_fd(), PollFlags::POLLIN),
            ];
            if let Some(w) = &witness {
                fds.push(PollFd::new(w.answers.as_fd(), PollFlags::POLLIN));
            }
            match poll(&mut fds, PollTimeout::from(ms)) {
                Ok(_) | Err(Errno::EINTR) => {}
                Err(e) => {
                    return Err(RunError::Failed(format!("poll failed: {e}")));
                }
            }
            fds[0].revents().is_some_and(|r| !r.is_empty())
        };
        if up_ready {
            st.pump(up_r);
        }
        if !st.own.is_empty() {
            events.own_addresses(&std::mem::take(&mut st.own));
        }
        st.report_uncounted(events);
        st.report_denied(events);
        // The firewall has closed all egress at a dropped packet. With
        // `stop` P stops the command as at the end time; its cut request
        // changes nothing, but confirms the cut before the notice. Nothing
        // is said when the command is being stopped already or has ended;
        // the summary tells.
        if let Some(tripped_by) = st.trip_pending.take()
            && shutdown.started.is_none()
            && st.status.is_none()
        {
            if plan.on_drop == Some(OnDrop::Stop) {
                let cut = cut_egress(&mut st, up_r, &control_w);
                events.tripped(&tripped_by, Some(&cut));
                stopped_by_drop = true;
                stop_after_cut(&cut, st.init, child, &down_w, &mut shutdown);
            } else {
                events.tripped(&tripped_by, None);
            }
        }
        // W's reports are read before P's own signals. A signal for the
        // whole group is pending here by the time W can have reported it,
        // so a report with no signal of P's own beside it is not a group's.
        if let Some(w) = witness.as_mut() {
            w.absorb();
        }
        if st.private_tstp.take() == Some(true) {
            if let Some(tty) = private_tty.as_mut()
                && let Err(e) = tty.relay.pause()
            {
                terminal_failure = Some(format!("cannot pause private terminal relay: {e}"));
            }
            suspend(&down_w);
        }
        // Read whether or not poll saw a signal: one that came after poll
        // returned belongs with the reports of W's just read.
        while let Ok(Some(info)) = sigfd.read_signal() {
            let Ok(sig) = Signal::try_from(i32::try_from(info.ssi_signo).unwrap_or(0)) else {
                continue;
            };
            match sig {
                Signal::SIGCHLD | Signal::SIGTTIN | Signal::SIGTTOU => {}
                // Signals are read only after "go"; I reads the bytes
                // once its loop runs, even if they come before that.
                Signal::SIGTSTP
                    if job == JobControl::PrivateTerminal && info.ssi_code == SI_KERNEL =>
                {
                    send_byte(&down_w, PRIVATE_TSTP);
                }
                Signal::SIGTSTP => {
                    if let Some(tty) = private_tty.as_mut()
                        && let Err(e) = tty.relay.pause()
                    {
                        terminal_failure =
                            Some(format!("cannot pause private terminal relay: {e}"));
                    }
                    suspend(&down_w);
                }
                Signal::SIGCONT => {
                    if let Some(tty) = private_tty.as_mut()
                        && let Err(e) = tty.relay.resume()
                    {
                        terminal_failure =
                            Some(format!("cannot resume private terminal relay: {e}"));
                    }
                    send_byte(&down_w, THAW);
                }
                Signal::SIGWINCH
                    if job == JobControl::PrivateTerminal && info.ssi_code == SI_KERNEL =>
                {
                    if let Some(tty) = private_tty.as_mut()
                        && let Err(e) = tty.relay.resize()
                    {
                        terminal_failure = Some(format!("cannot resize private terminal: {e}"));
                    }
                }
                Signal::SIGWINCH if job == JobControl::PrivateTerminal => {
                    pass_on(&down_w, sig);
                }
                // An attached foreground workload receives the terminal's
                // signal directly. Detached helpers have already left this
                // group, so P is the single route into a new session.
                _ if info.ssi_code == SI_KERNEL && job == JobControl::CallerTerminal => {}
                // Sent with kill(2) while the command shares P's group: to
                // P alone, or to the group and so to the command as well.
                _ if info.ssi_code == SI_USER && job == JobControl::CallerTerminal => {
                    if group_sent(sig, &mut witness, &mut st, up_r, &down_w) {
                        pass_on_group_sent(&down_w, sig);
                    } else {
                        pass_on(&down_w, sig);
                    }
                }
                _ => pass_on(&down_w, sig),
            }
        }
        // A report of W's that met no signal of P's is dropped here, so it
        // cannot be taken for part of a later send.
        if witness.as_mut().is_some_and(Witness::forget) {
            witness = None;
        }
        if terminal_failure.is_some() && shutdown.started.is_none() {
            shutdown.request(Instant::now());
            stop_command(st.init, child, &down_w);
        }
    }
    drop(down_w);
    drop(witness);
    st.report_uncounted(events);
    st.report_denied(events);
    events.ended(st.ended_at.unwrap_or_else(time::OffsetDateTime::now_utc));
    let _ = waitpid(child, None);
    if let Some(tty) = private_tty.take()
        && let Err(e) = tty.stop()
    {
        terminal_failure = Some(format!(
            "private terminal output did not drain cleanly: {e}"
        ));
    }
    if let Some(p) = pasta {
        p.stop();
    }
    st.launch_result()?;
    if let Some(error) = terminal_failure {
        return Err(RunError::Failed(error));
    }
    let status = match st.status {
        Some(s) => s,
        None if shutdown.killed => CommandStatus::Signaled(Signal::SIGKILL as i32),
        None => {
            return Err(RunError::Failed(
                "the sandbox ended without reporting the command's exit status".into(),
            ));
        }
    };
    Ok(RunResult {
        status,
        stopped_by_until: shutdown.started.is_some()
            && stopped_by_pass.is_none()
            && !stopped_by_drop,
        stopped_by_pass,
        drops: st
            .drops
            .unwrap_or_else(|| Err("the drop counters were not reported".into())),
        grant_packets: st.grant_packets,
        lookups: st
            .lookups
            .unwrap_or_else(|| Err("the names the command looked up were not reported".into())),
        refused_after_end: st.refused_after_end,
        contacts: plan.report_contacts.then(|| {
            st.contacts
                .unwrap_or_else(|| Err("the contacted destinations were not reported".into()))
        }),
        tripped_by: st.tripped,
        stopped_by_drop,
        cut_packets: st.cut_packets,
        uncounted: st.uncounted,
    })
}

/// The first withdrawal starts grace. Repeated withdrawals leave it fixed.
#[derive(Default)]
struct Shutdown {
    started: Option<Instant>,
    killed: bool,
}

impl Shutdown {
    fn request(&mut self, now: Instant) {
        self.started.get_or_insert(now);
    }

    fn kill_at(&self) -> Option<Instant> {
        self.started.filter(|_| !self.killed).map(|t| t + GRACE)
    }

    fn take_kill(&mut self, now: Instant) -> bool {
        if self.kill_at().is_some_and(|deadline| now >= deadline) {
            self.killed = true;
            true
        } else {
            false
        }
    }
}

/// When the approval ends, on two clocks.
///
/// The monotonic deadline is fixed when the sandbox starts, so setting the
/// system clock back cannot extend the run. But that clock stands still
/// while the machine is suspended, and the approval's end is a moment in
/// real time, so the wall clock is looked at as well: the approval is over
/// as soon as either clock says so.
#[derive(Debug, Clone, Copy)]
struct Deadline {
    monotonic: Instant,
    wall: time::OffsetDateTime,
}

impl Deadline {
    fn passed(self, now: Instant, wall_now: time::OffsetDateTime) -> bool {
        now >= self.monotonic || wall_now >= self.wall
    }
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

/// P asks I to pass `sig` on to the command only if the command has left
/// P's process group: the whole group was sent this signal.
fn pass_on_group_sent(down_w: &OwnedFd, sig: Signal) {
    if let Some(b) = signal_byte(sig) {
        send_byte(down_w, b | GROUP_SENT);
    }
}

/// True when the signal P just read was sent to P's whole process group,
/// so the kernel has given every member its own copy.
///
/// That is when W received it too and I, outside the group, did not. A
/// sender that picks playpen's processes one by one (`killall playpen`)
/// reaches I as well, and the command not at all: P passes that on.
fn group_sent(
    sig: Signal,
    witness: &mut Option<Witness>,
    st: &mut ParentState,
    up_r: &OwnedFd,
    down_w: &OwnedFd,
) -> bool {
    let Some(at) = signal_byte(sig).and_then(byte_index) else {
        return false;
    };
    let Some(w) = witness.as_mut() else {
        return false;
    };
    if !w.saw(at) {
        return false;
    }
    let fresh =
        |st: &ParentState| st.outside[at].is_some_and(|read| read.elapsed() < CONTROL_WINDOW);
    if fresh(st) {
        return false;
    }
    // I may hold a report it has not written yet.
    send_byte(down_w, SYNC);
    st.asked += 1;
    let deadline = Instant::now() + SYNC_LIMIT;
    while st.synced < st.asked {
        if st.eof || !wait_readable(up_r, deadline) {
            return false;
        }
        st.pump(up_r);
    }
    !fresh(st)
}

// ---------------------------------------------------------------- W ----

/// P's side of W, the witness for signals sent to P's whole process group.
///
/// `kill(-pgid)` gives each member of the group a copy, and nothing in a
/// copy says whether it was sent to the group or to one process. When the
/// command shares P's group (an attached terminal job), P has to know:
/// passing a group's signal on gives the command a second copy, not
/// passing on a signal sent to P alone loses it.
///
/// W is a child of P that stays in P's group and does nothing but report
/// the signals it receives. I leaves the group once the command is forked.
/// A signal P receives is then
///
/// - for P alone when W did not receive it: passed on;
/// - for the group when W received it and I did not: the command has its
///   copy (I passes it on all the same if the command left the group);
/// - for playpen's processes one by one when W and I both received it, as
///   `killall playpen` or `kill $(pidof playpen)` send it: passed on. W and
///   I look the same to such a sender (same name, same command line,
///   neither dumpable); only the process group tells them apart.
///
/// W is forked after I, so its PID is the higher one. A sender that walks
/// `/proc` reaches I before W in ascending order and P last in descending
/// order; either way I's copy exists by the time P has W's report and its
/// own signal. What is left is a sender that signals P and W, by PID, and
/// not I: that signal is taken for a group's and not passed on.
struct Witness {
    pid: Pid,
    /// Write end: one [`SYNC`] per question. Closing it ends W.
    ask: Option<OwnedFd>,
    /// Read end, non-blocking: a [`signal_byte`] per signal W received,
    /// [`SYNCED`] per question.
    answers: OwnedFd,
    asked: u64,
    answered: u64,
    /// Reports read in this turn of P's loop, by place in [`FORWARDED`].
    seen: [bool; FORWARDED.len()],
    lost: bool,
}

impl Witness {
    /// Forks W. `None` when it cannot be had; P then passes on every
    /// signal, as it does for a job without a witness.
    fn start(init: Pid) -> Option<Self> {
        let (ask_r, ask_w) = pipe2(OFlag::O_CLOEXEC).ok()?;
        let (answers_r, answers_w) = pipe2(OFlag::O_CLOEXEC).ok()?;
        fcntl(answers_r.as_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).ok()?;
        let parent = getpid();
        match fork_checked().ok()? {
            ForkResult::Child => witness_main(parent, &ask_r, &answers_w),
            ForkResult::Parent { child } => {
                let witness = Self {
                    pid: child,
                    ask: Some(ask_w),
                    answers: answers_r,
                    asked: 0,
                    answered: 0,
                    seen: [false; FORWARDED.len()],
                    lost: false,
                };
                // PIDs wrapped around between the two forks: the order
                // the type relies on does not hold.
                (child > init).then_some(witness)
            }
        }
    }

    /// Reads what W has written.
    fn absorb(&mut self) {
        let mut buf = [0u8; 64];
        loop {
            match read(&self.answers, &mut buf) {
                Ok(0) => self.lost = true,
                Ok(n) => {
                    for &b in &buf[..n] {
                        if b == SYNCED {
                            self.answered += 1;
                        } else if let Some(at) = byte_index(b) {
                            self.seen[at] = true;
                        }
                    }
                    continue;
                }
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => {}
                Err(_) => self.lost = true,
            }
            return;
        }
    }

    /// True when W received the signal at `at` in [`FORWARDED`] no later
    /// than now. Uses the report up.
    fn saw(&mut self, at: usize) -> bool {
        self.absorb();
        if !self.seen[at] {
            self.sync();
        }
        std::mem::take(&mut self.seen[at])
    }

    /// Has W report every signal it has received so far.
    fn sync(&mut self) {
        let sent = self.ask.as_ref().is_some_and(|ask| {
            loop {
                match nix::unistd::write(ask, &[SYNC]) {
                    Err(Errno::EINTR) => {}
                    wrote => return wrote == Ok(1),
                }
            }
        });
        if !sent {
            self.lost = true;
        }
        self.asked += 1;
        let deadline = Instant::now() + SYNC_LIMIT;
        while self.answered < self.asked && !self.lost {
            if wait_readable(&self.answers, deadline) {
                self.absorb();
            } else {
                self.lost = true;
            }
        }
    }

    /// Drops the reports left over. True when W is of no use any more.
    const fn forget(&mut self) -> bool {
        self.seen = [false; FORWARDED.len()];
        self.lost
    }
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.ask.take();
        let _ = kill(self.pid, Signal::SIGKILL);
        while waitpid(self.pid, None) == Err(Errno::EINTR) {}
    }
}

/// W. Never returns into P's code: this process is a copy of P and must
/// not run its destructors (one of them stops pasta) or flush its buffers.
fn witness_main(parent: Pid, ask: &OwnedFd, answers: &OwnedFd) -> ! {
    let code = i32::from(witness_loop(parent, ask, answers).is_err());
    // SAFETY: `_exit` takes no pointers and only ends this process.
    unsafe { libc::_exit(code) }
}

fn witness_loop(parent: Pid, ask: &OwnedFd, answers: &OwnedFd) -> Result<(), String> {
    die_with_parent(parent)?;
    // As I is: a sender that selects by executable must find both or neither.
    prctl::set_dumpable(false).map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    // P's descriptors, among them the pipe whose closing tells I that P
    // is gone, and the caller's standard streams.
    close_fds_except(&[ask.as_raw_fd(), answers.as_raw_fd()])?;
    let mut set = SigSet::empty();
    for s in FORWARDED {
        set.add(s);
    }
    // Blocked already: the mask is P's.
    let sigfd = SignalFd::with_flags(&set, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .map_err(|e| format!("cannot create signalfd: {e}"))?;
    loop {
        let mut fds = [
            PollFd::new(sigfd.as_fd(), PollFlags::POLLIN),
            PollFd::new(ask.as_fd(), PollFlags::POLLIN),
        ];
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => return Err(format!("poll failed: {e}")),
        }
        let mut questions = 0;
        if fds[1].revents().is_some_and(|r| !r.is_empty()) {
            let mut b = [0u8; 16];
            match read(ask, &mut b) {
                Ok(0) => return Ok(()),
                Ok(n) => questions = n,
                Err(Errno::EINTR) => {}
                Err(e) => return Err(format!("read failed: {e}")),
            }
        }
        // After the question, so the answer covers every signal sent
        // before P asked.
        let mut out = Vec::new();
        while let Ok(Some(info)) = sigfd.read_signal() {
            let sig = i32::try_from(info.ssi_signo)
                .ok()
                .and_then(|n| Signal::try_from(n).ok());
            if info.ssi_code == SI_USER
                && let Some(b) = sig.and_then(signal_byte)
            {
                out.push(b);
            }
        }
        out.resize(out.len() + questions, SYNCED);
        let mut rest = &out[..];
        while !rest.is_empty() {
            match nix::unistd::write(answers, rest) {
                Ok(n) => rest = &rest[n..],
                Err(Errno::EINTR) => {}
                Err(e) => return Err(format!("write failed: {e}")),
            }
        }
    }
}

/// Closes every descriptor of this process but `keep`.
pub(crate) fn close_fds_except(keep: &[RawFd]) -> Result<(), String> {
    let entries =
        fs::read_dir("/proc/self/fd").map_err(|e| format!("cannot list /proc/self/fd: {e}"))?;
    let fds: Vec<RawFd> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse().ok()))
        .filter(|fd| !keep.contains(fd))
        .collect();
    for fd in fds {
        // SAFETY: only called in W and in the DNS stub, which never again
        // use, or drop, any of the objects they inherited that own these
        // descriptors: both end with `_exit`. The listing's own descriptor
        // is closed already; closing its number again fails with EBADF.
        unsafe { libc::close(fd) };
    }
    Ok(())
}

// ---------------------------------------------------------------- C ----

pub(crate) fn die_with_parent(parent: Pid) -> Result<(), String> {
    prctl::set_pdeathsig(Signal::SIGKILL).map_err(|e| format!("PR_SET_PDEATHSIG: {e}"))?;
    if getppid() != parent {
        return Err("playpen exited during setup".into());
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "C receives the inherited sandbox setup channels and private tty descriptors"
)]
fn stage_c(
    plan: &Plan,
    ids: &Ids,
    ruleset_text: &str,
    files: &SandboxFiles,
    up_w: &OwnedFd,
    down_r: &OwnedFd,
    control_r: OwnedFd,
    job: JobControl,
    private_fds: Option<PrivateTtyFds>,
    tty_streams: [bool; 3],
) -> Result<(), String> {
    die_with_parent(ids.parent)?;
    if job == JobControl::PrivateTerminal {
        // Keep the setup process out of the caller's process group before any
        // later group-directed signal can become pending for the workload.
        make_process_group()?;
    }
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
    let with = plan.instrumentation();
    verify_ruleset(&plan.nft, &plan.approval, with)?;
    // After the ruleset: the kernel's own reports when the interface comes
    // up meet its uncounted drop rule. A packet to another host now has a
    // route, so the ruleset counts and refuses it (see `routes`).
    if !plan.network
        && let Err(why) = crate::routes::make_discard_interface()
    {
        write_line(up_w, &format!("uncounted {why}"));
    }
    // Made now, so that C can watch S and P's control pipe at once later,
    // and a failure stops the run before anything runs.
    let mut chld = SigSet::empty();
    chld.add(Signal::SIGCHLD);
    let chld = SignalFd::with_flags(&chld, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .map_err(|e| format!("cannot create signalfd: {e}"))?;
    write_line(up_w, "ready");

    let mut go = [0u8; 1];
    match read(down_r, &mut go) {
        Ok(1) if go[0] == GO => {}
        _ => exit_now(0),
    }
    // pasta is attached and has configured the namespace. No command exists
    // yet.
    if plan.network {
        // A family the host has no default route for gets one into pasta's
        // interface, so its packets reach the ruleset (see `routes`).
        if let Err(why) = crate::routes::route_missing_families() {
            write_line(up_w, &format!("uncounted {why}"));
        }
        let own = own_approved_addresses(plan);
        if !own.is_empty() {
            let list: Vec<String> = own.iter().map(ToString::to_string).collect();
            write_line(up_w, &format!("own {}", list.join(" ")));
        }
    }
    // This process holds every capability over the network namespace. It
    // stayed dumpable only so pasta (same user, outside) could open its
    // /proc/PID/ns entries; pasta is attached now and no command exists
    // yet. From here on nothing running as the same user may ptrace it or
    // open its /proc entries, and every child inherits that.
    prctl::set_dumpable(false).map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    // Before the command exists, while this process can bind port 53.
    let stub = crate::dns_stub::Stub::start(&plan.hosts, plan.landlock)?;

    match fork_checked()? {
        ForkResult::Child => {
            // Only C stops the stub; S keeps no handle on it. P's control
            // pipe and C's signals are C's alone.
            drop(stub);
            drop(control_r);
            drop(chld);
            let code = match stage_s(plan, files, up_w, down_r, job, private_fds, tty_streams) {
                Ok(()) => 0,
                Err(msg) => {
                    write_line(up_w, &format!("fail {msg}"));
                    1
                }
            };
            exit_now(code);
        }
        ForkResult::Parent { child } => {
            let live = plan.watch_drops.then(|| LiveDrops::new(with.tripwire));
            watch_sandbox(&plan.nft, live, child, &control_r, &chld, up_w);
        }
    }
    // S has ended, and with it the command: nothing can look up a name now.
    stub.report(up_w);
    report_counters(&plan.nft, with, plan.approval.ends_at.is_some(), up_w);
    Ok(())
}

/// C's work while the command runs: wait for S to end, close all egress in
/// the firewall when P asks ([`CUT`]), and, with `live` (for
/// [`Plan::watch_drops`]), read the drop counter every
/// [`live_drops::INTERVAL`] ([`read_drops_live`]).
///
/// One `poll` over P's control pipe and C's SIGCHLD, with the next reading
/// as its timeout; another duty for C while the command runs is one more
/// descriptor here. C answers every [`CUT`], so P never waits for an
/// answer that will not come; the element is added once by C (with
/// `--on-drop` the ruleset may have added it before, and adding it again
/// changes nothing). A reading waits for `nft` (about 1 ms, about 40 ms
/// when it lists the table with both drop sets full), and a [`CUT`] that
/// comes meanwhile is answered right after it.
fn watch_sandbox(
    nft: &Path,
    mut live: Option<LiveDrops>,
    s: Pid,
    control_r: &OwnedFd,
    chld: &SignalFd,
    up_w: &OwnedFd,
) {
    // False once P has closed its end: P is gone, and PR_SET_PDEATHSIG
    // ends C as well.
    let mut listening = true;
    let mut cut: Option<Result<(), String>> = None;
    let mut next_reading = Instant::now() + live_drops::INTERVAL;
    loop {
        let timeout = live.as_mut().map_or(PollTimeout::NONE, |live| {
            if Instant::now() >= next_reading {
                read_drops_live(nft, live, up_w);
                // A fixed schedule, unless C fell a whole interval behind.
                let now = Instant::now();
                next_reading += live_drops::INTERVAL;
                if next_reading <= now {
                    next_reading = now + live_drops::INTERVAL;
                }
            }
            let left = next_reading.saturating_duration_since(Instant::now());
            // Rounded up, so poll does not return just before the reading
            // is due.
            PollTimeout::from(u16::try_from(left.as_millis().saturating_add(1)).unwrap_or(u16::MAX))
        });
        let mut fds = vec![PollFd::new(chld.as_fd(), PollFlags::POLLIN)];
        if listening {
            fds.push(PollFd::new(control_r.as_fd(), PollFlags::POLLIN));
        }
        match poll(&mut fds, timeout) {
            Ok(_) | Err(Errno::EINTR) => {}
            // Nothing to wait on any more but S itself.
            Err(_) => {
                while waitpid(s, None) == Err(Errno::EINTR) {}
                return;
            }
        }
        let asked = fds
            .get(1)
            .and_then(PollFd::revents)
            .is_some_and(|r| !r.is_empty());
        if asked {
            let mut bytes = [0u8; 16];
            match read(control_r, &mut bytes) {
                Ok(0) => listening = false,
                Ok(n) => {
                    for _ in bytes[..n].iter().filter(|&&b| b == CUT) {
                        match cut.get_or_insert_with(|| close_egress(nft)) {
                            Ok(()) => write_line(up_w, "cut"),
                            Err(why) => write_line(up_w, &format!("cuterr {why}")),
                        }
                    }
                }
                Err(Errno::EINTR | Errno::EAGAIN) => {}
                Err(_) => listening = false,
            }
        }
        // SIGCHLD also comes from the nft run by `close_egress` and
        // `read_drops_live`, and from the DNS stub, which `Stub::report`
        // reaps.
        while let Ok(Some(_)) = chld.read_signal() {}
        match waitpid(s, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) | Err(Errno::EINTR) => {}
            _ => return,
        }
    }
}

/// One reading for [`watch_sandbox`] (see [`crate::live_drops`]): the
/// `dropped` counter, and the whole table when the counter has moved since
/// the last listing. Sends each destination not sent before to P as
/// `denied JSON`, and the first failure as `deniederr WHY`.
///
/// Packets refused by the cut or the time rule are counted in `cut` and
/// `late`, not in `dropped`, so after the end of egress there is nothing
/// new to send.
///
/// With `--on-drop` the ruleset closes egress by itself, and every packet
/// counted in `dropped` has tripped the cut on its way (see
/// [`crate::tripwire`]). So the first reading that finds the counter above
/// zero also sends `tripped JSON`, after the `denied` lines: the
/// destinations of this reading's listing (the drop sets hold nothing
/// else once the cut has tripped), at most [`live_drops::SHOWN`] of them,
/// so that the line stays one write; none when the listing failed. It
/// does not matter whether C has added the element too.
fn read_drops_live(nft: &Path, live: &mut LiveDrops, up_w: &OwnedFd) {
    let counter = list_dropped_counter(nft).and_then(|json| live_drops::parse_dropped(&json));
    let fresh = counter.clone().and_then(|packets| {
        if live.moved(packets) {
            list_table(nft).and_then(|table| live.fresh(packets, &table))
        } else {
            Ok(Vec::new())
        }
    });
    if let Ok(list) = &fresh {
        for dest in list {
            if let Ok(json) = serde_json::to_string(dest) {
                write_line(up_w, &format!("denied {json}"));
            }
        }
    }
    if let Ok(packets) = counter
        && live.tripped(packets)
    {
        let list = fresh.as_deref().unwrap_or_default();
        let shown = &list[..list.len().min(live_drops::SHOWN)];
        let json = serde_json::to_string(shown).unwrap_or_else(|_| "[]".into());
        write_line(up_w, &format!("tripped {json}"));
    }
    if let Err(why) = fresh
        && live.first_failure()
    {
        // Short enough to stay one write, and so one line, on the pipe S
        // and I write to as well.
        let why: String = why.chars().take(512).collect();
        write_line(up_w, &format!("deniederr {why}"));
    }
}

/// `nft --json list counter inet playpen dropped`.
fn list_dropped_counter(nft: &Path) -> Result<String, String> {
    let out = nft_command(nft)
        .stdin(Stdio::null())
        .args([
            "--json",
            "list",
            "counter",
            "inet",
            ruleset::TABLE,
            "dropped",
        ])
        .output()
        .map_err(|e| format!("cannot run {}: {e}", nft.display()))?;
    if !out.status.success() {
        return Err(format!(
            "nft could not list the drop counter ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|_| "nft printed non-UTF-8 output".into())
}

/// Adds the element [`ruleset::CUT_MARK`] to the [`ruleset::CUT_SET`]:
/// from now on the ruleset refuses every packet that is not loopback, in
/// both directions. Nothing else in the table changes.
fn close_egress(nft: &Path) -> Result<(), String> {
    let element = format!("{{ {} }}", ruleset::CUT_MARK);
    let out = nft_command(nft)
        .stdin(Stdio::null())
        .args([
            "add",
            "element",
            "inet",
            ruleset::TABLE,
            ruleset::CUT_SET,
            &element,
        ])
        .output()
        .map_err(|e| format!("cannot run {}: {e}", nft.display()))?;
    if !out.status.success() {
        return Err(format!(
            "nft add element failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// The addresses approved on their own that belong to an interface of this
/// network namespace.
///
/// pasta gives the sandbox the addresses of the host's interface it copies,
/// so a destination that is one of them is local here: a connection to it
/// never reaches pasta, and so never the host. Addresses playpen itself put
/// on `lo` (`--lo-addr`) are meant to be local and are left out.
fn own_approved_addresses(plan: &Plan) -> Vec<IpAddr> {
    let Ok(interfaces) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    let mut own: Vec<IpAddr> = interfaces
        .filter_map(|interface| {
            let address = interface.address?;
            address
                .as_sockaddr_in()
                .map(|v4| IpAddr::V4(v4.ip()))
                .or_else(|| address.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip())))
        })
        .filter(|ip| !plan.lo_addrs.contains(ip))
        .filter(|ip| {
            let alone =
                |rule: &crate::approval::AllowRule| rule.net.is_single() && rule.net.addr() == *ip;
            plan.approval.rules().iter().any(alone)
        })
        .collect();
    own.sort_unstable();
    own.dedup();
    own
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
        // nft prints `meta time` as a date in its own time zone.
        .env("TZ", crate::nft_readback::LISTING_TZ)
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

fn verify_ruleset(nft: &Path, approval: &Approval, with: Instrumentation) -> Result<(), String> {
    let json = list_table(nft).map_err(|e| format!("cannot verify the ruleset: {e}"))?;
    crate::nft_readback::verify_instrumented(&json, approval, with)
        .map_err(|e| format!("the loaded ruleset is not the one playpen built: {e}"))
}

/// C's teardown lines from one listing of the table: the drops, the
/// packets refused after the end, the cut's own count, and what `with`
/// recorded.
fn report_counters(nft: &Path, with: Instrumentation, timed: bool, up: &OwnedFd) {
    let snapshot = list_table(nft);
    match snapshot
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|json| ruleset::parse_counters(json))
    {
        Ok(summary) => {
            let json = serde_json::to_string(&summary).unwrap_or_default();
            write_line(up, &format!("drops {json}"));
        }
        Err(e) => write_line(up, &format!("dropserr {e}")),
    }
    if let Ok(refused) = snapshot
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|json| ruleset::parse_refused_after_end(json, timed))
    {
        write_line(up, &format!("afterend {refused}"));
    }
    if with.record_contacts {
        report_contacts(snapshot.as_deref(), up);
    }
    // The cut's packets alone: with `--on-drop`, the ones refused after the
    // trip (see `tripwire::OnDropReport::observe`).
    if let Ok(cut) = snapshot
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|json| live_drops::parse_counter(json, ruleset::CUT_COUNTER))
    {
        write_line(up, &format!("cutcount {cut}"));
    }
    if with.grant_counters != 0
        && let Ok(snapshot) = snapshot
    {
        let counters = crate::grant_use::read_packets(&snapshot, with.grant_counters);
        let json = serde_json::to_string(&counters).unwrap_or_default();
        write_line(up, &format!("grants {json}"));
    }
}

/// With `--report-contacts`: the destinations in the teardown listing, as
/// one `contacts JSON` line, or `contactserr WHY`.
fn report_contacts(snapshot: Result<&str, &String>, up: &OwnedFd) {
    match snapshot
        .map_err(Clone::clone)
        .and_then(crate::contacts::parse)
    {
        Ok(contacted) => {
            let json = serde_json::to_string(&contacted).unwrap_or_default();
            write_line(up, &format!("contacts {json}"));
        }
        Err(e) => write_line(up, &format!("contactserr {e}")),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JobControl {
    CallerTerminal,
    PrivateGroup,
    NewSession,
    PrivateTerminal,
}

impl JobControl {
    fn forward(self, child: Pid, sig: Signal, private_fds: Option<PrivateTtyFds>) {
        let target = match self {
            Self::CallerTerminal => child,
            Self::NewSession => Pid::from_raw(-child.as_raw()),
            Self::PrivateTerminal => {
                let Some(fds) = private_fds else {
                    return;
                };
                // X owns the private terminal session. I sees the foreground
                // group number in I's PID namespace and signals it here.
                let foreground = unsafe { libc::tcgetpgrp(fds.master) };
                if foreground <= 1 {
                    return;
                }
                Pid::from_raw(-foreground)
            }
            Self::PrivateGroup => match nix::unistd::getpgid(Some(child)) {
                // The workload may make its own session or change groups.
                // Never translate an invisible group or PID 1 to kill(0/-1).
                Ok(group) if group.as_raw() > 1 => Pid::from_raw(-group.as_raw()),
                _ => child,
            },
        };
        let _ = kill(target, sig);
    }

    fn for_run(new_session: bool, private_tty: bool) -> Result<Self, String> {
        if private_tty {
            return Ok(Self::PrivateTerminal);
        }
        if new_session {
            return Ok(Self::NewSession);
        }
        // Linux stat field 7 is tty_nr. A process can still open its
        // controlling terminal even when all three standard streams are pipes.
        let stat = fs::read("/proc/self/stat").map_err(|e| format!("cannot read tty_nr: {e}"))?;
        let fields = stat.rsplitn(2, |&b| b == b')').next().unwrap_or_default();
        let tty = fields
            .split(u8::is_ascii_whitespace)
            .filter(|v| !v.is_empty())
            .nth(4)
            .ok_or("missing tty_nr in /proc/self/stat")?;
        Ok(if tty == b"0" {
            Self::PrivateGroup
        } else {
            Self::CallerTerminal
        })
    }
}

fn make_process_group() -> Result<(), String> {
    nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0))
        .map_err(|e| format!("cannot create a process group: {e}"))
}

// ---------------------------------------------------------------- S ----

fn stage_s(
    plan: &Plan,
    files: &SandboxFiles,
    up_w: &OwnedFd,
    down_r: &OwnedFd,
    job: JobControl,
    private_fds: Option<PrivateTtyFds>,
    tty_streams: [bool; 3],
) -> Result<(), String> {
    prctl::set_pdeathsig(Signal::SIGKILL).map_err(|e| format!("PR_SET_PDEATHSIG: {e}"))?;
    unshare(CloneFlags::CLONE_NEWPID).map_err(|e| format!("cannot create a PID namespace: {e}"))?;
    match fork_checked()? {
        ForkResult::Child => {
            let code = match stage_i(plan, files, up_w, down_r, job, private_fds, tty_streams) {
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

/// The refusal when the mounts cannot be made private. With EPERM the
/// usual cause is a sandbox around playpen whose mounts are locked, so the
/// message says so.
fn mounts_private_error(e: Errno) -> String {
    if e == Errno::EPERM {
        format!(
            "cannot make mounts private: {e}; playpen cannot run inside playpen, or inside another sandbox that locks its mounts"
        )
    } else {
        format!("cannot make mounts private: {e}")
    }
}

fn stage_i(
    plan: &Plan,
    files: &SandboxFiles,
    up_w: &OwnedFd,
    down_r: &OwnedFd,
    job: JobControl,
    private_fds: Option<PrivateTtyFds>,
    tty_streams: [bool; 3],
) -> Result<i32, String> {
    prctl::set_pdeathsig(Signal::SIGKILL).map_err(|e| format!("PR_SET_PDEATHSIG: {e}"))?;
    if job == JobControl::PrivateTerminal {
        if private_fds.is_none() {
            return Err("private terminal descriptors were lost".into());
        }
    } else if job != JobControl::CallerTerminal {
        // Leave the caller's group before forking the workload. A
        // group signal during setup must never become pending in the workload.
        make_process_group()?;
    }
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
    .map_err(mounts_private_error)?;
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
            let msg = match stage_x(plan, job, private_fds, tty_streams) {
                Ok(never) => match never {},
                Err(msg) => msg,
            };
            write_line(&err_w, &msg);
            exit_now(127);
        }
        ForkResult::Parent { child } => child,
    };
    // The command shares the caller's process group, which it got from I.
    // I leaves it now, so that a signal for the whole group reaches the
    // command and not I; P's witness relies on that (see `Witness`). From
    // inside, that group has no number: both read 0 here. If I cannot
    // leave, P takes every signal for one sent to playpen's processes one
    // by one and passes it on.
    let shared_group = (job == JobControl::CallerTerminal).then(|| {
        let group = getpgrp();
        let _ = make_process_group();
        group
    });
    drop(err_w);
    let mut msg = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match read(&err_r, &mut chunk) {
            Ok(0) => break,
            Ok(n) => msg.extend_from_slice(&chunk[..n]),
            Err(Errno::EINTR) => {}
            Err(e) => {
                write_line(up_w, &format!("statuserr cannot read exec status: {e}"));
                return Ok(1);
            }
        }
    }
    if !msg.is_empty() {
        let _ = waitpid(child, None);
        return Err(String::from_utf8_lossy(&msg).trim().to_owned());
    }
    write_line(up_w, "started");
    match init_loop(child, job, shared_group, private_fds, &sigfd, up_w, down_r) {
        Ok(code) => Ok(code),
        Err(msg) => {
            write_line(up_w, &format!("statuserr {msg}"));
            Ok(1)
        }
    }
}

/// I's work while the command runs: pass the signals P names on to
/// the workload, freeze and thaw on P's request, reap orphans, and report how
/// the command ended.
///
/// PID 1 also accepts signals sent to it by processes in its own PID
/// namespace. Signals from outside the namespace use P's control pipe;
/// with `shared_group` (the group the command was started in, which I has
/// left) I tells P of the ones it receives all the same, because they show
/// that a sender reached playpen's processes one by one.
#[expect(
    clippy::too_many_lines,
    reason = "one event loop; splitting it would scatter its state"
)]
fn init_loop(
    child: Pid,
    job: JobControl,
    shared_group: Option<Pid>,
    private_fds: Option<PrivateTtyFds>,
    sigfd: &SignalFd,
    up_w: &OwnedFd,
    down_r: &OwnedFd,
) -> Result<i32, String> {
    let mut frozen: Vec<Pid> = Vec::new();
    // When P was last heard, whether P asked for the freeze in force
    // (Ctrl-Z), and whether I froze the sandbox because P went silent.
    let mut heard = Instant::now();
    let mut asked = false;
    let mut silent = false;
    loop {
        let mut fds = [
            PollFd::new(sigfd.as_fd(), PollFlags::POLLIN),
            PollFd::new(down_r.as_fd(), PollFlags::POLLIN),
        ];
        // Wake when P has been silent too long; while frozen for that,
        // every interval, to stop whatever a pass of the freeze missed.
        // Not after Ctrl-Z: P asked for that freeze before it stopped.
        let timeout = if asked {
            PollTimeout::NONE
        } else {
            let left = if silent {
                BEAT_INTERVAL
            } else {
                (heard + SILENCE_LIMIT).saturating_duration_since(Instant::now())
            };
            PollTimeout::from(u16::try_from(left.as_millis() + 1).unwrap_or(u16::MAX))
        };
        match poll(&mut fds, timeout) {
            Ok(_) | Err(Errno::EINTR) => {}
            Err(e) => return Err(format!("poll failed: {e}")),
        }
        let from_p = fds[1].revents().is_some_and(|r| !r.is_empty());
        let mut syncs = 0;
        if from_p {
            let mut b = [0u8; 16];
            match read(down_r, &mut b) {
                // P holds the other end until the sandbox is gone, so
                // this is P's death. PR_SET_PDEATHSIG is on its way down
                // the chain; do not depend on it (it is lost if a parent
                // dies before its child has asked for it). Init's exit
                // kills everything in the sandbox.
                Ok(0) | Err(Errno::EBADF) => {
                    return Err("playpen itself is gone; the sandbox was stopped".into());
                }
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
                            SYNC => syncs += 1,
                            FREEZE => {
                                asked = true;
                                freeze(&mut frozen);
                            }
                            THAW => {
                                asked = false;
                                thaw(&mut frozen);
                            }
                            PRIVATE_TSTP if job == JobControl::PrivateTerminal => {
                                let fds =
                                    private_fds.ok_or("private terminal descriptors were lost")?;
                                let foreground = unsafe { libc::tcgetpgrp(fds.master) };
                                let session = unsafe { libc::tcgetsid(fds.master) };
                                if foreground > 1 && session > 1 && foreground != session {
                                    let _ = kill(Pid::from_raw(-foreground), Signal::SIGTSTP);
                                    write_line(up_w, "private-tstp inner");
                                } else {
                                    write_line(up_w, "private-tstp outer");
                                }
                            }
                            _ => {
                                if let Some(sig) = byte_signal(byte) {
                                    job.forward(child, sig, private_fds);
                                } else if let Some(sig) = byte_group_signal(byte)
                                    && nix::unistd::getpgid(Some(child)).ok() != shared_group
                                {
                                    // The group was sent this signal, and
                                    // the command is not in it any more
                                    // (a shell with job control).
                                    job.forward(child, sig, private_fds);
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
        if !asked && heard.elapsed() >= SILENCE_LIMIT {
            if !silent {
                silent = true;
                eprintln!(
                    "playpen: playpen itself has been stopped or stuck for {} s, so nothing enforces the end time or re-reads the pass; the command is paused until playpen continues (`fg`, or `kill -CONT` its process)",
                    SILENCE_LIMIT.as_secs()
                );
            }
            freeze(&mut frozen);
        }
        // Every signal there is, so that the answer to P's SYNC covers
        // all that were sent before P asked.
        loop {
            let info = match sigfd.read_signal() {
                Ok(Some(info)) => info,
                Ok(None) | Err(Errno::EINTR | Errno::EAGAIN) => break,
                Err(e) => return Err(format!("signalfd read failed: {e}")),
            };
            let Ok(sig) = Signal::try_from(i32::try_from(info.ssi_signo).unwrap_or(0)) else {
                continue;
            };
            if sig == Signal::SIGCHLD {
                if reap(child, up_w) {
                    return Ok(0);
                }
                continue;
            }
            // Job-control signals are P's business (freeze and thaw).
            if !FORWARDED.contains(&sig) || info.ssi_code == SI_KERNEL {
                continue;
            }
            // A sender outside this PID namespace shows as pid 0.
            if info.ssi_pid > 1 {
                job.forward(child, sig, private_fds);
            } else if shared_group.is_some()
                && info.ssi_code == SI_USER
                && info.ssi_pid == 0
                && let Some(b) = signal_byte(sig)
            {
                write_line(up_w, &format!("outside {b}"));
            }
        }
        for _ in 0..syncs {
            write_line(up_w, "synced");
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
        return Err(
            "--host and --pass-hosts need /etc/hosts to exist on this system to bind over it"
                .into(),
        );
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

pub(crate) fn clear_capabilities() -> Result<(), String> {
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
pub(crate) fn verify_dropped(uid: Uid, gid: Gid) -> Result<(), String> {
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

/// Give the command a group distinct from init without making the command
/// a group leader. This preserves its ability to call `setsid()` after exec.
fn join_private_group() -> Result<(), String> {
    let (hold, release) = pipe2(OFlag::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
    let anchor = match fork_checked()? {
        ForkResult::Child => {
            drop(release);
            while read(&hold, &mut [0]) == Err(Errno::EINTR) {}
            exit_now(0);
        }
        ForkResult::Parent { child } => child,
    };
    let joined = nix::unistd::setpgid(anchor, anchor)
        .and_then(|()| nix::unistd::setpgid(Pid::from_raw(0), anchor));
    drop(release);
    while waitpid(anchor, None) == Err(Errno::EINTR) {}
    joined.map_err(|e| format!("cannot join the workload process group: {e}"))
}

fn stage_x(
    plan: &Plan,
    job: JobControl,
    private_fds: Option<PrivateTtyFds>,
    tty_streams: [bool; 3],
) -> Result<std::convert::Infallible, String> {
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
    match job {
        JobControl::NewSession => {
            nix::unistd::setsid().map_err(|e| format!("cannot start a new session: {e}"))?;
        }
        JobControl::PrivateGroup => join_private_group()?,
        JobControl::CallerTerminal => {}
        JobControl::PrivateTerminal => {
            let fds = private_fds.ok_or("private terminal descriptors were lost")?;
            nix::unistd::setsid()
                .map_err(|e| format!("cannot create private terminal session: {e}"))?;
            if unsafe { libc::ioctl(fds.slave, libc::TIOCSCTTY as libc::c_ulong, 0) } < 0 {
                return Err(format!(
                    "cannot make the private terminal controlling: {}",
                    Errno::last()
                ));
            }
            let group = getpgrp().as_raw();
            if unsafe { libc::tcsetpgrp(fds.slave, group) } != 0 {
                return Err(format!(
                    "cannot assign the private terminal: {}",
                    Errno::last()
                ));
            }
            for (fd, attach) in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO]
                .into_iter()
                .zip(tty_streams)
            {
                if attach && unsafe { libc::dup2(fds.slave, fd) } < 0 {
                    return Err(format!(
                        "cannot attach standard stream to private terminal: {}",
                        Errno::last()
                    ));
                }
            }
        }
    }
    sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)
        .map_err(|e| format!("cannot unblock signals: {e}"))?;
    let (program, args) = plan.command.split_first().ok_or("no command was given")?;
    let mut cmd = Command::new(program);
    if let Some(fixture) = &plan.fixture {
        cmd.env("PLAYPEN_FIXTURE_URL", fixture.start()?);
    }
    let err = cmd.args(args).exec();
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
    fn startup_evidence_survives_fragmentation_and_truncation() {
        for (wire, expected) in [
            ("started\nexit 0\n", "handshake"),
            ("fail exec refused\n", "refused"),
            ("statuserr interrupted\n", "unknown"),
            ("started\nstatuserr lost status\n", "unknown"),
            ("fail refused\nstarted\n", "unknown"),
            ("init 3\n", "unknown"),
            ("fail partial", "unknown"),
        ] {
            // Enumerate every two cuts of each ordered status stream, including
            // empty reads. EINTR/EAGAIN leave the parser state untouched.
            for a in 0..=wire.len() {
                for b in a..=wire.len() {
                    let mut state = ParentState::default();
                    for chunk in [&wire[..a], &wire[a..b], &wire[b..]] {
                        state.receive(chunk.as_bytes());
                    }
                    let actual = match state.launch_result() {
                        Ok(()) => "handshake",
                        Err(RunError::NotStarted(_)) => "refused",
                        Err(RunError::Failed(_)) => "unknown",
                    };
                    assert_eq!(actual, expected, "{wire:?}, cuts {a}, {b}");
                }
            }
        }
    }

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
    fn deadline_and_withdrawal_share_an_irreversible_grace_period() {
        let base = Instant::now();
        let epoch = time::macros::datetime!(2026-11-18 22:00:00 UTC);
        let deadline = Deadline {
            monotonic: base + Duration::from_secs(5),
            wall: epoch + time::Duration::seconds(5),
        };
        // Three ordered supervisor polls. A wall reading may jump in either
        // direction, a poll can be late, and withdrawal can arrive at any poll.
        for first in 0..=5 {
            for second in first..=8 {
                for third in second..=11 {
                    for choices in 0_u32..216 {
                        let mut digits = choices;
                        let mut shutdown = Shutdown::default();
                        let mut first_stop = None;
                        let mut kill_sent = false;
                        for seconds in [first, second, third] {
                            let choice = digits % 6;
                            digits /= 6;
                            let wall_seconds = [-2, 5, 9][(choice % 3) as usize];
                            let withdrawn = choice >= 3;
                            let now = base + Duration::from_secs(seconds);
                            if deadline.passed(now, epoch + time::Duration::seconds(wall_seconds))
                                || withdrawn
                            {
                                shutdown.request(now);
                            }
                            if seconds >= 5 || wall_seconds >= 5 || withdrawn {
                                first_stop.get_or_insert(seconds);
                            }
                            assert_eq!(
                                shutdown.started,
                                first_stop.map(|s| base + Duration::from_secs(s))
                            );
                            let due = first_stop.is_some_and(|s| seconds >= s + GRACE.as_secs());
                            assert_eq!(shutdown.take_kill(now), due && !kill_sent);
                            kill_sent |= due;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_approval_is_over_when_either_clock_says_so() {
        let start = Instant::now();
        let wall = time::macros::datetime!(2026-11-18 22:00:00 UTC);
        let d = Deadline {
            monotonic: start + Duration::from_secs(3600),
            wall,
        };
        let sec = time::Duration::SECOND;
        assert!(!d.passed(start, wall - sec));
        assert!(d.passed(start + Duration::from_secs(3600), wall - sec));
        // The machine slept: the monotonic clock stood still, the end
        // came all the same.
        assert!(d.passed(start, wall));
        // The system clock was set back: the run is not extended.
        assert!(d.passed(start + Duration::from_secs(3601), wall - 7200 * sec));
    }

    #[test]
    fn signal_bytes_round_trip_and_do_not_collide() {
        for sig in FORWARDED {
            let b = signal_byte(sig);
            assert_eq!(b.and_then(byte_signal), Some(sig));
            let group = b.map(|b| b | GROUP_SENT);
            assert_eq!(group.and_then(byte_group_signal), Some(sig));
            assert_eq!(group.and_then(byte_signal), None);
            assert_eq!(b.and_then(byte_group_signal), None);
            for b in [b, group] {
                let others = [FREEZE, THAW, GO, BEAT, PRIVATE_TSTP, SYNC, SYNCED];
                assert!(b.is_some_and(|b| !others.contains(&b)));
            }
        }
        assert_eq!(signal_byte(Signal::SIGKILL), None);
        for b in [
            0,
            8,
            GROUP_SENT,
            GROUP_SENT | 8,
            FREEZE,
            THAW,
            GO,
            BEAT,
            PRIVATE_TSTP,
            SYNC,
            SYNCED,
        ] {
            assert_eq!(byte_signal(b), None);
            assert_eq!(byte_group_signal(b), None);
            assert_eq!(byte_index(b), None);
        }
    }

    #[test]
    fn parent_state_parses_lines() {
        let mut st = ParentState {
            buf: Vec::new(),
            failure: None,
            status_error: None,
            private_tstp: None,
            init: None,
            started: false,
            status: None,
            ended_at: None,
            drops: None,
            grant_packets: Vec::new(),
            lookups: None,
            ready: false,
            eof: false,
            own: Vec::new(),
            asked: 0,
            synced: 0,
            outside: [None; FORWARDED.len()],
            cut: None,
            refused_after_end: None,
            denied: Vec::new(),
            denied_error: None,
            contacts: None,
            tripped: None,
            trip_pending: None,
            cut_packets: None,
            uncounted: None,
            uncounted_unsaid: None,
        };
        st.handle_line("uncounted IPv6 packets to other hosts fail at routing");
        st.handle_line("uncounted a second reason");
        assert_eq!(
            st.uncounted.as_deref(),
            Some("IPv6 packets to other hosts fail at routing; a second reason")
        );
        st.handle_line("cuterr nft could not close egress");
        assert_eq!(st.cut, Some(Err("nft could not close egress".into())));
        st.handle_line("cut");
        assert_eq!(st.cut, Some(Ok(())));
        st.handle_line("afterend 12");
        assert_eq!(st.refused_after_end, Some(12));
        st.handle_line(r#"contacts {"destinations":[{"address":"192.0.2.1","protocol":"tcp","port":443,"packets":1,"answered":true,"reset":false}],"truncated":false}"#);
        let Some(Ok(contacted)) = &st.contacts else {
            panic!("{:?}", st.contacts)
        };
        assert_eq!(contacted.destinations[0].port, 443);
        st.handle_line("contacts {\"destinations\":[{\"port\":-1}]}");
        assert!(matches!(&st.contacts, Some(Err(e)) if e.starts_with("bad report")));
        st.handle_line("contactserr nft could not list the table");
        assert_eq!(
            st.contacts,
            Some(Err("nft could not list the table".into()))
        );
        st.handle_line("own 192.0.2.10 2001:db8::10 nonsense");
        let own: Vec<IpAddr> = ["192.0.2.10", "2001:db8::10"]
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect();
        assert_eq!(st.own, own);
        st.handle_line("synced");
        st.handle_line("outside 5");
        st.handle_line("outside 8");
        st.handle_line("outside usr1");
        assert_eq!(st.synced, 1);
        let reported: Vec<bool> = st.outside.iter().map(Option::is_some).collect();
        assert_eq!(reported, [false, false, false, false, true, false, false]);
        assert_eq!(FORWARDED[4], Signal::SIGUSR1);
        st.handle_line("ready");
        st.handle_line("init 4321");
        st.handle_line("started");
        st.handle_line("private-tstp outer");
        assert_eq!(st.private_tstp, Some(true));
        st.private_tstp = None;
        st.handle_line("exit 7");
        st.handle_line(r#"drops {"packets":2,"destinations":[],"destinations_truncated":true}"#);
        assert!(st.ready && st.started);
        assert_eq!(st.init, Some(Pid::from_raw(4321)));
        assert_eq!(st.status, Some(CommandStatus::Exited(7)));
        assert!(matches!(st.drops, Some(Ok(DropSummary { packets: 2, .. }))));
        st.handle_line("signal 15");
        assert_eq!(st.status, Some(CommandStatus::Signaled(15)));
        st.handle_line(
            r#"lookups {"names":[{"name":"a.test","count":2,"mapped":false},{"name":"\u001b[2J","count":1,"mapped":false}],"truncated":false}"#,
        );
        let lookups = st.lookups.take().and_then(Result::ok).unwrap_or_default();
        assert_eq!(lookups.names.len(), 1);
        assert_eq!(lookups.names[0].name, "a.test");
        assert!(
            lookups.truncated,
            "an unusable entry makes the list incomplete"
        );
        st.handle_line("lookupserr the DNS stub ended before the end of the run");
        assert!(matches!(st.lookups, Some(Err(_))));
        st.handle_line("cutcount 37");
        assert_eq!(st.cut_packets, Some(37));
    }

    #[test]
    fn the_first_tripped_line_is_kept_and_acted_on_once() {
        let mut st = ParentState::default();
        st.receive(
            b"tripped [{\"address\":\"198.51.100.9\",\"protocol\":\"udp\",\"port\":9563,\"packets\":1}]\n",
        );
        let first = st.trip_pending.take().unwrap_or_default();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].address, "198.51.100.9");
        assert_eq!(first[0].port, Some(9563));
        assert_eq!(st.tripped.as_ref(), Some(&first));
        st.receive(b"tripped []\n");
        assert!(st.trip_pending.is_none(), "a second line is ignored");
        assert_eq!(st.tripped, Some(first));
        // A list that does not parse still says that the cut tripped.
        let mut st = ParentState::default();
        st.receive(b"tripped not-json\n");
        assert_eq!(st.trip_pending, Some(Vec::new()));
        assert_eq!(st.tripped, Some(Vec::new()));
    }

    /// Records what P passes on from C's readings while the command runs.
    #[derive(Default)]
    struct Seen {
        denied: Vec<ruleset::DroppedDest>,
        unreadable: Vec<String>,
    }

    impl Events for Seen {
        fn starting(&mut self) {}
        fn until_reached(&mut self, _cut: &Cut) {}
        fn pass_edited(&mut self, _message: &str) {}
        fn pass_withdrawn(&mut self, _reason: &str, _cut: &Cut) {}
        fn denied(&mut self, dest: &ruleset::DroppedDest) {
            self.denied.push(dest.clone());
        }
        fn denied_unreadable(&mut self, why: &str) {
            self.unreadable.push(why.to_owned());
        }
    }

    #[test]
    fn denied_lines_are_passed_on_once_each_in_order() {
        let mut st = ParentState::default();
        st.receive(
            b"denied {\"address\":\"192.0.2.2\",\"protocol\":\"udp\",\"port\":9602,\"packets\":3}\n\
              denied {\"address\":\"2001:db8::2\",\"protocol\":\"ipv6-icmp\",\"port\":null,\"packets\":1}\n\
              denied not json\n\
              deniederr nft could not list the drop counter\n",
        );
        let mut seen = Seen::default();
        st.report_denied(&mut seen);
        let got: Vec<_> = seen
            .denied
            .iter()
            .map(|d| (d.address.as_str(), d.protocol.as_str(), d.port, d.packets))
            .collect();
        assert_eq!(
            got,
            [
                ("192.0.2.2", "udp", Some(9602), 3),
                ("2001:db8::2", "ipv6-icmp", None, 1)
            ]
        );
        assert_eq!(seen.unreadable, ["nft could not list the drop counter"]);
        // Passed on once: nothing is left for the next call.
        st.report_denied(&mut seen);
        assert_eq!(seen.denied.len(), 2);
        assert_eq!(seen.unreadable.len(), 1);
    }

    #[test]
    fn the_command_ended_when_its_status_was_read() {
        let mut st = ParentState::default();
        st.receive(b"started\nexi");
        assert!(st.ended_at.is_none());
        let before = time::OffsetDateTime::now_utc();
        st.receive(b"t 0\ndrops {}\n");
        let ended = st.ended_at;
        assert!(ended.is_some_and(|t| t >= before));
        st.receive(b"signal 9\n");
        assert_eq!(st.ended_at, ended, "the first status counts");
    }
}
