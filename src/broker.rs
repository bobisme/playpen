//! The pass broker (`--pass-broker`): hallpass reads and spends for the
//! command, done by a process on the host.
//!
//! A process that can write a ledger or its witness can roll them back (a
//! writable descriptor allows `ftruncate` and `pwrite`, `O_APPEND` can be
//! cleared with `F_SETFL`, an unprivileged user cannot make a file
//! append-only, `flock` is advisory, and writing the witness means writing
//! the state directory). So the command gets no descriptor or path with
//! write access to the pass, its ledger or the witness. It asks the broker
//! instead, over one Unix socket that is the only thing `--pass-broker`
//! exposes.
//!
//! The broker, B, is a child of P forked before the sandbox exists: it
//! stays in the host's namespaces, as the caller's uid, outside the PID
//! namespace the command can see. It holds the pass through the
//! directory P opened at start ([`crate::pass::PassDir`]) and the hallpass
//! state directory through a descriptor of its own ([`StateGuard`]), and
//! calls hallpass's library on those: the guest names no file. B has a
//! thread per connection, so a client that sends nothing or waits on a
//! lock holds only its own thread; P's supervision loop never waits on B.
//!
//! The protocol (`pass-broker-v1`) is one JSON object per line in each
//! direction; docs/spec.md lists every operation.

use std::collections::BTreeMap;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use hallpass::{
    Charge, Digest, Error as HpError, NamedTarget, Refusal, SpendChargesBatchRequest,
    SpendChargesRequest, SpendRequest, StateDir,
};
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::{ForkResult, Pid, getuid};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::pass::{PassDir, PassWatch, Recheck};

/// The protocol name, also the capability `playpen version` lists.
pub const PROTOCOL: &str = "pass-broker-v1";

/// The environment variable that holds the socket's path inside.
pub const ENV: &str = "PLAYPEN_PASS_BROKER";

/// The hallpass revision this build links, from `Cargo.lock`.
pub const HALLPASS_REVISION: &str = env!("PLAYPEN_HALLPASS_REVISION");

/// The operations of [`PROTOCOL`], as `hello` lists them.
pub const OPS: [&str; 8] = [
    "hello",
    "pass",
    "watch",
    "block-spend",
    "referenced-spend",
    "spend-batch",
    "receipt",
    "verified-ledger",
];

/// The longest request line, newline included.
pub const MAX_LINE: usize = 1 << 20;

/// The most connections open at once.
pub const MAX_CONNECTIONS: usize = 64;

/// The lock wait when a request names none.
pub const DEFAULT_LOCK_TIMEOUT_MS: u64 = 10_000;

/// The longest lock wait a request may ask for.
pub const MAX_LOCK_TIMEOUT_MS: u64 = 60_000;

/// Events a watch connection may have queued before it is dropped.
const WATCH_QUEUE: usize = 64;

/// The socket's name in the broker's directory.
const SOCKET_NAME: &str = "pass-broker.sock";

/// The warning hallpass adds to an allowed spend that checked no target
/// (`hallpass spend` without `--to`), word for word.
const NO_TARGET_CHECKED: &str = "no destination was checked: this spend has no --to target, and the pass does not set require_target_v1. Supply --to for each debit. The owner can add require_target_v1 = true to the pass to refuse debits without a target";

/// The hallpass state directory, held open from the start of the run.
///
/// Every spend writes the witness through the descriptor, so renaming a
/// directory above it does not send the witness somewhere else; a path
/// that no longer leads to it refuses the broker's work instead.
#[derive(Debug)]
pub struct StateGuard {
    /// As hallpass names it from the environment (`XDG_STATE_HOME`, else
    /// `HOME`): `.../hallpass`.
    given: PathBuf,
    /// The same, with every link resolved: what the mount hides.
    canonical: PathBuf,
    /// The directory, opened `O_PATH`.
    fd: Arc<OwnedFd>,
}

impl StateGuard {
    /// The state directory hallpass would use in this environment.
    ///
    /// # Errors
    /// When neither `XDG_STATE_HOME` nor `HOME` is absolute.
    pub fn path_from_env() -> Result<PathBuf, String> {
        StateDir::from_env()
            .path()
            .map(Path::to_path_buf)
            .map_err(|e| format!("--pass-broker: {e}"))
    }

    /// Opens the state directory, creating it (mode 0700) when it is not
    /// there yet, as hallpass's first spend would.
    ///
    /// # Errors
    /// When there is none, it cannot be created or opened, is a link, or
    /// others can read or change it.
    pub fn open() -> Result<Self, String> {
        Self::open_at(Self::path_from_env()?)
    }

    /// As [`StateGuard::open`], for the directory `given`.
    fn open_at(given: PathBuf) -> Result<Self, String> {
        let shown = given.display();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&given)
            .map_err(|e| {
                format!("--pass-broker: cannot create the hallpass state directory {shown}: {e}")
            })?;
        let meta = std::fs::symlink_metadata(&given).map_err(|e| {
            format!("--pass-broker: cannot read the hallpass state directory {shown}: {e}")
        })?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(format!(
                "--pass-broker: the hallpass state directory {shown} is a symbolic link or not a directory; hallpass refuses it, so the broker could not record a spend"
            ));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(format!(
                "--pass-broker: the hallpass state directory {shown} has mode {:04o}, so other users can read or change the witnesses; run `chmod 700 {shown}`",
                meta.mode() & 0o7777
            ));
        }
        let canonical = std::fs::canonicalize(&given)
            .map_err(|e| format!("--pass-broker: cannot resolve {shown}: {e}"))?;
        let fd = nix::fcntl::open(
            &canonical,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("--pass-broker: cannot open {shown}: {e}"))?;
        Ok(Self {
            given,
            canonical,
            fd: Arc::new(fd),
        })
    }

    /// The directory as the environment names it.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.given
    }

    /// The directory with links resolved.
    #[must_use]
    pub fn canonical(&self) -> &Path {
        &self.canonical
    }

    /// The held directory as a path of this process.
    fn held_path(&self) -> String {
        format!("/proc/self/fd/{}", self.fd.as_raw_fd())
    }

    /// hallpass's handle on the held directory. The trailing `.` makes the
    /// path name the directory itself, not the `/proc` link to it.
    fn state_dir(&self) -> StateDir {
        StateDir::new(format!("{}/.", self.held_path()))
    }

    /// Why the path no longer leads to the held directory, or `None`.
    fn moved(&self) -> Option<String> {
        self.held().moved()
    }

    /// The state directory as a [`crate::pass::HeldDir`], for the
    /// supervisor's re-read: a moved state directory stops the run.
    #[must_use]
    pub fn held(&self) -> crate::pass::HeldDir {
        crate::pass::HeldDir {
            fd: Arc::clone(&self.fd),
            path: self.given.clone(),
            what: "the hallpass state directory",
            breaks: "host tools would no longer find the witness the broker writes",
        }
    }
}

/// The broker's socket, its private directory and the state directory,
/// made before the sandbox. Dropping it removes the socket and the
/// directory.
#[derive(Debug)]
pub struct Broker {
    /// The new 0700 directory that holds the socket.
    dir: PathBuf,
    /// The socket.
    socket: PathBuf,
    /// The listening socket.
    listener: UnixListener,
    /// The hallpass state directory.
    state: StateGuard,
}

impl Broker {
    /// Makes a new 0700 directory (in the runtime directory, else the
    /// temporary one) and a listening socket in it.
    ///
    /// # Errors
    /// When the directory or the socket cannot be made.
    pub fn create(state: StateGuard) -> Result<Self, String> {
        let dir = crate::sandbox::private_dir().map_err(|e| format!("--pass-broker: {e}"))?;
        let socket = dir.join(SOCKET_NAME);
        let listener = match UnixListener::bind(&socket) {
            Ok(l) => l,
            Err(e) => {
                let _ = std::fs::remove_dir(&dir);
                return Err(format!(
                    "--pass-broker: cannot listen on {}: {e}",
                    socket.display()
                ));
            }
        };
        let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
        Ok(Self {
            dir,
            socket,
            listener,
            state,
        })
    }

    /// The socket's path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The hallpass state directory.
    #[must_use]
    pub const fn state(&self) -> &StateGuard {
        &self.state
    }

    /// The listening socket's descriptor number.
    #[must_use]
    pub fn listener_fd(&self) -> i32 {
        self.listener.as_raw_fd()
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// What the broker did, as it reports it to P when it ends.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, Deserialize)]
pub struct Stats {
    /// Connections accepted from the caller's uid.
    pub connections: u64,
    /// Connections refused: another uid, or too many at once.
    pub refused_connections: u64,
    /// Request lines read.
    pub requests: u64,
    /// Spend requests that recorded a debit (batches count once).
    pub recorded: u64,
    /// Spend requests refused, by hallpass or by the broker.
    pub refused: u64,
    /// Requests answered with an error.
    pub errors: u64,
}

/// P's end of the broker.
#[derive(Debug)]
pub struct Link {
    /// B, until it was waited for.
    pid: Option<Pid>,
    /// To B: `stop REASON` lines; end of file ends B.
    control: Option<OwnedFd>,
    /// From B: its [`Stats`] as one line when it ends.
    stats: OwnedFd,
}

impl Link {
    /// Tells B that P is stopping the command, and why.
    pub fn stopping(&self, reason: &str) {
        if let Some(c) = &self.control {
            crate::sandbox::write_line(c, &format!("stop {reason}"));
        }
    }

    /// P's descriptors of the link, for a child of P to close.
    #[must_use]
    pub fn raw_fds(&self) -> Vec<i32> {
        self.control
            .iter()
            .map(std::os::fd::AsRawFd::as_raw_fd)
            .chain([self.stats.as_raw_fd()])
            .collect()
    }

    /// Kills B and waits for it.
    fn kill(&mut self) {
        if let Some(pid) = self.pid.take() {
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
            let _ = nix::sys::wait::waitpid(pid, None);
        }
    }

    /// Ends B and returns what it did, or `None` when it did not say.
    #[must_use]
    pub fn finish(mut self) -> Option<Stats> {
        drop(self.control.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut line = Vec::new();
        let mut buf = [0u8; 4096];
        while !line.ends_with(b"\n") {
            let left = deadline.saturating_duration_since(Instant::now());
            let ms = u16::try_from(left.as_millis().clamp(1, 5000)).unwrap_or(5000);
            let mut fds = [nix::poll::PollFd::new(
                self.stats.as_fd(),
                nix::poll::PollFlags::POLLIN,
            )];
            match nix::poll::poll(&mut fds, nix::poll::PollTimeout::from(ms)) {
                Ok(0) => break,
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => break,
            }
            match nix::unistd::read(&self.stats, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => line.extend_from_slice(&buf[..n]),
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        // B exits right after the line; one that does not is killed.
        let end = Instant::now() + Duration::from_secs(1);
        while let Some(pid) = self.pid {
            match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                Ok(nix::sys::wait::WaitStatus::StillAlive) if Instant::now() < end => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(nix::sys::wait::WaitStatus::StillAlive) => self.kill(),
                _ => self.pid = None,
            }
        }
        serde_json::from_slice(line.trim_ascii()).ok()
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Forks B for `plan`, when it has a broker.
///
/// # Errors
/// When the plan has a broker but no pass, or [`start`] fails.
pub fn start_for(plan: &crate::sandbox::Plan) -> Result<Option<Link>, String> {
    match (&plan.broker, &plan.watch) {
        (Some(b), Some(w)) => start(b, w).map(Some),
        (Some(_), None) => Err("--pass-broker needs --pass".to_owned()),
        (None, _) => Ok(None),
    }
}

/// Forks B. P must be single-threaded; B serves until P closes the link.
///
/// # Errors
/// When a pipe or the fork fails.
pub fn start(broker: &Arc<Broker>, watch: &PassWatch) -> Result<Link, String> {
    let pipe = || nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(|e| format!("pipe: {e}"));
    let (control_r, control_w) = pipe()?;
    let (stats_r, stats_w) = pipe()?;
    let parent = nix::unistd::getpid();
    match crate::sandbox::fork_checked()? {
        ForkResult::Child => {
            drop(control_w);
            drop(stats_r);
            let code = serve(broker, watch.clone(), control_r, stats_w, parent);
            // SAFETY: _exit ends the process at once; nothing B inherited is
            // dropped or flushed.
            unsafe { libc::_exit(code) }
        }
        ForkResult::Parent { child } => Ok(Link {
            pid: Some(child),
            control: Some(control_w),
            stats: stats_r,
        }),
    }
}

/// B's setup, then its accept loop. Returns only when B cannot run.
fn serve(
    broker: &Arc<Broker>,
    watch: PassWatch,
    control: OwnedFd,
    stats: OwnedFd,
    parent: Pid,
) -> i32 {
    use nix::sys::signal::{SigHandler, SigSet, SigmaskHow, Signal, signal, sigprocmask};
    // A process group of its own: a Ctrl-C or Ctrl-Z at the terminal is
    // for the command and P, not for B, which P ends itself.
    let _ = nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0));
    if crate::sandbox::die_with_parent(parent).is_err() {
        return 1;
    }
    for sig in [
        Signal::SIGINT,
        Signal::SIGQUIT,
        Signal::SIGHUP,
        Signal::SIGTERM,
        Signal::SIGUSR1,
        Signal::SIGUSR2,
        Signal::SIGPIPE,
        Signal::SIGTSTP,
        Signal::SIGTTIN,
        Signal::SIGTTOU,
    ] {
        // SAFETY: SIG_IGN installs no handler code.
        let _ = unsafe { signal(sig, SigHandler::SigIgn) };
    }
    let _ = sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None);
    let shown = watch.dir().file();
    let interval = watch.interval;
    let shared = Arc::new(Shared {
        broker: Arc::clone(broker),
        dir: watch.dir().clone(),
        shown,
        watch: Mutex::new(watch),
        status: Mutex::new(Status::default()),
        subscribers: Mutex::new(Vec::new()),
        counts: Counts::default(),
        active: AtomicUsize::new(0),
        recheck_ms: u64::try_from(interval.as_millis()).unwrap_or(u64::MAX),
    });
    shared.recheck();
    {
        let shared = Arc::clone(&shared);
        if std::thread::Builder::new()
            .name("watch".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(interval);
                    shared.recheck();
                }
            })
            .is_err()
        {
            return 1;
        }
    }
    {
        let shared = Arc::clone(&shared);
        if std::thread::Builder::new()
            .name("control".into())
            .spawn(move || control_loop(&shared, &control, &stats))
            .is_err()
        {
            return 1;
        }
    }
    for stream in broker.listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        accept(&shared, stream);
    }
    1
}

/// Reads P's `stop` lines; at end of file sends the stats and ends B.
fn control_loop(shared: &Arc<Shared>, control: &OwnedFd, stats: &OwnedFd) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match nix::unistd::read(control, &mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
        }
        while let Some(at) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=at).collect();
            let text = String::from_utf8_lossy(&line);
            if let Some(reason) = text.trim_end().strip_prefix("stop ") {
                shared.stopping(reason);
            }
        }
    }
    let counts = shared.counts.snapshot();
    let line = serde_json::to_string(&counts).unwrap_or_default();
    crate::sandbox::write_line(stats, &line);
    // SAFETY: as in `start`: B ends here, dropping and flushing nothing.
    unsafe { libc::_exit(0) }
}

/// Counters behind [`Stats`].
#[derive(Default)]
struct Counts {
    connections: AtomicU64,
    refused_connections: AtomicU64,
    requests: AtomicU64,
    recorded: AtomicU64,
    refused: AtomicU64,
    errors: AtomicU64,
}

impl Counts {
    fn snapshot(&self) -> Stats {
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Stats {
            connections: get(&self.connections),
            refused_connections: get(&self.refused_connections),
            requests: get(&self.requests),
            recorded: get(&self.recorded),
            refused: get(&self.refused),
            errors: get(&self.errors),
        }
    }
}

fn bump(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

/// Why the broker refuses every spend from now on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Withdrawn {
    code: &'static str,
    message: String,
}

/// What the broker last saw of the pass.
#[derive(Debug, Default)]
struct Status {
    /// The digest of the last read, if it could be read.
    digest: Option<Digest>,
    /// The kind and digest of the last event sent, so a repeated finding is
    /// not sent again.
    last_event: Option<(&'static str, Option<Digest>)>,
    /// Set once: every later spend is refused with it.
    withdrawn: Option<Withdrawn>,
    /// P is stopping the command.
    stopping: bool,
}

/// What every thread of B shares.
struct Shared {
    broker: Arc<Broker>,
    dir: PassDir,
    /// The pass as P verified it at start.
    shown: PathBuf,
    watch: Mutex<PassWatch>,
    status: Mutex<Status>,
    subscribers: Mutex<Vec<SyncSender<String>>>,
    counts: Counts,
    active: AtomicUsize,
    recheck_ms: u64,
}

/// A poisoned lock only means another thread panicked holding it; the
/// data is still what it last wrote.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One read of the pass, as `pass` and every watch event give it.
struct Snapshot {
    digest: Option<Digest>,
    pass_id: Option<String>,
    state: Option<&'static str>,
    window: Value,
    text: Option<String>,
    error: Option<Value>,
}

impl Snapshot {
    fn fields(&self) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        m.insert("digest".into(), json!(self.digest.map(|d| d.to_string())));
        m.insert("pass_id".into(), json!(self.pass_id));
        m.insert("state".into(), json!(self.state));
        m.insert("window".into(), self.window.clone());
        m.insert("text".into(), json!(self.text));
        m.insert("error".into(), self.error.clone().unwrap_or(Value::Null));
        m
    }
}

impl Shared {
    /// Reads the pass through the held directory now.
    fn read(&self) -> (Snapshot, Option<hallpass::LoadedPass>) {
        let now = OffsetDateTime::now_utc();
        match self.dir.load_bytes(&self.shown) {
            Ok((loaded, bytes)) => {
                let state = loaded.pass.window_at(now);
                let snap = Snapshot {
                    digest: Some(loaded.digest),
                    pass_id: Some(loaded.pass.id.clone()),
                    state: Some(state.as_str()),
                    window: window_json(&loaded.pass, &state),
                    text: Some(String::from_utf8_lossy(&bytes).into_owned()),
                    error: None,
                };
                (snap, Some(loaded))
            }
            Err(e) => (
                Snapshot {
                    digest: None,
                    pass_id: None,
                    state: None,
                    window: Value::Null,
                    text: None,
                    error: Some(error_json("pass", &e)),
                },
                None,
            ),
        }
    }

    /// Re-reads the pass, judges it as P does, and sends an event for
    /// anything new. A finding that stops the run withdraws every later
    /// spend.
    fn recheck(&self) {
        // Held throughout, so the watcher and a `stop` from P judge one at
        // a time and send their events in order.
        let mut watch = lock(&self.watch);
        let now = OffsetDateTime::now_utc();
        let (snap, loaded) = self.read();
        let (kind, message): (&'static str, Option<String>) = if let Some(why) = self.dir.moved() {
            ("moved", Some(why))
        } else if let Some(why) = self.broker.state.moved() {
            ("state-moved", Some(why))
        } else if let Some(loaded) = &loaded {
            match watch.judge(&loaded.pass, loaded.digest, now) {
                Recheck::Unchanged => ("pass", None),
                Recheck::Edited(m) => ("pass", Some(m)),
                Recheck::Stop(m) => match snap.state {
                    Some(s @ ("revoked" | "expired" | "not-yet-valid")) => (s, Some(m)),
                    _ => ("narrowed", Some(m)),
                },
            }
        } else {
            let msg = snap
                .error
                .as_ref()
                .and_then(|e| e["error"]["message"].as_str());
            (
                "unreadable",
                Some(format!(
                    "the pass can no longer be read ({})",
                    msg.unwrap_or("unknown error")
                )),
            )
        };
        let mut status = lock(&self.status);
        let first = status.last_event.is_none();
        status.digest = snap.digest;
        let key = (kind, snap.digest);
        if status.last_event == Some(key) {
            return;
        }
        status.last_event = Some(key);
        if kind != "pass" && status.withdrawn.is_none() {
            status.withdrawn = Some(Withdrawn {
                code: match kind {
                    "moved" => "pass-moved",
                    "unreadable" => "pass-unreadable",
                    other => other,
                },
                message: message.clone().unwrap_or_default(),
            });
        }
        drop(status);
        // The first read at start is the baseline, not news.
        if !first {
            self.broadcast(kind, &snap, message.as_deref());
        }
    }

    /// P is stopping the command: a fresh read first, so its finding comes
    /// before the `stopping` event, then the event; spends end.
    fn stopping(&self, reason: &str) {
        self.recheck();
        let (snap, _) = self.read();
        {
            let mut status = lock(&self.status);
            status.stopping = true;
            if status.withdrawn.is_none() {
                status.withdrawn = Some(Withdrawn {
                    code: "stopping",
                    message: format!("playpen is stopping the command: {reason}"),
                });
            }
        }
        self.broadcast("stopping", &snap, Some(reason));
    }

    fn broadcast(&self, kind: &str, snap: &Snapshot, message: Option<&str>) {
        let mut event = snap.fields();
        event.insert("op".into(), json!("watch"));
        event.insert("event".into(), json!(kind));
        event.insert("message".into(), json!(message));
        event.insert(
            "at".into(),
            json!(hallpass::stamp(OffsetDateTime::now_utc())),
        );
        let line = self.finish_reply(Value::Object(event)).to_string();
        lock(&self.subscribers).retain(|s| match s.try_send(line.clone()) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        });
    }

    /// Replaces the `/proc/self/fd` paths B reads through with the host
    /// paths P verified, in every string of `v`.
    fn finish_reply(&self, mut v: Value) -> Value {
        let pass_dir = self.dir.held_path();
        let state_held = self.broker.state.held_path();
        let pairs = [
            (
                format!("{state_held}/."),
                self.broker.state.given.display().to_string(),
            ),
            (state_held, self.broker.state.given.display().to_string()),
            (pass_dir, self.dir.path().display().to_string()),
        ];
        scrub(&mut v, &pairs);
        v
    }

    /// The reason every spend is refused, if one is.
    fn withdrawn(&self) -> Option<Withdrawn> {
        let latched = lock(&self.status).withdrawn.clone();
        if latched.is_some() {
            return latched;
        }
        if let Some(why) = self.dir.moved() {
            return Some(Withdrawn {
                code: "pass-moved",
                message: why,
            });
        }
        self.broker.state.moved().map(|why| Withdrawn {
            code: "state-moved",
            message: why,
        })
    }
}

fn scrub(v: &mut Value, pairs: &[(String, String)]) {
    match v {
        Value::String(s) => {
            for (from, to) in pairs {
                if s.contains(from.as_str()) {
                    *s = s.replace(from.as_str(), to);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| scrub(x, pairs)),
        Value::Object(o) => o.values_mut().for_each(|x| scrub(x, pairs)),
        _ => {}
    }
}

/// Checks the peer and the connection limit, then serves the connection on
/// a thread of its own.
fn accept(shared: &Arc<Shared>, mut stream: UnixStream) {
    let refuse = |stream: &mut UnixStream, code: &str, message: &str| {
        bump(&shared.counts.refused_connections);
        let line = json!({
            "result": "error",
            "error": {"code": code, "recording": "not-recorded", "message": message},
            "warnings": [],
        });
        let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
        let _ = writeln!(stream, "{line}");
    };
    let peer = nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials);
    match peer {
        Ok(c) if c.uid() == getuid().as_raw() => {}
        Ok(c) => {
            refuse(
                &mut stream,
                "peer-refused",
                &format!(
                    "the pass broker serves only uid {}, and this connection is from uid {}",
                    getuid(),
                    c.uid()
                ),
            );
            return;
        }
        Err(e) => {
            refuse(
                &mut stream,
                "peer-refused",
                &format!("the pass broker cannot tell who is connecting ({e})"),
            );
            return;
        }
    }
    if shared.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
        shared.active.fetch_sub(1, Ordering::SeqCst);
        refuse(
            &mut stream,
            "too-many-connections",
            &format!(
                "the pass broker serves at most {MAX_CONNECTIONS} connections at once; close one and connect again"
            ),
        );
        return;
    }
    bump(&shared.counts.connections);
    let worker = Arc::clone(shared);
    let spawned = std::thread::Builder::new()
        .name("conn".into())
        .spawn(move || {
            connection(&worker, stream);
            worker.active.fetch_sub(1, Ordering::SeqCst);
        });
    if spawned.is_err() {
        shared.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Reads request lines and answers each, until the client closes, sends a
/// line that is too long, or asks to watch.
fn connection(shared: &Arc<Shared>, stream: UnixStream) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::with_capacity(64 * 1024, read_half);
    let mut out = stream;
    loop {
        let mut line = Vec::new();
        let limit = u64::try_from(MAX_LINE).unwrap_or(u64::MAX);
        match reader.by_ref().take(limit).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if !line.ends_with(b"\n") && line.len() >= MAX_LINE {
            bump(&shared.counts.errors);
            let reply = protocol_error(
                None,
                None,
                "line-too-long",
                &format!(
                    "a request line is at most {MAX_LINE} bytes, newline included; the connection is closed"
                ),
            );
            let _ = writeln!(out, "{reply}");
            return;
        }
        bump(&shared.counts.requests);
        let (reply, watch) = handle(shared, &line);
        let reply = shared.finish_reply(reply);
        if writeln!(out, "{reply}").is_err() {
            return;
        }
        if let Some(rx) = watch {
            serve_watch(&out, &rx);
            return;
        }
    }
}

/// Sends the events of one watch connection until it closes or B ends.
fn serve_watch(out: &UnixStream, rx: &Receiver<String>) {
    let mut out = out;
    let mut sink = [0u8; 4096];
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(line) => {
                if writeln!(out, "{line}").is_err() {
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        // Anything the client sends now is ignored; end of file ends it.
        match nix::sys::socket::recv(
            out.as_raw_fd(),
            &mut sink,
            nix::sys::socket::MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(0) => return,
            Ok(_) | Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {}
            Err(_) => return,
        }
    }
}

/// A reply that refuses a request before any hallpass call.
fn protocol_error(op: Option<&str>, id: Option<&Value>, code: &str, message: &str) -> Value {
    let mut v = json!({
        "op": op,
        "command": op,
        "result": "error",
        "error": {
            "code": code,
            "recording": "not-recorded",
            "seq": null,
            "ledger": null,
            "message": message,
            "line": null,
            "last_line": null,
        },
        "problems": [],
        "warnings": [],
    });
    if let Some(id) = id {
        v["id"] = id.clone();
    }
    v
}

/// The fields every request may have.
#[derive(Deserialize)]
struct Head {
    op: Option<Value>,
    id: Option<Value>,
}

/// Answers one request line; with `watch`, also the receiver of its events.
fn handle(shared: &Arc<Shared>, line: &[u8]) -> (Value, Option<Receiver<String>>) {
    let usage = |op: Option<&str>, id: Option<&Value>, message: String| {
        bump(&shared.counts.errors);
        protocol_error(op, id, "usage", &message)
    };
    let value: Value = match serde_json::from_slice(line) {
        Ok(v @ Value::Object(_)) => v,
        Ok(_) => {
            return (
                usage(
                    None,
                    None,
                    "a request is one JSON object on one line, such as {\"op\":\"hello\"}".into(),
                ),
                None,
            );
        }
        Err(e) => {
            return (
                usage(None, None, format!("the request is not valid JSON: {e}")),
                None,
            );
        }
    };
    let head: Head = serde_json::from_value(value.clone()).unwrap_or(Head { op: None, id: None });
    let id = head.id.as_ref();
    let Some(op) = head.op.as_ref().and_then(Value::as_str).map(str::to_owned) else {
        return (
            usage(
                None,
                id,
                format!(
                    "the request has no \"op\"; the operations are {}",
                    OPS.join(", ")
                ),
            ),
            None,
        );
    };
    let op = op.as_str();
    let result: Result<(Value, Option<Receiver<String>>), String> = match op {
        "hello" => parse::<Bare>(&value).map(|_| (hello(shared), None)),
        "pass" => parse::<Bare>(&value).map(|_| (pass_reply(shared), None)),
        "watch" => parse::<Bare>(&value).map(|_| {
            let (tx, rx) = std::sync::mpsc::sync_channel(WATCH_QUEUE);
            lock(&shared.subscribers).push(tx);
            let mut reply = pass_reply(shared);
            reply["command"] = json!("watch");
            reply["event"] = json!("current");
            (reply, Some(rx))
        }),
        "block-spend" => parse::<BlockSpend>(&value).map(|r| (block_spend(shared, &r), None)),
        "referenced-spend" => {
            parse::<ReferencedSpend>(&value).map(|r| (referenced_spend(shared, &r), None))
        }
        "spend-batch" => parse::<SpendBatch>(&value).map(|r| (spend_batch(shared, &r), None)),
        "receipt" => parse::<ReceiptReq>(&value).map(|r| (receipt(shared, &r), None)),
        "verified-ledger" => {
            parse::<LedgerReq>(&value).map(|r| (verified_ledger(shared, &r), None))
        }
        other => {
            bump(&shared.counts.errors);
            return (
                protocol_error(
                    Some(other),
                    id,
                    "unknown-op",
                    &format!(
                        "{other:?} is not an operation of {PROTOCOL}; the operations are {}",
                        OPS.join(", ")
                    ),
                ),
                None,
            );
        }
    };
    match result {
        Ok((mut reply, watch)) => {
            reply["op"] = json!(op);
            if let Some(id) = id {
                reply["id"] = id.clone();
            }
            if reply.get("warnings").is_none() {
                reply["warnings"] = json!([]);
            }
            match reply["result"].as_str() {
                Some("error") => bump(&shared.counts.errors),
                Some("refused") if op.ends_with("spend") || op == "spend-batch" => {
                    bump(&shared.counts.refused);
                }
                Some("allowed") => bump(&shared.counts.recorded),
                _ => {}
            }
            (reply, watch)
        }
        Err(message) => (usage(Some(op), id, message), None),
    }
}

/// Parses a request, refusing any field the operation does not take: the
/// guest cannot name a pass, a ledger or a state directory.
fn parse<T: for<'de> Deserialize<'de>>(value: &Value) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|e| format!("{e}; nothing was recorded"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bare {
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    op: String,
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    id: Option<Value>,
}

/// `to`: one target or a list.
#[derive(Deserialize, Default)]
#[serde(untagged)]
enum Targets {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl Targets {
    fn list(&self) -> Vec<String> {
        match self {
            Self::None => Vec::new(),
            Self::One(t) => vec![t.clone()],
            Self::Many(v) => v.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockSpend {
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    op: String,
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    id: Option<Value>,
    counter: String,
    n: Option<u64>,
    #[serde(default)]
    to: Targets,
    name: Option<String>,
    digest: Option<String>,
    #[serde(default)]
    duration: u32,
    note: Option<String>,
    #[serde(default)]
    dry_run: bool,
    lock_timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChargeIn {
    counter: String,
    n: Option<u64>,
    amount: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferencedSpend {
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    op: String,
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    id: Option<Value>,
    charges: Vec<ChargeIn>,
    #[serde(default)]
    to: Targets,
    name: Option<String>,
    digest: Option<String>,
    #[serde(default)]
    duration: u32,
    note: Option<String>,
    caller_ref: Option<String>,
    #[serde(default)]
    require_new_ref: bool,
    #[serde(default)]
    record_target: bool,
    #[serde(default)]
    dry_run: bool,
    lock_timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchUnit {
    caller_ref: String,
    to: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SpendBatch {
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    op: String,
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    id: Option<Value>,
    counter: String,
    units: Vec<BatchUnit>,
    digest: Option<String>,
    #[serde(default)]
    duration: u32,
    lock_timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptReq {
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    op: String,
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    id: Option<Value>,
    caller_ref: String,
    lock_timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerReq {
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    op: String,
    #[expect(dead_code, reason = "read by `handle`; listed so that it is allowed")]
    id: Option<Value>,
    counter: Option<String>,
    tail: Option<usize>,
    since: Option<u64>,
    lock_timeout_ms: Option<u64>,
}

fn hello(shared: &Shared) -> Value {
    json!({
        "command": "hello",
        "result": "ok",
        "protocol": PROTOCOL,
        "playpen_version": env!("CARGO_PKG_VERSION"),
        "hallpass_revision": HALLPASS_REVISION,
        "capabilities": OPS,
        "file": shared.shown.display().to_string(),
        "state_directory": shared.broker.state.given.display().to_string(),
        "recheck_ms": shared.recheck_ms,
        "limits": {
            "max_line_bytes": MAX_LINE,
            "max_connections": MAX_CONNECTIONS,
            "default_lock_timeout_ms": DEFAULT_LOCK_TIMEOUT_MS,
            "max_lock_timeout_ms": MAX_LOCK_TIMEOUT_MS,
            "max_batch_units": hallpass::MAX_DEBIT_BATCH_UNITS,
            "max_targets": hallpass::MAX_TARGETS,
        },
    })
}

/// `pass`: a read now, and whether spends are withdrawn.
fn pass_reply(shared: &Shared) -> Value {
    let (snap, _) = shared.read();
    let withdrawn = shared.withdrawn();
    let stopping = lock(&shared.status).stopping;
    let mut reply = snap.fields();
    reply.insert("command".into(), json!("pass"));
    reply.insert(
        "result".into(),
        json!(if snap.error.is_some() { "error" } else { "ok" }),
    );
    reply.insert("file".into(), json!(shared.shown.display().to_string()));
    if let Some(e) = &snap.error {
        reply.insert("error".into(), e["error"].clone());
        reply.insert("problems".into(), e["problems"].clone());
    }
    reply.insert(
        "withdrawn".into(),
        withdrawn.map_or(
            Value::Null,
            |w| json!({"code": w.code, "message": w.message}),
        ),
    );
    reply.insert("stopping".into(), json!(stopping));
    Value::Object(reply)
}

/// The window as `hallpass status --format json` gives it.
fn window_json(pass: &hallpass::Pass, state: &hallpass::WindowState) -> Value {
    use hallpass::WindowState as W;
    let seconds = |d: &time::Duration| d.whole_seconds().max(0);
    let up = |d: &time::Duration| hallpass::whole_seconds_up(*d);
    let (remaining, opens, ended, reason) = match state {
        W::Valid { remaining } => (Some(seconds(remaining)), None, None, None),
        W::NotYetValid { opens_in } => (None, Some(up(opens_in)), None, None),
        W::Expired { ended_ago } => (None, None, Some(seconds(ended_ago)), None),
        W::Revoked { reason } => (None, None, None, reason.clone()),
    };
    json!({
        "state": state.as_str(),
        "valid_from": hallpass::stamp(pass.approval.valid_from),
        "valid_until": hallpass::stamp(pass.approval.valid_until),
        "seconds_remaining": remaining,
        "seconds_until_open": opens,
        "seconds_since_end": ended,
        "revoked_reason": reason,
    })
}

/// What a failed hallpass call left in the ledger, as `hallpass` says it
/// in `error.recording`.
fn recording(op: &str, error: &HpError) -> Option<&'static str> {
    let writes = matches!(op, "block-spend" | "referenced-spend" | "spend-batch");
    match error {
        HpError::WitnessNotUpdated { .. } => Some("recorded"),
        HpError::AppendUncertain { .. } => Some("uncertain"),
        HpError::LockTimeout { .. } | HpError::Usage(_) | HpError::SharedDirectory { .. } => {
            Some("not-recorded")
        }
        HpError::WitnessUnavailable { detail, .. }
            if !detail.contains("was recorded in the ledger") =>
        {
            Some("not-recorded")
        }
        _ if !writes => Some("not-recorded"),
        _ => None,
    }
}

/// An error reply in the shape of `hallpass --format json`.
fn error_json(op: &str, error: &HpError) -> Value {
    let writes = matches!(op, "block-spend" | "referenced-spend" | "spend-batch");
    let problems: &[hallpass::Problem] = match error {
        HpError::Invalid { problems, .. } => problems,
        _ => &[],
    };
    let message = if writes {
        error.to_string()
    } else {
        error.read_only_message()
    };
    json!({
        "command": op,
        "result": "error",
        "error": {
            "code": error.code(),
            "recording": recording(op, error),
            "seq": match error { HpError::WitnessNotUpdated { seq, .. } => Some(*seq), _ => None },
            "ledger": match error {
                HpError::WitnessNotUpdated { path, .. } | HpError::AppendUncertain { path, .. } => {
                    Some(path.display().to_string())
                }
                _ => None,
            },
            "message": message,
            "line": match error { HpError::LedgerCorrupt { line, .. } => Some(*line), _ => None },
            "last_line": match error { HpError::LedgerCorrupt { last, .. } => Some(*last), _ => None },
        },
        "problems": problems,
        "warnings": [],
    })
}

/// A spend the broker refuses itself, in the shape of a refused
/// `hallpass spend` reply; `source` says it was the broker.
fn withdrawn_reply(shared: &Shared, op: &str, w: &Withdrawn) -> Value {
    let digest = lock(&shared.status).digest;
    json!({
        "command": if op == "spend-batch" { "spend-batch" } else { "spend" },
        "result": "refused",
        "source": "broker",
        "file": shared.shown.display().to_string(),
        "digest": digest.map(|d| d.to_string()),
        "seq": null,
        "charges": [],
        "units": [],
        "committed": 0,
        "refusal": {"code": w.code, "message": format!("{}. Nothing was recorded", w.message)},
        "warnings": [],
    })
}

fn lock_timeout(ms: Option<u64>) -> Result<Duration, String> {
    let ms = ms.unwrap_or(DEFAULT_LOCK_TIMEOUT_MS);
    if ms > MAX_LOCK_TIMEOUT_MS {
        return Err(format!(
            "lock_timeout_ms is at most {MAX_LOCK_TIMEOUT_MS}; nothing was recorded"
        ));
    }
    Ok(Duration::from_millis(ms))
}

fn parse_digest(text: Option<&str>) -> Result<Option<Digest>, HpError> {
    text.map(str::parse::<Digest>)
        .transpose()
        .map_err(|m| HpError::Usage(format!("digest: {m}; nothing was recorded")))
}

/// The targets, as `hallpass spend --to ... [--name]` parses them.
fn parse_targets(values: &[String], name: Option<&str>) -> Result<Vec<NamedTarget>, HpError> {
    if values.len() > hallpass::MAX_TARGETS {
        return Err(HpError::Usage(format!(
            "at most {} targets can be checked per question",
            hallpass::MAX_TARGETS
        )));
    }
    let mut targets = values
        .iter()
        .map(|v| {
            v.parse::<NamedTarget>()
                .map_err(|e| HpError::Usage(format!("to: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(name) = name {
        let [target] = targets.as_mut_slice() else {
            return Err(HpError::Usage(
                "name requires exactly one target in to; use ADDRESS:PORT/PROTO@NAME for per-target names"
                    .into(),
            ));
        };
        if target.name.is_some() {
            return Err(HpError::Usage("supply the name once per target".into()));
        }
        target.name = Some(name.parse().map_err(HpError::Usage)?);
    }
    Ok(targets)
}

fn targets_json(targets: &[NamedTarget], labels: &[String]) -> Value {
    json!(
        targets
            .iter()
            .enumerate()
            .map(|(i, t)| json!({
                "target": t.target.to_string(),
                "name": t.name.as_ref().map(hallpass::HostName::as_str),
                "label": labels.get(i),
            }))
            .collect::<Vec<_>>()
    )
}

fn refusal_json(r: &Refusal) -> Value {
    json!({"code": r.code.as_str(), "message": r.message})
}

fn receipt_json(r: &hallpass::DebitReceipt) -> Value {
    json!({
        "caller_ref": r.caller_ref,
        "targets": r.targets.iter().map(|t| json!({
            "target": t.target,
            "name": t.name,
            "label": t.label,
        })).collect::<Vec<_>>(),
    })
}

/// One charge of a spend reply, every key present.
fn charge_json(
    counter: &str,
    n: u64,
    total: Option<u64>,
    spent: u64,
    remaining: Option<u64>,
    projected: Option<u64>,
) -> Value {
    json!({
        "counter": counter,
        "n": n,
        "total": total,
        "spent": spent,
        "remaining": remaining,
        "projected_spent": projected,
    })
}

/// The decision behind one spend reply.
struct SpendReply<'a> {
    result: &'static str,
    file: &'a Path,
    digest: Digest,
    pass_id: &'a str,
    now: OffsetDateTime,
    charges: Vec<Value>,
    seq: Option<u64>,
    note: Option<&'a str>,
    targets: &'a [NamedTarget],
    labels: &'a [String],
    refused_target: Option<usize>,
    receipt: Option<&'a hallpass::DebitReceipt>,
    refusal: Option<&'a Refusal>,
    reference_evidence: Option<&'a hallpass::ReferenceEvidence>,
    warnings: &'a [String],
}

impl SpendReply<'_> {
    /// The reply of `hallpass spend --format json`, key for key.
    fn json(&self) -> Value {
        let only = match self.charges.as_slice() {
            [charge] => Some(charge),
            _ => None,
        };
        let pick = |k: &str| only.map_or(Value::Null, |c| c[k].clone());
        let first = self.targets.first();
        let mut warnings = self.warnings.to_vec();
        if self.refusal.is_none() && self.targets.is_empty() {
            warnings.push(NO_TARGET_CHECKED.to_owned());
        }
        json!({
            "command": "spend",
            "result": self.result,
            "file": self.file.display().to_string(),
            "digest": self.digest.to_string(),
            "pass_id": self.pass_id,
            "now": hallpass::stamp(self.now),
            "test_clock": false,
            "charges": self.charges,
            "counter": pick("counter"),
            "n": pick("n"),
            "total": pick("total"),
            "spent": pick("spent"),
            "remaining": pick("remaining"),
            "projected_spent": pick("projected_spent"),
            "seq": self.seq,
            "note": self.note,
            "targets": targets_json(self.targets, self.labels),
            "refused_target": self.refused_target,
            "target": first.map(|t| t.target.to_string()),
            "name": first.and_then(|t| t.name.as_ref()).map(hallpass::HostName::as_str),
            "label": self.labels.first(),
            "receipt": self.receipt.map(receipt_json),
            "refusal": self.refusal.map(refusal_json),
            "reference_evidence": self.reference_evidence,
            "warnings": warnings,
        })
    }
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// `block-spend`: `hallpass spend FILE COUNTER --n N`, the scalar spend.
fn block_spend(shared: &Shared, r: &BlockSpend) -> Value {
    const OP: &str = "block-spend";
    if let Some(w) = shared.withdrawn() {
        return withdrawn_reply(shared, OP, &w);
    }
    let timeout = match lock_timeout(r.lock_timeout_ms) {
        Ok(t) => t,
        Err(e) => return error_json(OP, &HpError::Usage(e)),
    };
    let inputs = parse_digest(r.digest.as_deref())
        .and_then(|d| parse_targets(&r.to.list(), r.name.as_deref()).map(|t| (d, t)));
    let (digest, targets) = match inputs {
        Ok(i) => i,
        Err(e) => return error_json(OP, &e),
    };
    let mut request = SpendRequest::new(&r.counter, r.n.unwrap_or(1));
    request.expect_digest = digest;
    request.needed = time::Duration::seconds(i64::from(r.duration));
    request.target = targets.first().map(|t| t.target);
    request.name = targets.first().and_then(|t| t.name.as_ref());
    request.additional_targets = targets.get(1..).unwrap_or_default();
    request.lock_timeout = Some(timeout);
    request.note = r.note.as_deref();
    let state = shared.broker.state.state_dir();
    let path = shared.dir.through();
    let answer = if r.dry_run {
        hallpass::preview_spend_with_clock_in(&path, &request, &state, now)
    } else {
        hallpass::spend_with_clock_in(&path, &request, &state, now)
    };
    let outcome = match answer {
        Ok(o) => o,
        Err(e) => return error_json(OP, &e),
    };
    let projected = (r.dry_run && outcome.refusal.is_none())
        .then(|| outcome.spent.checked_add(outcome.amount))
        .flatten();
    SpendReply {
        result: if outcome.refusal.is_some() {
            "refused"
        } else if r.dry_run {
            "would-allow"
        } else {
            "allowed"
        },
        file: &shared.shown,
        digest: outcome.digest,
        pass_id: &outcome.pass_id,
        now: outcome.now,
        charges: vec![charge_json(
            &outcome.counter,
            outcome.amount,
            outcome.total,
            outcome.spent,
            outcome.remaining(),
            projected,
        )],
        seq: outcome.seq,
        note: r.note.as_deref(),
        targets: &targets,
        labels: &outcome.labels,
        refused_target: outcome.refused_target,
        receipt: None,
        refusal: outcome.refusal.as_ref(),
        reference_evidence: None,
        warnings: &outcome.warnings,
    }
    .json()
}

/// `referenced-spend`: `hallpass spend --charge ... [--caller-ref]`, one
/// versioned debit.
fn referenced_spend(shared: &Shared, r: &ReferencedSpend) -> Value {
    const OP: &str = "referenced-spend";
    if let Some(w) = shared.withdrawn() {
        return withdrawn_reply(shared, OP, &w);
    }
    let timeout = match lock_timeout(r.lock_timeout_ms) {
        Ok(t) => t,
        Err(e) => return error_json(OP, &HpError::Usage(e)),
    };
    let mut charges = Vec::new();
    for c in &r.charges {
        let amount = match (c.n, c.amount) {
            (Some(n), None) | (None, Some(n)) => n,
            (None, None) => 1,
            (Some(_), Some(_)) => {
                return error_json(
                    OP,
                    &HpError::Usage(
                        "a charge has n or amount, not both; nothing was recorded".into(),
                    ),
                );
            }
        };
        charges.push(Charge {
            counter: &c.counter,
            amount,
        });
    }
    let inputs = parse_digest(r.digest.as_deref())
        .and_then(|d| parse_targets(&r.to.list(), r.name.as_deref()).map(|t| (d, t)));
    let (digest, targets) = match inputs {
        Ok(i) => i,
        Err(e) => return error_json(OP, &e),
    };
    let mut request = SpendChargesRequest::new(&charges);
    request.policy.expect_digest = digest;
    request.policy.needed = time::Duration::seconds(i64::from(r.duration));
    request.policy.target = targets.first().map(|t| t.target);
    request.policy.name = targets.first().and_then(|t| t.name.as_ref());
    request.policy.additional_targets = targets.get(1..).unwrap_or_default();
    request.policy.lock_timeout = Some(timeout);
    request.policy.note = r.note.as_deref();
    request.caller_ref = r.caller_ref.as_deref();
    request.require_new_ref = r.require_new_ref;
    request.record_targets = r.record_target;
    request.dry_run = r.dry_run;
    let state = shared.broker.state.state_dir();
    let outcome =
        match hallpass::spend_charges_with_clock_in(&shared.dir.through(), &request, &state, now) {
            Ok(o) => o,
            Err(e) => return error_json(OP, &e),
        };
    let result = match (&outcome.refusal, outcome.seq) {
        (Some(_), _) => "refused",
        (None, Some(_)) => "allowed",
        (None, None) => "would-allow",
    };
    SpendReply {
        result,
        file: &shared.shown,
        digest: outcome.digest,
        pass_id: &outcome.pass_id,
        now: outcome.now,
        charges: outcome
            .charges
            .iter()
            .map(|c| {
                charge_json(
                    &c.counter,
                    c.amount,
                    c.total,
                    c.spent,
                    c.remaining,
                    c.projected_spent,
                )
            })
            .collect(),
        seq: outcome.seq,
        note: r.note.as_deref(),
        targets: &targets,
        labels: &outcome.labels,
        refused_target: outcome.refused_target,
        receipt: outcome.receipt.as_ref(),
        refusal: outcome.refusal.as_ref(),
        reference_evidence: outcome.reference_evidence.as_ref(),
        warnings: &outcome.warnings,
    }
    .json()
}

/// `spend-batch`: `spend_charges_batch`, all or none, for 1 to 1024
/// one-unit debits with distinct caller references.
fn spend_batch(shared: &Shared, r: &SpendBatch) -> Value {
    const OP: &str = "spend-batch";
    if let Some(w) = shared.withdrawn() {
        return withdrawn_reply(shared, OP, &w);
    }
    let timeout = match lock_timeout(r.lock_timeout_ms) {
        Ok(t) => t,
        Err(e) => return error_json(OP, &HpError::Usage(e)),
    };
    let digest = match parse_digest(r.digest.as_deref()) {
        Ok(d) => d,
        Err(e) => return error_json(OP, &e),
    };
    let mut targets = Vec::new();
    for (i, u) in r.units.iter().enumerate() {
        match u.to.as_deref().map(str::parse::<NamedTarget>).transpose() {
            Ok(t) => targets.push(t),
            Err(e) => {
                return error_json(
                    OP,
                    &HpError::Usage(format!("unit {}: to: {e}; nothing was recorded", i + 1)),
                );
            }
        }
    }
    let charge = [Charge {
        counter: &r.counter,
        amount: 1,
    }];
    let units: Vec<SpendChargesRequest<'_>> = r
        .units
        .iter()
        .zip(&targets)
        .map(|(u, t)| {
            let mut unit = SpendChargesRequest::new(&charge);
            unit.caller_ref = Some(&u.caller_ref);
            unit.require_new_ref = true;
            unit.policy.expect_digest = digest;
            unit.policy.needed = time::Duration::seconds(i64::from(r.duration));
            unit.policy.target = t.as_ref().map(|t| t.target);
            unit.policy.name = t.as_ref().and_then(|t| t.name.as_ref());
            unit.record_targets = t.is_some();
            unit
        })
        .collect();
    let mut request = SpendChargesBatchRequest::new(&units);
    request.lock_timeout = Some(timeout);
    let state = shared.broker.state.state_dir();
    let outcome = match hallpass::spend_charges_batch_with_clock_in(
        &shared.dir.through(),
        &request,
        &state,
        now,
    ) {
        Ok(o) => o,
        Err(e) => return error_json(OP, &e),
    };
    let requested = u64::try_from(units.len()).unwrap_or(u64::MAX);
    let committed = u64::try_from(outcome.units.len()).unwrap_or(u64::MAX);
    let before = outcome.spent.saturating_sub(committed);
    json!({
        "command": "spend-batch",
        "result": if outcome.refusal.is_some() { "refused" } else { "allowed" },
        "file": shared.shown.display().to_string(),
        "digest": outcome.digest.to_string(),
        "pass_id": outcome.pass_id,
        "now": hallpass::stamp(outcome.now),
        "test_clock": false,
        "counter": outcome.counter,
        "total": outcome.total,
        "spent_before": before,
        "spent": outcome.spent,
        "remaining": outcome.remaining,
        "requested": requested,
        "committed": committed,
        "projected_spent": before.checked_add(requested),
        "refused_unit": outcome.refused_unit,
        "refusal": outcome.refusal.as_ref().map(refusal_json),
        "reference_evidence": outcome.reference_evidence,
        "units": outcome.units.iter().map(|u| json!({
            "caller_ref": u.caller_ref,
            "seq": u.seq,
            "labels": u.labels,
            "receipt": receipt_json(&u.receipt),
        })).collect::<Vec<_>>(),
        "warnings": outcome.warnings,
    })
}

/// Loads the pass through the held directory for a read-only operation.
fn load_for(shared: &Shared, op: &str) -> Result<hallpass::LoadedPass, Value> {
    if let Some(why) = shared.dir.moved() {
        return Err(protocol_error(Some(op), None, "pass-moved", &why));
    }
    if let Some(why) = shared.broker.state.moved() {
        return Err(protocol_error(Some(op), None, "state-moved", &why));
    }
    shared
        .dir
        .load(&shared.shown)
        .map_err(|e| error_json(op, &e))
}

/// `receipt`: `hallpass receipt FILE --caller-ref REF`.
fn receipt(shared: &Shared, r: &ReceiptReq) -> Value {
    const OP: &str = "receipt";
    let timeout = match lock_timeout(r.lock_timeout_ms) {
        Ok(t) => t,
        Err(e) => return error_json(OP, &HpError::Usage(e)),
    };
    let loaded = match load_for(shared, OP) {
        Ok(l) => l,
        Err(v) => return v,
    };
    let state = shared.broker.state.state_dir();
    match hallpass::with_lock_wait(Some(timeout), None, || {
        hallpass::evidence::lookup_receipt(&loaded, &state, &r.caller_ref)
    }) {
        Ok(report) => {
            let mut v = json!(report);
            v["command"] = json!("receipt");
            v["file"] = json!(shared.shown.display().to_string());
            v
        }
        Err(e) => error_json(OP, &e),
    }
}

/// `verified-ledger`: `hallpass ledger FILE --format json`, the whole chain
/// verified against the witness.
fn verified_ledger(shared: &Shared, r: &LedgerReq) -> Value {
    const OP: &str = "verified-ledger";
    if let Some(name) = r.counter.as_deref()
        && !hallpass::is_counter_name(name)
    {
        return error_json(
            OP,
            &HpError::Usage(format!(
                "counter: `{name}` is not a counter name (lower-case letters, digits, `_` and `-`, starting with a letter)"
            )),
        );
    }
    let timeout = match lock_timeout(r.lock_timeout_ms) {
        Ok(t) => t,
        Err(e) => return error_json(OP, &HpError::Usage(e)),
    };
    let loaded = match load_for(shared, OP) {
        Ok(l) => l,
        Err(v) => return v,
    };
    let state = shared.broker.state.state_dir();
    let view = match hallpass::with_lock_wait(Some(timeout), None, || {
        hallpass::read_ledger(&loaded, &state)
    }) {
        Ok(v) => v,
        Err(e) => return error_json(OP, &e),
    };
    ledger_json(shared, &loaded, &view, r)
}

#[expect(
    clippy::too_many_lines,
    reason = "one JSON reply that mirrors `hallpass ledger`, field for field"
)]
fn ledger_json(
    shared: &Shared,
    loaded: &hallpass::LoadedPass,
    view: &hallpass::LedgerView,
    r: &LedgerReq,
) -> Value {
    let counter = r.counter.as_deref();
    let wanted = |name: &str| counter.is_none_or(|c| c == name);
    let mut entries: Vec<&hallpass::LedgerEntry> =
        view.entries.iter().filter(|e| wanted(&e.counter)).collect();
    let mut debits: Vec<&hallpass::LedgerDebit> = view
        .debits
        .iter()
        .filter(|e| e.charges.iter().any(|c| wanted(&c.counter)))
        .collect();
    let mut adoptions: Vec<&hallpass::Adoption> = view.adoptions.iter().collect();
    let mut reconciliations: Vec<&hallpass::ReferenceReconciliation> =
        view.reconciliations.iter().collect();
    let shown = if r.tail.is_some() || r.since.is_some() {
        let mut seqs: Vec<u64> = entries
            .iter()
            .map(|e| e.seq)
            .chain(debits.iter().map(|e| e.seq))
            .chain(adoptions.iter().map(|a| a.seq))
            .chain(reconciliations.iter().map(|x| x.seq))
            .filter(|seq| r.since.is_none_or(|s| *seq >= s))
            .collect();
        seqs.sort_unstable();
        if let Some(n) = r.tail {
            seqs.drain(..seqs.len().saturating_sub(n));
        }
        let keep: std::collections::HashSet<u64> = seqs.iter().copied().collect();
        entries.retain(|e| keep.contains(&e.seq));
        debits.retain(|e| keep.contains(&e.seq));
        adoptions.retain(|a| keep.contains(&a.seq));
        reconciliations.retain(|x| keep.contains(&x.seq));
        json!({
            "from": seqs.first(),
            "to": seqs.last(),
            "of": view.entries.len() + view.debits.len() + view.adoptions.len() + view.reconciliations.len(),
        })
    } else {
        Value::Null
    };
    let mut events: Vec<(u64, Value)> = entries
        .iter()
        .map(|e| {
            (
                e.seq,
                json!({
                    "seq": e.seq,
                    "time": hallpass::rfc3339(e.time),
                    "counter": e.counter,
                    "n": e.amount,
                    "digest": e.digest.to_string(),
                    "note": e.note,
                }),
            )
        })
        .chain(debits.iter().map(|e| {
            (
                e.seq,
                json!({
                    "seq": e.seq,
                    "time": hallpass::rfc3339(e.time),
                    "event": "debit",
                    "version": 1,
                    "charges": e.charges,
                    "digest": e.digest.to_string(),
                    "note": e.note,
                    "receipt": e.receipt,
                }),
            )
        }))
        .collect();
    events.sort_by_key(|(seq, _)| *seq);
    let pass = &loaded.pass;
    let mut names: Vec<&str> = pass
        .ceilings
        .keys()
        .chain(view.tally.spent.keys())
        .map(String::as_str)
        .filter(|n| wanted(n))
        .collect();
    if let Some(c) = counter {
        names.push(c);
    }
    names.sort_unstable();
    names.dedup();
    let totals: BTreeMap<&str, (u64, Option<u64>)> = names
        .iter()
        .map(|n| (*n, (view.tally.spent(n), pass.ceilings.get(*n).copied())))
        .collect();
    let witnessed = |w: &hallpass::Witnessed| json!({"ledger": w.ledger, "seq": w.seq, "totals": w.totals, "updated": w.updated});
    json!({
        "command": "ledger",
        "result": "ok",
        "file": shared.shown.display().to_string(),
        "ledger": view.path.display().to_string(),
        "exists": view.exists,
        "pass_id": pass.id,
        "digest": loaded.digest.to_string(),
        "counter": counter,
        "shown": shown,
        "verified": true,
        "witness": view.witness.as_str(),
        "moved_from": view.moved_from,
        "entries": events.into_iter().map(|(_, e)| e).collect::<Vec<_>>(),
        "adoptions": adoptions.iter().map(|a| json!({
            "seq": a.seq,
            "time": hallpass::rfc3339(a.time),
            "reason": a.reason,
            "digest": a.digest.to_string(),
            "carried": a.carried,
            "previous": a.previous.as_ref().map(witnessed),
            "may_have_lost_references": a.makes_references_inconclusive(),
        })).collect::<Vec<_>>(),
        "reference_reconciliations": reconciliations.iter().map(|x| json!({
            "seq": x.seq,
            "time": hallpass::rfc3339(x.time),
            "adoption": x.adoption,
            "reason": x.reason,
            "digest": x.digest.to_string(),
            "references": x.references,
        })).collect::<Vec<_>>(),
        "unreconciled_adoption": view.unreconciled_adoption,
        "totals": totals.iter().map(|(name, (spent, total))| json!({
            "name": name,
            "spent": spent,
            "total": total,
            "remaining": total.map(|t| t.saturating_sub(*spent)),
            "over_ceiling": total.is_some_and(|t| *spent > t),
            "over_by": total.map(|t| spent.saturating_sub(t)),
        })).collect::<Vec<_>>(),
        "warnings": view.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A new, empty directory for one test.
    fn tmpdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("playpen-broker-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        dir
    }

    #[test]
    fn the_socket_is_alone_in_a_new_private_directory_removed_at_the_end() {
        let root = tmpdir("socket");
        let state = StateGuard::open_at(root.join("state").join("hallpass"))
            .unwrap_or_else(|e| panic!("{e}"));
        let meta = std::fs::metadata(state.path()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(meta.mode() & 0o777, 0o700);
        let broker = Broker::create(state).unwrap_or_else(|e| panic!("{e}"));
        let dir = broker
            .socket()
            .parent()
            .map_or_else(PathBuf::new, Path::to_path_buf);
        let meta = std::fs::metadata(&dir).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(meta.mode() & 0o777, 0o700, "{}", dir.display());
        assert_eq!(meta.uid(), getuid().as_raw());
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{e}"))
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from(SOCKET_NAME)]);
        let sock = std::fs::symlink_metadata(broker.socket()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(sock.mode() & 0o777, 0o600);
        drop(broker);
        assert!(!dir.exists(), "{}", dir.display());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_state_directory_others_can_reach_or_a_link_is_refused() {
        let root = tmpdir("state");
        let open = std::fs::create_dir_all(root.join("open"));
        assert!(open.is_ok());
        let _ = std::fs::set_permissions(root.join("open"), std::fs::Permissions::from_mode(0o755));
        let e = StateGuard::open_at(root.join("open"))
            .err()
            .unwrap_or_default();
        assert!(e.contains("has mode 0755"), "{e}");
        let _ = std::os::unix::fs::symlink(root.join("open"), root.join("link"));
        let e = StateGuard::open_at(root.join("link"))
            .err()
            .unwrap_or_default();
        assert!(e.contains("symbolic link"), "{e}");
        let held = StateGuard::open_at(root.join("held")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(held.moved(), None);
        let _ = std::fs::rename(root.join("held"), root.join("held.moved"));
        assert!(held.moved().is_some_and(|m| m.contains("moved or removed")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_revision_is_a_full_commit() {
        assert_eq!(HALLPASS_REVISION.len(), 40, "{HALLPASS_REVISION}");
        assert_eq!(
            HALLPASS_REVISION,
            "7c06ea837ab6aa98858dc18e4be1fbaf6f3e85ff"
        );
    }

    #[test]
    fn host_paths_replace_the_proc_paths_everywhere() {
        let mut v = json!({"a": "/proc/self/fd/7/p.toml.ledger", "b": ["x /proc/self/fd/9/. y"]});
        scrub(
            &mut v,
            &[
                ("/proc/self/fd/9/.".into(), "/s/hallpass".into()),
                ("/proc/self/fd/7".into(), "/p".into()),
            ],
        );
        assert_eq!(
            v,
            json!({"a": "/p/p.toml.ledger", "b": ["x /s/hallpass y"]})
        );
    }

    #[test]
    fn every_failed_spend_says_what_it_left_in_the_ledger() {
        let usage = HpError::Usage("x".into());
        assert_eq!(recording("block-spend", &usage), Some("not-recorded"));
        let witness = HpError::WitnessNotUpdated {
            path: PathBuf::from("l"),
            seq: 3,
            detail: "d".into(),
        };
        assert_eq!(recording("spend-batch", &witness), Some("recorded"));
        let v = error_json("spend-batch", &witness);
        assert_eq!(v["error"]["seq"], 3);
        assert_eq!(v["result"], "error");
        let append = HpError::AppendUncertain {
            path: PathBuf::from("l"),
            event: "debit".into(),
            detail: "d".into(),
        };
        assert_eq!(recording("referenced-spend", &append), Some("uncertain"));
        let io = HpError::Io {
            path: PathBuf::from("l"),
            message: "m".into(),
        };
        assert_eq!(recording("referenced-spend", &io), None);
        assert_eq!(recording("receipt", &io), Some("not-recorded"));
    }

    #[test]
    fn targets_parse_as_hallpass_spend_parses_them() {
        let t = parse_targets(&["192.0.2.1:443/tcp".into()], Some("app.example.test"))
            .unwrap_or_default();
        assert_eq!(t.len(), 1);
        assert!(parse_targets(&["nonsense".into()], None).is_err());
        assert!(
            parse_targets(
                &["192.0.2.1:443/tcp".into(), "192.0.2.2:443/tcp".into()],
                Some("a.test")
            )
            .is_err()
        );
    }
}
