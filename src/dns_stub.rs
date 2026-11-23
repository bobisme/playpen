//! The DNS stub: a small server on the sandbox's loopback, `127.0.0.1`
//! port 53, UDP and TCP, that answers only the `--host` names and records
//! the names the command looked up.
//!
//! It reads the question of each query and nothing else. A `--host` name
//! gets its mapped A or AAAA records; every other name gets "no such name"
//! (NXDOMAIN). It forwards nothing, anywhere.
//!
//! C (see [`crate::sandbox`]) forks it before the command exists. It runs
//! in C's PID namespace, outside the command's, so the command can neither
//! see nor signal nor trace it. It binds port 53 with the capabilities C
//! holds over the network namespace, then drops them all, sets
//! `no_new_privs`, and checks the drop. When the command has ended, C
//! closes the stub's control pipe; the stub sends back what it recorded
//! and exits.
//!
//! The names come from the command. Before a name leaves the stub, every
//! byte other than a letter, a digit, `-` and `_` is written `\DDD` (its
//! decimal value, as in DNS presentation format), and a name longer than
//! [`NAME_MAX`] bytes is cut and ends in `...`.

use std::fmt::Write as _;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::prctl;
use nix::sys::signal::{Signal, kill};
use nix::sys::stat::Mode;
use nix::sys::wait::waitpid;
use nix::unistd::{ForkResult, Gid, Pid, Uid, getpid, pipe2, read};
use serde::{Deserialize, Serialize};

use crate::resolver::HostEntry;

/// The address the stub listens on, and the only nameserver in the
/// sandbox's `/etc/resolv.conf`.
pub const ADDRESS: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// The port the stub listens on.
pub const PORT: u16 = 53;

/// Most distinct names recorded. A new name after that sets `truncated`.
pub const LIMIT: usize = 256;

/// Longest name recorded, in bytes, after escaping.
pub const NAME_MAX: usize = 253;

/// Longest answer over UDP (no EDNS is offered).
const UDP_MAX: usize = 512;

/// Longest answer over TCP.
const TCP_MAX: usize = 65_535;

/// Most TCP connections served at once; more are closed at once.
const CONNECTIONS: usize = 16;

/// A TCP connection that makes no progress for this long is closed.
const IDLE: Duration = Duration::from_secs(5);

/// Most answer bytes kept for a TCP client that does not read them.
const PENDING_MAX: usize = 128 * 1024;

/// How long C waits for the stub to listen.
const READY_LIMIT: Duration = Duration::from_secs(5);

/// How long C waits for the stub's record once it has asked for it.
const RECORD_LIMIT: Duration = Duration::from_secs(2);

/// Most bytes C reads from the stub.
const RECORD_MAX: usize = 1024 * 1024;

const HEADER: usize = 12;
const QR: u16 = 0x8000;
const AA: u16 = 0x0400;
const TC: u16 = 0x0200;
const RD: u16 = 0x0100;
const RA: u16 = 0x0080;
const NOERROR: u16 = 0;
const FORMERR: u16 = 1;
const NXDOMAIN: u16 = 3;
const NOTIMP: u16 = 4;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
const CLASS_ANY: u16 = 255;

/// The names the command looked up. Report field `lookups`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lookups {
    /// Each distinct name, in the order it was first looked up.
    pub names: Vec<LookedUp>,
    /// True when the list is incomplete: more than [`LIMIT`] distinct
    /// names were looked up, or an entry was unusable.
    pub truncated: bool,
}

/// One name the command looked up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookedUp {
    /// The name, escaped (see the module comment), in lower case.
    pub name: String,
    /// How many queries asked for it.
    pub count: u64,
    /// Whether a `--host` entry maps it.
    pub mapped: bool,
}

impl Lookups {
    /// Counts one query for `name`.
    fn record(&mut self, name: String, mapped: bool) {
        if let Some(seen) = self.names.iter_mut().find(|n| n.name == name) {
            seen.count = seen.count.saturating_add(1);
        } else if self.names.len() < LIMIT {
            self.names.push(LookedUp {
                name,
                count: 1,
                mapped,
            });
        } else {
            self.truncated = true;
        }
    }

    /// The record as received from another process, with every entry that
    /// is not a shown name, has no count, or repeats an earlier one left
    /// out (and `truncated` set), and at most [`LIMIT`] entries.
    #[must_use]
    pub fn sanitized(self) -> Self {
        let mut out = Self {
            names: Vec::new(),
            truncated: self.truncated,
        };
        for entry in self.names {
            if !is_shown(&entry.name)
                || entry.count == 0
                || out.names.len() >= LIMIT
                || out.names.iter().any(|n| n.name == entry.name)
            {
                out.truncated = true;
            } else {
                out.names.push(entry);
            }
        }
        out
    }

    /// The names no `--host` entry maps, in the order first looked up.
    pub fn unmapped(&self) -> impl Iterator<Item = &LookedUp> {
        self.names.iter().filter(|n| !n.mapped)
    }
}

/// Whether `name` is safe to print and could have come from [`show`]:
/// at most [`NAME_MAX`] bytes of letters, digits, `.`, `-`, `_` and `\`.
#[must_use]
pub fn is_shown(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'\\'))
}

/// A name in the form the report shows it.
///
/// Labels are lower-cased and joined with `.`; a byte other than a letter,
/// a digit, `-` or `_` is written `\DDD`, so a `.` inside a label is
/// `\046` and an escape character `\027`. The root name is `.`. A result
/// longer than [`NAME_MAX`] bytes is cut, never inside an escape, and ends
/// in `...` (two dots in a row occur in no other shown name).
#[must_use]
pub fn show(labels: &[&[u8]]) -> String {
    if labels.is_empty() {
        return ".".to_owned();
    }
    let mut full = String::new();
    for (i, label) in labels.iter().enumerate() {
        if i > 0 {
            full.push('.');
        }
        for &b in *label {
            let b = b.to_ascii_lowercase();
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                full.push(char::from(b));
            } else {
                let _ = write!(full, "\\{b:03}");
            }
        }
    }
    if full.len() <= NAME_MAX {
        return full;
    }
    let mut cut = String::new();
    let mut rest = full.as_str();
    while !rest.is_empty() {
        let unit = if rest.starts_with('\\') { 4 } else { 1 };
        let Some((piece, tail)) = rest.split_at_checked(unit.min(rest.len())) else {
            break;
        };
        if cut.len() + piece.len() > NAME_MAX - 3 {
            break;
        }
        cut.push_str(piece);
        rest = tail;
    }
    cut.push_str("...");
    cut
}

/// The `--host` entries, by name.
#[derive(Debug, Clone, Default)]
pub struct Hosts(Vec<(String, Vec<IpAddr>)>);

impl Hosts {
    /// Groups the entries by name, keeping their order.
    #[must_use]
    pub fn new(entries: &[HostEntry]) -> Self {
        let mut out: Vec<(String, Vec<IpAddr>)> = Vec::new();
        for h in entries {
            match out.iter_mut().find(|(name, _)| *name == h.name) {
                Some((_, addrs)) if !addrs.contains(&h.addr) => addrs.push(h.addr),
                Some(_) => {}
                None => out.push((h.name.clone(), vec![h.addr])),
            }
        }
        Self(out)
    }

    fn get(&self, shown: &str) -> Option<&[IpAddr]> {
        self.0
            .iter()
            .find(|(name, _)| name == shown)
            .map(|(_, addrs)| addrs.as_slice())
    }
}

fn be16(msg: &[u8], at: usize) -> Option<u16> {
    let bytes: [u8; 2] = msg.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// The question of a query.
struct Question<'a> {
    labels: Vec<&'a [u8]>,
    qtype: u16,
    qclass: u16,
    /// The question as received (name, type, class), echoed in the answer.
    raw: &'a [u8],
}

/// Reads the one question after the header. `None` when it is malformed:
/// cut short, a label of a reserved type or a compression pointer (no
/// client compresses the only name of a query), or a name longer than
/// 255 bytes on the wire.
fn read_question(msg: &[u8]) -> Option<Question<'_>> {
    let mut at = HEADER;
    let mut wire = 1usize;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*msg.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        wire += len + 1;
        if wire > 255 {
            return None;
        }
        labels.push(msg.get(at..at + len)?);
        at += len;
    }
    let qtype = be16(msg, at)?;
    let qclass = be16(msg, at + 2)?;
    Some(Question {
        labels,
        qtype,
        qclass,
        raw: msg.get(HEADER..at + 4)?,
    })
}

/// What the stub does with one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The reply to send, if any.
    pub reply: Option<Vec<u8>>,
    /// The name asked for, as shown, and whether `--host` maps it.
    pub asked: Option<(String, bool)>,
}

fn header(id: u16, flags: u16, questions: u16, answers: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER);
    for word in [id, flags, questions, answers, 0, 0] {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out
}

/// The reply to `msg`, at most `max_len` bytes, and the name to record.
///
/// No reply to a message shorter than a header or to a response. A query
/// with an opcode other than QUERY gets NOTIMP; one without exactly one
/// well-formed question gets FORMERR; neither is recorded. Of a query the
/// stub reads the header and the question; other sections are ignored.
/// A name no `--host` entry maps gets NXDOMAIN. A mapped name gets its
/// addresses for type A, AAAA or ANY in class IN or ANY, and no records
/// (NOERROR) for any other type or class. An answer that does not fit is
/// sent without records and with the TC bit set, so the client asks again
/// over TCP.
#[must_use]
pub fn answer(msg: &[u8], hosts: &Hosts, max_len: usize) -> Answer {
    let nothing = Answer {
        reply: None,
        asked: None,
    };
    let (Some(id), Some(flags)) = (be16(msg, 0), be16(msg, 2)) else {
        return nothing;
    };
    if msg.len() < HEADER || flags & QR != 0 {
        return nothing;
    }
    let rd = flags & RD;
    let opcode = flags & 0x7800;
    if opcode != 0 {
        return Answer {
            reply: Some(header(id, QR | opcode | rd | RA | NOTIMP, 0, 0)),
            asked: None,
        };
    }
    let question = (be16(msg, 4) == Some(1))
        .then(|| read_question(msg))
        .flatten();
    let Some(q) = question else {
        return Answer {
            reply: Some(header(id, QR | rd | RA | FORMERR, 0, 0)),
            asked: None,
        };
    };
    let name = show(&q.labels);
    let mapped = hosts.get(&name);
    let flags = QR | AA | rd | RA;
    let reply = mapped.map_or_else(
        || {
            let mut out = header(id, flags | NXDOMAIN, 1, 0);
            out.extend_from_slice(q.raw);
            out
        },
        |addrs| records(id, flags, &q, addrs, max_len),
    );
    Answer {
        reply: Some(reply),
        asked: Some((name, mapped.is_some())),
    }
}

/// The NOERROR reply for a mapped name.
fn records(id: u16, flags: u16, q: &Question<'_>, addrs: &[IpAddr], max_len: usize) -> Vec<u8> {
    let class = matches!(q.qclass, CLASS_IN | CLASS_ANY);
    let wanted: Vec<&IpAddr> = addrs
        .iter()
        .filter(|a| {
            class
                && match q.qtype {
                    TYPE_A => a.is_ipv4(),
                    TYPE_AAAA => a.is_ipv6(),
                    TYPE_ANY => true,
                    _ => false,
                }
        })
        .collect();
    let mut body = Vec::new();
    for addr in &wanted {
        // The owner name is a pointer to the question's name at offset 12.
        body.extend_from_slice(&[0xc0, 0x0c]);
        let (rtype, rdata) = match addr {
            IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
            IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
        };
        body.extend_from_slice(&rtype.to_be_bytes());
        body.extend_from_slice(&CLASS_IN.to_be_bytes());
        // TTL 0: the answer holds for this run only.
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(16).to_be_bytes());
        body.extend_from_slice(&rdata);
    }
    let count = u16::try_from(wanted.len()).ok();
    match count {
        Some(n) if HEADER + q.raw.len() + body.len() <= max_len => {
            let mut out = header(id, flags | NOERROR, 1, n);
            out.extend_from_slice(q.raw);
            out.extend_from_slice(&body);
            out
        }
        _ => {
            let mut out = header(id, flags | TC | NOERROR, 1, 0);
            out.extend_from_slice(q.raw);
            out
        }
    }
}

// ------------------------------------------------------------ server ----

/// One TCP client.
struct Connection {
    stream: TcpStream,
    input: Vec<u8>,
    pending: Vec<u8>,
    eof: bool,
    broken: bool,
    deadline: Instant,
}

impl Connection {
    fn done(&self, now: Instant) -> bool {
        self.broken || now >= self.deadline || (self.eof && self.pending.is_empty())
    }

    fn interest(&self) -> PollFlags {
        let mut flags = PollFlags::empty();
        if !self.eof && self.pending.len() < PENDING_MAX {
            flags |= PollFlags::POLLIN;
        }
        if !self.pending.is_empty() {
            flags |= PollFlags::POLLOUT;
        }
        flags
    }
}

struct Server<'a> {
    hosts: &'a Hosts,
    lookups: Lookups,
}

impl Server<'_> {
    fn handle(&mut self, msg: &[u8], max_len: usize) -> Option<Vec<u8>> {
        let a = answer(msg, self.hosts, max_len);
        if let Some((name, mapped)) = a.asked {
            self.lookups.record(name, mapped);
        }
        a.reply
    }

    fn datagrams(&mut self, udp: &UdpSocket) {
        let mut buf = [0u8; 4096];
        for _ in 0..64 {
            match udp.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let msg = buf.get(..n).unwrap_or_default();
                    if let Some(reply) = self.handle(msg, UDP_MAX) {
                        let _ = udp.send_to(&reply, from);
                    }
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    }

    fn serve_connection(&mut self, c: &mut Connection, events: PollFlags, now: Instant) {
        if events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
            c.broken = true;
            return;
        }
        if events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
            let mut buf = [0u8; 4096];
            for _ in 0..16 {
                match c.stream.read(&mut buf) {
                    Ok(0) => {
                        c.eof = true;
                        break;
                    }
                    Ok(n) => {
                        c.input.extend_from_slice(buf.get(..n).unwrap_or_default());
                        c.deadline = now + IDLE;
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => {
                        c.broken = true;
                        return;
                    }
                }
                self.framed(c);
                if c.pending.len() >= PENDING_MAX {
                    break;
                }
            }
        }
        while !c.pending.is_empty() {
            match c.stream.write(&c.pending) {
                Ok(0) => {
                    c.broken = true;
                    return;
                }
                Ok(n) => {
                    c.pending.drain(..n.min(c.pending.len()));
                    c.deadline = now + IDLE;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => return,
                Err(_) => {
                    c.broken = true;
                    return;
                }
            }
        }
    }

    /// Answers every complete message in `c.input` (two length bytes, then
    /// the message).
    fn framed(&mut self, c: &mut Connection) {
        while let Some(len) = be16(&c.input, 0) {
            let total = 2 + usize::from(len);
            if c.input.len() < total || c.pending.len() >= PENDING_MAX {
                return;
            }
            let msg: Vec<u8> = c.input.drain(..total).skip(2).collect();
            if let Some(reply) = self.handle(&msg, TCP_MAX) {
                let len = u16::try_from(reply.len()).unwrap_or(u16::MAX);
                c.pending.extend_from_slice(&len.to_be_bytes());
                c.pending.extend_from_slice(&reply);
            }
        }
    }
}

/// Serves queries on `udp` and `tcp` (both non-blocking) until `stop` is
/// readable or closed, and returns what was looked up.
///
/// # Errors
/// When `poll` fails.
pub fn serve(
    udp: &UdpSocket,
    tcp: &TcpListener,
    stop: BorrowedFd<'_>,
    hosts: &Hosts,
) -> Result<Lookups, String> {
    let mut server = Server {
        hosts,
        lookups: Lookups::default(),
    };
    let mut conns: Vec<Connection> = Vec::new();
    loop {
        let now = Instant::now();
        conns.retain(|c| !c.done(now));
        let timeout = conns
            .iter()
            .map(|c| c.deadline)
            .min()
            .map_or(PollTimeout::NONE, |due| {
                let ms = due
                    .saturating_duration_since(now)
                    .as_millis()
                    .clamp(1, 10_000);
                PollTimeout::from(u16::try_from(ms).unwrap_or(10_000))
            });
        let events: Vec<PollFlags> = {
            let mut fds = vec![
                PollFd::new(stop, PollFlags::POLLIN),
                PollFd::new(udp.as_fd(), PollFlags::POLLIN),
                PollFd::new(tcp.as_fd(), PollFlags::POLLIN),
            ];
            fds.extend(
                conns
                    .iter()
                    .map(|c| PollFd::new(c.stream.as_fd(), c.interest())),
            );
            match poll(&mut fds, timeout) {
                Ok(_) | Err(Errno::EINTR) => {}
                Err(e) => return Err(format!("poll failed: {e}")),
            }
            fds.iter()
                .map(|f| f.revents().unwrap_or_else(PollFlags::empty))
                .collect()
        };
        let ready = |at: usize| events.get(at).copied().unwrap_or_else(PollFlags::empty);
        if !ready(0).is_empty() {
            return Ok(server.lookups);
        }
        let now = Instant::now();
        for (at, c) in conns.iter_mut().enumerate() {
            let ev = ready(at + 3);
            if !ev.is_empty() {
                server.serve_connection(c, ev, now);
            }
        }
        if !ready(1).is_empty() {
            server.datagrams(udp);
        }
        if !ready(2).is_empty() {
            accept(tcp, &mut conns, now);
        }
    }
}

fn accept(tcp: &TcpListener, conns: &mut Vec<Connection>, now: Instant) {
    for _ in 0..CONNECTIONS {
        match tcp.accept() {
            Ok((stream, _)) => {
                if conns.len() >= CONNECTIONS || stream.set_nonblocking(true).is_err() {
                    continue;
                }
                conns.push(Connection {
                    stream,
                    input: Vec::new(),
                    pending: Vec::new(),
                    eof: false,
                    broken: false,
                    deadline: now + IDLE,
                });
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

// ----------------------------------------------------------- process ----

/// C's handle on the stub process.
pub(crate) struct Stub {
    pid: Pid,
    /// The process that started the stub; only it stops it.
    owner: Pid,
    /// Closing it asks the stub for its record.
    ctl: Option<OwnedFd>,
    /// The stub's "ready" line, then its record.
    out: OwnedFd,
    buf: Vec<u8>,
    reaped: bool,
}

impl Stub {
    /// Forks the stub and waits until it listens. With `landlock`, the
    /// stub also confines itself with Landlock (`landlock::deny_all`).
    ///
    /// The caller must be single-threaded and hold `CAP_NET_BIND_SERVICE`
    /// over the network namespace (C does).
    ///
    /// # Errors
    /// When the stub cannot be started or cannot listen.
    pub(crate) fn start(hosts: &[HostEntry], landlock: bool) -> Result<Self, String> {
        let (ctl_r, ctl_w) = pipe2(OFlag::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
        let (out_r, out_w) = pipe2(OFlag::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
        let owner = getpid();
        match crate::sandbox::fork_checked()? {
            ForkResult::Child => {
                drop(ctl_w);
                drop(out_r);
                stub_main(owner, hosts, landlock, &ctl_r, &out_w)
            }
            ForkResult::Parent { child } => {
                drop(ctl_r);
                drop(out_w);
                let mut stub = Self {
                    pid: child,
                    owner,
                    ctl: Some(ctl_w),
                    out: out_r,
                    buf: Vec::new(),
                    reaped: false,
                };
                let line = stub
                    .read_line(READY_LIMIT)
                    .map_err(|e| format!("cannot start the DNS stub: {e}"))?;
                if line == "ready" {
                    Ok(stub)
                } else {
                    Err(format!(
                        "cannot start the DNS stub: {}",
                        line.strip_prefix("error ").unwrap_or(&line)
                    ))
                }
            }
        }
    }

    /// Stops the stub and sends its record up: `lookups {json}`, or
    /// `lookupserr why`.
    pub(crate) fn report(self, up: &OwnedFd) {
        match self.finish() {
            Ok(lookups) => crate::sandbox::write_line(
                up,
                &format!(
                    "lookups {}",
                    serde_json::to_string(&lookups).unwrap_or_default()
                ),
            ),
            Err(e) => crate::sandbox::write_line(up, &format!("lookupserr {e}")),
        }
    }

    fn finish(mut self) -> Result<Lookups, String> {
        self.ctl.take();
        let line = self.read_line(RECORD_LIMIT);
        if line.is_err() {
            let _ = kill(self.pid, Signal::SIGKILL);
        }
        while waitpid(self.pid, None) == Err(Errno::EINTR) {}
        self.reaped = true;
        let line = line?;
        serde_json::from_str::<Lookups>(&line)
            .map(Lookups::sanitized)
            // Only the position: the message could quote the record.
            .map_err(|e| {
                format!(
                    "the DNS stub sent a bad record (line {}, column {})",
                    e.line(),
                    e.column()
                )
            })
    }

    /// Reads one line from the stub within `limit`.
    fn read_line(&mut self, limit: Duration) -> Result<String, String> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(end) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=end).collect();
                let text = line.get(..end).unwrap_or_default();
                return Ok(String::from_utf8_lossy(text).into_owned());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("the DNS stub did not answer in time".into());
            }
            let ms = u16::try_from(left.as_millis().clamp(1, 10_000)).unwrap_or(10_000);
            let mut fds = [PollFd::new(self.out.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, PollTimeout::from(ms)) {
                Ok(0) | Err(Errno::EINTR) => continue,
                Ok(_) => {}
                Err(e) => return Err(format!("poll failed: {e}")),
            }
            let mut chunk = [0u8; 8192];
            match read(&self.out, &mut chunk) {
                Ok(0) => return Err("the DNS stub ended before the end of the run".into()),
                Ok(n) => self
                    .buf
                    .extend_from_slice(chunk.get(..n).unwrap_or_default()),
                Err(Errno::EINTR | Errno::EAGAIN) => {}
                Err(e) => return Err(format!("cannot read from the DNS stub: {e}")),
            }
            if self.buf.len() > RECORD_MAX {
                return Err("the DNS stub sent too much".into());
            }
        }
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        // A copy of this handle in a process forked from the owner (S)
        // only closes its descriptors.
        if self.reaped || getpid() != self.owner {
            return;
        }
        let _ = kill(self.pid, Signal::SIGKILL);
        while waitpid(self.pid, None) == Err(Errno::EINTR) {}
    }
}

/// The stub process. Never returns into C's code: this process is a copy
/// of C and must not run its destructors.
fn stub_main(owner: Pid, hosts: &[HostEntry], landlock: bool, ctl: &OwnedFd, out: &OwnedFd) -> ! {
    let code = match stub_run(owner, hosts, landlock, ctl, out) {
        Ok(()) => 0,
        Err(e) => {
            write_all(out, format!("error {}\n", e.replace('\n', " ")).as_bytes());
            1
        }
    };
    // SAFETY: `_exit` takes no pointers and only ends this process.
    unsafe { libc::_exit(code) }
}

fn stub_run(
    owner: Pid,
    hosts: &[HostEntry],
    landlock: bool,
    ctl: &OwnedFd,
    out: &OwnedFd,
) -> Result<(), String> {
    crate::sandbox::die_with_parent(owner)?;
    // Inherited from C already; said again because it matters here: no
    // process of the same user may trace this one or open its /proc
    // entries.
    prctl::set_dumpable(false).map_err(|e| format!("PR_SET_DUMPABLE: {e}"))?;
    let udp = UdpSocket::bind(SocketAddr::from((ADDRESS, PORT)))
        .map_err(|e| format!("cannot listen on {ADDRESS} UDP port {PORT}: {e}"))?;
    let tcp = TcpListener::bind(SocketAddr::from((ADDRESS, PORT)))
        .map_err(|e| format!("cannot listen on {ADDRESS} TCP port {PORT}: {e}"))?;
    udp.set_nonblocking(true).map_err(|e| e.to_string())?;
    tcp.set_nonblocking(true).map_err(|e| e.to_string())?;
    // The sockets are bound; nothing else needs a capability.
    crate::sandbox::clear_capabilities()?;
    prctl::set_no_new_privs().map_err(|e| format!("PR_SET_NO_NEW_PRIVS: {e}"))?;
    crate::sandbox::verify_dropped(Uid::from_raw(0), Gid::from_raw(0))
        .map_err(|e| format!("the privilege drop could not be verified: {e}"))?;
    null_stdio()?;
    // C's descriptors, among them the pipes to P, and the caller's
    // standard streams.
    crate::sandbox::close_fds_except(&[
        0,
        1,
        2,
        udp.as_raw_fd(),
        tcp.as_raw_fd(),
        ctl.as_raw_fd(),
        out.as_raw_fd(),
    ])?;
    // The stub sees the host's processes and file system; once confined it
    // can use only the descriptors it holds.
    if landlock {
        crate::landlock::deny_all().map_err(|e| format!("cannot confine the DNS stub: {e}"))?;
    }
    write_all(out, b"ready\n");
    let lookups = serve(&udp, &tcp, ctl.as_fd(), &Hosts::new(hosts))?;
    let json = serde_json::to_string(&lookups).map_err(|e| e.to_string())?;
    write_all(out, format!("{json}\n").as_bytes());
    Ok(())
}

/// Points standard input, output and error at `/dev/null`, so that no
/// socket accepted later can take their numbers.
fn null_stdio() -> Result<(), String> {
    let null = nix::fcntl::open("/dev/null", OFlag::O_RDWR | OFlag::O_CLOEXEC, Mode::empty())
        .map_err(|e| format!("cannot open /dev/null: {e}"))?;
    nix::unistd::dup2_stdin(&null).map_err(|e| format!("dup2: {e}"))?;
    nix::unistd::dup2_stdout(&null).map_err(|e| format!("dup2: {e}"))?;
    nix::unistd::dup2_stderr(&null).map_err(|e| format!("dup2: {e}"))?;
    Ok(())
}

fn write_all(fd: &OwnedFd, mut rest: &[u8]) {
    while !rest.is_empty() {
        match nix::unistd::write(fd, rest) {
            Ok(n) => rest = rest.get(n..).unwrap_or_default(),
            Err(Errno::EINTR) => {}
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn hosts() -> Hosts {
        let parse = |s: &str| crate::resolver::parse_host(s).unwrap_or_else(|e| panic!("{e}"));
        Hosts::new(&[
            parse("svc.example.test=192.0.2.10"),
            parse("svc.example.test=[2001:db8::10]"),
            parse("svc.example.test=192.0.2.11"),
            parse("v4.example.test=192.0.2.12"),
        ])
    }

    /// A query for `labels` with ID 0x1234 and RD set.
    fn query(labels: &[&[u8]], qtype: u16, qclass: u16) -> Vec<u8> {
        let mut q = header(0x1234, RD, 1, 0);
        for l in labels {
            q.push(u8::try_from(l.len()).unwrap_or(0));
            q.extend_from_slice(l);
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&qclass.to_be_bytes());
        q
    }

    fn rcode(reply: &[u8]) -> u16 {
        be16(reply, 2).unwrap_or(0xffff) & 0xf
    }

    fn addresses(reply: &[u8], question_end: usize) -> Vec<IpAddr> {
        let count = be16(reply, 6).unwrap_or(0);
        let mut at = question_end;
        let mut out = Vec::new();
        for _ in 0..count {
            let len = usize::from(be16(reply, at + 10).unwrap_or(0));
            let data = reply.get(at + 12..at + 12 + len).unwrap_or_default();
            if let Ok(v4) = <[u8; 4]>::try_from(data) {
                out.push(IpAddr::from(v4));
            } else if let Ok(v6) = <[u8; 16]>::try_from(data) {
                out.push(IpAddr::from(v6));
            }
            at += 12 + len;
        }
        out
    }

    #[test]
    fn mapped_names_get_their_addresses_and_others_do_not_exist() {
        let hosts = hosts();
        let labels: &[&[u8]] = &[b"SVC", b"Example", b"test"];
        let q = query(labels, TYPE_A, CLASS_IN);
        let a = answer(&q, &hosts, UDP_MAX);
        let reply = a.reply.unwrap_or_default();
        assert_eq!(a.asked, Some(("svc.example.test".to_owned(), true)));
        assert_eq!(&reply[..2], &[0x12, 0x34]);
        let flags = be16(&reply, 2).unwrap_or(0);
        assert_eq!(flags & (QR | AA | RD | TC), QR | AA | RD);
        assert_eq!(rcode(&reply), NOERROR);
        // The question is echoed as received, case included.
        assert_eq!(&reply[HEADER..q.len()], &q[HEADER..]);
        let v4: Vec<IpAddr> = ["192.0.2.10", "192.0.2.11"]
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect();
        assert_eq!(addresses(&reply, q.len()), v4);

        let q = query(labels, TYPE_AAAA, CLASS_IN);
        let reply = answer(&q, &hosts, UDP_MAX).reply.unwrap_or_default();
        let v6: Vec<IpAddr> = "2001:db8::10".parse().into_iter().collect();
        assert_eq!(addresses(&reply, q.len()), v6);

        let q = query(labels, TYPE_ANY, CLASS_ANY);
        let reply = answer(&q, &hosts, UDP_MAX).reply.unwrap_or_default();
        assert_eq!(addresses(&reply, q.len()).len(), 3);

        // The name exists, without records of this type or class.
        for (qtype, qclass) in [(TYPE_AAAA, CLASS_IN), (65, CLASS_IN), (TYPE_A, 3)] {
            let q = query(&[b"v4", b"example", b"test"], qtype, qclass);
            let reply = answer(&q, &hosts, UDP_MAX).reply.unwrap_or_default();
            assert_eq!(rcode(&reply), NOERROR);
            assert_eq!(be16(&reply, 6), Some(0));
        }

        let q = query(&[b"unmapped", b"example"], TYPE_A, CLASS_IN);
        let a = answer(&q, &hosts, UDP_MAX);
        let reply = a.reply.unwrap_or_default();
        assert_eq!(rcode(&reply), NXDOMAIN);
        assert_eq!(be16(&reply, 4), Some(1));
        assert_eq!(be16(&reply, 6), Some(0));
        assert_eq!(a.asked, Some(("unmapped.example".to_owned(), false)));
    }

    #[test]
    fn malformed_queries_are_refused_and_not_recorded() {
        let hosts = hosts();
        let good = query(&[b"a", b"test"], TYPE_A, CLASS_IN);
        // Too short, and a response: no reply at all.
        assert_eq!(answer(&good[..11], &hosts, UDP_MAX).reply, None);
        let mut response = good.clone();
        response[2] |= 0x80;
        assert_eq!(answer(&response, &hosts, UDP_MAX).reply, None);
        let mut bad = Vec::new();
        // A label length of 70 (a reserved label type), a pointer, a name
        // cut short, a missing type, two questions, no question.
        let mut long = query(&[b"a"], TYPE_A, CLASS_IN);
        long[HEADER] = 70;
        bad.push(long);
        let mut pointer = query(&[b"a"], TYPE_A, CLASS_IN);
        pointer[HEADER] = 0xc0;
        bad.push(pointer);
        bad.push(good[..HEADER + 3].to_vec());
        bad.push(good[..good.len() - 2].to_vec());
        let mut two = good.clone();
        two[5] = 2;
        bad.push(two);
        let mut none = good.clone();
        none[5] = 0;
        bad.push(none);
        // 255 bytes of labels and length bytes, plus the root: too long.
        let label = [b'a'; 63];
        let l: &[u8] = &label;
        bad.push(query(&[l, l, l, l], TYPE_A, CLASS_IN));
        for msg in bad {
            let a = answer(&msg, &hosts, UDP_MAX);
            let reply = a.reply.unwrap_or_default();
            assert_eq!(rcode(&reply), FORMERR, "{msg:?}");
            assert_eq!(be16(&reply, 4), Some(0));
            assert_eq!(a.asked, None);
        }
        // Another opcode (here NOTIFY, 4).
        let mut notify = good;
        notify[2] |= 4 << 3;
        let a = answer(&notify, &hosts, UDP_MAX);
        assert_eq!(rcode(&a.reply.unwrap_or_default()), NOTIMP);
        assert_eq!(a.asked, None);
    }

    #[test]
    fn names_are_escaped_and_long_ones_cut() {
        assert_eq!(show(&[]), ".");
        assert_eq!(show(&[b"A_b-1", b"Test"]), "a_b-1.test");
        assert_eq!(show(&[b"a.b", b"c"]), "a\\046b.c");
        assert_eq!(show(&[b"\x1b[31m", b"x"]), "\\027\\09131m.x");
        assert_eq!(show(&[b"\\", b" "]), "\\092.\\032");
        assert_eq!(show(&[b"\xff\x00"]), "\\255\\000");
        let label = [b'a'; 63];
        let l: &[u8] = &label;
        let long = show(&[l, l, l, &label[..61]]);
        assert_eq!(long.len(), 253);
        assert!(is_shown(&long));
        let cut = show(&[l, l, l, l]);
        assert_eq!(cut.len(), 253);
        assert!(cut.ends_with("a..."), "{cut}");
        // A cut never splits an escape.
        let esc = [0x1b_u8; 63];
        let e: &[u8] = &esc;
        let cut = show(&[e, e]);
        assert!(cut.len() <= NAME_MAX, "{cut}");
        assert!(cut.trim_end_matches("...").ends_with("\\027"), "{cut}");
        assert!(!is_shown("a\x1bb"));
        assert!(!is_shown(""));
        assert!(!is_shown(&"a".repeat(254)));
    }

    #[test]
    fn answers_that_do_not_fit_ask_for_tcp() {
        let entries: Vec<HostEntry> = (1..=40)
            .filter_map(|i| crate::resolver::parse_host(&format!("many.test=192.0.2.{i}")).ok())
            .collect();
        let hosts = Hosts::new(&entries);
        let q = query(&[b"many", b"test"], TYPE_A, CLASS_IN);
        let udp = answer(&q, &hosts, UDP_MAX).reply.unwrap_or_default();
        assert_eq!(be16(&udp, 2).unwrap_or(0) & TC, TC);
        assert_eq!(be16(&udp, 6), Some(0));
        let tcp = answer(&q, &hosts, TCP_MAX).reply.unwrap_or_default();
        assert_eq!(be16(&tcp, 2).unwrap_or(0) & TC, 0);
        assert_eq!(addresses(&tcp, q.len()).len(), 40);
    }

    #[test]
    fn the_record_is_bounded_and_checked() {
        let mut l = Lookups::default();
        for i in 0..300 {
            l.record(format!("n{i}.test"), false);
        }
        l.record("n0.test".into(), false);
        assert_eq!(l.names.len(), LIMIT);
        assert!(l.truncated);
        assert_eq!(l.names[0].count, 2);
        let wire = Lookups {
            names: vec![
                LookedUp {
                    name: "ok.test".into(),
                    count: 1,
                    mapped: true,
                },
                LookedUp {
                    name: "\x1b]0;x\x07".into(),
                    count: 1,
                    mapped: false,
                },
                LookedUp {
                    name: "ok.test".into(),
                    count: 3,
                    mapped: false,
                },
            ],
            truncated: false,
        };
        let clean = wire.sanitized();
        assert_eq!(clean.names.len(), 1);
        assert!(clean.truncated);
        let json = serde_json::to_value(&clean).unwrap_or_default();
        assert_eq!(
            json,
            serde_json::json!({"names":[{"name":"ok.test","count":1,"mapped":true}],"truncated":true})
        );
    }

    #[test]
    fn the_server_answers_over_udp_and_tcp_and_stops_on_request() {
        // Ephemeral ports on this host's loopback; nothing leaves it.
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
        let udp_at = udp.local_addr().unwrap_or_else(|e| panic!("{e}"));
        let tcp_at = tcp.local_addr().unwrap_or_else(|e| panic!("{e}"));
        udp.set_nonblocking(true).unwrap_or_else(|e| panic!("{e}"));
        tcp.set_nonblocking(true).unwrap_or_else(|e| panic!("{e}"));
        let (stop_r, stop_w) = pipe2(OFlag::O_CLOEXEC).unwrap_or_else(|e| panic!("{e}"));
        let server = std::thread::spawn(move || {
            serve(&udp, &tcp, stop_r.as_fd(), &hosts()).unwrap_or_else(|e| panic!("{e}"))
        });
        let timeout = Some(Duration::from_secs(5));
        let client = UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
        client
            .set_read_timeout(timeout)
            .unwrap_or_else(|e| panic!("{e}"));
        let q = query(&[b"svc", b"example", b"test"], TYPE_A, CLASS_IN);
        client.send_to(&q, udp_at).unwrap_or_else(|e| panic!("{e}"));
        let mut buf = [0u8; 600];
        let n = client.recv(&mut buf).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(addresses(&buf[..n], q.len()).len(), 2);

        // Two queries in one TCP write, sent a byte at a time after that.
        let mut stream = TcpStream::connect(tcp_at).unwrap_or_else(|e| panic!("{e}"));
        stream
            .set_read_timeout(timeout)
            .unwrap_or_else(|e| panic!("{e}"));
        let unmapped = query(&[b"nope", b"test"], TYPE_AAAA, CLASS_IN);
        let mut wire = Vec::new();
        for m in [&q, &unmapped, &q] {
            wire.extend_from_slice(&u16::try_from(m.len()).unwrap_or(0).to_be_bytes());
            wire.extend_from_slice(m);
        }
        let split = 4 + q.len() + unmapped.len();
        stream
            .write_all(&wire[..split])
            .unwrap_or_else(|e| panic!("{e}"));
        for b in &wire[split..] {
            stream.write_all(&[*b]).unwrap_or_else(|e| panic!("{e}"));
        }
        let mut rcodes = Vec::new();
        for _ in 0..3 {
            let mut len = [0u8; 2];
            stream
                .read_exact(&mut len)
                .unwrap_or_else(|e| panic!("{e}"));
            let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
            stream
                .read_exact(&mut reply)
                .unwrap_or_else(|e| panic!("{e}"));
            rcodes.push(rcode(&reply));
        }
        assert_eq!(rcodes, [NOERROR, NXDOMAIN, NOERROR]);
        drop(stop_w);
        let lookups = server.join().unwrap_or_default();
        assert_eq!(
            lookups,
            Lookups {
                names: vec![
                    LookedUp {
                        name: "svc.example.test".into(),
                        count: 3,
                        mapped: true
                    },
                    LookedUp {
                        name: "nope.test".into(),
                        count: 1,
                        mapped: false
                    },
                ],
                truncated: false,
            }
        );
    }

    fn labels_strategy() -> impl Strategy<Value = Vec<Vec<u8>>> {
        proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..=63), 0..6)
    }

    proptest! {
        #[test]
        fn any_message_gets_a_bounded_reply_and_a_safe_name(
            msg in proptest::collection::vec(any::<u8>(), 0..400),
            max in prop_oneof![Just(UDP_MAX), Just(TCP_MAX)],
        ) {
            let a = answer(&msg, &hosts(), max);
            if let Some(reply) = &a.reply {
                prop_assert!(reply.len() <= max);
                prop_assert!(reply.len() >= HEADER);
                prop_assert_eq!(&reply[..2], &msg[..2]);
                prop_assert_eq!(be16(reply, 2).unwrap_or(0) & QR, QR);
            }
            if let Some((name, _)) = &a.asked {
                prop_assert!(is_shown(name), "{:?}", name);
            }
        }

        #[test]
        fn queries_for_any_labels_are_recorded_safely(
            labels in prop_oneof![
                labels_strategy(),
                Just(vec![b"SVC".to_vec(), b"example".to_vec(), b"Test".to_vec()]),
            ],
            qtype in any::<u16>(),
            qclass in any::<u16>(),
            cut in any::<prop::sample::Index>(),
        ) {
            let refs: Vec<&[u8]> = labels.iter().map(Vec::as_slice).collect();
            let wire: usize = 1 + labels.iter().map(|l| l.len() + 1).sum::<usize>();
            let q = query(&refs, qtype, qclass);
            let a = answer(&q, &hosts(), UDP_MAX);
            if wire <= 255 {
                let (name, mapped) = a.asked.clone().unwrap_or_default();
                let known = hosts().get(&show(&refs)).is_some();
                prop_assert_eq!(mapped, known);
                prop_assert!(is_shown(&name), "{:?}", name);
                prop_assert_eq!(name, show(&refs));
                let reply = a.reply.unwrap_or_default();
                prop_assert_eq!(rcode(&reply), if known { 0 } else { NXDOMAIN });
            } else {
                prop_assert_eq!(a.asked, None);
            }
            // Any prefix of a query is answered without a panic.
            let short = &q[..cut.index(q.len() + 1).min(q.len())];
            let _ = answer(short, &hosts(), UDP_MAX);
        }

        #[test]
        fn plain_names_are_shown_as_typed(labels in proptest::collection::vec("[a-z0-9_-]{1,63}", 1..8)) {
            let refs: Vec<&[u8]> = labels.iter().map(String::as_bytes).collect();
            let joined = labels.join(".");
            if joined.len() <= NAME_MAX {
                prop_assert_eq!(show(&refs), joined);
            } else {
                let shown = show(&refs);
                prop_assert!(shown.len() <= NAME_MAX);
                prop_assert!(shown.ends_with("..."));
                prop_assert!(joined.starts_with(shown.trim_end_matches('.')));
            }
        }
    }
}
