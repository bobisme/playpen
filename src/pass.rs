//! Reading the approval from a hallpass pass (`--pass FILE`).
//!
//! A pass is the written permission slip that hallpass reads: owner,
//! literal destinations with protocol and ports, an approval window with a
//! revocation marker, and ceilings. This module turns it into the same
//! [`Approval`] that `--allow` and `--until` produce, so the namespace code
//! does not know where the rules came from, plus a [`PassWatch`] that the
//! supervisor uses to re-read the file while the command runs.
//!
//! The pass is loaded with hallpass's own loader ([`hallpass::load`]): no
//! symbolic links, no file writable by group or others, full validation.
//! It is read through its directory, held open from the first read
//! ([`PassDir`]), so a re-read reads the file in that directory and
//! nowhere else, and a path that now leads to another directory stops the
//! run. Ceilings are not used: playpen limits where packets go, not how
//! many, so it never spends from the ledger.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hallpass::{Destination, Digest, Pass};
use nix::fcntl::OFlag;
use nix::sys::stat::{Mode, fstat};
use time::OffsetDateTime;

use crate::approval::{AllowRule, Approval, EndsAt, Net, Ports, Proto, ipv4_edges};
use crate::resolver::{HostEntry, valid_hostname};

/// How often the supervisor re-reads the pass while the command runs.
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(2);

/// The shortest re-read interval the hidden test override accepts.
pub const MIN_RECHECK_INTERVAL: Duration = Duration::from_millis(50);

/// Who approved the run, as named in the start line and the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassIdentity {
    /// The pass file as given.
    pub file: PathBuf,
    /// The pass id.
    pub id: String,
    /// The pass name.
    pub name: String,
    /// `approval.owner`.
    pub owner: String,
    /// The digest of the file's bytes at start.
    pub digest: Digest,
    /// `approval.valid_until`.
    pub valid_until: OffsetDateTime,
    /// The labels of the destinations in use, in file order.
    pub labels: Vec<String>,
}

/// A destination in use that names a host name. The name grants nothing
/// and is never resolved; the operator can map it with `--host`, or with
/// `--pass-hosts` when the destination is a single address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedDestination {
    /// The destination's label.
    pub label: String,
    /// The informational `hostname`.
    pub hostname: String,
    /// The destination's address or network, as text.
    pub destination: String,
    /// The address, when the destination is a single address.
    pub address: Option<IpAddr>,
}

/// A hosts entry that `--pass-hosts` takes from the pass: a destination's
/// own `hostname` and its single address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassHost {
    /// The entry for `/etc/hosts`, with the name in lower case.
    pub entry: HostEntry,
    /// The labels of the destinations that give this name this address,
    /// in file order.
    pub labels: Vec<String>,
}

impl fmt::Display for PassHost {
    /// `NAME=ADDR (pass: LABEL, ...)`, as in the start line, the plan and
    /// the report.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}={} (pass: {})",
            self.entry.name,
            self.entry.addr,
            self.labels.join(", ")
        )
    }
}

/// What `--pass-hosts` makes of the host names of the destinations in use.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassHosts {
    /// The entries written into `/etc/hosts`, in file order.
    pub entries: Vec<PassHost>,
    /// The entries left out because a `--host` maps the same name.
    pub replaced: Vec<PassHost>,
    /// Why a destination's host name is not mapped, one line per
    /// destination.
    pub notes: Vec<String>,
}

/// The hosts entries `--pass-hosts` takes from `named`, the destinations in
/// use that have a `hostname`.
///
/// Each entry maps a destination's own `hostname` to that destination's
/// single address, so it points at an address the pass approves. Nothing is
/// looked up. A network destination is skipped with a note, and so is a
/// `hostname` that `/etc/hosts` cannot hold (see
/// [`valid_hostname`]). Two destinations with the same `hostname` give
/// that name both addresses. A name that `explicit` (the `--host` entries)
/// maps is not taken from the pass: the entries go to
/// [`PassHosts::replaced`].
#[must_use]
pub fn pass_hosts(named: &[NamedDestination], explicit: &[HostEntry]) -> PassHosts {
    let mut out = PassHosts::default();
    for n in named {
        let name = n.hostname.to_ascii_lowercase();
        let mapped = explicit.iter().any(|h| h.name == name);
        let Some(addr) = n.address else {
            if !mapped {
                out.notes.push(format!(
                    "--pass-hosts does not map {name}: destination `{}` is a network ({}), not one address. If the tool needs the name, map it with --host {name}=ADDR-IN-{}",
                    n.label, n.destination, n.destination
                ));
            }
            continue;
        };
        if !valid_hostname(&name) {
            out.notes.push(format!(
                "--pass-hosts does not map {}: the hostname of destination `{}` is not a plain host name (letters, digits, '-' and '.') that /etc/hosts can hold",
                n.hostname, n.label
            ));
            continue;
        }
        let list = if mapped {
            &mut out.replaced
        } else {
            &mut out.entries
        };
        match list
            .iter_mut()
            .find(|p| p.entry.name == name && p.entry.addr == addr)
        {
            Some(p) => p.labels.push(n.label.clone()),
            None => list.push(PassHost {
                entry: HostEntry { name, addr },
                labels: vec![n.label.clone()],
            }),
        }
    }
    out
}

/// Enforcement coverage of the selected pass terms.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Coverage {
    /// Packet address, port and protocol filtering.
    pub packet_filter: bool,
    /// Approval window enforcement.
    pub time_window: bool,
    /// Selected labels with externally enforced name restrictions.
    pub external_names: Vec<String>,
    /// Pass-wide application counters enforced externally.
    pub external_ceilings: Vec<String>,
}
impl Coverage {
    /// Whether every applicable term is enforced by playpen.
    #[must_use]
    pub const fn fully_enforced(&self) -> bool {
        self.external_names.is_empty() && self.external_ceilings.is_empty()
    }
}

/// Everything `--pass` contributes to a run.
#[derive(Debug, Clone)]
pub struct FromPass {
    /// The allow rules of the destinations in use; `ends_at` is the pass's
    /// `valid_until`.
    pub approval: Approval,
    /// Who approved it.
    pub identity: PassIdentity,
    /// Destinations in use that carry a `hostname`.
    pub named: Vec<NamedDestination>,
    /// Destinations in use that the pass approves only for listed host
    /// names, as `label (name, name)`. playpen filters addresses and
    /// ports and cannot enforce this.
    pub name_limited: Vec<String>,
    /// Typed coverage for the selected terms.
    pub coverage: Coverage,
    /// The handle the supervisor re-reads the pass with.
    pub watch: PassWatch,
}

impl FromPass {
    /// Source label for each converted rule, in the same order as approval.
    pub(crate) fn rule_labels(&self) -> Vec<String> {
        self.watch
            .in_use
            .iter()
            .flat_map(|(label, rules)| std::iter::repeat_n(label.clone(), rules.len()))
            .take(crate::grant_use::LIMIT)
            .collect()
    }
}

/// Loads the pass at `path` and checks it at `now`.
///
/// `only` narrows the destinations to these labels (empty: all of them).
///
/// # Errors
/// A message, without the "nothing was run" suffix, when the pass cannot be
/// read, is invalid, is not valid at `now` (not yet valid, expired,
/// revoked), names an unknown label in `only`, or holds a destination
/// playpen cannot enforce.
pub fn load(path: &Path, only: &[String], now: OffsetDateTime) -> Result<FromPass, String> {
    let dir = PassDir::open(path).map_err(|e| load_error(path, &e))?;
    let loaded = dir.load(path).map_err(|e| load_error(path, &e))?;
    from_pass(path, &loaded.pass, loaded.digest, only, now, dir)
}

/// The directory of the pass, held open from the first read.
///
/// Every read of the pass goes through it, so it reads the file of that
/// name in that directory, wherever the directory has been moved since.
/// [`PassDir::moved`] says when the pass's path no longer leads to it: the
/// owner's edits, made through the path, would then go somewhere playpen
/// does not read.
#[derive(Debug, Clone)]
pub struct PassDir {
    /// The directory, opened `O_PATH`.
    fd: Arc<OwnedFd>,
    /// Its path: the parent of the pass's path made absolute, symbolic
    /// links not resolved.
    path: PathBuf,
    /// The pass's name in it.
    name: OsString,
}

impl PassDir {
    /// Opens the directory of the pass at `path`.
    ///
    /// # Errors
    /// hallpass's `io` error when the directory cannot be opened, and
    /// `not-regular-file` when `path` names no file in a directory (`/`).
    pub fn open(path: &Path) -> Result<Self, hallpass::Error> {
        let io = |e: &dyn fmt::Display| hallpass::Error::Io {
            path: path.to_path_buf(),
            message: e.to_string(),
        };
        let absolute = std::path::absolute(path).map_err(|e| io(&e))?;
        let (Some(name), Some(dir)) = (absolute.file_name(), absolute.parent()) else {
            return Err(hallpass::Error::NotRegular {
                path: path.to_path_buf(),
            });
        };
        let fd = nix::fcntl::open(
            dir,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| match e {
            nix::errno::Errno::ENOENT => io(&"no such file; check the path"),
            e => io(&format!("cannot open its directory {}: {e}", dir.display())),
        })?;
        Ok(Self {
            fd: Arc::new(fd),
            path: dir.to_path_buf(),
            name: name.to_owned(),
        })
    }

    /// The directory's path (absolute, as given).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The pass's path: the directory's path and the pass's name.
    #[must_use]
    pub fn file(&self) -> PathBuf {
        self.path.join(&self.name)
    }

    /// Reads the pass with hallpass's own loader, through the held
    /// directory. Errors name `shown`, the path as the operator gave it,
    /// exactly as `hallpass::load(shown)` would.
    ///
    /// # Errors
    /// Every error of [`hallpass::load`].
    pub fn load(&self, shown: &Path) -> Result<hallpass::LoadedPass, hallpass::Error> {
        // The kernel resolves /proc/self/fd/N to the held directory, and the
        // loader inspects and opens NAME in it without following a link.
        let mut through = PathBuf::from(format!("/proc/self/fd/{}", self.fd.as_raw_fd()));
        through.push(&self.name);
        hallpass::load(&through).map_err(|e| naming(e, shown))
    }

    /// Why the pass's path no longer leads into the held directory, or
    /// `None` when it still does (same device and inode).
    #[must_use]
    pub fn moved(&self) -> Option<String> {
        let shown = self.path.display();
        let held = match fstat(&*self.fd) {
            Ok(st) => st,
            Err(e) => {
                return Some(format!(
                    "the directory of the pass, {shown}, cannot be inspected ({e})"
                ));
            }
        };
        match nix::sys::stat::stat(&self.path) {
            Ok(now) if now.st_dev == held.st_dev && now.st_ino == held.st_ino => None,
            Ok(_) => Some(format!(
                "the directory of the pass, {shown}, was moved or replaced: the path now leads to another directory, so the owner's edits would no longer reach the file playpen reads"
            )),
            Err(e) => Some(format!(
                "the directory of the pass, {shown}, was moved or removed ({e})"
            )),
        }
    }
}

/// `e`, about `shown` instead of the path it was read through.
fn naming(e: hallpass::Error, shown: &Path) -> hallpass::Error {
    use hallpass::Error as E;
    let path = shown.to_path_buf();
    match e {
        E::Io { message, .. } => E::Io { path, message },
        E::Symlink { .. } => E::Symlink { path },
        E::NotRegular { .. } => E::NotRegular { path },
        E::TooLarge { limit, .. } => E::TooLarge { path, limit },
        E::Insecure { mode, who, fix, .. } => E::Insecure {
            path,
            mode,
            who,
            fix,
        },
        E::Invalid { problems, .. } => E::Invalid { path, problems },
        other => other,
    }
}

fn from_pass(
    path: &Path,
    pass: &Pass,
    digest: Digest,
    only: &[String],
    now: OffsetDateTime,
    dir: PassDir,
) -> Result<FromPass, String> {
    pass.check_window(now, time::Duration::ZERO)
        .map_err(|r| format!("--pass {}: {}: {r}", path.display(), r.code.as_str()))?;
    let selected = select(pass, only)?;
    let edge_addresses = pass_edges(pass);
    let mut rules = Vec::new();
    let mut in_use = Vec::new();
    let mut named = Vec::new();
    let mut hostnames = Vec::new();
    let mut name_limited = Vec::new();
    for d in &selected {
        if !d.names.is_empty() {
            let hosts: Vec<&str> = d.names.iter().map(hallpass::HostName::as_str).collect();
            name_limited.push(format!("{} ({})", d.label, hosts.join(", ")));
        }
        let converted = rules_for(d).map_err(|e| {
            format!(
                "--pass {}: destination `{}` ({}): {e}; playpen cannot enforce it. Leave it out with --only, naming the other labels",
                path.display(),
                d.label,
                d.network
            )
        })?;
        rules.extend(converted.iter().copied());
        in_use.push((d.label.clone(), converted));
        if let Some(h) = &d.hostname {
            named.push(NamedDestination {
                label: d.label.clone(),
                hostname: h.clone(),
                destination: d.network.to_string(),
                address: d.network.is_host().then(|| d.network.addr()),
            });
        }
        if d.network.is_host() {
            hostnames.push((d.label.clone(), d.hostname.clone()));
        }
    }
    let identity = PassIdentity {
        file: path.to_path_buf(),
        id: pass.id.clone(),
        name: pass.name.clone(),
        owner: pass.approval.owner.clone(),
        digest,
        valid_until: pass.approval.valid_until,
        labels: selected.iter().map(|d| d.label.clone()).collect(),
    };
    let coverage = Coverage {
        packet_filter: true,
        time_window: true,
        external_names: selected
            .iter()
            .filter(|d| !d.names.is_empty())
            .map(|d| d.label.clone())
            .collect(),
        external_ceilings: pass.ceilings.keys().cloned().collect(),
    };
    let watch = PassWatch {
        path: path.to_path_buf(),
        dir,
        id: pass.id.clone(),
        owner: pass.approval.owner.clone(),
        digest,
        in_use,
        hostnames,
        edge_addresses: edge_addresses.clone(),
        require_enforced: false,
        pass_hosts: false,
        interval: RECHECK_INTERVAL,
    };
    Ok(FromPass {
        approval: Approval::with_edge_scope(
            rules,
            Some(EndsAt::from_time(pass.approval.valid_until)),
            edge_addresses,
        ),
        identity,
        named,
        name_limited,
        coverage,
        watch,
    })
}

/// The hallpass error in words. An invalid pass gets playpen's own text: a
/// heading, then one indented line per problem (`field: message`). hallpass's
/// own wording points to its `hallpass check` command, which playpen does not
/// ship, so it is not used here.
fn load_error(path: &Path, e: &hallpass::Error) -> String {
    let shown = path.display();
    let hallpass::Error::Invalid { problems, .. } = e else {
        return format!("--pass {shown}: {}: {e}", e.code());
    };
    let n = problems.len();
    let mut msg = format!(
        "--pass {shown}: {}: not a valid pass, {n} {}; fix each one, then check the file with `playpen rules --pass {shown}`",
        e.code(),
        if n == 1 { "problem" } else { "problems" },
    );
    for p in problems {
        let _ = write!(msg, "\n{PROBLEM_INDENT}{}: {}", p.field, p.message);
    }
    msg
}

/// The indent of each problem line in a multi-line refusal. A message whose
/// lines after the first start with it carries a list of problems.
pub const PROBLEM_INDENT: &str = "  ";

/// Splits a refusal into its heading and its problem lines.
///
/// The problems are returned without the indent. A message is split only
/// when every line after the first is a problem line; any other message is
/// kept whole, with no problems.
#[must_use]
pub fn split_problems(message: &str) -> (&str, Vec<&str>) {
    let Some((heading, rest)) = message.split_once('\n') else {
        return (message, Vec::new());
    };
    rest.lines()
        .map(|l| l.strip_prefix(PROBLEM_INDENT))
        .collect::<Option<Vec<_>>>()
        .map_or((message, Vec::new()), |problems| (heading, problems))
}

/// The NOTE texts for the terms of the pass that playpen does not enforce:
/// destination `names` and ceilings. Empty when it enforces every term.
#[must_use]
pub fn unenforced_notes(p: &FromPass) -> Vec<String> {
    let mut notes = Vec::new();
    if !p.name_limited.is_empty() {
        notes.push(format!(
            "the pass approves these destinations only for the listed host names: {}. playpen filters addresses and ports and cannot see the name inside a request, so it does NOT enforce this; the command must send only those names",
            p.name_limited.join("; ")
        ));
    }
    if !p.coverage.external_ceilings.is_empty() {
        notes.push(format!(
            "the pass's ceilings ({}) are not enforced by playpen, which limits where packets go and not how many; an application-level enforcer must apply them",
            p.coverage.external_ceilings.join(", ")
        ));
    }
    notes
}

/// The destinations named by `only`, in file order (all when empty).
fn select<'p>(pass: &'p Pass, only: &[String]) -> Result<Vec<&'p Destination>, String> {
    for label in only {
        if !pass.destinations.iter().any(|d| &d.label == label) {
            let known: Vec<&str> = pass.destinations.iter().map(|d| d.label.as_str()).collect();
            return Err(format!(
                "--only {label:?}: the pass has no destination with this label; its labels are {}",
                known.join(", ")
            ));
        }
    }
    Ok(pass
        .destinations
        .iter()
        .filter(|d| only.is_empty() || only.contains(&d.label))
        .collect())
}

fn pass_edges(pass: &Pass) -> BTreeSet<Ipv4Addr> {
    pass.destinations
        .iter()
        .filter_map(|d| ipv4_edges(d.network.addr(), d.network.prefix()))
        .flatten()
        .collect()
}

// Hallpass 05d657a rejects these address classes per target; a packet
// filter over a prefix must not silently admit them. A masked-pattern
// intersection catches ISATAP even though it is not a contiguous prefix.
fn transition_overlap(address: std::net::Ipv6Addr, prefix: u8) -> bool {
    let bits = u128::from(address);
    let fixed = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    let patterns = [
        (0xffff_u128 << 112, 0x2002_u128 << 112),
        (0xffff_ffff_u128 << 96, 0x2001_0000_u128 << 96),
        (u128::MAX << 32, 0xffff_u128 << 48), // SIIT
        (u128::MAX << 32, 0xffff_u128 << 32), // mapped
        (u128::MAX << 32, 0),                 // compatible
        (u128::MAX << 32, 0x0064_ff9b_u128 << 96),
        (u128::MAX << 80, 0x0064_ff9b_0001_u128 << 80),
        (0xfcff_ffff_u128 << 32, 0x5efe_u128 << 32), // ISATAP
    ];
    patterns
        .iter()
        .any(|(mask, value)| (bits ^ value) & fixed & mask == 0)
}

/// One allow rule per port range of the destination.
///
/// # Errors
/// When playpen cannot approve the address (it refuses loopback, which
/// hallpass accepts when listed: loopback inside the sandbox is always
/// allowed and the host's cannot be reached).
pub fn rules_for(d: &Destination) -> Result<Vec<AllowRule>, crate::approval::SpecError> {
    if let std::net::IpAddr::V6(ip) = d.network.addr()
        && transition_overlap(ip, d.network.prefix())
    {
        return Err(crate::approval::SpecError::from_message(
            "IPv6 prefix may contain an IPv4 transition or embedded address",
        ));
    }
    let net = Net::new(d.network.addr(), d.network.prefix())?;
    let proto = match d.protocol {
        hallpass::Protocol::Tcp => Proto::Tcp,
        hallpass::Protocol::Udp => Proto::Udp,
    };
    d.ports
        .ranges()
        .iter()
        .map(|&(first, last)| Ports::new(first, last).map(|ports| AllowRule { net, ports, proto }))
        .collect()
}

/// What a re-read of the pass found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recheck {
    /// Same bytes, still valid.
    Unchanged,
    /// The file was edited, but nothing in use changed and it is still
    /// valid. The run continues under the rules loaded at start; the message
    /// says so. Reported once per new digest.
    Edited(String),
    /// The command must be stopped; the message says why.
    Stop(String),
}

/// The supervisor's handle on the pass file: re-reads it and decides
/// whether the run may continue.
///
/// The rules in the kernel are fixed at start. A re-read can only stop the
/// run, never widen it.
#[derive(Debug, Clone)]
pub struct PassWatch {
    /// The pass file as given.
    path: PathBuf,
    /// Its directory, held open since the first read.
    dir: PassDir,
    id: String,
    owner: String,
    digest: Digest,
    in_use: Vec<(String, Vec<AllowRule>)>,
    /// The `hostname` of each single-address destination in use (the
    /// ones `--pass-hosts` maps), by label, at start.
    hostnames: Vec<(String, Option<String>)>,
    edge_addresses: BTreeSet<Ipv4Addr>,
    /// Stop when an unsupported restriction becomes applicable.
    pub require_enforced: bool,
    /// `--pass-hosts`: the run's `/etc/hosts` holds host names from the
    /// pass, so the notice for an edit names a changed `hostname`.
    pub pass_hosts: bool,
    /// How often to re-read.
    pub interval: Duration,
}

impl PassWatch {
    /// The directory the pass is read from.
    #[must_use]
    pub const fn dir(&self) -> &PassDir {
        &self.dir
    }

    /// Re-reads the file through its directory and judges it at `now`. A
    /// path that no longer leads to that directory stops the run, whatever
    /// the file says.
    pub fn recheck(&mut self, now: OffsetDateTime) -> Recheck {
        let read = self.dir.load(&self.path);
        if let Some(why) = self.dir.moved() {
            return Recheck::Stop(why);
        }
        match read {
            Ok(loaded) => self.judge(&loaded.pass, loaded.digest, now),
            Err(e) => Recheck::Stop(format!(
                "the pass can no longer be read ({}: {e})",
                e.code()
            )),
        }
    }

    /// Judges a pass read again with digest `digest` at `now`.
    pub fn judge(&mut self, pass: &Pass, digest: Digest, now: OffsetDateTime) -> Recheck {
        if let Err(r) = pass.check_window(now, time::Duration::ZERO) {
            return Recheck::Stop(format!(
                "the pass no longer permits anything ({}): {r}",
                r.code.as_str()
            ));
        }
        if digest == self.digest {
            return Recheck::Unchanged;
        }
        if pass.id != self.id {
            return Recheck::Stop(format!(
                "the pass was edited: its id changed from `{}` to `{}`, so it is no longer the approval this run started under",
                self.id, pass.id
            ));
        }
        if pass.approval.owner != self.owner {
            return Recheck::Stop(format!(
                "the pass was edited: its owner changed from `{}` to `{}`, so it is no longer the approval this run started under",
                self.owner, pass.approval.owner
            ));
        }
        if self.require_enforced && !pass.ceilings.is_empty() {
            return Recheck::Stop(
                "the pass now has application ceilings playpen cannot enforce".into(),
            );
        }
        for (label, rules) in &self.in_use {
            let Some(d) = pass.destinations.iter().find(|d| &d.label == label) else {
                return Recheck::Stop(format!(
                    "the pass was edited and destination `{label}`, which this run uses, was removed"
                ));
            };
            if self.require_enforced && !d.names.is_empty() {
                return Recheck::Stop(format!(
                    "destination `{label}` now has a name restriction playpen cannot enforce"
                ));
            }
            if rules_for(d).ok().as_ref() != Some(rules) {
                return Recheck::Stop(format!(
                    "the pass was edited and destination `{label}`, which this run uses, changed"
                ));
            }
        }
        if let Some(edge) = pass_edges(pass)
            .difference(&self.edge_addresses)
            .find(|&&edge| {
                self.in_use
                    .iter()
                    .flat_map(|(_, rules)| rules)
                    .any(|rule| !rule.net.is_single() && rule.net.contains(edge.into()))
            })
        {
            return Recheck::Stop(format!(
                "the pass was edited and {edge} is now a network or broadcast address within a destination this run uses"
            ));
        }
        self.digest = digest;
        let renamed = self.renamed(pass);
        if !renamed.is_empty() {
            let what = if renamed.len() == 1 {
                "the hostname of destination"
            } else {
                "the hostnames of destinations"
            };
            return Recheck::Edited(format!(
                "the pass was edited (now {digest}): {what} {} changed. No rule changed, so the command continues under the rules loaded at start, and /etc/hosts keeps the names --pass-hosts wrote at start; start a new run to use the new names",
                renamed.join(", ")
            ));
        }
        Recheck::Edited(format!(
            "the pass was edited (now {digest}); nothing this run uses changed, so the command continues under the rules loaded at start. Anything the edit adds (destinations, a later valid_until) does not apply to this run; start a new run to use it"
        ))
    }

    /// With `--pass-hosts`: the labels, quoted, of the single-address
    /// destinations in use whose `hostname` in `pass` differs from the one
    /// at start.
    fn renamed(&self, pass: &Pass) -> Vec<String> {
        if !self.pass_hosts {
            return Vec::new();
        }
        self.hostnames
            .iter()
            .filter(|(label, before)| {
                pass.destinations
                    .iter()
                    .find(|d| &d.label == label)
                    .is_some_and(|d| d.hostname != *before)
            })
            .map(|(label, _)| format!("`{label}`"))
            .collect()
    }
}

/// Text form of the pass in the start line: id, name, owner, digest,
/// window end and labels. Ceilings are not mentioned: playpen does not
/// count anything against them.
#[must_use]
pub fn describe(identity: &PassIdentity) -> String {
    format!(
        "pass {} ({:?}, owner {:?}, {}, window ends {}, destinations {})",
        identity.id,
        identity.name,
        identity.owner,
        identity.digest,
        hallpass::stamp(identity.valid_until),
        identity.labels.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn only_a_list_of_indented_problems_is_split() {
        assert_eq!(split_problems("one line"), ("one line", vec![]));
        assert_eq!(
            split_problems("heading\n  a: x\n  b: y"),
            ("heading", vec!["a: x", "b: y"])
        );
        let mixed = "heading\n  a: x\nnot a problem";
        assert_eq!(split_problems(mixed), (mixed, vec![]));
    }

    const PASS: &str = r#"
format = 1
id = "example-1"
name = "Example"

[approval]
owner = "Pat Owner"
reference = "email"
operator = "Sam Tester"
valid_from = 2026-01-01T00:00:00Z
valid_until = 2026-01-02T00:00:00Z
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = [443, "8000-8001"]
hostname = "app.example.test"

[[destination]]
label = "v6"
network = "2001:db8::/120"
protocol = "udp"
ports = 5060

[ceilings]
calls = 6
"#;

    const NOW: OffsetDateTime = datetime!(2026-01-01 12:00:00 UTC);

    fn parse(text: &str) -> Pass {
        Pass::parse(text).unwrap_or_else(|p| panic!("{p:?}"))
    }

    fn watch_for(text: &str, labels: &[&str]) -> PassWatch {
        let pass = parse(text);
        let in_use = pass
            .destinations
            .iter()
            .filter(|d| labels.contains(&d.label.as_str()))
            .map(|d| (d.label.clone(), rules_for(d).unwrap_or_default()))
            .collect();
        let hostnames = pass
            .destinations
            .iter()
            .filter(|d| labels.contains(&d.label.as_str()) && d.network.is_host())
            .map(|d| (d.label.clone(), d.hostname.clone()))
            .collect();
        let edge_addresses = pass_edges(&pass);
        PassWatch {
            path: PathBuf::from("unused"),
            dir: dir_of(Path::new("unused")),
            id: pass.id,
            owner: pass.approval.owner,
            digest: Digest::of(text.as_bytes()),
            in_use,
            hostnames,
            edge_addresses,
            require_enforced: false,
            pass_hosts: false,
            interval: RECHECK_INTERVAL,
        }
    }

    fn judge(w: &mut PassWatch, text: &str, now: OffsetDateTime) -> Recheck {
        w.judge(&parse(text), Digest::of(text.as_bytes()), now)
    }

    /// The held directory of a pass at `path` (which need not exist).
    pub(super) fn dir_of(path: &Path) -> PassDir {
        PassDir::open(path).unwrap_or_else(|e| panic!("{e}"))
    }

    /// A new, empty directory for one test, mode 0700.
    fn tmpdir(name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("playpen-pass-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("{e}"));
        dir
    }

    /// Writes `text` to `path`, mode 0600, as a new file renamed over the
    /// old one (as `sed -i` and most editors do).
    fn replace_file(path: &Path, text: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text).unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|e| panic!("{e}"));
        std::fs::rename(&tmp, path).unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn the_pass_is_read_through_its_directory_and_a_moved_directory_stops_the_run() {
        let root = tmpdir("moved");
        let sub = root.join("eng");
        std::fs::create_dir(&sub).unwrap_or_else(|e| panic!("{e}"));
        let path = sub.join("p.pass.toml");
        replace_file(&path, PASS);
        let only = ["web".to_owned()];
        let loaded = load(&path, &only, NOW).unwrap_or_else(|e| panic!("{e}"));
        let mut w = loaded.watch;
        assert_eq!(w.dir().file(), path);
        assert_eq!(w.dir().moved(), None);
        // The owner's edit writes a new file in the same directory: no
        // tampering, the re-read judges what it says.
        replace_file(&path, &PASS.replace("revoked = false", "revoked = true"));
        assert_eq!(w.dir().moved(), None);
        let Recheck::Stop(m) = w.recheck(NOW) else {
            panic!("a revoked pass must stop")
        };
        assert!(m.contains("revoked"), "{m}");
        replace_file(&path, PASS);
        assert_eq!(w.recheck(NOW), Recheck::Unchanged);

        // The directory moved away, and a new one with a valid pass in its
        // place: the edits of the owner would go to the new one.
        std::fs::rename(&sub, root.join("eng.moved")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir(&sub).unwrap_or_else(|e| panic!("{e}"));
        replace_file(&path, PASS);
        let Recheck::Stop(m) = w.recheck(NOW) else {
            panic!("a replaced directory must stop")
        };
        assert!(
            m.contains(&format!(
                "the directory of the pass, {}, was moved or replaced",
                sub.display()
            )),
            "{m}"
        );
        // Still read through the held directory, now at its new path.
        assert!(w.dir().load(&path).is_ok());
        std::fs::remove_dir_all(&sub).unwrap_or_else(|e| panic!("{e}"));
        let Recheck::Stop(m) = w.recheck(NOW) else {
            panic!("a removed directory must stop")
        };
        assert!(m.contains("was moved or removed"), "{m}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn errors_name_the_path_as_given_not_the_one_read_through() {
        let root = tmpdir("errors");
        let missing = root.join("missing.pass.toml");
        let e = load(&missing, &[], NOW).err().unwrap_or_default();
        assert_eq!(
            e,
            format!(
                "--pass {}: io: {}: no such file; check the path",
                missing.display(),
                missing.display()
            )
        );
        let target = root.join("real.pass.toml");
        replace_file(&target, PASS);
        let link = root.join("link.pass.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|e| panic!("{e}"));
        let e = load(&link, &[], NOW).err().unwrap_or_default();
        assert!(
            e.starts_with(&format!(
                "--pass {}: symlink: {} is a symbolic link",
                link.display(),
                link.display()
            )),
            "{e}"
        );
        assert!(!e.contains("/proc/"), "{e}");
        let e = load(&root.join("nodir").join("p.toml"), &[], NOW)
            .err()
            .unwrap_or_default();
        assert!(e.contains("no such file"), "{e}");
        let e = load(Path::new("/"), &[], NOW).err().unwrap_or_default();
        assert!(e.contains("not-regular-file"), "{e}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ipv6_transition_ranges_are_conservatively_refused() {
        // Independent address-class witnesses for the pinned Hallpass predicate.
        for text in [
            "2002:c000:201::1",
            "2001:0:c000:201::1",
            "::ffff:0:c000:201",
            "::ffff:c000:201",
            "::c000:201",
            "64:ff9b::c000:201",
            "64:ff9b:1::1",
            "2001:db8:1234:5678:200:5efe:c000:201",
        ] {
            let ip: std::net::Ipv6Addr = text.parse().unwrap_or_else(|e| panic!("{e}"));
            assert!(
                hallpass::ipv6_transition(ip).is_some() || hallpass::embedded_ipv4(ip).is_some(),
                "{text}"
            );
            for prefix in 0..=128 {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                let network = std::net::Ipv6Addr::from(u128::from(ip) & mask);
                assert!(transition_overlap(network, prefix), "{text}/{prefix}");
            }
        }
        for text in [
            "2001:db8::1",
            "2001:db8:1:2:abcd:1234:5678:9abc",
            "2606:4700:4700::1111",
        ] {
            let ip: std::net::Ipv6Addr = text.parse().unwrap_or_else(|e| panic!("{e}"));
            assert!(!transition_overlap(ip, 128), "{text}");
        }
        assert!(transition_overlap(
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            32
        ));
        assert!(!transition_overlap(
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            120
        ));
    }

    #[test]
    fn destinations_become_one_rule_per_port_range() {
        let pass = parse(PASS);
        let web = rules_for(&pass.destinations[0]).unwrap_or_default();
        let text: Vec<String> = web.iter().map(ToString::to_string).collect();
        assert_eq!(text, ["192.0.2.10:443/tcp", "192.0.2.10:8000-8001/tcp"]);
        let v6 = rules_for(&pass.destinations[1]).unwrap_or_default();
        assert_eq!(v6[0].to_string(), "[2001:db8::/120]:5060/udp");
    }

    #[test]
    fn loopback_in_a_pass_is_refused_by_playpen() {
        let text = PASS.replace("192.0.2.10", "127.0.0.1");
        let pass = parse(&text);
        let err = rules_for(&pass.destinations[0])
            .err()
            .map(|e| e.to_string());
        assert!(err.unwrap_or_default().contains("loopback"));
    }

    #[test]
    fn unchanged_and_window_states() {
        let mut w = watch_for(PASS, &["web"]);
        assert_eq!(judge(&mut w, PASS, NOW), Recheck::Unchanged);
        let Recheck::Stop(m) = judge(&mut w, PASS, datetime!(2026-01-02 00:00:00 UTC)) else {
            panic!("expired must stop")
        };
        assert!(m.contains("expired"), "{m}");
        let revoked = PASS.replace("revoked = false", "revoked = true");
        let Recheck::Stop(m) = judge(&mut w, &revoked, NOW) else {
            panic!("revoked must stop")
        };
        assert!(m.contains("revoked"), "{m}");
        let later_start = PASS.replace(
            "valid_from = 2026-01-01T00:00:00Z",
            "valid_from = 2026-01-01T13:00:00Z",
        );
        assert!(matches!(judge(&mut w, &later_start, NOW), Recheck::Stop(_)));
    }

    #[test]
    fn harmless_edits_continue_and_never_widen() {
        let mut w = watch_for(PASS, &["web"]);
        let raised = PASS.replace("calls = 6", "calls = 60");
        let Recheck::Edited(m) = judge(&mut w, &raised, NOW) else {
            panic!("a raised ceiling is harmless")
        };
        assert!(m.contains("rules loaded at start"), "{m}");
        // The same edit seen again is no longer news.
        assert_eq!(judge(&mut w, &raised, NOW), Recheck::Unchanged);
        let later = raised.replace("2026-01-02T00:00:00Z", "2026-02-01T00:00:00Z");
        assert!(matches!(judge(&mut w, &later, NOW), Recheck::Edited(_)));
        // A change to a destination not in use is harmless too.
        let other = later.replace("ports = 5060", "ports = 5061");
        assert!(matches!(judge(&mut w, &other, NOW), Recheck::Edited(_)));
        // The hostname grants nothing; changing it changes no rule.
        let renamed = other.replace("app.example.test", "www.example.test");
        let Recheck::Edited(m) = judge(&mut w, &renamed, NOW) else {
            panic!("a changed hostname is harmless")
        };
        assert!(m.contains("nothing this run uses changed"), "{m}");
    }

    #[test]
    fn with_pass_hosts_a_hostname_edit_continues_and_names_the_destination() {
        let mut w = watch_for(PASS, &["web", "v6"]);
        w.pass_hosts = true;
        // The network `v6` gets a hostname: --pass-hosts does not map a
        // network, so there is no news about names.
        let other = PASS.replace(
            "ports = 5060",
            "ports = 5060\nhostname = \"sip.example.test\"",
        );
        let Recheck::Edited(m) = judge(&mut w, &other, NOW) else {
            panic!("a hostname on a network changes no rule")
        };
        assert!(m.contains("nothing this run uses changed"), "{m}");
        // The hostname of a destination in use changes: the existing rule
        // for edits that change no rule applies, and the notice says what
        // the run keeps.
        for edited in [
            other.replace("app.example.test", "www.example.test"),
            other.replace("hostname = \"app.example.test\"\n", ""),
        ] {
            let Recheck::Edited(m) = judge(&mut w, &edited, NOW) else {
                panic!("a changed hostname changes no rule:\n{edited}")
            };
            assert!(
                m.contains("the hostname of destination `web` changed"),
                "{m}"
            );
            assert!(m.contains("/etc/hosts keeps the names"), "{m}");
        }
    }

    /// A pass with named single addresses, a named network, a name
    /// `/etc/hosts` cannot hold and a destination without a name.
    fn named_pass() -> String {
        let header = PASS
            .split("[[destination]]")
            .next()
            .unwrap_or_default()
            .to_owned();
        let destinations = [
            (
                "web",
                "address = \"192.0.2.10\"",
                "tcp",
                "hostname = \"App.Example.Test\"",
            ),
            (
                "web-udp",
                "address = \"192.0.2.10\"",
                "udp",
                "hostname = \"app.example.test\"",
            ),
            (
                "alt",
                "address = \"192.0.2.11\"",
                "tcp",
                "hostname = \"app.example.test\"",
            ),
            (
                "sip",
                "address = \"2001:db8::5\"",
                "udp",
                "hostname = \"sip.example.test\"",
            ),
            (
                "lab",
                "network = \"198.51.100.0/28\"",
                "tcp",
                "hostname = \"lab.example.test\"",
            ),
            (
                "srv",
                "address = \"192.0.2.20\"",
                "tcp",
                "hostname = \"_srv.example.test\"",
            ),
            ("plain", "address = \"192.0.2.30\"", "tcp", ""),
        ];
        let mut text = header;
        for (label, target, protocol, hostname) in destinations {
            let _ = write!(
                text,
                "[[destination]]\nlabel = \"{label}\"\n{target}\nprotocol = \"{protocol}\"\nports = 443\n{hostname}\n\n"
            );
        }
        text
    }

    fn named(only: &[&str]) -> Vec<NamedDestination> {
        let text = named_pass();
        let only: Vec<String> = only.iter().map(|&l| l.to_owned()).collect();
        from_pass(
            Path::new("p.toml"),
            &parse(&text),
            Digest::of(text.as_bytes()),
            &only,
            NOW,
            dir_of(Path::new("p.toml")),
        )
        .unwrap_or_else(|e| panic!("{e}"))
        .named
    }

    fn texts(hosts: &[PassHost]) -> Vec<String> {
        hosts.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn pass_hosts_map_each_named_single_address() {
        let hosts = pass_hosts(&named(&[]), &[]);
        assert_eq!(
            texts(&hosts.entries),
            [
                "app.example.test=192.0.2.10 (pass: web, web-udp)",
                "app.example.test=192.0.2.11 (pass: alt)",
                "sip.example.test=2001:db8::5 (pass: sip)",
            ]
        );
        assert_eq!(hosts.replaced, []);
        assert_eq!(hosts.notes.len(), 2, "{:?}", hosts.notes);
        assert!(
            hosts.notes[0].contains(
                "destination `lab` is a network (198.51.100.0/28), not one address. If the tool needs the name, map it with --host lab.example.test=ADDR-IN-198.51.100.0/28"
            ),
            "{:?}",
            hosts.notes
        );
        assert!(
            hosts.notes[1].contains("_srv.example.test: the hostname of destination `srv`"),
            "{:?}",
            hosts.notes
        );
        // Every entry's text is a --host entry with a marker after a space.
        for text in texts(&hosts.entries) {
            let (entry, _) = text.split_once(' ').unwrap_or_default();
            assert!(crate::resolver::parse_host(entry).is_ok(), "{text}");
        }
    }

    #[test]
    fn pass_hosts_follow_only_and_yield_to_host() {
        let hosts = pass_hosts(&named(&["alt", "plain"]), &[]);
        assert_eq!(
            texts(&hosts.entries),
            ["app.example.test=192.0.2.11 (pass: alt)"]
        );
        assert_eq!(hosts.notes, [] as [String; 0]);

        let explicit = [
            crate::resolver::parse_host("APP.example.test=192.0.2.11")
                .unwrap_or_else(|e| panic!("{e}")),
            crate::resolver::parse_host("lab.example.test=198.51.100.7")
                .unwrap_or_else(|e| panic!("{e}")),
        ];
        let hosts = pass_hosts(&named(&[]), &explicit);
        assert_eq!(
            texts(&hosts.entries),
            ["sip.example.test=2001:db8::5 (pass: sip)"]
        );
        assert_eq!(
            texts(&hosts.replaced),
            [
                "app.example.test=192.0.2.10 (pass: web, web-udp)",
                "app.example.test=192.0.2.11 (pass: alt)",
            ]
        );
        // The network's name is mapped by --host: no note for it.
        assert_eq!(hosts.notes.len(), 1, "{:?}", hosts.notes);
        assert!(hosts.notes[0].contains("`srv`"), "{:?}", hosts.notes);
    }

    #[test]
    fn edits_to_destinations_in_use_stop() {
        let cases = [
            PASS.replace("ports = [443, \"8000-8001\"]", "ports = [443]"),
            PASS.replace(
                "ports = [443, \"8000-8001\"]",
                "ports = [443, \"8000-8002\"]",
            ),
            PASS.replace("192.0.2.10", "192.0.2.11"),
            PASS.replace("protocol = \"tcp\"", "protocol = \"udp\""),
            PASS.replace("label = \"web\"", "label = \"web2\""),
            PASS.replace("id = \"example-1\"", "id = \"example-2\""),
            PASS.replace("owner = \"Pat Owner\"", "owner = \"Someone Else\""),
        ];
        for text in cases {
            let mut w = watch_for(PASS, &["web"]);
            assert!(
                matches!(judge(&mut w, &text, NOW), Recheck::Stop(_)),
                "should stop for:\n{text}"
            );
        }
    }

    #[test]
    fn select_by_label() {
        let pass = parse(PASS);
        assert_eq!(select(&pass, &[]).map(|v| v.len()), Ok(2));
        let one = select(&pass, &["v6".to_owned()]).unwrap_or_default();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].label, "v6");
        let err = select(&pass, &["nope".to_owned()])
            .err()
            .unwrap_or_default();
        assert!(err.contains("web, v6"), "{err}");
    }

    #[test]
    fn description_names_the_pass_and_not_the_ceilings() {
        let pass = parse(PASS);
        let id = PassIdentity {
            file: PathBuf::from("p.toml"),
            id: pass.id.clone(),
            name: pass.name.clone(),
            owner: pass.approval.owner,
            digest: Digest::of(PASS.as_bytes()),
            valid_until: pass.approval.valid_until,
            labels: vec!["web".into()],
        };
        let d = describe(&id);
        assert!(d.contains("pass example-1"), "{d}");
        assert!(d.contains("owner \"Pat Owner\""), "{d}");
        assert!(d.contains("sha256:"), "{d}");
        assert!(d.contains("window ends 2026-01-02T00:00:00Z"), "{d}");
        assert!(!d.contains("calls"), "{d}");
    }
}

#[cfg(test)]
#[path = "pass_scope_tests.rs"]
mod scope_tests;
