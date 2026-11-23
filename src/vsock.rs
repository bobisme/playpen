//! VM sockets (`AF_VSOCK`): the sandbox's network namespace in the kernel's
//! VSOCK `local` mode, so that the command's VM sockets reach only sockets
//! of the sandbox itself.
//!
//! The nft table sees IPv4 and IPv6 only. In the kernel's default `global`
//! mode an `AF_VSOCK` socket reaches the hypervisor host from a VM, and the
//! machine's VMs and VM-socket listeners from a host (docs/DESIGN.md,
//! "VM sockets (`AF_VSOCK`)"). Since Linux 7.0 a network namespace has a mode,
//! fixed when it is created: it is the `child_ns_mode` of the namespace of
//! the process that creates it. The mode is in `/proc/sys/net/vsock/`,
//! which exists only while the `vsock` module is loaded, and a namespace
//! that exists when the module is loaded is `global`.
//!
//! So three steps, before any command exists:
//!
//! 1. P, before any sandbox namespace exists: [`prepare`] loads `vsock`
//!    when it is not loaded, by creating and closing one `AF_VSOCK` socket.
//!    That is the module autoload any user can trigger, and the command
//!    could trigger it too: done later, by the command, it would leave the
//!    sandbox `global`.
//! 2. C, in the user and network namespace it creates first (the
//!    intermediate one): [`ask_local`] writes `local` to its
//!    `child_ns_mode`. C then creates the sandbox's network namespace from
//!    there, and leaves the intermediate one, which nothing holds and the
//!    kernel frees.
//! 3. C, in the sandbox's namespace: [`sandbox_mode`] reads `ns_mode`. A
//!    namespace that is not `local` where the kernel has the mode stops the
//!    run ([`Mode::Global`]).

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};

/// The directory of the VSOCK settings of the reading process's network
/// namespace. It exists only while the `vsock` module is loaded, on Linux
/// 7.0 and later.
const DIR: &str = "/proc/sys/net/vsock";

/// This namespace's mode, `global` or `local`; read-only.
const NS_MODE: &str = "/proc/sys/net/vsock/ns_mode";

/// The mode of the namespaces this namespace creates. The first write locks
/// it, and a `local` namespace cannot have `global` children.
const CHILD_NS_MODE: &str = "/proc/sys/net/vsock/child_ns_mode";

/// What P found before any sandbox namespace existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    /// The kernel has the VSOCK namespace mode: `/proc/sys/net/vsock/`
    /// exists, perhaps because [`prepare`] loaded `vsock`.
    Modes,
    /// `AF_VSOCK` sockets can be created, but the kernel has no namespace
    /// mode (Linux before 7.0): every socket behaves as `global`.
    NoModes,
    /// `AF_VSOCK` sockets cannot be created: the kernel has no VM sockets,
    /// or their module cannot be loaded.
    Unavailable,
}

/// The sandbox's VSOCK mode, as C found it in the sandbox's namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `ns_mode` is `local`: the command's VM sockets reach only VM
    /// sockets of the sandbox.
    Local,
    /// The kernel has the mode, and the sandbox's namespace is not
    /// `local`: its VM sockets would reach the hypervisor, the machine's VMs
    /// and VM-socket listeners. The run stops.
    Global,
    /// The command cannot create `AF_VSOCK` sockets.
    Unavailable,
    /// The command can create `AF_VSOCK` sockets, and the kernel has no
    /// namespace mode to confine them (Linux before 7.0).
    NotConfined,
}

impl Mode {
    /// The value in the report's `vsock` field and on C's report line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Global => "global",
            Self::Unavailable => "unavailable",
            Self::NotConfined => "not_confined",
        }
    }

    /// The mode [`Mode::name`] gives `text` for.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Local,
            Self::Global,
            Self::Unavailable,
            Self::NotConfined,
        ]
        .into_iter()
        .find(|m| m.name() == text)
    }

    /// The start-line clause about VM sockets.
    #[must_use]
    pub const fn clause(self) -> &'static str {
        match self {
            Self::Local => "VM sockets (AF_VSOCK): only the sandbox's own (VSOCK mode local)",
            Self::Global => {
                "VM sockets (AF_VSOCK): not confined (VSOCK mode global); nothing is run"
            }
            Self::Unavailable => "VM sockets (AF_VSOCK): none, this kernel cannot create them",
            Self::NotConfined => {
                "VM sockets (AF_VSOCK): NOT confined, this kernel has no VSOCK namespace mode (Linux 7.0 has it): the command can reach the hypervisor, this machine's VMs and their VM-socket listeners; --hide /dev/vhost-vsock at least keeps it from acting as a VM"
            }
        }
    }
}

/// P, before any sandbox namespace exists: makes sure `vsock` is loaded
/// where it can be, and says what the kernel offers.
///
/// When `/proc/sys/net/vsock/` is absent, creating one `AF_VSOCK` socket
/// makes the kernel load the module (the same autoload any user, and the
/// command, can trigger); the socket is closed at once. Nothing else is
/// done: no `modprobe`, no privilege.
#[must_use]
pub fn prepare() -> Host {
    if Path::new(DIR).is_dir() {
        return Host::Modes;
    }
    // Any type loads the family's module; the socket is never used.
    match socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    ) {
        Ok(fd) => drop(fd),
        Err(_) => return Host::Unavailable,
    }
    if Path::new(DIR).is_dir() {
        Host::Modes
    } else {
        Host::NoModes
    }
}

/// C, in the intermediate namespace: asks for `local` children.
///
/// Nothing to do where the kernel has no mode. When the write fails and
/// this namespace is `local` already, its children are `local` anyway (a
/// `local` namespace cannot have `global` children).
///
/// # Errors
/// Why the children of this namespace may not be `local`. The run does not
/// stop here: [`sandbox_mode`] reads the mode the sandbox actually got.
pub fn ask_local() -> Result<(), String> {
    let path = Path::new(CHILD_NS_MODE);
    if !path.exists() {
        return Ok(());
    }
    match fs::write(path, "local") {
        Ok(()) => Ok(()),
        Err(_) if read_mode(NS_MODE).as_deref() == Ok("local") => Ok(()),
        Err(e) => Err(format!("cannot write local to {CHILD_NS_MODE}: {e}")),
    }
}

/// C, in the sandbox's namespace: the mode the sandbox got.
#[must_use]
pub fn sandbox_mode(host: Host) -> Mode {
    classify(read_mode(NS_MODE).as_deref().map_err(|e| *e), host)
}

/// The text of one of the mode files, trimmed.
fn read_mode(path: &str) -> Result<String, ErrorKind> {
    fs::read_to_string(path)
        .map(|t| t.trim().to_owned())
        .map_err(|e| e.kind())
}

/// The sandbox's mode from what reading its `ns_mode` gave, and what P
/// found before.
///
/// Anything but `local` where there is a mode is [`Mode::Global`]: an
/// unknown value, a file that cannot be read, and a module that was there
/// for P and is gone now (loaded again, by the command, it would leave this
/// namespace `global`).
fn classify(ns_mode: Result<&str, ErrorKind>, host: Host) -> Mode {
    match (ns_mode, host) {
        (Ok("local"), _) => Mode::Local,
        (Err(ErrorKind::NotFound), Host::Unavailable) => Mode::Unavailable,
        (Err(ErrorKind::NotFound), Host::NoModes) => Mode::NotConfined,
        _ => Mode::Global,
    }
}

/// Why the run stops when the sandbox is [`Mode::Global`], with the reason
/// [`ask_local`] gave, if it gave one.
#[must_use]
pub fn refusal(asked: Option<&str>) -> String {
    let why = asked.map_or_else(String::new, |w| format!(" ({w})"));
    format!(
        "the sandbox's network namespace did not get VSOCK mode local{why}, so the command's VM sockets (AF_VSOCK) could reach the hypervisor, this machine's VMs and VM-socket listeners outside the sandbox, which the firewall does not see; playpen does not run a command without that confinement where the kernel offers it (docs/DESIGN.md, \"VSOCK mode local for the sandbox\")"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_where_the_kernel_has_the_mode_is_local() {
        for host in [Host::Modes, Host::NoModes, Host::Unavailable] {
            assert_eq!(classify(Ok("local"), host), Mode::Local);
            assert_eq!(classify(Ok("global"), host), Mode::Global);
            // A value a later kernel might add is not taken for local.
            assert_eq!(classify(Ok("isolated"), host), Mode::Global);
            assert_eq!(
                classify(Err(ErrorKind::PermissionDenied), host),
                Mode::Global
            );
        }
    }

    #[test]
    fn without_the_mode_the_kernel_decides_what_is_reported() {
        assert_eq!(
            classify(Err(ErrorKind::NotFound), Host::Unavailable),
            Mode::Unavailable
        );
        assert_eq!(
            classify(Err(ErrorKind::NotFound), Host::NoModes),
            Mode::NotConfined
        );
        // The module was there before the namespace and is gone: loaded
        // again, it would leave the namespace global.
        assert_eq!(
            classify(Err(ErrorKind::NotFound), Host::Modes),
            Mode::Global
        );
    }

    #[test]
    fn names_round_trip() {
        for mode in [
            Mode::Local,
            Mode::Global,
            Mode::Unavailable,
            Mode::NotConfined,
        ] {
            assert_eq!(Mode::parse(mode.name()), Some(mode));
        }
        assert_eq!(Mode::parse("Local"), None);
    }

    #[test]
    fn the_refusal_says_why_when_known() {
        assert!(
            refusal(None)
                .starts_with("the sandbox's network namespace did not get VSOCK mode local, so")
        );
        assert!(
            refusal(Some("cannot write local: EACCES"))
                .contains("local (cannot write local: EACCES), so")
        );
    }
}
