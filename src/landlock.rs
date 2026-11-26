//! Landlock: refuse connections from the command to Unix sockets that were
//! created outside the sandbox.
//!
//! `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (Landlock ABI 9) restricts `connect(2)`
//! and `sendmsg(2)` with an explicit address on pathname Unix sockets whose
//! server was created outside the restricting Landlock domain. Sockets the
//! command creates itself stay usable. A path-beneath rule lets one socket,
//! or every socket below one directory, through again (`--expose`).
//!
//! The ruleset also handles `LANDLOCK_ACCESS_FS_REFER` and grants it on `/`.
//! Landlock denies reparenting (a rename or hard link into another
//! directory) in every domain that handles any file system right, even when
//! `REFER` is not handled, and the call fails with `EXDEV`. With `REFER`
//! granted on `/`, Landlock still refuses, also with `EXDEV`, a rename or
//! link that would give the file a right it did not have before: so nothing
//! can be moved or linked into an exposed directory from outside it, and a
//! host socket cannot be brought under an `--expose` rule that way.
//!
//! The ruleset handles nothing else, so files, directories and devices are
//! not restricted by it; abstract Unix sockets are scoped as well (they are
//! already private to the sandbox's network namespace).
//!
//! `deny_all` is for the DNS stub, which needs no file and no new
//! connection once its sockets are bound.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;

/// The Landlock ABI that added `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`.
pub const RESOLVE_UNIX_ABI: u32 = 9;

const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: libc::c_int = 1;
/// `LANDLOCK_ACCESS_FS_REFER` (ABI 2): rename or link into another directory.
const ACCESS_FS_REFER: u64 = 1 << 13;
const ACCESS_FS_RESOLVE_UNIX: u64 = 1 << 16;
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;

/// `struct landlock_ruleset_attr`.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `struct landlock_path_beneath_attr` (packed in the kernel's header).
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// The Landlock ABI version of the running kernel, or `None` when Landlock
/// is not built in or not enabled.
#[must_use]
pub fn abi() -> Option<u32> {
    // SAFETY: with a null attribute pointer, size 0 and the VERSION flag,
    // landlock_create_ruleset(2) reads no memory and returns the ABI version
    // (or -1 with errno set). No descriptor is created.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    u32::try_from(rc).ok().filter(|&v| v > 0)
}

/// True when this kernel can refuse connections to outside Unix sockets.
#[must_use]
pub fn resolve_unix_supported() -> bool {
    abi().is_some_and(|v| v >= RESOLVE_UNIX_ABI)
}

fn create_ruleset() -> Result<OwnedFd, String> {
    let attr = RulesetAttr {
        handled_access_fs: ACCESS_FS_RESOLVE_UNIX | ACCESS_FS_REFER,
        handled_access_net: 0,
        scoped: SCOPE_ABSTRACT_UNIX_SOCKET,
    };
    // SAFETY: `attr` is a live `repr(C)` struct with the kernel's layout for
    // ABI 6 and later (three u64), and its exact size is passed.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    let fd = i32::try_from(rc).map_err(|_| "landlock_create_ruleset: bad return".to_owned())?;
    if fd < 0 {
        return Err(format!("landlock_create_ruleset: {}", Errno::last()));
    }
    // SAFETY: the kernel just returned this descriptor to us; nothing else
    // owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn add_rule(ruleset: &OwnedFd, path: &Path, access: u64) -> Result<(), String> {
    let target = open(path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())
        .map_err(|e| format!("cannot open {} for a Landlock rule: {e}", path.display()))?;
    let attr = PathBeneathAttr {
        allowed_access: access,
        parent_fd: target.as_raw_fd(),
    };
    // SAFETY: `attr` is a live packed struct matching
    // `landlock_path_beneath_attr`; `ruleset` and `target` are open
    // descriptors that outlive the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &raw const attr,
            0u32,
        )
    };
    if rc != 0 {
        return Err(format!(
            "cannot add a Landlock rule for {}: {}",
            path.display(),
            Errno::last()
        ));
    }
    Ok(())
}

/// Every file system access right up to ABI 9 (`EXECUTE` to `RESOLVE_UNIX`).
const ACCESS_FS_ALL: u64 = (1 << 17) - 1;
/// `LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP`.
const ACCESS_NET_ALL: u64 = 0b11;
const SCOPE_SIGNAL: u64 = 1 << 1;

/// Restricts this process to the descriptors it holds.
///
/// No file system access at all, no TCP bind or connect, no abstract Unix
/// sockets, and no signal to (or trace of) a process outside the domain.
/// Requires `no_new_privs` and ABI 9.
///
/// # Errors
/// When the kernel refuses any step.
pub fn deny_all() -> Result<(), String> {
    let attr = RulesetAttr {
        handled_access_fs: ACCESS_FS_ALL,
        handled_access_net: ACCESS_NET_ALL,
        scoped: SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL,
    };
    // SAFETY: as in `create_ruleset`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    let fd = i32::try_from(rc).map_err(|_| "landlock_create_ruleset: bad return".to_owned())?;
    if fd < 0 {
        return Err(format!("landlock_create_ruleset: {}", Errno::last()));
    }
    // SAFETY: the kernel just returned this descriptor to us; nothing else
    // owns it.
    let ruleset = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: plain syscall on a descriptor we own, flags 0.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) };
    if rc != 0 {
        return Err(format!("landlock_restrict_self: {}", Errno::last()));
    }
    Ok(())
}

/// Restricts this process and everything it starts: no connection to a
/// Unix socket created outside, except at or below `exposed`.
///
/// Renames and hard links across directories stay allowed, except into an
/// exposed path from outside it (`EXDEV`). Requires `no_new_privs` and ABI
/// 9 (`REFER` needs only ABI 2).
///
/// # Errors
/// When the kernel refuses any step; the caller must not run the command.
pub fn restrict(exposed: &[PathBuf]) -> Result<(), String> {
    let ruleset = create_ruleset()?;
    add_rule(&ruleset, Path::new("/"), ACCESS_FS_REFER)?;
    for path in exposed {
        add_rule(&ruleset, path, ACCESS_FS_RESOLVE_UNIX)?;
    }
    // SAFETY: plain syscall on a descriptor we own, flags 0.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) };
    if rc != 0 {
        return Err(format!("landlock_restrict_self: {}", Errno::last()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::wait::{WaitStatus, waitpid};
    use nix::unistd::{ForkResult, fork, getppid};
    use std::io::{Read as _, Write as _};

    /// What a process confined by `deny_all` can still do, as an exit code:
    /// 0 when it uses what it held and is refused everything else.
    fn confined_child(held: &mut std::fs::File, udp: &std::net::UdpSocket) -> i32 {
        if nix::sys::prctl::set_no_new_privs().is_err() || deny_all().is_err() {
            return 1;
        }
        if std::fs::File::open("/etc/hostname").is_ok() || std::fs::read_dir("/").is_ok() {
            return 2;
        }
        if nix::sys::signal::kill(getppid(), None).is_ok() {
            return 3;
        }
        let connect = std::net::TcpStream::connect("127.0.0.1:9").map_err(|e| e.raw_os_error());
        if connect.err() != Some(Some(libc::EACCES)) {
            return 4;
        }
        if std::net::TcpListener::bind("127.0.0.1:0").is_ok() {
            return 5;
        }
        let mut byte = [0u8; 1];
        if held.read_exact(&mut byte).is_err() {
            return 6;
        }
        let to_self = udp.local_addr().map(|a| udp.send_to(b"x", a));
        if !matches!(to_self, Ok(Ok(1))) || udp.recv(&mut byte).is_err() {
            return 7;
        }
        0
    }

    /// What a process confined by `restrict(&[dir/exp])` can do in `dir`,
    /// as an exit code: 0 when renames and links across directories work,
    /// the host socket is refused, and nothing can be moved or linked into
    /// the exposed directory.
    fn reparenting_child(dir: &Path) -> i32 {
        let exp = dir.join("exp");
        if nix::sys::prctl::set_no_new_privs().is_err()
            || restrict(std::slice::from_ref(&exp)).is_err()
        {
            return 1;
        }
        let (a, b, host) = (dir.join("a"), dir.join("b"), dir.join("host"));
        if std::fs::rename(a.join("f"), b.join("f")).is_err()
            || std::fs::hard_link(b.join("f"), a.join("l")).is_err()
            || std::fs::rename(a.join("d"), b.join("d")).is_err()
        {
            return 2;
        }
        let refused = |r: std::io::Result<()>| r.err().and_then(|e| e.raw_os_error());
        let sock = host.join("s");
        if refused(std::os::unix::net::UnixStream::connect(&sock).map(drop)) != Some(libc::EACCES) {
            return 3;
        }
        if refused(std::fs::rename(&sock, exp.join("s"))) != Some(libc::EXDEV)
            || refused(std::fs::hard_link(&sock, exp.join("s"))) != Some(libc::EXDEV)
            || refused(std::fs::rename(&host, exp.join("host"))) != Some(libc::EXDEV)
        {
            return 4;
        }
        if refused(std::fs::rename(b.join("f"), exp.join("f"))) != Some(libc::EXDEV) {
            return 5;
        }
        0
    }

    #[test]
    fn restrict_allows_reparenting_except_into_an_exposed_directory() {
        if !resolve_unix_supported() {
            eprintln!("SKIPPED: Landlock ABI {RESOLVE_UNIX_ABI} is not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("playpen-refer-{}", std::process::id()));
        for d in ["a/d", "b", "host", "exp"] {
            std::fs::create_dir_all(dir.join(d)).unwrap_or_else(|e| panic!("{e}"));
        }
        std::fs::write(dir.join("a/f"), "x").unwrap_or_else(|e| panic!("{e}"));
        let listener = std::os::unix::net::UnixListener::bind(dir.join("host/s"))
            .unwrap_or_else(|e| panic!("{e}"));
        // SAFETY: as in `deny_all_leaves_only_the_descriptors_held`.
        let status = match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                let code = reparenting_child(&dir);
                // SAFETY: ends the child at once, without unwinding into
                // the test harness.
                unsafe { libc::_exit(code) }
            }
            Ok(ForkResult::Parent { child }) => waitpid(child, None),
            Err(e) => panic!("fork: {e}"),
        };
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(status, Ok(WaitStatus::Exited(_, 0))), "{status:?}");
    }

    #[test]
    fn deny_all_leaves_only_the_descriptors_held() {
        if !resolve_unix_supported() {
            eprintln!("SKIPPED: Landlock ABI {RESOLVE_UNIX_ABI} is not available");
            return;
        }
        let mut held = std::fs::File::open("/proc/self/stat").unwrap_or_else(|e| panic!("{e}"));
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
        // SAFETY: the child makes system calls, allocates (glibc's malloc
        // is reset in a forked child) and ends with `_exit`; it returns to
        // no test code.
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                let code = confined_child(&mut held, &udp);
                let _ = std::io::stdout().flush();
                // SAFETY: ends the child at once, without unwinding into
                // the test harness.
                unsafe { libc::_exit(code) }
            }
            Ok(ForkResult::Parent { child }) => {
                assert_eq!(waitpid(child, None), Ok(WaitStatus::Exited(child, 0)));
            }
            Err(e) => panic!("fork: {e}"),
        }
    }
}
