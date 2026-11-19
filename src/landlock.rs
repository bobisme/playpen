//! Landlock: refuse connections from the command to Unix sockets that were
//! created outside the sandbox.
//!
//! `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (Landlock ABI 9) restricts `connect(2)`
//! and `sendmsg(2)` with an explicit address on pathname Unix sockets whose
//! server was created outside the restricting Landlock domain. Sockets the
//! command creates itself stay usable. A path-beneath rule lets one socket,
//! or every socket below one directory, through again (`--expose`).
//!
//! The ruleset handles nothing else, so files, directories and devices are
//! not restricted by it; abstract Unix sockets are scoped as well (they are
//! already private to the sandbox's network namespace).

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;

/// The Landlock ABI that added `LANDLOCK_ACCESS_FS_RESOLVE_UNIX`.
pub const RESOLVE_UNIX_ABI: u32 = 9;

const CREATE_RULESET_VERSION: u32 = 1;
const RULE_PATH_BENEATH: libc::c_int = 1;
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
        handled_access_fs: ACCESS_FS_RESOLVE_UNIX,
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

fn add_rule(ruleset: &OwnedFd, path: &Path) -> Result<(), String> {
    let target = open(path, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty())
        .map_err(|e| format!("cannot open {} for a Landlock rule: {e}", path.display()))?;
    let attr = PathBeneathAttr {
        allowed_access: ACCESS_FS_RESOLVE_UNIX,
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
            "cannot let {} through Landlock: {}",
            path.display(),
            Errno::last()
        ));
    }
    Ok(())
}

/// Restricts this process and everything it starts: no connection to a
/// Unix socket created outside, except at or below `exposed`. Requires
/// `no_new_privs`.
///
/// # Errors
/// When the kernel refuses any step; the caller must not run the command.
pub fn restrict(exposed: &[PathBuf]) -> Result<(), String> {
    let ruleset = create_ruleset()?;
    for path in exposed {
        add_rule(&ruleset, path)?;
    }
    // SAFETY: plain syscall on a descriptor we own, flags 0.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0u32) };
    if rc != 0 {
        return Err(format!("landlock_restrict_self: {}", Errno::last()));
    }
    Ok(())
}
