//! Host Unix sockets: what the command can reach, and the mount layer that
//! hides the places where host daemons keep them.
//!
//! Two layers, described in DESIGN.md:
//!
//! 1. Landlock (`crate::landlock`, applied in X just before `exec`): no
//!    connection to any pathname Unix socket created outside the sandbox,
//!    wherever it is, except the exposed ones.
//! 2. Mounts (applied in I): the runtime directory, the X11/ICE socket
//!    directories in `/tmp`, `/dev/shm` and `/dev/mqueue` are replaced by
//!    fresh, empty, writable private ones, so the command neither sees the
//!    host's sockets there nor finds a broken runtime directory. With
//!    `--without-landlock`, every socket found under `/run`, `/tmp` and
//!    `/var/tmp` at start is also covered with `/dev/null`.
//!
//! Exposed paths (`--expose`, `--display`) are bound back into place after
//! the mount layer and are let through Landlock.

use std::fs;
use std::os::unix::fs::{DirBuilderExt as _, FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use nix::unistd::Uid;

/// A directory replaced by a fresh, empty, writable tmpfs inside the
/// sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cover {
    /// The directory.
    pub path: PathBuf,
    /// Mode of the fresh directory (the host directory's own mode).
    pub mode: u32,
    /// A subdirectory to create inside, mode 0700 (the caller's runtime
    /// directory under `/run/user`).
    pub child: Option<String>,
}

/// Directories in `/tmp` where X11, ICE and font servers put their sockets.
const TMP_SOCKET_DIRS: [&str; 4] = [
    "/tmp/.X11-unix",
    "/tmp/.ICE-unix",
    "/tmp/.XIM-unix",
    "/tmp/.font-unix",
];

/// Where the fallback walk (`--without-landlock`) looks for sockets.
pub const WALK_ROOTS: [&str; 3] = ["/run", "/tmp", "/var/tmp"];

/// Most entries the fallback walk looks at before it gives up (and the run
/// is not started).
pub const WALK_LIMIT: usize = 2_000_000;

fn dir_mode(path: &Path) -> Option<u32> {
    fs::symlink_metadata(path)
        .ok()
        .filter(fs::Metadata::is_dir)
        .map(|m| m.mode() & 0o7777)
}

/// The directories the mount layer replaces, for this caller and
/// `XDG_RUNTIME_DIR` value. Only directories that exist are listed.
#[must_use]
pub fn covers(uid: Uid, runtime_dir: Option<&Path>) -> Vec<Cover> {
    let mut out = Vec::new();
    let run_user = Path::new("/run/user");
    if let Some(mode) = dir_mode(run_user) {
        out.push(Cover {
            path: run_user.to_path_buf(),
            mode,
            child: Some(uid.to_string()),
        });
    }
    if let Some(dir) = runtime_dir
        && dir.is_absolute()
        && !dir.starts_with(run_user)
        && let Some(mode) = dir_mode(dir)
    {
        out.push(Cover {
            path: dir.to_path_buf(),
            mode,
            child: None,
        });
    }
    let tmux = format!("/tmp/tmux-{uid}");
    for p in TMP_SOCKET_DIRS.iter().copied().chain([tmux.as_str()]) {
        if let Some(mode) = dir_mode(Path::new(p)) {
            out.push(Cover {
                path: PathBuf::from(p),
                mode,
                child: None,
            });
        }
    }
    if let Some(mode) = dir_mode(Path::new("/dev/shm")) {
        out.push(Cover {
            path: PathBuf::from("/dev/shm"),
            mode,
            child: None,
        });
    }
    out
}

/// The display sockets `--display` exposes, from `WAYLAND_DISPLAY`,
/// `DISPLAY` and `XAUTHORITY`. Only local sockets that exist are returned.
///
/// # Errors
/// When neither variable names a local display socket that exists.
pub fn display_paths(
    wayland: Option<&str>,
    x11: Option<&str>,
    xauthority: Option<&str>,
    runtime_dir: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut why = Vec::new();
    match wayland.filter(|w| !w.is_empty()) {
        Some(w) => {
            let p = if Path::new(w).is_absolute() {
                Some(PathBuf::from(w))
            } else {
                runtime_dir.map(|d| d.join(w))
            };
            match p {
                Some(p) if is_socket(&p) => out.push(p),
                Some(p) => why.push(format!(
                    "WAYLAND_DISPLAY names {}, which is not a socket",
                    p.display()
                )),
                None => {
                    why.push("WAYLAND_DISPLAY is relative but XDG_RUNTIME_DIR is not set".into());
                }
            }
        }
        None => why.push("WAYLAND_DISPLAY is not set".into()),
    }
    match x11.filter(|d| !d.is_empty()) {
        Some(d) => match x11_socket(d) {
            Some(p) if is_socket(&p) => {
                out.push(p);
                if let Some(a) = xauthority.filter(|a| !a.is_empty()) {
                    let a = PathBuf::from(a);
                    if a.is_file() {
                        out.push(a);
                    }
                }
            }
            Some(p) => why.push(format!("DISPLAY {d} would be {}, which is not a socket", p.display())),
            None => why.push(format!(
                "DISPLAY {d} is not a local display (:N); a display over the network is never exposed"
            )),
        },
        None => why.push("DISPLAY is not set".into()),
    }
    if out.is_empty() {
        return Err(format!(
            "--display found no local display socket to expose ({})",
            why.join("; ")
        ));
    }
    Ok(out)
}

/// `/tmp/.X11-unix/XN` for a local `DISPLAY` (`:N`, `:N.S`, `unix:N`).
#[must_use]
pub fn x11_socket(display: &str) -> Option<PathBuf> {
    let rest = display
        .strip_prefix("unix:")
        .or_else(|| display.strip_prefix(':'))?;
    let number = rest.split('.').next()?;
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(PathBuf::from(format!("/tmp/.X11-unix/X{number}")))
}

fn is_socket(p: &Path) -> bool {
    fs::metadata(p).is_ok_and(|m| m.file_type().is_socket())
}

/// Checks and canonicalises one `--expose` path.
///
/// # Errors
/// When it does not exist or is not a socket, a regular file or a
/// directory.
pub fn check_expose(path: &Path) -> Result<PathBuf, String> {
    let canon = fs::canonicalize(path).map_err(|e| {
        format!(
            "--expose {}: {e}; only an existing path can be exposed",
            path.display()
        )
    })?;
    let meta = fs::metadata(&canon).map_err(|e| format!("--expose {}: {e}", path.display()))?;
    let ft = meta.file_type();
    if !(ft.is_socket() || ft.is_dir() || ft.is_file()) {
        return Err(format!(
            "--expose {}: not a socket, a directory or a regular file",
            path.display()
        ));
    }
    if canon == Path::new("/") {
        return Err(
            "--expose /: that would let every host socket through; expose the socket or directory you need"
                .into(),
        );
    }
    Ok(canon)
}

/// Every Unix socket below `roots` (not following symbolic links), except
/// below `skip`.
///
/// Unreadable directories are passed over: the command, which has no more
/// access than this process, cannot list them either.
///
/// # Errors
/// When more than `limit` entries are found.
pub fn find_sockets(
    roots: &[PathBuf],
    skip: &[PathBuf],
    limit: usize,
) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    let mut seen = 0usize;
    let mut stack: Vec<PathBuf> = roots.to_vec();
    while let Some(dir) = stack.pop() {
        if skip.iter().any(|s| dir.starts_with(s)) {
            continue;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.filter_map(Result::ok) {
            seen += 1;
            if seen > limit {
                return Err(format!(
                    "more than {limit} entries below {}; cannot check them all for sockets",
                    roots
                        .iter()
                        .map(|r| r.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            let Ok(ft) = e.file_type() else { continue };
            let path = e.path();
            if skip.iter().any(|s| path.starts_with(s)) {
                continue;
            }
            if ft.is_socket() {
                found.push(path);
            } else if ft.is_dir() {
                stack.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Creates `path` and its missing parents as directories with mode 0700.
///
/// # Errors
/// When a directory cannot be created.
pub fn mkdir_all(path: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x11_display_names() {
        assert_eq!(x11_socket(":0"), Some(PathBuf::from("/tmp/.X11-unix/X0")));
        assert_eq!(
            x11_socket(":12.1"),
            Some(PathBuf::from("/tmp/.X11-unix/X12"))
        );
        assert_eq!(
            x11_socket("unix:3"),
            Some(PathBuf::from("/tmp/.X11-unix/X3"))
        );
        assert_eq!(x11_socket("host.example.test:0"), None);
        assert_eq!(x11_socket("192.0.2.1:0"), None);
        assert_eq!(x11_socket(":"), None);
        assert_eq!(x11_socket(":0/../x"), None);
    }

    #[test]
    fn display_without_any_socket_is_refused() {
        let e = display_paths(None, Some("host.example.test:0"), None, None);
        assert!(e.is_err_and(|m| m.contains("network")));
        let e = display_paths(
            Some("no-such-wayland"),
            None,
            None,
            Some(Path::new("/nonexistent")),
        );
        assert!(e.is_err_and(|m| m.contains("not a socket")));
    }

    #[test]
    fn expose_needs_an_existing_path_and_not_root() {
        assert!(check_expose(Path::new("/nonexistent/playpen")).is_err());
        assert!(check_expose(Path::new("/")).is_err());
        assert_eq!(check_expose(Path::new("/tmp")), Ok(PathBuf::from("/tmp")));
    }

    #[test]
    fn covers_put_the_runtime_dir_under_run_user() {
        let c = covers(Uid::from_raw(4242), None);
        if Path::new("/run/user").is_dir() {
            let first = c.first().map(|c| (c.path.clone(), c.child.clone()));
            assert_eq!(
                first,
                Some((PathBuf::from("/run/user"), Some("4242".to_owned())))
            );
        }
        assert!(c.iter().all(|c| c.path.is_absolute()));
    }

    #[test]
    fn find_sockets_skips_and_limits() {
        let dir = std::env::temp_dir().join(format!("playpen-unit-{}", std::process::id()));
        let _ = fs::create_dir_all(dir.join("a/b"));
        let sock = dir.join("a/b/s");
        let _ = fs::remove_file(&sock);
        let listener = std::os::unix::net::UnixListener::bind(&sock);
        assert!(listener.is_ok());
        let all = find_sockets(std::slice::from_ref(&dir), &[], 1000);
        assert_eq!(all, Ok(vec![sock]));
        let skipped = find_sockets(std::slice::from_ref(&dir), &[dir.join("a")], 1000);
        assert_eq!(skipped, Ok(vec![]));
        assert!(find_sockets(std::slice::from_ref(&dir), &[], 1).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
