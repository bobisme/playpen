//! The `--report FILE` of `run`: created before anything else, hidden from
//! the command, and written by playpen last.
//!
//! The command runs as the same user, so it could write the file or put
//! another one at its path. Inside the sandbox the file is `/dev/null` (the
//! CLI adds it to the hidden paths), so the command can neither change it
//! nor rename, remove or link it there. It can still move a directory
//! above the file and put a new directory with a forged report in its
//! place. So at the end, after every process of the command is gone,
//! playpen checks that the path still leads to the file it created, in the
//! directory it was created in. If not, it writes the report to a new file
//! at the path as well (a temporary file renamed into place, which replaces
//! whatever is there without following it), and the caller warns and exits
//! non-zero.
//!
//! Only a regular file is hidden and checked: a report written to a pipe or
//! a terminal (`/dev/stdout`) is written as before.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{AsFd as _, OwnedFd};
use std::path::{Path, PathBuf};

use nix::fcntl::{OFlag, open, openat, renameat};
use nix::sys::stat::{FileStat, Mode, SFlag, fchmod, fstat, stat};
use nix::unistd::{UnlinkatFlags, unlinkat};

/// The report file playpen created at start.
#[derive(Debug)]
pub struct ReportFile {
    /// The path as given.
    shown: PathBuf,
    /// The path made absolute (symbolic links not resolved).
    path: PathBuf,
    /// The file, created (or truncated) at start.
    file: File,
    /// With a regular file: the directory the path led into at start,
    /// opened `O_PATH`.
    dir: Option<OwnedFd>,
}

impl ReportFile {
    /// Creates (or truncates) the report file at `path`, following a
    /// symbolic link as before.
    ///
    /// # Errors
    /// When the file cannot be created.
    pub fn create(path: &Path) -> std::io::Result<Self> {
        let file = File::create(path)?;
        let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        let dir = if fstat(&file).is_ok_and(|st| is_regular(&st)) {
            let parent = absolute.parent().unwrap_or_else(|| Path::new("/"));
            Some(open(
                parent,
                OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )?)
        } else {
            None
        };
        Ok(Self {
            shown: path.to_path_buf(),
            path: absolute,
            file,
            dir,
        })
    }

    /// The path to hide from the command (`/dev/null` inside), or `None`
    /// when the report does not go to a regular file.
    #[must_use]
    pub fn hidden(&self) -> Option<&Path> {
        self.dir.as_ref().map(|_| self.path.as_path())
    }

    /// The path as given.
    #[must_use]
    pub fn shown(&self) -> &Path {
        &self.shown
    }

    /// Why the path no longer leads to the file playpen created, in the
    /// directory it was created in; `None` when it does, and for a report
    /// that does not go to a regular file.
    #[must_use]
    pub fn replaced(&self) -> Option<String> {
        let dir = self.dir.as_ref()?;
        let same = |a: &FileStat, b: &FileStat| a.st_dev == b.st_dev && a.st_ino == b.st_ino;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("/"));
        match (fstat(dir), stat(parent)) {
            (Ok(held), Ok(now)) if same(&held, &now) => {}
            _ => return Some("its directory was moved or replaced".into()),
        }
        let own = fstat(&self.file).ok()?;
        match stat(&self.path) {
            Ok(now) if same(&now, &own) => None,
            Ok(_) => Some("the path now leads to another file".into()),
            Err(e) => Some(format!("the path no longer leads to a file: {e}")),
        }
    }

    /// Writes `bytes` through the file created at start.
    ///
    /// # Errors
    /// When the write fails.
    pub fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.file.write_all(bytes)?;
        self.file.flush()
    }

    /// Writes `bytes` through the file created at start, and to a new file
    /// at the path: a temporary file in the directory the path leads into
    /// now, renamed over whatever is at the path (a forged report, a
    /// symbolic link), with the mode of the file created at start. When
    /// that fails, whatever is at the path is removed, so that no forged
    /// report is left there.
    ///
    /// # Errors
    /// When the new file cannot be written at the path.
    pub fn write_again(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        // Best effort: the file created at start may now be anywhere.
        let _ = self.write(bytes);
        let name = self
            .path
            .file_name()
            .ok_or_else(|| std::io::Error::other("the report path names no file"))?;
        let parent = self.path.parent().unwrap_or_else(|| Path::new("/"));
        let mode = fstat(&self.file).map_or(0o600, |st| st.st_mode & 0o777);
        let dir = open(
            parent,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        let mut tmp = OsString::from(".");
        tmp.push(name);
        tmp.push(format!(".playpen-{}", std::process::id()));
        let written = new_file(&dir, &tmp, mode, bytes).and_then(|()| {
            renameat(dir.as_fd(), tmp.as_os_str(), dir.as_fd(), name).map_err(Into::into)
        });
        if written.is_err() {
            let _ = unlinkat(&dir, tmp.as_os_str(), UnlinkatFlags::NoRemoveDir);
            let _ = unlinkat(&dir, name, UnlinkatFlags::NoRemoveDir);
        }
        written
    }
}

/// Creates `name` in `dir` (never through a link, never an existing file)
/// with `mode`, and writes `bytes` to it.
fn new_file(dir: &OwnedFd, name: &OsString, mode: u32, bytes: &[u8]) -> std::io::Result<()> {
    let mode = Mode::from_bits_truncate(mode);
    let fd = openat(
        dir,
        name.as_os_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        mode,
    )?;
    // The umask may have narrowed the mode.
    fchmod(&fd, mode)?;
    let mut file = File::from(fd);
    file.write_all(bytes)?;
    file.sync_all()
}

/// Whether `st` is a regular file.
const fn is_regular(st: &FileStat) -> bool {
    st.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFREG.bits()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("playpen-report-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        dir
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn an_untouched_report_is_written_through_the_file_created_at_start() {
        let dir = tmpdir("untouched");
        let path = dir.join("r.json");
        std::fs::write(&path, "old content").unwrap_or_else(|e| panic!("{e}"));
        let mut r = ReportFile::create(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(read(&path), "", "truncated at start");
        assert_eq!(r.hidden(), Some(path.as_path()));
        assert_eq!(r.replaced(), None);
        r.write(b"{}\n").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(read(&path), "{}\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_replaced_report_is_written_again_at_the_path() {
        let dir = tmpdir("replaced");
        let path = dir.join("r.json");
        let mut r = ReportFile::create(&path).unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .unwrap_or_else(|e| panic!("{e}"));
        let forged = dir.join("forged");
        std::fs::write(&forged, "forged").unwrap_or_else(|e| panic!("{e}"));
        std::fs::rename(&forged, &path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            r.replaced().as_deref(),
            Some("the path now leads to another file")
        );
        r.write_again(b"real").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(read(&path), "real");
        let meta = std::fs::symlink_metadata(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(meta.permissions().mode() & 0o777, 0o640);
        // Nothing else is left in the directory.
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{e}"))
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names, ["r.json"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_moved_directory_and_a_link_in_its_place_are_found_and_the_link_is_not_followed() {
        let root = tmpdir("moved");
        let sub = root.join("out");
        std::fs::create_dir(&sub).unwrap_or_else(|e| panic!("{e}"));
        let path = sub.join("r.json");
        let mut r = ReportFile::create(&path).unwrap_or_else(|e| panic!("{e}"));
        std::fs::rename(&sub, root.join("out.moved")).unwrap_or_else(|e| panic!("{e}"));
        std::fs::create_dir(&sub).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            r.replaced().as_deref(),
            Some("its directory was moved or replaced")
        );
        // A link at the path to a file the command wants overwritten.
        let victim = root.join("victim");
        std::fs::write(&victim, "keep").unwrap_or_else(|e| panic!("{e}"));
        std::os::unix::fs::symlink(&victim, &path).unwrap_or_else(|e| panic!("{e}"));
        assert!(r.replaced().is_some());
        r.write_again(b"real").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(read(&victim), "keep");
        let meta = std::fs::symlink_metadata(&path).unwrap_or_else(|e| panic!("{e}"));
        assert!(meta.is_file(), "{meta:?}");
        assert_eq!(read(&path), "real");
        // The file created at start got the report too.
        assert_eq!(read(&root.join("out.moved").join("r.json")), "real");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_removed_report_is_found_and_written_again() {
        let dir = tmpdir("removed");
        let path = dir.join("r.json");
        let mut r = ReportFile::create(&path).unwrap_or_else(|e| panic!("{e}"));
        std::fs::remove_file(&path).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            r.replaced().as_deref(),
            Some("the path no longer leads to a file: ENOENT: No such file or directory")
        );
        r.write_again(b"real").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(read(&path), "real");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_report_that_is_not_a_regular_file_is_neither_hidden_nor_checked() {
        let r = ReportFile::create(Path::new("/dev/null")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.hidden(), None);
        assert_eq!(r.replaced(), None);
    }
}
