//! The packet capture of `run --capture FILE`.
//!
//! pasta writes it (`--pcap`). pasta cannot be handed a descriptor: it
//! closes every descriptor it inherits when it starts, and it joins the
//! sandbox's user namespace before it opens the file, after which the
//! kernel refuses it playpen's `/proc/PID/fd` entries. So pasta opens the
//! file by name, with `O_CREAT | O_TRUNC`, following symbolic links.
//!
//! playpen therefore creates the file itself first (a new file, mode 0600,
//! never through a link), only in a directory that no other user can change,
//! starts pasta in that directory and gives it the bare name, and then
//! checks that pasta wrote its header into the file playpen created.

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt as _;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// The magic numbers a pcap file starts with: microsecond and nanosecond
/// timestamps, as written on a little-endian or a big-endian machine.
const PCAP_MAGIC: [[u8; 4]; 4] = [
    [0xd4, 0xc3, 0xb2, 0xa1],
    [0xa1, 0xb2, 0xc3, 0xd4],
    [0x4d, 0x3c, 0xb2, 0xa1],
    [0xa1, 0xb2, 0x3c, 0x4d],
];

/// A capture file playpen created for pasta to write.
#[derive(Debug)]
pub struct Capture {
    /// Where the file is: the kernel's name for it once created.
    path: PathBuf,
    /// The directory the file was created in, held open from then on.
    dir: OwnedFd,
    /// The file's name in `dir`.
    name: OsString,
    /// The file itself, open for reading and writing.
    file: File,
}

/// `capture` in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureReport {
    /// The capture file (absolute).
    pub file: String,
    /// Its size in bytes.
    pub bytes: u64,
    /// The SHA-256 of its bytes, lower-case hex, as `sha256sum` prints it.
    pub sha256: String,
}

impl Capture {
    /// Creates the capture file at `path`.
    ///
    /// # Errors
    /// The refusal, when `path` exists (a symbolic link included), its
    /// directory cannot be written or can be written by another user, or
    /// it names no file.
    pub fn create(path: &Path) -> Result<Self, String> {
        let shown = path.display();
        let name = path
            .file_name()
            .ok_or_else(|| format!("--capture {shown} does not name a file"))?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let dir = open(
            parent,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            format!(
                "cannot open the directory {} for the capture file: {e}",
                parent.display()
            )
        })?;
        let mode = fstat(&dir)
            .map_err(|e| format!("cannot inspect the directory {}: {e}", parent.display()))?
            .st_mode;
        // Only the sticky bit stops another user who can write the
        // directory from replacing the file before pasta opens it by name.
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(format!(
                "the directory {} of the capture file can be written by its group or others (mode {:04o}). pasta opens the capture file by name and follows links, so another user could swap the file for a link before pasta writes. Put the capture in a directory only you can write to, or remove group and other write permission (chmod go-w)",
                parent.display(),
                mode & 0o7777
            ));
        }
        let fd = openat(
            &dir,
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .map_err(|e| match e {
            Errno::EEXIST if is_link(&dir, name) => format!(
                "the capture file {shown} is a symbolic link; playpen does not follow links for the capture. Give the name of a new file"
            ),
            Errno::EEXIST => format!(
                "the capture file {shown} already exists; playpen never overwrites a capture. Give the name of a new file"
            ),
            e => format!("cannot create the capture file {shown}: {e}"),
        })?;
        let file = File::from(fd);
        let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .ok()
            .filter(|p| p.is_absolute())
            .or_else(|| std::path::absolute(path).ok())
            .unwrap_or_else(|| path.to_path_buf());
        let capture = Self {
            path,
            dir,
            name: name.to_owned(),
            file,
        };
        // The mode the umask may have narrowed: pasta must be able to open
        // the file for writing.
        if let Err(e) = fchmod(&capture.file, Mode::S_IRUSR | Mode::S_IWUSR) {
            capture.discard();
            return Err(format!(
                "cannot set mode 0600 on the capture file {shown}: {e}"
            ));
        }
        Ok(capture)
    }

    /// Where the file is (absolute).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The name to give pasta's `--pcap`, relative to [`Self::pasta_dir`].
    #[must_use]
    pub fn name(&self) -> &OsStr {
        &self.name
    }

    /// The working directory to start pasta in: the directory the file was
    /// created in, reached through playpen's descriptor, so that no change
    /// to the path above it can redirect pasta.
    #[must_use]
    pub fn pasta_dir(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.dir.as_raw_fd()))
    }

    /// Checks that pasta, now running, opened the file playpen created: it
    /// writes the pcap header as soon as it has opened the file.
    ///
    /// # Errors
    /// When the file has no pcap header, or its name no longer leads to it.
    pub fn check_written(&self) -> Result<(), String> {
        let mut magic = [0u8; 4];
        let header = self.file.read_exact_at(&mut magic, 0).is_ok() && PCAP_MAGIC.contains(&magic);
        if !header || !self.still_named() {
            return Err(format!(
                "pasta did not write the packet capture to {} (pasta goes on without a capture when it cannot open the file)",
                self.path.display()
            ));
        }
        Ok(())
    }

    /// The size and SHA-256 of the file as it is now, read through the
    /// descriptor playpen created it with.
    ///
    /// # Errors
    /// When the file cannot be read.
    pub fn summary(&self) -> Result<CaptureReport, String> {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut bytes = 0u64;
        loop {
            let n = match self.file.read_at(&mut buf, bytes) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(format!(
                        "cannot read the capture file {}: {e}",
                        self.path.display()
                    ));
                }
            };
            hasher.update(&buf[..n]);
            bytes += n as u64;
        }
        let mut sha256 = String::with_capacity(64);
        for byte in hasher.finalize() {
            let _ = write!(sha256, "{byte:02x}");
        }
        Ok(CaptureReport {
            file: self.path.display().to_string(),
            bytes,
            sha256,
        })
    }

    /// Removes the file when the command was never released, if its name
    /// still leads to the file playpen created.
    pub fn discard(&self) {
        if self.still_named() {
            let _ = unlinkat(&self.dir, self.name.as_os_str(), UnlinkatFlags::NoRemoveDir);
        }
    }

    /// Whether the name in the directory still leads to the file playpen
    /// created.
    fn still_named(&self) -> bool {
        match (
            fstatat(
                &self.dir,
                self.name.as_os_str(),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            ),
            fstat(&self.file),
        ) {
            (Ok(named), Ok(own)) => named.st_dev == own.st_dev && named.st_ino == own.st_ino,
            _ => false,
        }
    }
}

/// Whether `name` in `dir` is a symbolic link.
fn is_link(dir: &OwnedFd, name: &OsStr) -> bool {
    fstatat(dir, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .is_ok_and(|st| st.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFLNK.bits())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("playpen-capture-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("{e}"));
        dir
    }

    #[test]
    fn creates_a_new_private_file_and_digests_it() {
        let dir = tmpdir("new");
        let path = dir.join("run.pcap");
        let c = Capture::create(&path).unwrap_or_else(|e| panic!("{e}"));
        let meta = std::fs::symlink_metadata(&path).unwrap_or_else(|e| panic!("{e}"));
        assert!(meta.is_file());
        assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
        assert!(c.path().is_absolute(), "{}", c.path().display());
        assert!(c.check_written().is_err(), "an empty file has no header");
        c.file
            .write_all_at(b"abc", 0)
            .unwrap_or_else(|e| panic!("{e}"));
        let s = c.summary().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.bytes, 3);
        assert_eq!(
            s.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        c.file
            .write_all_at(&[0xd4, 0xc3, 0xb2, 0xa1], 0)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(c.check_written().is_ok());
        // A file moved away is no longer the one at the name.
        std::fs::rename(&path, dir.join("moved")).unwrap_or_else(|e| panic!("{e}"));
        assert!(c.check_written().is_err());
        std::fs::write(&path, "someone else's").unwrap_or_else(|e| panic!("{e}"));
        c.discard();
        assert!(
            path.exists(),
            "discard removed a file playpen did not create"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refuses_existing_files_links_and_shared_directories() {
        let dir = tmpdir("refuse");
        let existing = dir.join("existing.pcap");
        std::fs::write(&existing, "keep").unwrap_or_else(|e| panic!("{e}"));
        let e = Capture::create(&existing).err().unwrap_or_default();
        assert!(e.contains("already exists"), "{e}");
        assert_eq!(
            std::fs::read_to_string(&existing).unwrap_or_default(),
            "keep"
        );

        let link = dir.join("link.pcap");
        let target = dir.join("target");
        std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|e| panic!("{e}"));
        let e = Capture::create(&link).err().unwrap_or_default();
        assert!(e.contains("symbolic link"), "{e}");
        assert!(!target.exists());

        let shared = dir.join("shared");
        std::fs::create_dir(&shared).unwrap_or_else(|e| panic!("{e}"));
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o770))
            .unwrap_or_else(|e| panic!("{e}"));
        let e = Capture::create(&shared.join("x.pcap"))
            .err()
            .unwrap_or_default();
        assert!(
            e.contains("can be written by its group or others (mode 0770)"),
            "{e}"
        );
        assert!(!shared.join("x.pcap").exists());
        // Sticky, like /tmp: others cannot rename or remove the file.
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777))
            .unwrap_or_else(|e| panic!("{e}"));
        let c = Capture::create(&shared.join("x.pcap")).unwrap_or_else(|e| panic!("{e}"));
        c.discard();
        assert!(!shared.join("x.pcap").exists());

        let e = Capture::create(Path::new("/")).err().unwrap_or_default();
        assert!(e.contains("does not name a file"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
