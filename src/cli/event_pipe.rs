//! Supervisor-owned, best-effort lifecycle notifications on a caller's pipe.
use std::cell::{Cell, RefCell};
use std::fs::File;
use std::io::Write as _;
use std::os::fd::{FromRawFd as _, RawFd};
use std::os::unix::fs::FileTypeExt as _;

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use serde_json::{Value, json};

use crate::report::Report;

pub(super) struct EventPipe {
    pipe: RefCell<Option<File>>,
    sequence: Cell<u32>,
}

impl EventPipe {
    pub(super) fn open(fd: Option<RawFd>) -> Result<Self, String> {
        let pipe = fd.map(Self::take_writer).transpose()?;
        Ok(Self {
            pipe: RefCell::new(pipe),
            sequence: Cell::new(0),
        })
    }

    fn take_writer(fd: RawFd) -> Result<File, String> {
        // SAFETY: F_GETFD checks an integer without dereferencing memory.
        if fd < 3 || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err("--events-fd requires an inherited writable pipe above stderr".into());
        }
        // SAFETY: the single-threaded CLI takes ownership of the validated,
        // caller-supplied descriptor before opening report or helper files.
        let file = unsafe { File::from_raw_fd(fd) };
        let flags =
            OFlag::from_bits_retain(fcntl(&file, FcntlArg::F_GETFL).map_err(|e| e.to_string())?);
        if !file
            .metadata()
            .map_err(|e| e.to_string())?
            .file_type()
            .is_fifo()
            || flags & OFlag::O_ACCMODE != OFlag::O_WRONLY
        {
            return Err("--events-fd requires the write end of a pipe".into());
        }
        fcntl(&file, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(|e| e.to_string())?;
        fcntl(&file, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).map_err(|e| e.to_string())?;
        Ok(file)
    }

    pub(super) fn close(&self) {
        self.pipe.borrow_mut().take();
    }

    pub(super) fn send(&self, event: &str, details: &Value) {
        let mut slot = self.pipe.borrow_mut();
        let Some(file) = slot.as_mut() else { return };
        let seq = self.sequence.get() + 1;
        self.sequence.set(seq);
        let mut record = json!({"version":1,"seq":seq,"event":event,"details":details}).to_string();
        record.push('\n');
        // All fields are internal enums, small integers, or (`denied`) a parsed
        // address and a protocol name. One write <= PIPE_BUF is atomic, and the
        // writer can never wait for an unresponsive reader.
        if record.len() > libc::PIPE_BUF || file.write(record.as_bytes()).ok() != Some(record.len())
        {
            slot.take();
        }
    }

    pub(super) fn terminal(&self, r: &Report) {
        self.send(
            "terminal",
            &json!({"outcome":r.outcome,"startup_evidence":r.startup_evidence,
            "child_exit":r.exit_code,"signal":r.signal,"wrapper_exit":r.playpen_exit_status,
            "drop_assertion":r.drop_assertion}),
        );
    }
}
