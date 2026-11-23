//! Output that never panics.
//!
//! `eprintln!` and `println!` panic when the write fails (a hung-up
//! terminal gives `EIO` on stderr, a reader that left early gives `EPIPE`
//! on stdout). playpen must keep supervising, tearing down and writing its
//! report in those cases, so it writes through these macros instead
//! (`clippy.toml` forbids the std ones):
//!
//! - [`say!`] and [`sayln!`] write to stderr and ignore every error.
//! - [`out!`] and [`outln!`] write to stdout. After the first failed write
//!   nothing more is written to stdout, and the error is dropped.
//!
//! The text of a message is the same as with the std macros.

use std::fmt::Arguments;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// Set once a write to stdout failed; later stdout writes are skipped.
static STDOUT_GONE: AtomicBool = AtomicBool::new(false);

/// Writes `args` (and a newline when `newline`) to stderr, ignoring errors.
pub fn to_stderr(args: Arguments<'_>, newline: bool) {
    let mut err = io::stderr().lock();
    let _ = err.write_fmt(args);
    if newline {
        let _ = err.write_all(b"\n");
    }
}

/// Writes `args` (and a newline when `newline`) to stdout, unless an
/// earlier write to it failed. The first failure ends all stdout output.
pub fn to_stdout(args: Arguments<'_>, newline: bool) {
    if STDOUT_GONE.load(Ordering::Relaxed) {
        return;
    }
    let mut out = io::stdout().lock();
    let mut result = out.write_fmt(args);
    if result.is_ok() && newline {
        result = out.write_all(b"\n");
    }
    if result.is_err() {
        STDOUT_GONE.store(true, Ordering::Relaxed);
    }
}

/// Whether `e` says nobody can read stdout any more: the reader closed the
/// pipe (`EPIPE`) or the terminal went away (`EIO`).
pub fn stdout_reader_gone(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::BrokenPipe || e.raw_os_error() == Some(libc::EIO)
}

/// Marks stdout as unusable, so [`out!`] and [`outln!`] stop writing.
pub fn stdout_lost() {
    STDOUT_GONE.store(true, Ordering::Relaxed);
}

/// Writes to stderr like `eprint!`, and ignores a failed write.
macro_rules! say {
    ($($arg:tt)*) => { $crate::say::to_stderr(format_args!($($arg)*), false) };
}

/// Writes a line to stderr like `eprintln!`, and ignores a failed write.
macro_rules! sayln {
    () => { $crate::say::to_stderr(format_args!(""), true) };
    ($($arg:tt)*) => { $crate::say::to_stderr(format_args!($($arg)*), true) };
}

/// Writes to stdout like `print!`; a failed write stops all stdout output.
macro_rules! out {
    ($($arg:tt)*) => { $crate::say::to_stdout(format_args!($($arg)*), false) };
}

/// Writes a line to stdout like `println!`; a failed write stops all
/// stdout output.
macro_rules! outln {
    () => { $crate::say::to_stdout(format_args!(""), true) };
    ($($arg:tt)*) => { $crate::say::to_stdout(format_args!($($arg)*), true) };
}
