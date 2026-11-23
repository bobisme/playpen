//! Host-side private PTY byte relay for explicitly exclusive terminal input.
//!
//! The caller owns PTY allocation, the slave's controlling session, and the
//! decision which workload descriptors are attached to it. This relay opens
//! its own controlling-terminal descriptor and requires foreground tty stdin.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const CAPACITY: usize = 16 * 1024;
const ACK_TIMEOUT_MS: i32 = 1000;

/// Handle for a separately supervised relay helper.
pub struct Relay {
    control: OwnedFd,
    pid: libc::pid_t,
    tty: OwnedFd,
    original: libc::termios,
    stopped: bool,
}

impl Relay {
    /// Open and validate the exclusive foreground controlling terminal, then
    /// start the relay. The caller attaches only tty-backed standard streams to
    /// the private slave and initializes that slave from the original tty.
    ///
    /// # Errors
    /// If stdin is redirected, another process group owns the terminal, or
    /// relay setup fails. Nothing is started on validation failure.
    ///
    /// # Safety
    /// The caller must be single threaded: the helper executes Rust after fork.
    pub unsafe fn start(master: OwnedFd) -> io::Result<Self> {
        // Open the actual terminal device, not the /dev/tty alias: when a
        // session leader dies, /dev/tty stops resolving in its old session.
        // A separate open-file description also keeps O_NONBLOCK local.
        let mut path = [libc::c_char::default(); 4096];
        let name_error = unsafe { libc::ttyname_r(0, path.as_mut_ptr(), path.len()) };
        if name_error != 0 {
            return Err(io::Error::from_raw_os_error(name_error));
        }
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let outer_tty = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut source: libc::stat = unsafe { std::mem::zeroed() };
        let mut opened: libc::stat = unsafe { std::mem::zeroed() };
        let session = unsafe { libc::tcgetsid(fd) };
        if unsafe { libc::isatty(0) } != 1
            || unsafe { libc::fstat(0, &raw mut source) } != 0
            || unsafe { libc::fstat(fd, &raw mut opened) } != 0
            || source.st_dev != opened.st_dev
            || source.st_ino != opened.st_ino
            || source.st_rdev != opened.st_rdev
            || session < 0
            || unsafe { libc::tcgetsid(0) } != session
            || unsafe { libc::tcgetpgrp(0) != libc::getpgrp() }
            || unsafe { libc::tcgetpgrp(fd) != libc::getpgrp() }
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private tty requires foreground controlling-terminal stdin",
            ));
        }
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(outer_tty.as_raw_fd(), &raw mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut pair = [0; 2];
        // SAFETY: pair has space for two descriptors.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: socketpair returned owned descriptors.
        let parent = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        let child = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        let parent_pid = unsafe { libc::getpid() };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            drop(parent);
            let code = helper(
                master.as_raw_fd(),
                outer_tty.as_raw_fd(),
                child.as_raw_fd(),
                parent_pid,
            );
            unsafe { libc::_exit(code) }
        }
        drop(child);
        drop(master);
        let mut relay = Self {
            control: parent,
            pid,
            tty: outer_tty,
            original,
            stopped: false,
        };
        if let Err(e) = relay.resize().and_then(|()| relay.exchange(b'r')) {
            let _ = relay.stop();
            return Err(e);
        }
        Ok(relay)
    }

    /// Restore the host tty before the supervisor suspends.
    ///
    /// # Errors
    /// If the relay cannot acknowledge restoration.
    pub fn pause(&self) -> io::Result<()> {
        self.exchange(b'p')
    }
    /// Resume only while the outer tty belongs to the caller's foreground group.
    ///
    /// # Errors
    /// If the relay cannot acknowledge the request.
    pub fn resume(&self) -> io::Result<()> {
        self.exchange(b'r')
    }
    /// Copy the host tty's current window size to the private PTY.
    ///
    /// # Errors
    /// If querying or applying the size fails.
    pub fn resize(&self) -> io::Result<()> {
        self.exchange(b'w')
    }
    /// Detect an unexpected helper exit; restores the terminal if foreground.
    ///
    /// # Errors
    /// If the relay has exited or cannot be observed.
    pub fn check(&mut self) -> io::Result<()> {
        if self.stopped {
            return Err(io::Error::other("terminal relay is stopped"));
        }
        let mut status = 0;
        let result = unsafe { libc::waitpid(self.pid, &raw mut status, libc::WNOHANG) };
        if result == 0 {
            return Ok(());
        }
        if result == self.pid {
            self.stopped = true;
            self.restore();
            return Err(io::Error::other("terminal relay exited unexpectedly"));
        }
        Err(io::Error::last_os_error())
    }
    fn restore(&self) {
        if unsafe { libc::tcgetpgrp(self.tty.as_raw_fd()) == libc::getpgrp() } {
            unsafe {
                libc::tcsetattr(
                    self.tty.as_raw_fd(),
                    libc::TCSANOW,
                    &raw const self.original,
                );
            }
        }
    }
    /// Restore the host tty and reap the helper.
    ///
    /// # Errors
    /// If pending output cannot be drained or restoration cannot be confirmed.
    pub fn stop(&mut self) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        let result = self.exchange(b'q');
        self.stopped = true;
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(self.pid, &raw mut status, libc::WNOHANG) };
            if waited == self.pid || waited < 0 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                    libc::waitpid(self.pid, &raw mut status, 0);
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        self.restore();
        result
    }
    fn exchange(&self, command: u8) -> io::Result<()> {
        let fd = self.control.as_raw_fd();
        if unsafe { libc::send(fd, (&raw const command).cast(), 1, libc::MSG_NOSIGNAL) } != 1 {
            return Err(io::Error::last_os_error());
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&raw mut poll, 1, ACK_TIMEOUT_MS) } <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "terminal relay acknowledgement timed out",
            ));
        }
        let mut response = 0_u8;
        if unsafe { libc::read(fd, (&raw mut response).cast(), 1) } != 1 || response != b'k' {
            return Err(io::Error::other(
                "terminal relay rejected command or exited",
            ));
        }
        Ok(())
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

const extern "C" fn terminate(_: libc::c_int) {}

#[expect(
    clippy::too_many_lines,
    reason = "one bounded poll loop handles relay and control together"
)]
fn helper(master: RawFd, tty: RawFd, control: RawFd, parent: libc::pid_t) -> i32 {
    unsafe {
        libc::signal(libc::SIGTERM, terminate as *const () as libc::sighandler_t);
        for sig in [
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTSTP,
            libc::SIGCONT,
            libc::SIGWINCH,
            libc::SIGTTIN,
            libc::SIGTTOU,
            libc::SIGPIPE,
            libc::SIGHUP,
            libc::SIGUSR1,
            libc::SIGUSR2,
        ] {
            libc::signal(sig, libc::SIG_IGN);
        }
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut mask);
        libc::sigprocmask(libc::SIG_SETMASK, &raw const mask, std::ptr::null_mut());
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 || libc::getppid() != parent {
            return 1;
        }
    }
    // No inherited caller descriptor may keep a pipe or socket alive.
    // Set the parent-death signal before closing potentially many descriptors.
    close_except([master, tty, control]);
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(tty, &raw mut original) } != 0 {
        return 1;
    }
    for fd in [master, tty] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return 1;
        }
    }
    let mut active = false;
    let mut enabled = false;
    let mut master_eof = false;
    let mut to_master = Vec::with_capacity(CAPACITY);
    let mut to_tty = Vec::with_capacity(CAPACITY);
    loop {
        if unsafe { libc::getppid() != parent } {
            break;
        }
        let foreground = unsafe { libc::tcgetpgrp(tty) == libc::getpgrp() };
        if active && (!enabled || !foreground) {
            if foreground {
                unsafe {
                    libc::tcsetattr(tty, libc::TCSANOW, &raw const original);
                }
            }
            active = false;
        }
        if enabled && foreground {
            if set_outer_mode(master, tty, &original).is_err() {
                break;
            }
            active = true;
        }
        let output_allowed = foreground || terminal_background_output_allowed(tty);
        let mut fds = [
            libc::pollfd {
                fd: control,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if master_eof { -1 } else { master },
                events: (if to_tty.len() < CAPACITY {
                    libc::POLLIN
                } else {
                    0
                }) | (if to_master.is_empty() {
                    0
                } else {
                    libc::POLLOUT
                }),
                revents: 0,
            },
            libc::pollfd {
                fd: tty,
                events: (if enabled && foreground && active && to_master.len() < CAPACITY {
                    libc::POLLIN
                } else {
                    0
                }) | (if enabled && output_allowed && !to_tty.is_empty() {
                    libc::POLLOUT
                } else {
                    0
                }),
                revents: 0,
            },
        ];
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 3, 20) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            break;
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let mut byte = 0_u8;
            if unsafe { libc::read(control, (&raw mut byte).cast(), 1) } != 1 {
                break;
            }
            let mut ok = true;
            match byte {
                b'p' => {
                    enabled = false;
                    if active {
                        ok = restore_foreground(tty, &original);
                        active = false;
                    }
                }
                b'r' => {
                    enabled = true;
                    if unsafe { libc::tcgetpgrp(tty) == libc::getpgrp() } {
                        if set_outer_mode(master, tty, &original).is_err() {
                            break;
                        }
                        active = true;
                    }
                }
                b'w' => {
                    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
                    ok = unsafe {
                        libc::ioctl(tty, libc::TIOCGWINSZ, &raw mut size) == 0
                            && libc::ioctl(master, libc::TIOCSWINSZ, &raw const size) == 0
                    };
                }
                b'q' => {
                    ok = drain_output(master, tty, &mut to_tty);
                    if active {
                        ok &= restore_foreground(tty, &original);
                        active = false;
                    }
                }
                _ => break,
            }
            let reply = if ok { b'k' } else { b'e' };
            if unsafe { libc::send(control, (&raw const reply).cast(), 1, libc::MSG_NOSIGNAL) } != 1
            {
                break;
            }
            if byte == b'q' {
                break;
            }
        }
        if fds[1].revents & libc::POLLIN != 0 {
            read_into(master, &mut to_tty);
        }
        if enabled
            && active
            && unsafe { libc::tcgetpgrp(tty) == libc::getpgrp() }
            && fds[2].revents & libc::POLLIN != 0
        {
            read_into(tty, &mut to_master);
        }
        if fds[1].revents & libc::POLLOUT != 0 {
            write_from(master, &mut to_master);
        }
        if enabled
            && (unsafe { libc::tcgetpgrp(tty) == libc::getpgrp() }
                || terminal_background_output_allowed(tty))
            && fds[2].revents & libc::POLLOUT != 0
        {
            write_from(tty, &mut to_tty);
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
            && to_tty.is_empty()
        {
            master_eof = true;
        }
        if fds[2].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            break;
        }
    }
    // If the supervisor was the terminal's session leader, its death can
    // disassociate the tty entirely. Restore that unowned tty, but never one
    // already reassigned to another foreground session.
    if active
        && (unsafe { libc::tcgetpgrp(tty) == libc::getpgrp() }
            || unsafe { libc::tcgetsid(tty) < 0 })
    {
        unsafe {
            libc::tcsetattr(tty, libc::TCSANOW, &raw const original);
        }
    }
    0
}
fn read_into(fd: RawFd, buffer: &mut Vec<u8>) {
    let mut temp = [0_u8; 4096];
    let available = (CAPACITY - buffer.len()).min(temp.len());
    let n = unsafe { libc::read(fd, temp.as_mut_ptr().cast(), available) };
    if n > 0 {
        buffer.extend_from_slice(&temp[..n.cast_unsigned()]);
    }
}
fn write_from(fd: RawFd, buffer: &mut Vec<u8>) {
    let n = unsafe { libc::write(fd, buffer.as_ptr().cast(), buffer.len()) };
    if n > 0 {
        buffer.drain(..n.cast_unsigned());
    }
}

// Called only after the supervisor has observed workload exit. The relay
// continues draining available output even if init temporarily retains a
// slave fd; a blocked or background tty fails within a bounded interval.
#[expect(
    clippy::comparison_chain,
    clippy::collapsible_if,
    reason = "explicit read outcomes and tty ownership conditions"
)]
fn drain_output(master: RawFd, tty: RawFd, buffer: &mut Vec<u8>) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(600);
    let mut eof = false;
    loop {
        if unsafe { libc::tcgetpgrp(tty) == libc::getpgrp() }
            || terminal_background_output_allowed(tty)
        {
            if !buffer.is_empty() {
                write_from(tty, buffer);
            }
        }
        if !eof && buffer.len() < CAPACITY {
            let mut bytes = [0_u8; 4096];
            let room = (CAPACITY - buffer.len()).min(bytes.len());
            let n = unsafe { libc::read(master, bytes.as_mut_ptr().cast(), room) };
            if n > 0 {
                buffer.extend_from_slice(&bytes[..n.cast_unsigned()]);
            } else if n == 0 {
                eof = true;
            } else {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EIO) {
                    eof = true;
                } else if !matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    return false;
                }
            }
        }
        if eof && buffer.is_empty() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        let mut fds = [libc::pollfd {
            fd: tty,
            events: libc::POLLOUT,
            revents: 0,
        }];
        unsafe {
            libc::poll(fds.as_mut_ptr(), 1, 10);
        }
    }
}
fn terminal_background_output_allowed(tty: RawFd) -> bool {
    let mut current: libc::termios = unsafe { std::mem::zeroed() };
    unsafe { libc::tcgetattr(tty, &raw mut current) == 0 && current.c_lflag & libc::TOSTOP == 0 }
}

// Mirror slave signal settings for its session leader. A nested foreground
// job receives control characters as bytes, letting its own line discipline
// signal it without affecting other stages in the outer pipeline. The 20 ms
// polling interval leaves a mode and foreground-group transition race.
#[expect(
    clippy::collapsible_if,
    reason = "mode difference is separate from syscall failure"
)]
fn set_outer_mode(master: RawFd, tty: RawFd, original: &libc::termios) -> io::Result<()> {
    let mut inner: libc::termios = unsafe { std::mem::zeroed() };
    let mut current: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(master, &raw mut inner) } != 0
        || unsafe { libc::tcgetattr(tty, &raw mut current) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut raw = *original;
    unsafe {
        libc::cfmakeraw(&raw mut raw);
    }
    let session = unsafe { libc::tcgetsid(master) };
    let foreground = unsafe { libc::tcgetpgrp(master) };
    if outer_signals(inner.c_lflag, session, foreground) {
        raw.c_lflag |= libc::ISIG;
    }
    for index in [libc::VINTR, libc::VQUIT, libc::VSUSP] {
        raw.c_cc[index] = inner.c_cc[index];
    }
    if current.c_iflag != raw.c_iflag
        || current.c_oflag != raw.c_oflag
        || current.c_cflag != raw.c_cflag
        || current.c_lflag != raw.c_lflag
        || current.c_cc != raw.c_cc
    {
        if unsafe { libc::tcsetattr(tty, libc::TCSANOW, &raw const raw) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn close_except(mut keep: [RawFd; 3]) {
    keep.sort_unstable();
    let mut first = 0_u32;
    let mut supported = true;
    for fd in keep {
        let end = u32::try_from(fd).unwrap_or(0);
        if first < end && unsafe { libc::syscall(libc::SYS_close_range, first, end - 1, 0) } < 0 {
            supported = false;
            break;
        }
        first = end.saturating_add(1);
    }
    if supported && unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0) } == 0 {
        return;
    }
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }.clamp(3, 1_048_576);
    for fd in 0..max as i32 {
        if !keep.contains(&fd) {
            unsafe {
                libc::close(fd);
            }
        }
    }
}

fn restore_foreground(tty: RawFd, original: &libc::termios) -> bool {
    unsafe {
        libc::tcgetpgrp(tty) == libc::getpgrp()
            && libc::tcsetattr(tty, libc::TCSANOW, original) == 0
    }
}

const fn outer_signals(
    flags: libc::tcflag_t,
    session: libc::pid_t,
    foreground: libc::pid_t,
) -> bool {
    let nested = session > 0 && foreground > 0 && session != foreground;
    !nested && flags & libc::ISIG != 0
}

#[cfg(test)]
mod tests {
    use super::outer_signals;

    #[test]
    fn signal_mode_distinguishes_nested_top_level_and_raw() {
        assert!(outer_signals(libc::ISIG, 100, 100));
        assert!(!outer_signals(libc::ISIG, 100, 101));
        assert!(!outer_signals(0, 100, 100));
        assert!(!outer_signals(0, 100, 101));
        // Before a private session is installed, preserve top-level behavior.
        assert!(outer_signals(libc::ISIG, -1, -1));
    }
}
