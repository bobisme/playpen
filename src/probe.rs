//! `playpen probe`: small checks run *inside* the sandbox by `playpen
//! doctor` and by the tests. Hidden from `--help`; not a stable interface.

use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::time::Duration;

use std::os::fd::AsRawFd as _;

use nix::errno::Errno;
use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockProtocol, SockType, UnixAddr, bind, connect,
    listen as listen_on, socket,
};
use serde_json::{Value, json};

/// A probe target: `ADDR:PORT/tcp` or `ADDR:PORT/udp` (IPv6 in brackets).
#[derive(Debug, Clone, Copy)]
pub struct Target {
    /// Socket address.
    pub addr: SocketAddr,
    /// True for UDP.
    pub udp: bool,
}

/// Lists interface names visible through the current network namespace.
#[must_use]
pub fn interfaces() -> String {
    let contents = fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let names = contents
        .lines()
        .skip(2)
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim().to_owned()))
        .collect::<Vec<_>>();
    json!({"interfaces": names}).to_string()
}

/// Parses a probe target.
///
/// # Errors
/// On malformed text.
pub fn parse_target(text: &str) -> Result<Target, String> {
    let (addr, proto) = text
        .rsplit_once('/')
        .ok_or_else(|| format!("{text:?}: expected ADDR:PORT/tcp or /udp"))?;
    let udp = match proto {
        "tcp" => false,
        "udp" => true,
        _ => return Err(format!("{text:?}: protocol must be tcp or udp")),
    };
    let addr = addr
        .parse()
        .map_err(|e| format!("{text:?}: bad address: {e}"))?;
    Ok(Target { addr, udp })
}

fn serve(target: Target) -> Result<(), String> {
    if target.udp {
        let sock =
            UdpSocket::bind(target.addr).map_err(|e| format!("bind {}: {e}", target.addr))?;
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let _ = sock.send_to(&buf[..n], from);
            }
        });
    } else {
        let listener =
            TcpListener::bind(target.addr).map_err(|e| format!("listen {}: {e}", target.addr))?;
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                drop(conn);
            }
        });
    }
    Ok(())
}

/// Tries to reach `target`. Returns the error text when it was not reached.
fn attempt(target: Target) -> Result<(), String> {
    if target.udp {
        let local: SocketAddr = if target.addr.is_ipv4() {
            "0.0.0.0:0".parse().map_err(|_| "addr")?
        } else {
            "[::]:0".parse().map_err(|_| "addr")?
        };
        let sock = UdpSocket::bind(local).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_millis(1500)))
            .map_err(|e| e.to_string())?;
        sock.send_to(b"playpen-probe", target.addr)
            .map_err(|e| e.to_string())?;
        let mut buf = [0u8; 64];
        sock.recv_from(&mut buf)
            .map(|_| ())
            .map_err(|e| e.to_string())
    } else {
        TcpStream::connect_timeout(&target.addr, Duration::from_secs(3))
            .map(drop)
            .map_err(|e| e.to_string())
    }
}

/// `probe reach`: starts listeners for `serve`, then tries each of `tries`.
///
/// # Errors
/// When a listener cannot be started.
pub fn reach(serve_on: &[Target], tries: &[Target]) -> Result<Vec<Value>, String> {
    for t in serve_on {
        serve(*t)?;
    }
    Ok(tries
        .iter()
        .map(|t| {
            let target = format!("{}/{}", t.addr, if t.udp { "udp" } else { "tcp" });
            match attempt(*t) {
                Ok(()) => json!({"target": target, "reached": true}),
                Err(e) => json!({"target": target, "reached": false, "error": e}),
            }
        })
        .collect())
}

fn outcome(r: Result<(), String>) -> Value {
    match r {
        Ok(()) => json!("ALLOWED"),
        Err(e) => json!(format!("denied: {e}")),
    }
}

fn errno_outcome(r: Result<(), Errno>) -> Value {
    outcome(r.map_err(|e| e.to_string()))
}

fn try_socket(family: AddressFamily, proto: Option<SockProtocol>) -> Result<(), Errno> {
    socket(family, SockType::Raw, SockFlag::SOCK_CLOEXEC, proto).map(drop)
}

/// `probe privs`: tries everything the command must not be able to do.
#[must_use]
pub fn privs(nft: &str) -> Value {
    let nft_flush = match Command::new(nft).args(["flush", "ruleset"]).output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_owned()),
        Err(e) => Err(format!("cannot run nft: {e}")),
    };
    let nft_add = match Command::new(nft)
        .args(["add", "table", "inet", "escape"])
        .output()
    {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_owned()),
        Err(e) => Err(format!("cannot run nft: {e}")),
    };
    let doc = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 77));
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .map_or_else(String::new, |v| v.trim().to_owned())
    };
    json!({
        "nft_flush_ruleset": outcome(nft_flush),
        "nft_add_table": outcome(nft_add),
        "add_address": errno_outcome(crate::netlink::add_address(crate::netlink::LO_INDEX, doc)),
        "add_link": errno_outcome(crate::netlink::add_link("escape0", "dummy")),
        "set_link_up": errno_outcome(crate::netlink::set_link_up(crate::netlink::LO_INDEX)),
        "raw_socket_v4": errno_outcome(try_socket(AddressFamily::Inet, Some(SockProtocol::Icmp))),
        "raw_socket_v6": errno_outcome(try_socket(AddressFamily::Inet6, Some(SockProtocol::IcmpV6))),
        "packet_socket": errno_outcome(try_socket(AddressFamily::Packet, None)),
        "setns_net_of_pid1": outcome(setns_pid1()),
        "read_pid1_memory": outcome(std::fs::File::open("/proc/1/mem").map(drop).map_err(|e| e.to_string())),
        "cap_eff": field("CapEff:"),
        "cap_prm": field("CapPrm:"),
        "no_new_privs": field("NoNewPrivs:"),
        "uid": nix::unistd::getuid().as_raw(),
        "gid": nix::unistd::getgid().as_raw(),
    })
}

/// Tries to join the user namespace of PID 1 (the sandbox's init, which
/// holds the capabilities over the network namespace).
fn setns_pid1() -> Result<(), String> {
    let f = std::fs::File::open("/proc/1/ns/user").map_err(|e| e.to_string())?;
    nix::sched::setns(f, nix::sched::CloneFlags::CLONE_NEWUSER).map_err(|e| e.to_string())
}

fn unix_addr(target: &str) -> Result<UnixAddr, Errno> {
    target.strip_prefix('@').map_or_else(
        || UnixAddr::new(target),
        |name| UnixAddr::new_abstract(name.as_bytes()),
    )
}

/// Connects to one Unix socket (`@NAME` for the abstract namespace) and
/// closes at once; nothing is written. Tries stream, datagram and
/// seqpacket in turn, since `connect` fails with `EPROTOTYPE` on a socket
/// of another type.
fn unix_connect(target: &str) -> Result<(), String> {
    let addr = unix_addr(target).map_err(|e| e.to_string())?;
    let mut last = Errno::EPROTOTYPE;
    for ty in [SockType::Stream, SockType::Datagram, SockType::SeqPacket] {
        let fd = socket(AddressFamily::Unix, ty, SockFlag::SOCK_CLOEXEC, None)
            .map_err(|e| e.to_string())?;
        match connect(fd.as_raw_fd(), &addr) {
            Ok(()) => return Ok(()),
            Err(Errno::EPROTOTYPE) => last = Errno::EPROTOTYPE,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err(last.to_string())
}

/// `probe unix`: listens on each of `listen` (the command's own sockets),
/// then connects to each of `tries` and closes again. One JSON line per
/// try: `{"path", "connected", "error"}`.
///
/// # Errors
/// When a listener cannot be created.
pub fn unix(listen: &[String], tries: &[String]) -> Result<Vec<Value>, String> {
    let mut keep = Vec::new();
    for path in listen {
        let addr = unix_addr(path).map_err(|e| format!("{path}: {e}"))?;
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|e| format!("socket: {e}"))?;
        bind(fd.as_raw_fd(), &addr).map_err(|e| format!("bind {path}: {e}"))?;
        listen_on(&fd, Backlog::new(8).map_err(|e| e.to_string())?)
            .map_err(|e| format!("listen {path}: {e}"))?;
        keep.push(fd);
    }
    let lines = tries
        .iter()
        .map(|t| match unix_connect(t) {
            Ok(()) => json!({"path": t, "connected": true}),
            Err(e) => json!({"path": t, "connected": false, "error": e}),
        })
        .collect();
    drop(keep);
    Ok(lines)
}

/// Read exactly one connection result per requested Unix endpoint and return
/// the paths that connected. The probe can emit results in any order.
///
/// # Errors
/// Returns an error for malformed, contradictory, duplicate or missing evidence.
pub fn connected_unix_paths(
    output: &str,
    paths: &[impl AsRef<str>],
) -> Result<Vec<String>, String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Record {
        path: String,
        connected: bool,
        error: Option<String>,
    }

    let mut pending: std::collections::BTreeSet<&str> = paths.iter().map(AsRef::as_ref).collect();
    if pending.len() != paths.len() {
        return Err("duplicate Unix probe request".into());
    }
    let mut connected = Vec::new();
    for (index, line) in output.lines().enumerate() {
        let record: Record = serde_json::from_str(line)
            .map_err(|e| format!("invalid Unix probe record on line {}: {e}", index + 1))?;
        if !pending.remove(record.path.as_str()) {
            return Err(format!(
                "unexpected or repeated Unix endpoint {:?}",
                record.path
            ));
        }
        match (record.connected, record.error) {
            (true, None) => connected.push(record.path),
            (false, Some(error)) if !error.trim().is_empty() => {}
            _ => {
                return Err(format!(
                    "inconsistent Unix probe result for {:?}",
                    record.path
                ));
            }
        }
    }
    if let Some(path) = pending.first() {
        return Err(format!("missing Unix probe result for {path:?}"));
    }
    Ok(connected)
}

/// `probe unix-send PATH`: sends one datagram, `playpen-probe`, by address
/// from an unconnected datagram socket. Only for sockets the caller made
/// for the test.
#[must_use]
pub fn unix_send(path: &str) -> Value {
    let sent = unix_addr(path)
        .and_then(|addr| {
            let fd = socket(
                AddressFamily::Unix,
                SockType::Datagram,
                SockFlag::SOCK_CLOEXEC,
                None,
            )?;
            nix::sys::socket::sendto(
                fd.as_raw_fd(),
                b"playpen-probe",
                &addr,
                nix::sys::socket::MsgFlags::empty(),
            )
        })
        .map(drop)
        .map_err(|e| e.to_string());
    json!({"path": path, "sent": outcome(sent)})
}

/// `probe listen`: listens on a TCP address for `ms` milliseconds.
///
/// Prints `{"listening": ADDR}` once the socket is bound, `{"accepted":
/// FROM}` for each connection as it arrives, and the count at the end.
///
/// # Errors
/// When the address cannot be bound.
pub fn listen_tcp(target: Target, ms: u64) -> Result<Value, String> {
    use std::io::Write as _;
    let listener =
        TcpListener::bind(target.addr).map_err(|e| format!("listen {}: {e}", target.addr))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    println!("{}", json!({"listening": target.addr.to_string()}));
    let _ = std::io::stdout().flush();
    let end = std::time::Instant::now() + Duration::from_millis(ms);
    let mut accepted = 0u32;
    while std::time::Instant::now() < end {
        match listener.accept() {
            Ok((_, from)) => {
                accepted += 1;
                println!("{}", json!({"accepted": from.to_string()}));
                let _ = std::io::stdout().flush();
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    Ok(json!({"total": accepted}))
}

/// `probe tty`: whether this process can push a character into the input
/// of the terminal on standard input (`TIOCSTI`), and open `/dev/tty`.
///
/// The character pushed would be a NUL byte, harmless if it got through.
#[must_use]
pub fn tty() -> Value {
    let byte: libc::c_char = 0;
    // SAFETY: TIOCSTI reads exactly one `char` through the pointer, which
    // points at a live local. On a descriptor that is not a terminal the
    // kernel only returns an error.
    let rc = unsafe { libc::ioctl(0, libc::TIOCSTI, &raw const byte) };
    let tiocsti = if rc == 0 {
        Ok(())
    } else {
        Err(Errno::last().to_string())
    };
    let dev_tty = std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/tty")
        .map(drop)
        .map_err(|e| e.to_string());
    json!({"tiocsti": outcome(tiocsti), "dev_tty": outcome(dev_tty)})
}

/// `probe fds`: the descriptors this process has open, with what they
/// point to.
#[must_use]
pub fn fds() -> Value {
    let mut list = Vec::new();
    if let Ok(dir) = std::fs::read_dir("/proc/self/fd") {
        for e in dir.filter_map(Result::ok) {
            let name = e.file_name().to_string_lossy().into_owned();
            let target = std::fs::read_link(e.path())
                .map_or_else(|_| String::new(), |p| p.display().to_string());
            list.push(json!({"fd": name.parse::<i32>().unwrap_or(-1), "target": target}));
        }
    }
    json!({"fds": list})
}

/// `probe resolve NAME`: what the system resolver returns for `name`.
#[must_use]
pub fn resolve(name: &str) -> Value {
    match (name, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            let mut list: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
            list.sort();
            list.dedup();
            json!({"name": name, "addresses": list})
        }
        Err(e) => json!({"name": name, "addresses": [], "error": e.to_string()}),
    }
}

/// Counts deliveries of SIGUSR1 until SIGTERM arrives. Prints `ready` once
/// both are blocked and `usr1` for each receipt. Two
/// copies that arrive apart are counted separately.
///
/// # Errors
/// When the signals cannot be blocked or waited for.
pub fn signals() -> Result<Value, String> {
    use nix::sys::signal::{SigSet, SigmaskHow, Signal, sigprocmask};
    let mut set = SigSet::empty();
    set.add(Signal::SIGUSR1);
    set.add(Signal::SIGTERM);
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&set), None).map_err(|e| e.to_string())?;
    println!("ready");
    let mut usr1 = 0u32;
    loop {
        match set.wait() {
            Ok(Signal::SIGUSR1) => {
                usr1 += 1;
                println!("usr1");
            }
            Ok(_) => return Ok(json!({ "usr1": usr1 })),
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// `probe unix-recv-fd`: takes a descriptor passed over a Unix socket.
///
/// Connects to the Unix stream socket at `path`, takes one descriptor the
/// peer passes (`SCM_RIGHTS`), and sends one datagram to `to` through it.
/// Shows what the peer of a reachable socket can hand the command. Only
/// for sockets the caller made for the test.
#[must_use]
pub fn unix_recv_fd(path: &str, to: SocketAddr) -> Value {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};
    let received = (|| -> Result<OwnedFd, String> {
        let addr = unix_addr(path).map_err(|e| e.to_string())?;
        let sock = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .map_err(|e| e.to_string())?;
        connect(sock.as_raw_fd(), &addr).map_err(|e| format!("connect: {e}"))?;
        let mut byte = [0u8; 1];
        let mut iov = [std::io::IoSliceMut::new(&mut byte)];
        let mut space = nix::cmsg_space!([RawFd; 1]);
        let msg = recvmsg::<()>(
            sock.as_raw_fd(),
            &mut iov,
            Some(&mut space),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )
        .map_err(|e| format!("recvmsg: {e}"))?;
        let fd = msg
            .cmsgs()
            .map_err(|e| e.to_string())?
            .find_map(|c| match c {
                ControlMessageOwned::ScmRights(fds) => fds.first().copied(),
                _ => None,
            })
            .ok_or("the peer passed no descriptor")?;
        // SAFETY: the kernel just installed this descriptor for us with
        // the message; nothing else owns it.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    })();
    match received {
        Err(e) => json!({"path": path, "received": false, "error": e}),
        Ok(fd) => {
            let sent = UdpSocket::from(fd)
                .send_to(b"playpen-probe", to)
                .map(drop)
                .map_err(|e| e.to_string());
            json!({"path": path, "received": true, "sent": outcome(sent)})
        }
    }
}

/// `probe stdout-reconnect`: tries to point the socket on standard output
/// somewhere else.
///
/// Dissolves the socket's association (`connect` with `AF_UNSPEC`), then
/// connects it to `target` (`ADDR:PORT/tcp`, a Unix path, or `@NAME`) and
/// writes a few bytes. The socket was made by the caller, in the host's
/// network namespace, so where it can be pointed is outside the filter.
/// Only for sockets and listeners the caller made for the test.
#[must_use]
pub fn stdout_reconnect(target: &str) -> Value {
    let unspec = libc::sockaddr {
        sa_family: libc::sa_family_t::try_from(libc::AF_UNSPEC).unwrap_or(0),
        sa_data: [0; 14],
    };
    let len = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr>()).unwrap_or(0);
    // SAFETY: connect(2) reads `len` bytes of a live `sockaddr` on the
    // stack; descriptor 1 is this process's standard output.
    let rc = unsafe { libc::connect(1, &raw const unspec, len) };
    let dissolved = if rc == 0 {
        Ok(())
    } else {
        Err(Errno::last().to_string())
    };
    let connected = parse_target(target).map_or_else(
        |_| {
            unix_addr(target)
                .and_then(|addr| connect(1, &addr))
                .map_err(|e| e.to_string())
        },
        |t| {
            match t.addr {
                SocketAddr::V4(a) => connect(1, &nix::sys::socket::SockaddrIn::from(a)),
                SocketAddr::V6(a) => connect(1, &nix::sys::socket::SockaddrIn6::from(a)),
            }
            .map_err(|e| e.to_string())
        },
    );
    let wrote = connected.clone().and_then(|()| {
        nix::sys::socket::send(
            1,
            b"playpen-probe",
            nix::sys::socket::MsgFlags::MSG_NOSIGNAL,
        )
        .map(drop)
        .map_err(|e| e.to_string())
    });
    json!({
        "target": target,
        "dissolved": outcome(dissolved),
        "connected": outcome(connected),
        "wrote": outcome(wrote),
    })
}

#[cfg(test)]
mod tests {
    use super::connected_unix_paths;

    #[test]
    fn unix_evidence_matches_the_requested_paths_and_decodes_boolean_values() {
        let lines = r#"{"connected": false,"error":"unreachable","path":"@host"}
{"path":"/own/socket", "connected": true}
"#;
        assert_eq!(
            connected_unix_paths(lines, &["/own/socket", "@host"]).expect("valid records"),
            ["/own/socket"]
        );
    }

    #[test]
    fn incomplete_or_malformed_output_cannot_establish_socket_isolation() {
        let denied = r#"{"path":"@a","connected":false,"error":"unreachable"}"#;
        for other in [
            "",
            "{}",
            "malformed",
            denied,
            r#"{"path":"@unknown","connected":false,"error":"unreachable"}"#,
            r#"{"path":"@b","connected":"false","error":"unreachable"}"#,
            r#"{"path":"@b","connected":false}"#,
            r#"{"path":"@b","connected":false,"error":""}"#,
            r#"{"path":"@b","connected":true,"error":"unreachable"}"#,
            r#"{"path":"@b","connected":false,"connected":true}"#,
            r#"{"path":"@b","reachable":false,"error":"unreachable"}"#,
        ] {
            assert!(
                connected_unix_paths(&format!("{denied}\n{other}"), &["@a", "@b"]).is_err(),
                "{other}"
            );
        }
        assert!(connected_unix_paths(denied, &["@a", "@a"]).is_err());
    }
}
