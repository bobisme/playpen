//! `playpen probe`: small checks run *inside* the sandbox by `playpen
//! doctor` and by the tests. Hidden from `--help`; not a stable interface.

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
