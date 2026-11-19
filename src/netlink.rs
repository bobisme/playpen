//! A few route-netlink requests, built by hand.
//!
//! They bring an interface up, add an address and create a link. Used to set
//! up `lo` inside the namespace and by the probes that check the command
//! cannot change the network.

use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};

use nix::errno::Errno;
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, recv, sendto, socket,
};

const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const IFF_UP: u32 = 0x1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_F_NODAD: u8 = 0x02;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const RT_SCOPE_HOST: u8 = 254;

/// Interface index of `lo`, which is always 1 in a new network namespace.
pub const LO_INDEX: u32 = 1;

fn attr(buf: &mut Vec<u8>, ty: u16, data: &[u8]) {
    let len = u16::try_from(4 + data.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(data);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

fn message(ty: u16, flags: u16, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(16 + body.len()).unwrap_or(u32::MAX);
    let mut msg = Vec::with_capacity(16 + body.len());
    msg.extend_from_slice(&len.to_ne_bytes());
    msg.extend_from_slice(&ty.to_ne_bytes());
    msg.extend_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // sequence
    msg.extend_from_slice(&0u32.to_ne_bytes()); // port id: kernel assigns
    msg.extend_from_slice(body);
    msg
}

fn open() -> Result<OwnedFd, Errno> {
    socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )
}

/// Sends one request and waits for the kernel's acknowledgement.
fn request(msg: &[u8]) -> Result<(), Errno> {
    let fd = open()?;
    let kernel = NetlinkAddr::new(0, 0);
    sendto(fd.as_raw_fd(), msg, &kernel, MsgFlags::empty())?;
    let mut buf = [0u8; 4096];
    let n = recv(fd.as_raw_fd(), &mut buf, MsgFlags::empty())?;
    if n < 20 {
        return Err(Errno::EPROTO);
    }
    let ty = u16::from_ne_bytes([buf[4], buf[5]]);
    if ty != NLMSG_ERROR {
        return Err(Errno::EPROTO);
    }
    let code = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
    if code == 0 {
        Ok(())
    } else {
        Err(Errno::from_raw(-code))
    }
}

/// Sets interface `index` up.
///
/// # Errors
/// The kernel's error, for example `EPERM` without `CAP_NET_ADMIN`.
pub fn set_link_up(index: u32) -> Result<(), Errno> {
    let mut body = Vec::new();
    body.push(0); // family: unspecified
    body.push(0); // pad
    body.extend_from_slice(&0u16.to_ne_bytes()); // device type
    body.extend_from_slice(&index.to_ne_bytes());
    body.extend_from_slice(&IFF_UP.to_ne_bytes()); // flags
    body.extend_from_slice(&IFF_UP.to_ne_bytes()); // change mask
    request(&message(RTM_NEWLINK, 0, &body))
}

/// Adds `addr` with a full-length prefix to interface `index`.
///
/// # Errors
/// The kernel's error.
pub fn add_address(index: u32, addr: IpAddr) -> Result<(), Errno> {
    let (family, prefix, bytes, flags): (u8, u8, Vec<u8>, u8) = match addr {
        IpAddr::V4(a) => (AF_INET, 32, a.octets().to_vec(), 0),
        IpAddr::V6(a) => (AF_INET6, 128, a.octets().to_vec(), IFA_F_NODAD),
    };
    let mut body = vec![family, prefix, flags, RT_SCOPE_HOST];
    body.extend_from_slice(&index.to_ne_bytes());
    if family == AF_INET {
        attr(&mut body, IFA_LOCAL, &bytes);
    }
    attr(&mut body, IFA_ADDRESS, &bytes);
    request(&message(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &body))
}

/// Tries to create a link of `kind` (for example `dummy`) called `name`.
///
/// # Errors
/// The kernel's error.
pub fn add_link(name: &str, kind: &str) -> Result<(), Errno> {
    let mut body = vec![0u8, 0];
    body.extend_from_slice(&0u16.to_ne_bytes());
    body.extend_from_slice(&0i32.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    let mut ifname = name.as_bytes().to_vec();
    ifname.push(0);
    attr(&mut body, IFLA_IFNAME, &ifname);
    let mut info = Vec::new();
    let mut kind_z = kind.as_bytes().to_vec();
    kind_z.push(0);
    attr(&mut info, IFLA_INFO_KIND, &kind_z);
    attr(&mut body, IFLA_LINKINFO, &info);
    request(&message(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &body))
}
