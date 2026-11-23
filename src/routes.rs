//! A route for every packet, so that the firewall sees every attempt.
//!
//! The kernel routes a packet before the output hook sees it. A packet
//! with no route fails at once with "Network is unreachable" and never
//! reaches the ruleset, so it is neither counted nor refused by it, and
//! `--fail-on-drop`, `--on-drop` and `--live-drops` miss it. That happens
//! to every packet for another host under `--no-network`, where the
//! namespace would have only `lo`, and to one address family with pasta
//! when the host has no default route for it (pasta copies the host's
//! routes).
//!
//! So C gives the sandbox a default route for each family before the
//! command exists:
//!
//! - under `--no-network`, out of [`DISCARD`], a `dummy` interface, which
//!   frees every packet handed to it. It has the addresses [`DISCARD_V4`]
//!   and [`DISCARD_V6`] so that the kernel has a source address to put on
//!   a packet to another host. The ruleset approves nothing there, so
//!   every such packet is counted and refused before it gets to the
//!   interface;
//! - with pasta, for each family that has no default route once pasta has
//!   configured the namespace, out of pasta's interface, without a
//!   gateway. pasta answers address resolution for any address on that
//!   link, so a refused packet fails as fast as any other, and an approved
//!   one reaches pasta, which tries it from the host as usual.
//!
//! When this cannot be done, C says why ([`crate::sandbox`]), and the run
//! says that such packets are not counted.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nix::errno::Errno;

use crate::netlink::{self, Family};

/// The name of the discard interface under `--no-network`.
pub const DISCARD: &str = "discard0";

/// The IPv4 address of [`DISCARD`]: the "IPv4 dummy address" of RFC 7600,
/// which IANA lists as a source only, never a destination, and neither
/// forwardable nor globally reachable.
pub const DISCARD_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 8);

/// The IPv6 address of [`DISCARD`], in the "Dummy IPv6 Prefix"
/// `100:0:0:1::/64` (RFC 9780), which IANA lists with the same properties
/// as [`DISCARD_V4`].
pub const DISCARD_V6: Ipv6Addr = Ipv6Addr::new(0x100, 0, 0, 1, 0, 0, 0, 8);

/// `RTF_UP` in the route flags of `/proc/net/route` and `ipv6_route`.
const RTF_UP: u32 = 0x0001;
/// `RTF_REJECT`: an unreachable or prohibit route, which is no route out.
const RTF_REJECT: u32 = 0x0200;

/// The interfaces that carry a default route, per address family.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct DefaultRoutes {
    /// Interfaces with an IPv4 default route in the main table.
    pub ipv4: Vec<String>,
    /// Interfaces with an IPv6 default route.
    pub ipv6: Vec<String>,
}

impl DefaultRoutes {
    /// Reads the routes of the current network namespace from
    /// `/proc/self/net/route` (the main table) and
    /// `/proc/self/net/ipv6_route`.
    ///
    /// # Errors
    /// When either file cannot be read.
    pub fn read() -> Result<Self, String> {
        let read = |name: &str| {
            std::fs::read_to_string(format!("/proc/self/net/{name}"))
                .map_err(|e| format!("cannot read /proc/self/net/{name}: {e}"))
        };
        Ok(Self::parse(&read("route")?, &read("ipv6_route")?))
    }

    /// Parses the text of `/proc/net/route` and `/proc/net/ipv6_route`.
    /// A default route is one to every address that is up and not a
    /// reject route (the kernel lists one of those for `lo`).
    #[must_use]
    pub fn parse(route: &str, ipv6_route: &str) -> Self {
        let usable = |flags: &str| {
            u32::from_str_radix(flags, 16).is_ok_and(|f| f & RTF_UP != 0 && f & RTF_REJECT == 0)
        };
        let mut out = Self::default();
        // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        for line in route.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if let [iface, "00000000", _, flags, _, _, _, "00000000", ..] = f[..]
                && usable(flags)
            {
                out.ipv4.push(iface.to_owned());
            }
        }
        // dest dst_len src src_len next_hop metric refcnt use flags iface
        let any = "0".repeat(32);
        for line in ipv6_route.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if let [dest, "00", _, "00", _, _, _, _, flags, iface] = f[..]
                && dest == any
                && usable(flags)
            {
                out.ipv6.push(iface.to_owned());
            }
        }
        out
    }

    /// The interfaces with a default route for `family`.
    #[must_use]
    pub fn of(&self, family: Family) -> &[String] {
        match family {
            Family::V4 => &self.ipv4,
            Family::V6 => &self.ipv6,
        }
    }
}

/// What C says when packets of `families` cannot reach the firewall.
fn uncounted(families: &[Family], why: &str) -> String {
    let names: Vec<&str> = families.iter().map(|f| f.name()).collect();
    format!(
        "{} packets to other hosts fail at routing and are not counted ({why})",
        names.join(" and ")
    )
}

/// The reason for a failed netlink request, with the kernel's error.
fn because(what: &str, e: Errno) -> String {
    format!("{what}: {}", e.desc())
}

/// Under `--no-network`: creates [`DISCARD`] with its addresses, sets it
/// up and routes both families out of it.
///
/// # Errors
/// What is not counted and why, one sentence per cause.
pub fn make_discard_interface() -> Result<(), String> {
    let both = Family::BOTH;
    match netlink::add_link(DISCARD, "dummy") {
        Ok(()) => {}
        Err(Errno::EOPNOTSUPP) => {
            return Err(uncounted(
                &both,
                &format!(
                    "cannot create {DISCARD}: this kernel has no dummy interface driver and cannot load it (CONFIG_DUMMY)"
                ),
            ));
        }
        Err(e) => {
            return Err(uncounted(
                &both,
                &because(&format!("cannot create {DISCARD}"), e),
            ));
        }
    }
    let index = nix::net::if_::if_nametoindex(DISCARD)
        .map_err(|e| uncounted(&both, &because(&format!("cannot find {DISCARD}"), e)))?;
    netlink::set_link_up(index)
        .map_err(|e| uncounted(&both, &because(&format!("cannot set {DISCARD} up"), e)))?;
    let mut failed = Vec::new();
    for (family, addr) in [
        (Family::V4, IpAddr::V4(DISCARD_V4)),
        (Family::V6, IpAddr::V6(DISCARD_V6)),
    ] {
        let done = netlink::add_source_address(index, addr)
            .map_err(|e| because(&format!("cannot add {addr} to {DISCARD}"), e))
            .and_then(|()| {
                netlink::add_default_route(family, index).map_err(|e| {
                    because(
                        &format!("cannot add the {} default route", family.name()),
                        e,
                    )
                })
            });
        if let Err(why) = done {
            failed.push(uncounted(&[family], &why));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// With pasta, once it has configured the namespace: adds a default route
/// out of pasta's interface for each family that has none. Returns the
/// families it added one for.
///
/// # Errors
/// What is not counted and why, one sentence per cause.
pub fn route_missing_families() -> Result<Vec<Family>, String> {
    let both = Family::BOTH;
    let routes = DefaultRoutes::read().map_err(|why| uncounted(&both, &why))?;
    let missing: Vec<Family> = both
        .into_iter()
        .filter(|&f| routes.of(f).is_empty())
        .collect();
    if missing.is_empty() {
        return Ok(missing);
    }
    let index = pasta_interface().map_err(|why| uncounted(&missing, &why))?;
    let mut failed = Vec::new();
    for &family in &missing {
        if let Err(e) = netlink::add_default_route(family, index) {
            let why = because(
                &format!(
                    "the host has no {} default route, and playpen could not add one to pasta's interface",
                    family.name()
                ),
                e,
            );
            failed.push(uncounted(&[family], &why));
        }
    }
    if failed.is_empty() {
        Ok(missing)
    } else {
        Err(failed.join("; "))
    }
}

/// The index of pasta's interface: the one interface of the namespace
/// besides `lo`.
fn pasta_interface() -> Result<u32, String> {
    let all = nix::net::if_::if_nameindex()
        .map_err(|e| because("cannot list the interfaces of the sandbox", e))?;
    let others: Vec<u32> = all
        .iter()
        .map(nix::net::if_::Interface::index)
        .filter(|&i| i != netlink::LO_INDEX)
        .collect();
    match others[..] {
        [index] => Ok(index),
        _ => Err(format!(
            "cannot tell pasta's interface: the sandbox has {} interfaces besides lo",
            others.len()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
enp1s0\t00000000\t0100A8C0\t0003\t0\t0\t1024\t00000000\t0\t0\t0
enp1s0\t0000A8C0\t00000000\t0001\t0\t0\t1024\t00FFFFFF\t0\t0\t0
dead0\t00000000\t00000000\t0200\t0\t0\t0\t00000000\t0\t0\t0
";

    #[test]
    fn a_default_route_is_up_to_every_address_and_not_a_reject_route() {
        let v6 = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001 discard0
fdf6d98c8ec8581b0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001   enp1s0
00000000000000000000000000000000 00 20010db8000000000000000000000000 30 00000000000000000000000000000000 00000400 00000001 00000000 00000001   enp1s0
";
        let routes = DefaultRoutes::parse(ROUTE, v6);
        assert_eq!(routes.ipv4, ["enp1s0"]);
        assert_eq!(routes.ipv6, ["discard0"]);
        assert_eq!(routes.of(Family::V6), ["discard0"]);
    }

    #[test]
    fn a_host_with_prefix_routes_only_has_no_default_route() {
        // This host's IPv6: unique local addresses, no default route.
        let v6 = "\
fdf6d98c8ec8581b0000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001   enp1s0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001   enp1s0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
";
        let routes = DefaultRoutes::parse(ROUTE, v6);
        assert_eq!(routes.of(Family::V6), [] as [String; 0]);
        assert_eq!(DefaultRoutes::parse("", ""), DefaultRoutes::default());
    }

    #[test]
    fn the_discard_addresses_are_never_destinations() {
        // IANA: source only, not forwardable, not globally reachable.
        assert_eq!(DISCARD_V4.to_string(), "192.0.0.8");
        assert_eq!(DISCARD_V6.to_string(), "100:0:0:1::8");
        assert!(!DISCARD_V4.is_loopback() && !DISCARD_V6.is_loopback());
    }

    #[test]
    fn the_reason_names_the_families() {
        assert_eq!(
            uncounted(&Family::BOTH, "why"),
            "IPv4 and IPv6 packets to other hosts fail at routing and are not counted (why)"
        );
        assert_eq!(
            uncounted(&[Family::V6], "why"),
            "IPv6 packets to other hosts fail at routing and are not counted (why)"
        );
    }
}
