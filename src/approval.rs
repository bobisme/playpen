//! What was approved: the allow rules and the time the approval ends.
//!
//! This module is deliberately independent of the namespace code. The rules
//! come from `--allow` and `--until` on the command line, or from a hallpass
//! pass (`--pass`, see [`crate::pass`]). Both sources produce the same typed
//! values, and nothing downstream sees text a user typed.

use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Transport protocol of an allow rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Proto {
    /// The lower-case name used in specs and in the ruleset.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An inclusive port range; `first == last` for a single port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ports {
    first: u16,
    last: u16,
}

impl Ports {
    /// A range of ports. Port 0 and reversed ranges are refused.
    ///
    /// # Errors
    /// When `first` is 0 or `first > last`.
    pub fn new(first: u16, last: u16) -> Result<Self, SpecError> {
        if first == 0 {
            return Err(SpecError::new("port 0 cannot be approved"));
        }
        if first > last {
            return Err(SpecError::new(format!(
                "port range {first}-{last} is reversed; write the lower port first"
            )));
        }
        Ok(Self { first, last })
    }

    /// First port of the range.
    #[must_use]
    pub const fn first(self) -> u16 {
        self.first
    }

    /// Last port of the range (inclusive).
    #[must_use]
    pub const fn last(self) -> u16 {
        self.last
    }

    /// Whether `port` lies in the range.
    #[must_use]
    pub const fn contains(self, port: u16) -> bool {
        self.first <= port && port <= self.last
    }
}

impl fmt::Display for Ports {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

/// A literal address or a network given as address and prefix length, with
/// no host bits set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Net {
    /// Builds a network and checks it.
    ///
    /// # Errors
    /// When the prefix is too long, host bits are set, or the range holds
    /// unspecified, multicast, broadcast, loopback or link-local addresses
    /// that cannot be approved.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, SpecError> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(SpecError::new(format!(
                "prefix /{prefix} is longer than the {max} bits of the address"
            )));
        }
        if mask_host_bits(addr, prefix) != addr {
            return Err(SpecError::new(format!(
                "{addr}/{prefix} has host bits set; the network address is {}/{prefix}",
                mask_host_bits(addr, prefix)
            )));
        }
        let net = Self { addr, prefix };
        net.check_approvable()?;
        Ok(net)
    }

    /// The network (or single) address.
    #[must_use]
    pub const fn addr(self) -> IpAddr {
        self.addr
    }

    /// Prefix length in bits.
    #[must_use]
    pub const fn prefix(self) -> u8 {
        self.prefix
    }

    /// Whether this is a single address (/32 or /128).
    #[must_use]
    pub const fn is_single(self) -> bool {
        match self.addr {
            IpAddr::V4(_) => self.prefix == 32,
            IpAddr::V6(_) => self.prefix == 128,
        }
    }

    /// Whether `ip` lies inside this network.
    #[must_use]
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask_host_bits(ip, self.prefix) == self.addr
            }
            _ => false,
        }
    }

    /// The network address and the broadcast (all-ones) address of an IPv4
    /// network of /30 or broader. Those two are not hosts: a packet to the
    /// all-ones address may reach every host on the network. /31 (RFC 3021)
    /// and /32 have no such addresses, and IPv6 has no broadcast. The same
    /// rule as hallpass's `Network::is_network_or_broadcast`.
    #[must_use]
    pub fn edges(self) -> Option<[Ipv4Addr; 2]> {
        ipv4_edges(self.addr, self.prefix)
    }

    /// Whether the two networks share at least one address.
    pub(crate) fn overlaps(self, other: Self) -> bool {
        let shorter = self.prefix.min(other.prefix);
        match (self.addr, other.addr) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask_host_bits(self.addr, shorter) == mask_host_bits(other.addr, shorter)
            }
            _ => false,
        }
    }

    fn check_approvable(self) -> Result<(), SpecError> {
        let forbidden: &[(IpAddr, u8, &str)] = &[
            (
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                8,
                "unspecified (0.0.0.0/8)",
            ),
            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8, "loopback"),
            (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)), 4, "multicast"),
            (IpAddr::V4(Ipv4Addr::BROADCAST), 32, "broadcast"),
            (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128, "unspecified"),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), 128, "loopback"),
            (
                IpAddr::V6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0)),
                8,
                "multicast",
            ),
            (
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
                10,
                "link-local (it needs an interface, which playpen does not take)",
            ),
            (
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0)),
                96,
                "IPv4-mapped IPv6",
            ),
        ];
        for &(addr, prefix, what) in forbidden {
            let bad = Self { addr, prefix };
            if self.overlaps(bad) {
                let extra = match what {
                    "loopback" => {
                        "; loopback inside the sandbox is always allowed and the host's loopback cannot be approved"
                    }
                    "IPv4-mapped IPv6" => "; write the IPv4 address instead",
                    _ => "",
                };
                return Err(SpecError::new(format!(
                    "{self} includes {what} addresses, which cannot be approved{extra}"
                )));
            }
        }
        Ok(())
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix)
        }
    }
}

fn mask_host_bits(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let bits = u32::from(a);
            let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(bits & mask))
        }
    }
}

// Used by both Playpen networks and already-validated Hallpass networks.
pub(crate) fn ipv4_edges(addr: IpAddr, prefix: u8) -> Option<[Ipv4Addr; 2]> {
    match addr {
        IpAddr::V4(a) if prefix <= 30 => {
            let first = u32::from(a);
            let host_bits = u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0);
            Some([a, Ipv4Addr::from(first | host_bits)])
        }
        _ => None,
    }
}

/// One approved destination: a network, a port range and a protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllowRule {
    /// Destination address or network.
    pub net: Net,
    /// Destination ports.
    pub ports: Ports,
    /// Transport protocol.
    pub proto: Proto,
}

impl AllowRule {
    /// Whether `ip` lies in this rule's network (any port, any protocol).
    /// For what a set of rules lets through, which leaves out the network
    /// and broadcast addresses, see [`Approval::covers_addr`].
    #[must_use]
    pub fn covers_addr(&self, ip: IpAddr) -> bool {
        self.net.contains(ip)
    }
}

/// The addresses inside `rule`'s network that the rule does not open: the
/// network and broadcast addresses of every IPv4 network (/30 or broader)
/// in `rules`. Sorted, without duplicates.
///
/// A rule for a single address excludes nothing: an address listed on its
/// own is a host, whatever network it is also in, and is open on that
/// rule's own ports and protocol only.
#[must_use]
pub fn excluded_addrs(rules: &[AllowRule], rule: &AllowRule) -> Vec<Ipv4Addr> {
    let edges: BTreeSet<_> = rules
        .iter()
        .filter_map(|r| r.net.edges())
        .flatten()
        .collect();
    excluded_for(&edges, rule)
}

fn excluded_for(edges: &BTreeSet<Ipv4Addr>, rule: &AllowRule) -> Vec<Ipv4Addr> {
    if rule.net.is_single() || rule.net.addr().is_ipv6() {
        return Vec::new();
    }
    edges
        .iter()
        .copied()
        .filter(|a| rule.net.contains(IpAddr::V4(*a)))
        .collect()
}

impl fmt::Display for AllowRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.net.addr {
            IpAddr::V4(_) => write!(f, "{}:{}/{}", self.net, self.ports, self.proto),
            IpAddr::V6(_) => write!(f, "[{}]:{}/{}", self.net, self.ports, self.proto),
        }
    }
}

/// Why a spec or timestamp was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecError {
    message: String,
}

impl SpecError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// An error with this message, for other sources of approval data.
    pub(crate) fn from_message(message: impl Into<String>) -> Self {
        Self::new(message)
    }
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SpecError {}

/// Parses `ADDR:PORT/PROTO`, `ADDR:FROM-TO/PROTO` or `NET/PREFIX:PORTS/PROTO`;
/// IPv6 goes in brackets: `[2001:db8::1]:443/tcp`, `[2001:db8::/32]:443/tcp`.
///
/// # Errors
/// On anything that is not exactly one of those forms with a literal
/// address, or on an address that cannot be approved.
pub fn parse_allow(spec: &str) -> Result<AllowRule, SpecError> {
    parse_allow_inner(spec).map_err(|e| SpecError::new(format!("--allow {spec:?}: {e}")))
}

fn parse_allow_inner(spec: &str) -> Result<AllowRule, SpecError> {
    if spec.is_empty() {
        return Err(SpecError::new("empty spec"));
    }
    if !spec.is_ascii()
        || spec
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(SpecError::new(
            "only ASCII letters, digits and the characters . : / - [ ] are allowed",
        ));
    }
    let (rest, proto) = spec
        .rsplit_once('/')
        .ok_or_else(|| SpecError::new("missing /PROTO at the end (for example :443/tcp)"))?;
    let proto = match proto {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        other => {
            return Err(SpecError::new(format!(
                "protocol {other:?} is not supported; use tcp or udp (lower case)"
            )));
        }
    };
    let (net_text, ports_text, v6) = if let Some(after) = rest.strip_prefix('[') {
        let (inner, tail) = after
            .split_once(']')
            .ok_or_else(|| SpecError::new("missing ] after the IPv6 address"))?;
        let ports = tail
            .strip_prefix(':')
            .ok_or_else(|| SpecError::new("missing :PORT after the ]"))?;
        (inner, ports, true)
    } else {
        let (net, ports) = rest
            .rsplit_once(':')
            .ok_or_else(|| SpecError::new("missing :PORT (for example 192.0.2.1:443/tcp)"))?;
        if net.contains(':') {
            return Err(SpecError::new(
                "IPv6 addresses must be written in brackets, for example [2001:db8::1]:443/tcp",
            ));
        }
        (net, ports, false)
    };
    let ports = parse_ports(ports_text)?;
    let (addr_text, prefix_text) = match net_text.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (net_text, None),
    };
    let addr = if v6 {
        parse_v6(addr_text)?
    } else {
        IpAddr::V4(parse_v4(addr_text)?)
    };
    let prefix = match prefix_text {
        None => match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        },
        Some(p) => parse_decimal_u8(p)
            .ok_or_else(|| SpecError::new(format!("prefix {p:?} is not a plain decimal number")))?,
    };
    let net = Net::new(addr, prefix)?;
    Ok(AllowRule { net, ports, proto })
}

fn parse_ports(text: &str) -> Result<Ports, SpecError> {
    let (first, last) = match text.split_once('-') {
        Some((a, b)) => (a, b),
        None => (text, text),
    };
    let first = parse_decimal_u16(first)
        .ok_or_else(|| SpecError::new(format!("port {first:?} is not a number from 1 to 65535")))?;
    let last = parse_decimal_u16(last)
        .ok_or_else(|| SpecError::new(format!("port {last:?} is not a number from 1 to 65535")))?;
    Ports::new(first, last)
}

/// Plain decimal, no sign, no leading zeros (except "0" itself).
fn plain_decimal(text: &str) -> bool {
    !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'))
}

fn parse_decimal_u16(text: &str) -> Option<u16> {
    if plain_decimal(text) {
        text.parse().ok()
    } else {
        None
    }
}

fn parse_decimal_u8(text: &str) -> Option<u8> {
    if plain_decimal(text) {
        text.parse().ok()
    } else {
        None
    }
}

/// Dotted quad with exactly four plain decimal parts.
fn parse_v4(text: &str) -> Result<Ipv4Addr, SpecError> {
    let parts: Vec<&str> = text.split('.').collect();
    let looks_like_name = text.bytes().any(|b| b.is_ascii_alphabetic());
    if looks_like_name {
        return Err(SpecError::new(format!(
            "{text:?} is not a literal address; host names are refused (approve the address, and use --host NAME=ADDR if the tool needs the name)"
        )));
    }
    if parts.len() != 4 || !parts.iter().all(|p| plain_decimal(p)) {
        return Err(SpecError::new(format!(
            "{text:?} is not a plain dotted-quad IPv4 address (no leading zeros, exactly four parts)"
        )));
    }
    text.parse::<Ipv4Addr>()
        .map_err(|_| SpecError::new(format!("{text:?} is not a valid IPv4 address")))
}

fn parse_v6(text: &str) -> Result<IpAddr, SpecError> {
    if text.contains('%') {
        return Err(SpecError::new(
            "IPv6 zone identifiers (%...) are not supported",
        ));
    }
    let addr: Ipv6Addr = text
        .parse()
        .map_err(|_| SpecError::new(format!("{text:?} is not a valid IPv6 address")))?;
    Ok(IpAddr::V6(addr))
}

/// Parses a literal address on its own (for `--host NAME=ADDR`), with the
/// same strictness as `--allow`. IPv6 may be written with or without
/// brackets.
///
/// # Errors
/// When the text is not a plain literal address.
pub fn parse_literal_addr(text: &str) -> Result<IpAddr, SpecError> {
    let bracketed = text.strip_prefix('[').and_then(|t| t.strip_suffix(']'));
    let inner = bracketed.unwrap_or(text);
    if inner.contains(':') {
        parse_v6(inner)
    } else if bracketed.is_some() {
        Err(SpecError::new(format!(
            "{text} has brackets around an IPv4 address; brackets are for IPv6 only, so write {inner}"
        )))
    } else {
        parse_v4(inner).map(IpAddr::V4)
    }
}

/// When the approval ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndsAt(OffsetDateTime);

impl EndsAt {
    /// Parses an RFC 3339 timestamp with an explicit offset (`Z` or
    /// `+hh:mm`). `-00:00` ("offset unknown" in RFC 3339) is refused.
    ///
    /// # Errors
    /// When the text is not RFC 3339 or has no usable offset.
    pub fn parse(text: &str) -> Result<Self, SpecError> {
        if text.ends_with("-00:00") {
            return Err(SpecError::new(format!(
                "--until {text:?}: the offset -00:00 means \"unknown\" in RFC 3339; give the real offset, for example Z or +01:00"
            )));
        }
        OffsetDateTime::parse(text, &Rfc3339).map(Self).map_err(|_| {
            SpecError::new(format!(
                "--until {text:?} is not an RFC 3339 timestamp with an explicit offset, for example 2026-11-18T22:00:00Z or 2026-11-18T23:00:00+01:00"
            ))
        })
    }

    /// An end time taken from another source (a pass's `valid_until`).
    #[must_use]
    pub const fn from_time(at: OffsetDateTime) -> Self {
        Self(at)
    }

    /// The moment as a time value.
    #[must_use]
    pub const fn at(self) -> OffsetDateTime {
        self.0
    }

    /// RFC 3339 text in UTC.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        self.0
            .to_offset(time::UtcOffset::UTC)
            .format(&Rfc3339)
            .unwrap_or_else(|_| self.0.unix_timestamp().to_string())
    }
}

/// The whole approval: what may be reached, and until when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// Approved destinations. Empty means nothing may be reached.
    rules: Vec<AllowRule>,
    /// When the approval ends; `None` means no time limit was given.
    pub ends_at: Option<EndsAt>,
    edge_addresses: BTreeSet<Ipv4Addr>,
}

impl Approval {
    /// Approval from a complete list of literal allow rules.
    #[must_use]
    pub fn new(rules: Vec<AllowRule>, ends_at: Option<EndsAt>) -> Self {
        let edge_addresses = rules
            .iter()
            .filter_map(|r| r.net.edges())
            .flatten()
            .collect();
        Self::with_edge_scope(rules, ends_at, edge_addresses)
    }

    pub(crate) const fn with_edge_scope(
        rules: Vec<AllowRule>,
        ends_at: Option<EndsAt>,
        edge_addresses: BTreeSet<Ipv4Addr>,
    ) -> Self {
        Self {
            rules,
            ends_at,
            edge_addresses,
        }
    }

    /// Rules in source order.
    #[must_use]
    pub fn rules(&self) -> &[AllowRule] {
        &self.rules
    }

    pub(crate) fn exclusions(&self, rule: &AllowRule) -> Vec<Ipv4Addr> {
        excluded_for(&self.edge_addresses, rule)
    }

    /// Checks that the approval is still in force at `now`.
    ///
    /// # Errors
    /// When the end time is at or before `now`.
    pub fn check_active(&self, now: OffsetDateTime) -> Result<(), SpecError> {
        if let Some(end) = self.ends_at
            && end.at() <= now
        {
            return Err(SpecError::new(format!(
                "the approval ended at {} (now is {}); nothing was run",
                end.to_rfc3339(),
                EndsAt(now).to_rfc3339()
            )));
        }
        Ok(())
    }

    fn rule_covers_addr(&self, rule: &AllowRule, ip: IpAddr) -> bool {
        rule.covers_addr(ip)
            && (rule.net.is_single()
                || match ip {
                    IpAddr::V4(addr) => !self.edge_addresses.contains(&addr),
                    IpAddr::V6(_) => true,
                })
    }

    /// Whether some rule lets traffic to `ip` through on any port and protocol.
    #[must_use]
    pub fn covers_addr(&self, ip: IpAddr) -> bool {
        self.rules.iter().any(|r| self.rule_covers_addr(r, ip))
    }

    /// Whether an explicit grant admits this destination tuple. The caller
    /// handles sandbox exceptions such as established traffic and loopback.
    #[must_use]
    pub fn permits_packet(&self, ip: IpAddr, proto: Proto, port: u16) -> bool {
        self.matching_grant(ip, proto, port).is_some()
    }

    /// The first explicit grant that permits the tuple after all address exclusions.
    pub(crate) fn matching_grant(&self, ip: IpAddr, proto: Proto, port: u16) -> Option<&AllowRule> {
        self.rules
            .iter()
            .find(|r| r.proto == proto && r.ports.contains(port) && self.rule_covers_addr(r, ip))
    }

    /// For an address inside a listed network that [`Self::covers_addr`]
    /// still refuses: why, and what to do. Empty for any other address.
    #[must_use]
    pub fn edge_hint(&self, ip: IpAddr) -> String {
        if self.covers_addr(ip) || !self.rules.iter().any(|r| r.covers_addr(ip)) {
            return String::new();
        }
        format!(
            ". {ip} is the network or broadcast address of a listed network, not a host: a packet to it may reach every host on that network, so playpen drops it. If it is one host of a larger network, it must be listed as its own address"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ok(spec: &str) -> AllowRule {
        match parse_allow(spec) {
            Ok(r) => r,
            Err(e) => panic!("{spec} should parse: {e}"),
        }
    }

    fn refused(spec: &str) -> String {
        match parse_allow(spec) {
            Ok(r) => panic!("{spec} should be refused, got {r}"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn parses_the_three_forms() {
        let r = ok("192.0.2.1:443/tcp");
        assert_eq!(r.to_string(), "192.0.2.1:443/tcp");
        assert_eq!(
            r.ports,
            Ports {
                first: 443,
                last: 443
            }
        );
        let r = ok("192.0.2.1:5060-5070/udp");
        assert_eq!(
            r.ports,
            Ports {
                first: 5060,
                last: 5070
            }
        );
        assert_eq!(r.proto, Proto::Udp);
        let r = ok("198.51.100.0/24:80/tcp");
        assert_eq!(r.net.prefix(), 24);
        assert_eq!(r.to_string(), "198.51.100.0/24:80/tcp");
        let r = ok("[2001:db8::1]:443/tcp");
        assert_eq!(r.to_string(), "[2001:db8::1]:443/tcp");
        let r = ok("[2001:db8::/32]:1-65535/udp");
        assert_eq!(r.to_string(), "[2001:db8::/32]:1-65535/udp");
        let r = ok("192.0.2.7/32:9/tcp");
        assert!(r.net.is_single());
    }

    #[test]
    fn refuses_host_names() {
        assert!(refused("example.test:443/tcp").contains("host names are refused"));
        assert!(refused("localhost:80/tcp").contains("host names are refused"));
    }

    #[test]
    fn refuses_ambiguous_spellings() {
        assert!(refused("192.0.2.01:443/tcp").contains("leading zeros"));
        assert!(refused("010.0.0.1:443/tcp").contains("leading zeros"));
        assert!(refused("192.0.2:443/tcp").contains("four parts"));
        assert!(refused("3221225985:443/tcp").contains("four parts"));
        assert!(refused("0x7f.0.0.1:443/tcp").contains("host names"));
        assert!(refused("192.0.2.1:0443/tcp").contains("port"));
        assert!(refused("192.0.2.1:+443/tcp").contains("port"));
        assert!(refused("192.0.2.0/024:443/tcp").contains("prefix"));
        assert!(refused("192.0.2.1/24:443/tcp").contains("host bits"));
        assert!(refused("[2001:db8::1/32]:443/tcp").contains("host bits"));
        assert!(refused("2001:db8::1:443/tcp").contains("brackets"));
        assert!(refused("[fe80::1%eth0]:443/tcp").contains("zone"));
        assert!(refused("192.0.2.1:443/TCP").contains("lower case"));
        assert!(refused("192.0.2.1:443").contains("PROTO"));
        assert!(refused("192.0.2.1/tcp").contains("PORT"));
        assert!(refused("192.0.2.1:443/sctp").contains("not supported"));
        assert!(refused("192.0.2.1:0/tcp").contains("port 0"));
        assert!(refused("192.0.2.1:90-80/tcp").contains("reversed"));
        assert!(refused("192.0.2.1:70000/tcp").contains("port"));
        assert!(refused("192.0.2.0/33:1/tcp").contains("longer"));
        assert!(refused("").contains("empty"));
        assert!(refused("192.0.2.1 :443/tcp").contains("ASCII"));
    }

    #[test]
    fn refuses_unapprovable_addresses() {
        assert!(refused("0.0.0.0:443/tcp").contains("unspecified"));
        assert!(refused("0.0.0.0/0:443/tcp").contains("unspecified"));
        assert!(refused("255.255.255.255:9/udp").contains("broadcast"));
        assert!(refused("240.0.0.0/4:9/udp").contains("broadcast"));
        assert!(refused("224.0.0.1:9/udp").contains("multicast"));
        assert!(refused("239.255.255.250:1900/udp").contains("multicast"));
        assert!(refused("127.0.0.1:80/tcp").contains("loopback"));
        assert!(refused("[::]:443/tcp").contains("unspecified"));
        assert!(refused("[::/0]:443/tcp").contains("unspecified"));
        assert!(refused("[::1]:443/tcp").contains("loopback"));
        assert!(refused("[ff02::1]:443/udp").contains("multicast"));
        assert!(refused("[fe80::1]:443/tcp").contains("link-local"));
        let mapped = refused("[::ffff:192.0.2.1]:443/tcp");
        assert!(
            mapped.contains("includes IPv4-mapped IPv6 addresses, which cannot be approved; write the IPv4 address instead"),
            "{mapped}"
        );
    }

    #[test]
    fn hostile_input_is_refused() {
        for spec in [
            "192.0.2.1:443/tcp; flush ruleset",
            "192.0.2.1:443/tcp accept",
            "192.0.2.1:443/tcp\naccept",
            "192.0.2.1:443/tcp}",
            "{192.0.2.1}:443/tcp",
            "192.0.2.1:443/tcp\"",
            "[2001:db8::1] accept:443/tcp",
            "192.0.2.1:443-/tcp",
            "192.0.2.1:{443,80}/tcp",
            "192.0.2.1:443/tcp#",
        ] {
            assert!(parse_allow(spec).is_err(), "{spec:?} should be refused");
        }
    }

    #[test]
    fn literal_addresses_for_hosts() {
        assert_eq!(
            parse_literal_addr("192.0.2.5").ok(),
            Some(
                "192.0.2.5"
                    .parse()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            )
        );
        assert!(parse_literal_addr("[2001:db8::5]").is_ok());
        assert!(parse_literal_addr("2001:db8::5").is_ok());
        assert!(parse_literal_addr("192.0.2.05").is_err());
        assert!(parse_literal_addr("[192.0.2.5]").is_err());
        assert!(parse_literal_addr("example.test").is_err());
    }

    #[test]
    fn covers_addr() {
        let r = ok("198.51.100.0/24:80/tcp");
        assert!(r.covers_addr(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200))));
        assert!(!r.covers_addr(IpAddr::V4(Ipv4Addr::new(198, 51, 101, 1))));
        assert!(!r.covers_addr(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn network_and_broadcast_addresses_are_not_covered() {
        let v4 = |s: &str| s.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED);
        let ip = |s: &str| IpAddr::V4(v4(s));
        let approval = |specs: &[&str]| Approval::new(specs.iter().map(|s| ok(s)).collect(), None);
        let none: [Ipv4Addr; 0] = [];
        let a = approval(&["198.51.100.0/24:80/tcp"]);
        assert!(a.covers_addr(ip("198.51.100.1")));
        assert!(a.covers_addr(ip("198.51.100.254")));
        assert!(!a.covers_addr(ip("198.51.100.0")));
        assert!(!a.covers_addr(ip("198.51.100.255")));
        assert!(a.edge_hint(ip("198.51.100.255")).contains("broadcast"));
        assert_eq!(a.edge_hint(ip("198.51.100.1")), "");
        assert_eq!(a.edge_hint(ip("198.51.101.255")), "");
        assert_eq!(
            excluded_addrs(&a.rules, &a.rules[0]),
            [v4("198.51.100.0"), v4("198.51.100.255")]
        );
        // /31 and /32 have no such addresses; neither has IPv6.
        for spec in ["198.51.100.4/31:80/tcp", "198.51.100.255:80/tcp"] {
            let a = approval(&[spec]);
            assert_eq!(excluded_addrs(&a.rules, &a.rules[0]), none, "{spec}");
        }
        let a = approval(&["198.51.100.4/31:80/tcp"]);
        assert!(a.covers_addr(ip("198.51.100.4")) && a.covers_addr(ip("198.51.100.5")));
        let a = approval(&["[2001:db8::/120]:80/tcp"]);
        assert_eq!(excluded_addrs(&a.rules, &a.rules[0]), none);
        assert!(a.covers_addr(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0))));
        assert!(a.covers_addr(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xff
        ))));
        // A /30 has two hosts.
        let a = approval(&["198.51.100.4/30:80/tcp"]);
        assert!(!a.covers_addr(ip("198.51.100.4")) && !a.covers_addr(ip("198.51.100.7")));
        assert!(a.covers_addr(ip("198.51.100.5")) && a.covers_addr(ip("198.51.100.6")));
        // The edge of one listed network is not opened by another listed
        // network that holds it as an ordinary address.
        let a = approval(&["198.51.100.0/24:80/tcp", "198.51.100.0/25:443/tcp"]);
        assert!(!a.covers_addr(ip("198.51.100.127")));
        assert_eq!(
            excluded_addrs(&a.rules, &a.rules[0]),
            [
                v4("198.51.100.0"),
                v4("198.51.100.127"),
                v4("198.51.100.255")
            ]
        );
        // An address listed on its own is a host.
        let a = approval(&["198.51.100.0/24:80/tcp", "198.51.100.255:443/tcp"]);
        assert!(a.covers_addr(ip("198.51.100.255")));
        assert_eq!(excluded_addrs(&a.rules, &a.rules[1]), none);
        assert_eq!(excluded_addrs(&a.rules, &a.rules[0]).len(), 2);
    }

    #[test]
    fn until_needs_an_offset_and_must_be_ahead() {
        assert!(EndsAt::parse("2026-11-18T22:00:00").is_err());
        assert!(EndsAt::parse("2026-11-18T22:00:00-00:00").is_err());
        assert!(EndsAt::parse("tomorrow").is_err());
        let end = EndsAt::parse("2026-11-18T23:00:00+01:00");
        let Ok(end) = end else { panic!("should parse") };
        assert_eq!(end.to_rfc3339(), "2026-11-18T22:00:00Z");
        let approval = Approval::new(vec![], Some(end));
        let before = time::macros::datetime!(2026-11-18 21:59:59 UTC);
        let at = time::macros::datetime!(2026-11-18 22:00:00 UTC);
        assert!(approval.check_active(before).is_ok());
        let Err(e) = approval.check_active(at) else {
            panic!("should be refused")
        };
        assert!(e.to_string().contains("nothing was run"));
        let open = Approval::new(vec![], None);
        assert!(open.check_active(at).is_ok());
    }

    fn approvable_v4() -> impl Strategy<Value = Ipv4Addr> {
        any::<u32>()
            .prop_map(Ipv4Addr::from)
            .prop_filter("approvable", |a| {
                let o = a.octets();
                o[0] != 0 && o[0] != 127 && o[0] < 224
            })
    }

    proptest! {
        #[test]
        fn display_round_trips_v4(addr in approvable_v4(), prefix in 0u8..=32, a in 1u16.., b in 1u16.., udp in any::<bool>()) {
            let net_addr = mask_host_bits(IpAddr::V4(addr), prefix);
            let Ok(net) = Net::new(net_addr, prefix) else { return Ok(()); };
            let ports = Ports::new(a.min(b), a.max(b)).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let rule = AllowRule { net, ports, proto: if udp { Proto::Udp } else { Proto::Tcp } };
            let text = rule.to_string();
            prop_assert_eq!(parse_allow(&text).ok(), Some(rule));
        }

        #[test]
        fn display_round_trips_v6(bits in any::<u128>(), prefix in 0u8..=128, a in 1u16.., udp in any::<bool>()) {
            let net_addr = mask_host_bits(IpAddr::V6(Ipv6Addr::from(bits)), prefix);
            let Ok(net) = Net::new(net_addr, prefix) else { return Ok(()); };
            let ports = Ports::new(a, a).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let rule = AllowRule { net, ports, proto: if udp { Proto::Udp } else { Proto::Tcp } };
            prop_assert_eq!(parse_allow(&rule.to_string()).ok(), Some(rule));
        }

        #[test]
        fn arbitrary_text_never_panics_and_accepted_specs_are_canonical(s in "\\PC{0,40}") {
            if let Ok(rule) = parse_allow(&s) {
                // Whatever is accepted re-renders to text that parses to the same rule.
                prop_assert_eq!(parse_allow(&rule.to_string()).ok(), Some(rule));
            }
        }

        #[test]
        fn spec_shaped_text_never_panics(s in "[0-9a-f:./\\[\\]-]{0,30}/(tcp|udp)") {
            let _ = parse_allow(&s);
        }
    }
}

#[cfg(kani)]
#[path = "approval_proofs.rs"]
mod proofs;
