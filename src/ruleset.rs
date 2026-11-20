//! The nftables ruleset loaded inside the namespace, and reading its drop
//! counters back.
//!
//! The ruleset text is built only from typed values ([`AllowRule`]: parsed
//! addresses, integers and an enum). No string a user typed reaches it, so
//! nothing on the command line can inject nftables syntax.

use std::fmt::Write as _;
use std::net::IpAddr;

use serde::Serialize;

use crate::approval::{AllowRule, Approval, Proto};
pub use crate::nft_readback::verify_policy;

/// Name of the nftables table playpen loads.
pub const TABLE: &str = "playpen";
/// Most distinct dropped destinations remembered per address family.
pub const DROP_SET_SIZE: u32 = 1024;

/// Renders the complete ruleset for `rules`.
///
/// Output, input and forward chains all have policy drop. Output accepts
/// established and related traffic, loopback destinations on `lo`, the
/// kernel's own IPv6 neighbour discovery, and the approved destinations.
/// Everything else is counted (in total and per destination) and rejected,
/// so a blocked connection fails at once instead of hanging. A rule for an
/// IPv4 network does not accept the network and broadcast addresses of any
/// listed network (see [`Approval::covers_addr`]); they are counted and rejected
/// like any other unapproved destination.
#[must_use]
pub fn render(rules: &[AllowRule]) -> String {
    render_approval(&Approval::new(rules.to_vec(), None))
}

/// Renders an approval with the edge exclusions inherited from its source.
#[must_use]
pub fn render_approval(approval: &Approval) -> String {
    render_instrumented(approval, 0)
}

pub(crate) fn render_instrumented(approval: &Approval, grant_counters: usize) -> String {
    let mut out = String::new();
    // A table of our own; flush it first so a reload replaces it whole.
    let _ = writeln!(out, "table inet {TABLE} {{}}");
    let _ = writeln!(out, "delete table inet {TABLE}");
    let _ = writeln!(out, "table inet {TABLE} {{");
    let _ = writeln!(out, "\tcounter dropped {{");
    let _ = writeln!(out, "\t}}");
    for index in 0..grant_counters {
        let _ = writeln!(
            out,
            "\tcounter {} {{}}",
            crate::grant_use::counter_name(index)
        );
    }
    for (name, ty) in [("drop4", "ipv4_addr"), ("drop6", "ipv6_addr")] {
        let _ = writeln!(out, "\tset {name} {{");
        let _ = writeln!(out, "\t\ttype {ty} . inet_proto . inet_service");
        let _ = writeln!(out, "\t\tsize {DROP_SET_SIZE}");
        let _ = writeln!(out, "\t\tflags dynamic");
        let _ = writeln!(out, "\t\tcounter");
        let _ = writeln!(out, "\t}}");
    }
    let _ = writeln!(out, "\tchain output {{");
    let _ = writeln!(
        out,
        "\t\ttype filter hook output priority filter; policy drop;"
    );
    let _ = writeln!(out, "\t\tct state established,related accept");
    let _ = writeln!(out, "\t\toif \"lo\" ip daddr 127.0.0.0/8 accept");
    let _ = writeln!(out, "\t\toif \"lo\" ip6 daddr ::1 accept");
    // Neighbour discovery: only the two messages address resolution needs,
    // and only with hop limit 255 (RFC 4861), so it never leaves the link.
    let _ = writeln!(
        out,
        "\t\ticmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} ip6 hoplimit 255 accept"
    );
    // The kernel's own multicast listener reports and router solicitations
    // when an interface comes up: dropped, but not counted, because the
    // command did not send them.
    let _ = writeln!(
        out,
        "\t\tip6 daddr ff02::/16 icmpv6 type {{ mld-listener-report, mld2-listener-report, nd-router-solicit }} drop"
    );
    for (index, rule) in approval.rules().iter().enumerate() {
        let matches = match_expr(rule, &approval.exclusions(rule));
        let _ = write!(out, "\t\t{matches}");
        if index < grant_counters {
            let _ = write!(
                out,
                " counter name {}",
                crate::grant_use::counter_name(index)
            );
        }
        let _ = writeln!(out, " accept");
    }
    let _ = writeln!(
        out,
        "\t\tmeta nfproto ipv4 meta l4proto {{ tcp, udp }} add @drop4 {{ ip daddr . meta l4proto . th dport }}"
    );
    let _ = writeln!(
        out,
        "\t\tmeta nfproto ipv4 meta l4proto != {{ tcp, udp }} add @drop4 {{ ip daddr . meta l4proto . 0 }}"
    );
    let _ = writeln!(
        out,
        "\t\tmeta nfproto ipv6 meta l4proto {{ tcp, udp }} add @drop6 {{ ip6 daddr . meta l4proto . th dport }}"
    );
    let _ = writeln!(
        out,
        "\t\tmeta nfproto ipv6 meta l4proto != {{ tcp, udp }} add @drop6 {{ ip6 daddr . meta l4proto . 0 }}"
    );
    let _ = writeln!(out, "\t\tcounter name \"dropped\"");
    let _ = writeln!(out, "\t\treject with icmpx admin-prohibited");
    let _ = writeln!(out, "\t}}");
    let _ = writeln!(out, "\tchain input {{");
    let _ = writeln!(
        out,
        "\t\ttype filter hook input priority filter; policy drop;"
    );
    let _ = writeln!(out, "\t\tct state established,related accept");
    let _ = writeln!(out, "\t\tiif \"lo\" accept");
    let _ = writeln!(
        out,
        "\t\ticmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} ip6 hoplimit 255 accept"
    );
    let _ = writeln!(out, "\t}}");
    let _ = writeln!(out, "\tchain forward {{");
    let _ = writeln!(
        out,
        "\t\ttype filter hook forward priority filter; policy drop;"
    );
    let _ = writeln!(out, "\t}}");
    let _ = writeln!(out, "}}");
    out
}

fn match_expr(rule: &AllowRule, excluded: &[std::net::Ipv4Addr]) -> String {
    let family = match rule.net.addr() {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    };
    let proto = match rule.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    let except = if excluded.is_empty() {
        String::new()
    } else {
        let list: Vec<String> = excluded.iter().map(ToString::to_string).collect();
        format!(" {family} daddr != {{ {} }}", list.join(", "))
    };
    format!(
        "{family} daddr {}{except} {proto} dport {}",
        rule.net, rule.ports
    )
}

/// One dropped destination with its packet count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, PartialOrd, Ord)]
pub struct DroppedDest {
    /// Destination address.
    pub address: String,
    /// Protocol name as nftables reports it (`tcp`, `udp`, `icmp`, ...).
    pub protocol: String,
    /// Destination port for TCP and UDP; `None` otherwise.
    pub port: Option<u16>,
    /// Packets dropped to this destination.
    pub packets: u64,
}

/// What the drop counters said after the command finished.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DropSummary {
    /// Packets to unapproved destinations that were dropped, in total.
    pub packets: u64,
    /// Per-destination breakdown, largest first.
    pub destinations: Vec<DroppedDest>,
    /// True when the per-destination list does not account for every
    /// dropped packet (more distinct destinations than the set holds).
    pub destinations_truncated: bool,
}

/// Parses `nft --json list table inet playpen`.
///
/// # Errors
/// When the output is not the JSON nftables writes or the counter is
/// missing.
pub fn parse_counters(json: &str) -> Result<DropSummary, String> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| format!("nft printed JSON that does not parse: {e}"))?;
    let items = value
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or("nft JSON has no \"nftables\" array")?;
    let mut total = None;
    let mut dests = Vec::new();
    let mut detail_uncertain = false;
    let mut seen_sets = std::collections::HashSet::new();
    let mut identities = std::collections::HashSet::new();
    for item in items {
        if let Some(c) = item.get("counter")
            && c.get("name").and_then(serde_json::Value::as_str) == Some("dropped")
        {
            if total.is_some() {
                return Err("nft JSON has duplicate dropped counters".into());
            }
            total = Some(
                c.get("packets")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or("invalid dropped counter")?,
            );
        }
        if let Some(s) = item.get("set") {
            let name = s.get("name").and_then(serde_json::Value::as_str);
            if !matches!(name, Some("drop4" | "drop6")) {
                continue;
            }
            if !seen_sets.insert(name.unwrap_or_default().to_owned()) {
                detail_uncertain = true;
            }
            match s.get("elem") {
                None => {} // nft omits elem for an empty set
                Some(serde_json::Value::Array(elems)) => {
                    for elem in elems {
                        if let Some(d) = parse_elem(elem, name.unwrap_or_default()) {
                            if !identities.insert((d.address.clone(), d.protocol.clone(), d.port)) {
                                detail_uncertain = true;
                            }
                            dests.push(d);
                        } else {
                            detail_uncertain = true;
                        }
                    }
                }
                Some(_) => detail_uncertain = true,
            }
        }
    }
    let packets = total.ok_or("nft JSON has no \"dropped\" counter")?;
    dests.sort_by(|a, b| b.packets.cmp(&a.packets).then_with(|| a.cmp(b)));
    let listed = dests
        .iter()
        .try_fold(0_u64, |sum, d| sum.checked_add(d.packets));
    detail_uncertain |= seen_sets.len() != 2;
    Ok(DropSummary {
        packets,
        destinations_truncated: detail_uncertain || listed != Some(packets),
        destinations: dests,
    })
}

fn parse_elem(elem: &serde_json::Value, family: &str) -> Option<DroppedDest> {
    let inner = elem.get("elem")?;
    let concat = inner.get("val")?.get("concat")?.as_array()?;
    if concat.len() != 3 {
        return None;
    }
    let address = concat
        .first()?
        .as_str()?
        .parse::<std::net::IpAddr>()
        .ok()?
        .to_string();
    let ip = address.parse::<std::net::IpAddr>().ok()?;
    if (family == "drop4") != ip.is_ipv4() {
        return None;
    }
    // nft prints the protocol by name when it knows it, else as a number.
    let raw_protocol = match concat.get(1)? {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.as_u64()?.to_string(),
        _ => return None,
    };
    let protocol = match raw_protocol.as_str() {
        "tcp" | "6" => "tcp".to_owned(),
        "udp" | "17" => "udp".to_owned(),
        "icmp" | "1" => "icmp".to_owned(),
        "ipv6-icmp" | "58" => "ipv6-icmp".to_owned(),
        other => other.parse::<u8>().ok()?.to_string(),
    };
    let port = match (protocol.as_str(), concat.get(2)?) {
        ("tcp" | "udp", serde_json::Value::Number(n)) => {
            n.as_u64().and_then(|p| u16::try_from(p).ok())
        }
        ("tcp" | "udp", serde_json::Value::String(s)) => s.parse().ok(),
        _ => None,
    };
    if matches!(protocol.as_str(), "tcp" | "udp") && port.is_none() {
        return None;
    }
    let packets = inner.get("counter")?.get("packets")?.as_u64()?;
    Some(DroppedDest {
        address,
        protocol,
        port,
        packets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{Net, Ports, parse_allow};
    use proptest::prelude::*;
    use std::net::Ipv4Addr;

    fn rules(specs: &[&str]) -> Vec<AllowRule> {
        specs
            .iter()
            .map(|s| parse_allow(s).unwrap_or_else(|e| panic!("{e}")))
            .collect()
    }

    #[test]
    fn renders_allow_rules() {
        let text = render(&rules(&[
            "192.0.2.1:443/tcp",
            "198.51.100.0/24:5060-5070/udp",
            "[2001:db8::1]:53/udp",
            "[2001:db8:1::/48]:1-1024/tcp",
        ]));
        assert!(text.contains("\t\tip daddr 192.0.2.1 tcp dport 443 accept\n"));
        assert!(text.contains(
            "\t\tip daddr 198.51.100.0/24 ip daddr != { 198.51.100.0, 198.51.100.255 } udp dport 5060-5070 accept\n"
        ));
        assert!(text.contains("\t\tip6 daddr 2001:db8::1 udp dport 53 accept\n"));
        assert!(text.contains("\t\tip6 daddr 2001:db8:1::/48 tcp dport 1-1024 accept\n"));
        assert_eq!(text.matches("policy drop;").count(), 3);
        // The approved rules come after the fixed accepts and before counting.
        let allow = text.find("192.0.2.1 tcp").unwrap_or(0);
        let count = text.find("add @drop4").unwrap_or(0);
        let lo = text.find("oif \"lo\"").unwrap_or(usize::MAX);
        assert!(lo < allow && allow < count);
    }

    #[test]
    fn empty_rules_accept_only_fixed_traffic() {
        let text = render(&[]);
        assert_eq!(text.matches(" accept").count(), 7);
        assert!(!text.contains("dport 1"));
    }

    #[test]
    fn hostile_specs_cannot_reach_the_ruleset() {
        // Anything with nft syntax in it is refused before rendering.
        for spec in [
            "192.0.2.1:443/tcp;flush ruleset",
            "192.0.2.1:443/tcp } table ip x {",
            "192.0.2.1:443/tcp\nflush ruleset",
            "[2001:db8::1]:443/tcp accept",
        ] {
            assert!(parse_allow(spec).is_err(), "{spec:?}");
        }
    }

    fn generated_rule() -> impl Strategy<Value = AllowRule> {
        (
            any::<bool>(),
            any::<bool>(),
            0_u8..6,
            any::<u32>(),
            1_u16..=u16::MAX,
            1_u16..=u16::MAX,
            any::<bool>(),
        )
            .prop_map(|(v6, udp, depth, bits, a, b, single_port)| {
                let host_bits = [8, 7, 4, 2, 1, 0][usize::from(depth)];
                let host = ((bits & 255) >> host_bits << host_bits).to_le_bytes()[0];
                let (addr, prefix) = if v6 {
                    (
                        IpAddr::from((0x2001_0db8_u128 << 96 | u128::from(host)).to_be_bytes()),
                        128 - host_bits,
                    )
                } else {
                    (IpAddr::from([192, 0, 2, host]), 32 - host_bits)
                };
                AllowRule {
                    net: Net::new(addr, prefix).expect("canonical documentation network"),
                    ports: Ports::new(a.min(b), if single_port { a.min(b) } else { a.max(b) })
                        .expect("ordered nonzero ports"),
                    proto: if udp { Proto::Udp } else { Proto::Tcp },
                }
            })
    }

    fn ipv4_span(rule: &AllowRule) -> Option<(u32, u32)> {
        let IpAddr::V4(addr) = rule.net.addr() else {
            return None;
        };
        let start = u32::from(addr);
        // All generated and deterministic IPv4 networks are within a /24.
        Some((start, start + (1 << (32 - rule.net.prefix())) - 1))
    }

    fn expected_grant(rule: &AllowRule, rules: &[AllowRule]) -> String {
        let (family, width) = match rule.net.addr() {
            IpAddr::V4(_) => ("ip", 32),
            IpAddr::V6(_) => ("ip6", 128),
        };
        let addr = rule.net.addr();
        let prefix = rule.net.prefix();
        let network = if prefix == width {
            addr.to_string()
        } else {
            format!("{addr}/{prefix}")
        };
        let mut exclusion = String::new();
        if let Some((start, end)) = ipv4_span(rule)
            && start < end
        {
            let edges: std::collections::BTreeSet<_> = rules
                .iter()
                .filter_map(ipv4_span)
                .filter(|(a, b)| b - a >= 3)
                .flat_map(<[u32; 2]>::from)
                .filter(|edge| (start..=end).contains(edge))
                .collect();
            let list: Vec<_> = edges
                .into_iter()
                .map(|ip| Ipv4Addr::from(ip).to_string())
                .collect();
            if !list.is_empty() {
                exclusion = format!(" ip daddr != {{ {} }}", list.join(", "));
            }
        }
        let proto = match rule.proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        };
        let first = rule.ports.first();
        let last = rule.ports.last();
        let port = if first == last {
            first.to_string()
        } else {
            format!("{first}-{last}")
        };
        format!("\t\t{family} daddr {network}{exclusion} {proto} dport {port} accept")
    }

    fn check_rendered_grants(rules: &[AllowRule]) -> Result<(), TestCaseError> {
        let actual = render(rules);
        let baseline = render(&[]);
        let insertion = baseline
            .find("\t\tmeta nfproto ipv4")
            .expect("output accounting marker");
        let (before, after) = baseline.split_at(insertion);
        let expected: String = rules
            .iter()
            .map(|rule| expected_grant(rule, rules) + "\n")
            .collect();
        prop_assert_eq!(
            actual
                .strip_prefix(before)
                .and_then(|text| text.strip_suffix(after)),
            Some(expected.as_str())
        );
        Ok(())
    }

    #[test]
    fn renders_both_families_protocols_and_nested_networks() {
        let rules = rules(&[
            "192.0.2.0/24:1/tcp",
            "192.0.2.8/30:2-3/udp",
            "192.0.2.9:65535/tcp",
            "[2001:db8::/120]:1/udp",
            "[2001:db8::8/126]:2-3/tcp",
            "[2001:db8::9]:65534-65535/udp",
        ]);
        check_rendered_grants(&rules).expect("both families, nesting, protocols and port shapes");
    }

    proptest! {
        #[test]
        fn rendered_rules_have_a_fixed_shape(rules in proptest::collection::vec(generated_rule(), 1..8)) {
            check_rendered_grants(&rules)?;
        }
    }

    #[test]
    fn parses_counter_json() {
        let json = r#"{"nftables": [{"metainfo": {"version": "1.1.7"}},
          {"table": {"family": "inet", "name": "playpen", "handle": 1}},
          {"counter": {"family": "inet", "name": "dropped", "table": "playpen", "handle": 1, "packets": 5, "bytes": 269}},
          {"set": {"family": "inet", "name": "drop4", "table": "playpen", "type": ["ipv4_addr", "inet_proto", "inet_service"], "handle": 2, "size": 1024, "flags": ["dynamic"],
            "elem": [{"elem": {"val": {"concat": ["192.0.2.1", "tcp", 8081]}, "counter": {"packets": 2, "bytes": 120}}},
                     {"elem": {"val": {"concat": ["192.0.2.2", "udp", 53]}, "counter": {"packets": 1, "bytes": 29}}},
                     {"elem": {"val": {"concat": ["192.0.2.3", "icmp", 0]}, "counter": {"packets": 1, "bytes": 84}}}]}},
          {"set": {"family": "inet", "name": "drop6", "table": "playpen", "type": ["ipv6_addr", "inet_proto", "inet_service"], "handle": 3, "size": 1024, "flags": ["dynamic"]}}]}"#;
        let s = parse_counters(json).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(s.packets, 5);
        assert_eq!(s.destinations.len(), 3);
        assert_eq!(s.destinations[0].address, "192.0.2.1");
        assert_eq!(s.destinations[0].port, Some(8081));
        assert_eq!(s.destinations[2].protocol, "icmp");
        assert_eq!(s.destinations[2].port, None);
        assert!(s.destinations_truncated);
    }

    #[test]
    fn counter_completeness_is_conservative() {
        fn snapshot(total: u64, elems: &str) -> DropSummary {
            parse_counters(&format!(r#"{{"nftables":[{{"counter":{{"name":"dropped","packets":{total}}}}},{{"set":{{"name":"drop4","elem":[{elems}]}}}},{{"set":{{"name":"drop6"}}}}]}}"#)).unwrap_or_else(|e| panic!("{e}"))
        }
        let entry = r#"{"elem":{"val":{"concat":["192.0.2.1","tcp",80]},"counter":{"packets":3}}}"#;
        assert!(!snapshot(0, "").destinations_truncated);
        assert!(!snapshot(3, entry).destinations_truncated);
        assert!(snapshot(2, entry).destinations_truncated);
        assert!(snapshot(4, entry).destinations_truncated);
        assert!(snapshot(3, "{}").destinations_truncated);
        assert!(snapshot(3, &entry.replace("192.0.2.1", "2001:db8::1")).destinations_truncated);
        assert!(snapshot(3, &entry.replace("80]", "80,1]")).destinations_truncated);
        assert!(snapshot(3, &entry.replace("\"tcp\"", "256")).destinations_truncated);
        assert!(snapshot(3, &entry.replace("\"tcp\"", "\"unknown\"")).destinations_truncated);
        let alias = entry.replace("\"tcp\"", "6");
        assert!(snapshot(6, &format!("{entry},{alias}")).destinations_truncated);

        assert!(snapshot(6, &format!("{entry},{entry}")).destinations_truncated);
        let max = entry.replace("\"packets\":3", &format!("\"packets\":{}", u64::MAX));
        assert!(snapshot(u64::MAX, &format!("{max},{entry}")).destinations_truncated);
        assert!(parse_counters(r#"{"nftables":[{"counter":{"name":"dropped","packets":0}},{"set":{"name":"drop4"}}]}"#).unwrap_or_default().destinations_truncated);
    }

    #[test]
    fn counter_json_errors() {
        assert!(parse_counters("not json").is_err());
        assert!(parse_counters("{}").is_err());
        assert!(parse_counters(r#"{"nftables": []}"#).is_err());
    }
}
