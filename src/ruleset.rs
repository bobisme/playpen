//! The nftables ruleset loaded inside the namespace, and reading its drop
//! counters back.
//!
//! The ruleset text is built only from typed values ([`AllowRule`]: parsed
//! addresses, integers and an enum). No string a user typed reaches it, so
//! nothing on the command line can inject nftables syntax.

use std::fmt::Write as _;
use std::net::IpAddr;

use serde::Serialize;

use crate::approval::{AllowRule, Proto};

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
/// so a blocked connection fails at once instead of hanging.
#[must_use]
pub fn render(rules: &[AllowRule]) -> String {
    let mut out = String::new();
    // A table of our own; flush it first so a reload replaces it whole.
    let _ = writeln!(out, "table inet {TABLE} {{}}");
    let _ = writeln!(out, "delete table inet {TABLE}");
    let _ = writeln!(out, "table inet {TABLE} {{");
    let _ = writeln!(out, "\tcounter dropped {{");
    let _ = writeln!(out, "\t}}");
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
    for rule in rules {
        let _ = writeln!(out, "\t\t{} accept", match_expr(rule));
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

fn match_expr(rule: &AllowRule) -> String {
    let family = match rule.net.addr() {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    };
    let proto = match rule.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    format!("{family} daddr {} {proto} dport {}", rule.net, rule.ports)
}

/// Rules in the output chain for `allow_count` approved destinations.
#[must_use]
pub const fn output_rule_count(allow_count: usize) -> usize {
    // established, two loopback, NDP, silent MLD/RS drop, the approved
    // rules, four set updates, the counter, the reject.
    5 + allow_count + 6
}

/// Checks `nft --json list table inet playpen` against what we loaded: the
/// three base chains exist on the right hooks with policy drop, and the
/// output chain holds the expected number of rules.
///
/// # Errors
/// Says which part does not match.
pub fn verify_loaded(json: &str, allow_count: usize) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| format!("nft printed JSON that does not parse: {e}"))?;
    let items = value
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or("nft JSON has no \"nftables\" array")?;
    for hook in ["output", "input", "forward"] {
        let found = items.iter().filter_map(|i| i.get("chain")).any(|c| {
            let s = |k: &str| c.get(k).and_then(serde_json::Value::as_str);
            s("family") == Some("inet")
                && s("table") == Some(TABLE)
                && s("name") == Some(hook)
                && s("hook") == Some(hook)
                && s("policy") == Some("drop")
        });
        if !found {
            return Err(format!("no {hook} chain with policy drop"));
        }
    }
    let rules = items
        .iter()
        .filter_map(|i| i.get("rule"))
        .filter(|r| r.get("chain").and_then(serde_json::Value::as_str) == Some("output"))
        .count();
    let want = output_rule_count(allow_count);
    if rules != want {
        return Err(format!("output chain has {rules} rules, expected {want}"));
    }
    Ok(())
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
    for item in items {
        if let Some(c) = item.get("counter")
            && c.get("name").and_then(serde_json::Value::as_str) == Some("dropped")
        {
            total = c.get("packets").and_then(serde_json::Value::as_u64);
        }
        if let Some(s) = item.get("set") {
            let name = s.get("name").and_then(serde_json::Value::as_str);
            if !matches!(name, Some("drop4" | "drop6")) {
                continue;
            }
            for elem in s
                .get("elem")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(d) = parse_elem(elem) {
                    dests.push(d);
                }
            }
        }
    }
    let packets = total.ok_or("nft JSON has no \"dropped\" counter")?;
    dests.sort_by(|a, b| b.packets.cmp(&a.packets).then_with(|| a.cmp(b)));
    let listed: u64 = dests.iter().map(|d| d.packets).sum();
    Ok(DropSummary {
        packets,
        destinations_truncated: listed < packets,
        destinations: dests,
    })
}

fn parse_elem(elem: &serde_json::Value) -> Option<DroppedDest> {
    let inner = elem.get("elem")?;
    let concat = inner.get("val")?.get("concat")?.as_array()?;
    let address = concat.first()?.as_str()?.to_owned();
    // nft prints the protocol by name when it knows it, else as a number.
    let protocol = match concat.get(1)? {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => return None,
    };
    let port = match (protocol.as_str(), concat.get(2)?) {
        ("tcp" | "udp", serde_json::Value::Number(n)) => {
            n.as_u64().and_then(|p| u16::try_from(p).ok())
        }
        ("tcp" | "udp", serde_json::Value::String(s)) => s.parse().ok(),
        _ => None,
    };
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
    use crate::approval::parse_allow;
    use proptest::prelude::*;

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
        assert!(text.contains("\t\tip daddr 198.51.100.0/24 udp dport 5060-5070 accept\n"));
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

    /// Every rendered allow line has exactly the fixed shape, whatever the
    /// (valid) input.
    fn allow_line_is_well_formed(line: &str) -> bool {
        let words: Vec<&str> = line.trim().split(' ').collect();
        words.len() == 6
            && matches!(words[0], "ip" | "ip6")
            && words[1] == "daddr"
            && words[2]
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b".:/".contains(&b))
            && matches!(words[3], "tcp" | "udp")
            && words[4] == "dport"
            && words[5].bytes().all(|b| b.is_ascii_digit() || b == b'-')
    }

    proptest! {
        #[test]
        fn rendered_rules_have_a_fixed_shape(specs in proptest::collection::vec("[0-9a-f:./\\[\\]-]{1,24}/(tcp|udp)", 0..8)) {
            let parsed: Vec<AllowRule> = specs.iter().filter_map(|s| parse_allow(s).ok()).collect();
            let text = render(&parsed);
            let fixed = render(&[]);
            let fixed_lines: Vec<&str> = fixed.lines().collect();
            let extra: Vec<&str> = text.lines().filter(|l| !fixed_lines.contains(l)).collect();
            prop_assert_eq!(extra.len(), parsed.len());
            for line in extra {
                let body = line.trim().strip_suffix(" accept").unwrap_or("");
                prop_assert!(allow_line_is_well_formed(body), "bad line {:?}", line);
            }
            prop_assert_eq!(text.matches(';').count(), 6);
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
    fn counter_json_errors() {
        assert!(parse_counters("not json").is_err());
        assert!(parse_counters("{}").is_err());
        assert!(parse_counters(r#"{"nftables": []}"#).is_err());
    }
}
