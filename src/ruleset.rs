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
use crate::contacts;
pub use crate::nft_readback::verify_policy;

/// Name of the nftables table playpen loads.
pub const TABLE: &str = "playpen";
/// Most distinct dropped destinations remembered per address family.
pub const DROP_SET_SIZE: u32 = 1024;
/// The set that closes all egress once it holds [`CUT_MARK`]. Empty when
/// the ruleset is loaded.
pub const CUT_SET: &str = "cut";
/// The packet mark of every packet in the sandbox. Setting another mark
/// needs a capability over the network namespace, which only the
/// setup process has.
pub const CUT_MARK: u32 = 0;
/// With `--on-drop`, the declared size of [`CUT_SET`].
///
/// A rule adds to the set then, and nft gives such a set this size when
/// none is declared. It is declared so that the readback does not depend
/// on that default.
pub const CUT_SET_SIZE: u32 = 65535;
/// Counter of the packets the cut refused on their way out.
pub const CUT_COUNTER: &str = "cut";
/// Counter of the packets refused on their way out because the approval's
/// end time had passed.
pub const LATE_COUNTER: &str = "late";
/// The latest second `meta time` can hold: it counts nanoseconds since
/// 1970 in 64 bits (2554-07-21T23:34:33Z). nft wraps larger values silently.
pub const LATEST_END: i64 = 18_446_744_073;

/// The second from which the time rule refuses traffic: the approval's end
/// rounded down to a whole second (so never later than the end), and at
/// most [`LATEST_END`]. `None` without an end time.
#[must_use]
pub fn end_second(approval: &Approval) -> Option<i64> {
    approval
        .ends_at
        .map(|end| end.at().unix_timestamp().clamp(0, LATEST_END))
}

/// Renders the complete ruleset for `rules`.
///
/// Output, input and forward chains all have policy drop. Output accepts
/// loopback destinations on `lo`, established and related traffic, the
/// kernel's own IPv6 neighbour discovery, and the approved destinations.
/// Everything else is counted (in total and per destination) and rejected,
/// so a blocked connection fails at once instead of hanging. A rule for an
/// IPv4 network does not accept the network and broadcast addresses of any
/// listed network (see [`Approval::covers_addr`]); they are counted and rejected
/// like any other unapproved destination.
///
/// Between the loopback accepts and the established accept, in output and
/// input, are the rules that end egress: the cut (every packet once
/// [`CUT_SET`] holds [`CUT_MARK`]) and, when the approval has an end time,
/// the time rule (every packet from [`end_second`] on). This renders no end
/// time; see [`render_approval`].
#[must_use]
pub fn render(rules: &[AllowRule]) -> String {
    render_approval(&Approval::new(rules.to_vec(), None))
}

/// Renders an approval with the edge exclusions inherited from its source,
/// and its end time.
#[must_use]
pub fn render_approval(approval: &Approval) -> String {
    render_instrumented(approval, Instrumentation::default())
}

/// What a ruleset holds beyond the approval. The default holds nothing
/// more: the ruleset is then [`render_approval`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Instrumentation {
    /// A counter on each of the first this many grants
    /// (`--report-grant-use`).
    pub grant_counters: usize,
    /// The record of contacted destinations (`--report-contacts`).
    pub record_contacts: bool,
    /// The tripwire on the refusal path (`--on-drop`).
    pub tripwire: bool,
}

/// The table's counters and sets. With `record_contacts`, also the counter
/// and the sets of [`crate::contacts`]. With `tripwire`, the cut set has a
/// declared size.
fn declarations(out: &mut String, timed: bool, with: Instrumentation) {
    let _ = writeln!(out, "\tcounter dropped {{");
    let _ = writeln!(out, "\t}}");
    if timed {
        let _ = writeln!(out, "\tcounter {LATE_COUNTER} {{");
        let _ = writeln!(out, "\t}}");
    }
    let _ = writeln!(out, "\tcounter {CUT_COUNTER} {{");
    let _ = writeln!(out, "\t}}");
    for index in 0..with.grant_counters {
        let _ = writeln!(
            out,
            "\tcounter {} {{}}",
            crate::grant_use::counter_name(index)
        );
    }
    if with.record_contacts {
        let _ = writeln!(out, "\tcounter {} {{}}", contacts::COUNTER);
    }
    let mut sets = vec![("drop4", "ipv4_addr"), ("drop6", "ipv6_addr")];
    if with.record_contacts {
        sets.extend([
            (contacts::SEEN4, "ipv4_addr"),
            (contacts::SEEN6, "ipv6_addr"),
        ]);
    }
    // The contacted sets have the shape of the drop sets.
    for (name, ty) in sets {
        let _ = writeln!(out, "\tset {name} {{");
        let _ = writeln!(out, "\t\ttype {ty} . inet_proto . inet_service");
        let _ = writeln!(out, "\t\tsize {DROP_SET_SIZE}");
        let _ = writeln!(out, "\t\tflags dynamic");
        let _ = writeln!(out, "\t\tcounter");
        let _ = writeln!(out, "\t}}");
    }
    let _ = writeln!(out, "\tset {CUT_SET} {{");
    let _ = writeln!(out, "\t\ttype mark");
    if with.tripwire {
        let _ = writeln!(out, "\t\tsize {CUT_SET_SIZE}");
    }
    let _ = writeln!(out, "\t\tflags dynamic");
    let _ = writeln!(out, "\t}}");
}

/// The ruleset for `approval` with what `with` asks for.
///
/// A counter on each of the first `grant_counters` grants. With
/// `record_contacts` each grant ends in `goto contacted` instead of
/// `accept` (see [`crate::contacts`]).
///
/// With `tripwire` (`--on-drop`), the refusal path adds [`CUT_MARK`] to
/// [`CUT_SET`] after the drop sets and before the `dropped` counter, and
/// drops the packet instead of rejecting it. The first packet refused
/// there closes all egress, and every later one meets the cut rule first,
/// so the drop sets keep the destination that tripped it. A reject would
/// send its ICMP error to the command through the cut it has just closed:
/// the cut would drop and count it, and the command would not see it
/// either.
#[must_use]
pub fn render_instrumented(approval: &Approval, with: Instrumentation) -> String {
    let end = end_second(approval);
    let mut out = String::new();
    // A table of our own; flush it first so a reload replaces it whole.
    let _ = writeln!(out, "table inet {TABLE} {{}}");
    let _ = writeln!(out, "delete table inet {TABLE}");
    let _ = writeln!(out, "table inet {TABLE} {{");
    declarations(&mut out, end.is_some(), with);
    let _ = writeln!(out, "\tchain output {{");
    let _ = writeln!(
        out,
        "\t\ttype filter hook output priority filter; policy drop;"
    );
    let _ = writeln!(out, "\t\toif \"lo\" ip daddr 127.0.0.0/8 accept");
    let _ = writeln!(out, "\t\toif \"lo\" ip6 daddr ::1 accept");
    // The kernel's own multicast listener reports and router solicitations
    // when an interface comes up: dropped, but not counted, because the
    // command did not send them. Before the rules that end egress, so they
    // are not counted there either.
    let _ = writeln!(
        out,
        "\t\tip6 daddr ff02::/16 icmpv6 type {{ mld-listener-report, mld2-listener-report, nd-router-solicit }} drop"
    );
    end_rules(&mut out, end, true);
    let _ = writeln!(out, "\t\tct state established,related accept");
    // Neighbour discovery: only the two messages address resolution needs,
    // and only with hop limit 255 (RFC 4861), so it never leaves the link.
    let _ = writeln!(
        out,
        "\t\ticmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} ip6 hoplimit 255 accept"
    );
    for (index, rule) in approval.rules().iter().enumerate() {
        let matches = match_expr(rule, &approval.exclusions(rule));
        let _ = write!(out, "\t\t{matches}");
        if index < with.grant_counters {
            let _ = write!(
                out,
                " counter name {}",
                crate::grant_use::counter_name(index)
            );
        }
        if with.record_contacts {
            let _ = writeln!(out, " goto {}", contacts::CHAIN);
        } else {
            let _ = writeln!(out, " accept");
        }
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
    if with.tripwire {
        let _ = writeln!(
            out,
            "\t\t# --on-drop: the first packet that gets here closes all egress, and is dropped."
        );
        let _ = writeln!(out, "\t\tadd @{CUT_SET} {{ {CUT_MARK} }}");
    }
    let _ = writeln!(out, "\t\tcounter name \"dropped\"");
    if with.tripwire {
        let _ = writeln!(out, "\t\tdrop");
    } else {
        let _ = writeln!(out, "\t\treject with icmpx admin-prohibited");
    }
    let _ = writeln!(out, "\t}}");
    if with.record_contacts {
        contacted_chain(&mut out);
    }
    let _ = writeln!(out, "\tchain input {{");
    let _ = writeln!(
        out,
        "\t\ttype filter hook input priority filter; policy drop;"
    );
    let _ = writeln!(out, "\t\tiif \"lo\" accept");
    end_rules(&mut out, end, false);
    let _ = writeln!(out, "\t\tct state established,related accept");
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

/// The regular chain every grant goes to with `--report-contacts`: count
/// the packet, add its destination to the set of its family, accept it.
fn contacted_chain(out: &mut String) {
    let _ = writeln!(out, "\tchain {} {{", contacts::CHAIN);
    let _ = writeln!(
        out,
        "\t\t# A full set ends only the rule that adds to it; the accept below still applies."
    );
    let _ = writeln!(out, "\t\tcounter name \"{}\"", contacts::COUNTER);
    for (family, addr, set) in [
        ("ipv4", "ip", contacts::SEEN4),
        ("ipv6", "ip6", contacts::SEEN6),
    ] {
        let _ = writeln!(
            out,
            "\t\tmeta nfproto {family} add @{set} {{ {addr} daddr . meta l4proto . th dport }}"
        );
    }
    let _ = writeln!(out, "\t\taccept");
    let _ = writeln!(out, "\t}}");
}

/// The time rule (with an end time) and the cut rule. Only the output
/// chain counts what they refuse: what arrives was not sent by the command.
fn end_rules(out: &mut String, end: Option<i64>, output: bool) {
    let count = |name: &str| {
        if output {
            format!(" counter name \"{name}\"")
        } else {
            String::new()
        }
    };
    if let Some(second) = end {
        if output {
            let stamp = time::OffsetDateTime::from_unix_timestamp(second)
                .ok()
                .and_then(|t| {
                    t.format(&time::format_description::well_known::Rfc3339)
                        .ok()
                })
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "\t\t# From {stamp}, when the approval ends, everything but loopback is refused."
            );
        }
        let _ = writeln!(out, "\t\tmeta time >= {second}{} drop", count(LATE_COUNTER));
    }
    let _ = writeln!(out, "\t\tmeta mark @{CUT_SET}{} drop", count(CUT_COUNTER));
}

/// Packets refused on their way out after the approval ended.
///
/// The sum of the [`LATE_COUNTER`] (present when `timed`) and
/// [`CUT_COUNTER`] counters in `nft --json list table inet playpen`. A
/// packet meets at most one of the two rules, so none is counted twice.
///
/// # Errors
/// When the JSON does not parse, or a counter is missing, repeated or
/// invalid.
pub fn parse_refused_after_end(json: &str, timed: bool) -> Result<u64, String> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| format!("nft printed JSON that does not parse: {e}"))?;
    let items = value
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or("nft JSON has no \"nftables\" array")?;
    let mut late = None;
    let mut cut = None;
    for counter in items.iter().filter_map(|item| item.get("counter")) {
        let slot = match counter.get("name").and_then(serde_json::Value::as_str) {
            Some(LATE_COUNTER) => &mut late,
            Some(CUT_COUNTER) => &mut cut,
            _ => continue,
        };
        if slot.is_some() {
            return Err("nft JSON repeats a counter of refused packets".into());
        }
        *slot = Some(
            counter
                .get("packets")
                .and_then(serde_json::Value::as_u64)
                .ok_or("invalid counter of refused packets")?,
        );
    }
    let cut = cut.ok_or("nft JSON has no \"cut\" counter")?;
    let late = match (timed, late) {
        (true, Some(n)) => n,
        (false, None) => 0,
        (true, None) => return Err("nft JSON has no \"late\" counter".into()),
        (false, Some(_)) => return Err("nft JSON has an unexpected \"late\" counter".into()),
    };
    late.checked_add(cut)
        .ok_or_else(|| "the counters of refused packets overflow".into())
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
                        if let Some(d) = parse_elem(elem, name == Some("drop4")) {
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

/// One element of a set of destinations (address, protocol, port) with
/// its counter: of an IPv4 set when `v4`, else of an IPv6 set. `None` for
/// an element of any other shape or family.
pub(crate) fn parse_elem(elem: &serde_json::Value, v4: bool) -> Option<DroppedDest> {
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
    if v4 != ip.is_ipv4() {
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
    use crate::approval::{EndsAt, Net, Ports, parse_allow};
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

    fn ending(end: &str) -> Approval {
        Approval::new(
            rules(&["192.0.2.1:443/tcp"]),
            Some(EndsAt::parse(end).unwrap_or_else(|e| panic!("{e}"))),
        )
    }

    /// The chain named `name` in `text`, from its header to its end.
    fn chain<'a>(text: &'a str, name: &str) -> &'a str {
        let start = text.find(&format!("chain {name} {{")).unwrap_or(0);
        let rest = &text[start..];
        &rest[..rest.find("\n\t}").unwrap_or(rest.len())]
    }

    #[test]
    fn without_an_end_time_there_is_no_time_rule() {
        let text = render_approval(&Approval::new(rules(&["192.0.2.1:443/tcp"]), None));
        assert!(!text.contains("meta time"));
        assert!(!text.contains("counter late"));
        assert!(!text.contains("name \"late\""));
        // The cut rule is always there; its set starts empty.
        assert!(text.contains("\tset cut {\n\t\ttype mark\n\t\tflags dynamic\n\t}\n"));
        assert!(text.contains("\t\tmeta mark @cut counter name \"cut\" drop\n"));
        assert!(text.contains("\t\tmeta mark @cut drop\n"));
        assert!(!text.contains("elements"));
    }

    #[test]
    fn end_rules_follow_loopback_and_precede_everything_else() {
        let text = render_approval(&ending("2026-12-01T12:34:56.7+01:00"));
        assert_eq!(text.matches("meta time").count(), 2);
        assert_eq!(text.matches("meta mark @cut").count(), 2);
        assert_eq!(text.matches("\tcounter late {").count(), 1);
        let output = chain(&text, "output");
        let at = |needle: &str| output.find(needle).unwrap_or(usize::MAX);
        let order = [
            "oif \"lo\" ip daddr 127.0.0.0/8 accept",
            "oif \"lo\" ip6 daddr ::1 accept",
            "mld-listener-report",
            "# From 2026-12-01T11:34:56Z, when the approval ends,",
            "meta time >= 1796124896 counter name \"late\" drop",
            "meta mark @cut counter name \"cut\" drop",
            "ct state established,related accept",
            "nd-neighbor-solicit",
            "ip daddr 192.0.2.1 tcp dport 443 accept",
            "counter name \"dropped\"",
        ];
        for pair in order.windows(2) {
            assert!(at(pair[0]) < at(pair[1]), "{pair:?} in\n{output}");
        }
        let input = chain(&text, "input");
        let at = |needle: &str| input.find(needle).unwrap_or(usize::MAX);
        let order = [
            "iif \"lo\" accept",
            "meta time >= 1796124896 drop",
            "meta mark @cut drop",
            "ct state established,related accept",
        ];
        for pair in order.windows(2) {
            assert!(at(pair[0]) < at(pair[1]), "{pair:?} in\n{input}");
        }
        // Arriving packets are refused but not counted.
        assert!(!input.contains("counter"));
    }

    /// The record of contacted destinations with `grant_counters`.
    fn contacts(grant_counters: usize) -> Instrumentation {
        Instrumentation {
            grant_counters,
            record_contacts: true,
            ..Instrumentation::default()
        }
    }

    #[test]
    fn the_contacted_record_only_adds_and_turns_accept_into_goto() {
        let approval = Approval::new(
            rules(&["192.0.2.0/30:8000-8002/tcp", "[2001:db8::1]:53/udp"]),
            Some(EndsAt::parse("2099-01-01T00:00:00Z").unwrap_or_else(|e| panic!("{e}"))),
        );
        for counters in [0, 1, 2] {
            let plain = render_instrumented(
                &approval,
                Instrumentation {
                    grant_counters: counters,
                    ..Instrumentation::default()
                },
            );
            let recorded = render_instrumented(&approval, contacts(counters));
            assert!(!plain.contains("contacted") && !plain.contains("seen"));
            assert_eq!(recorded.matches(" goto contacted\n").count(), 2);
            let added = [
                "\tcounter contacted {}\n".to_owned(),
                "\tset seen4 {\n\t\ttype ipv4_addr . inet_proto . inet_service\n\t\tsize 1024\n\t\tflags dynamic\n\t\tcounter\n\t}\n".into(),
                "\tset seen6 {\n\t\ttype ipv6_addr . inet_proto . inet_service\n\t\tsize 1024\n\t\tflags dynamic\n\t\tcounter\n\t}\n".into(),
                format!("\t{}\n\t}}\n", chain(&recorded, "contacted")),
            ];
            let mut stripped = recorded.replace(" goto contacted\n", " accept\n");
            for text in &added {
                assert_eq!(stripped.matches(text.as_str()).count(), 1, "{text}");
                stripped = stripped.replacen(text.as_str(), "", 1);
            }
            assert_eq!(stripped, plain);
        }
        let output = render_instrumented(&approval, contacts(1));
        assert!(output.contains(
            "\t\tip daddr 192.0.2.0/30 ip daddr != { 192.0.2.0, 192.0.2.3 } tcp dport 8000-8002 counter name grant_1 goto contacted\n"
        ));
        let record = chain(&output, "contacted");
        let at = |needle: &str| record.find(needle).unwrap_or(usize::MAX);
        let order = [
            "counter name \"contacted\"",
            "meta nfproto ipv4 add @seen4 { ip daddr . meta l4proto . th dport }",
            "meta nfproto ipv6 add @seen6 { ip6 daddr . meta l4proto . th dport }",
            "\t\taccept",
        ];
        for pair in order.windows(2) {
            assert!(at(pair[0]) < at(pair[1]), "{pair:?} in\n{record}");
        }
        assert!(record.ends_with("\t\taccept"), "{record}");
    }

    #[test]
    fn the_tripwire_is_on_the_refusal_path_only_with_the_option() {
        let approval = ending("2026-12-01T12:34:56Z");
        assert_eq!(
            render_instrumented(&approval, Instrumentation::default()),
            render_approval(&approval)
        );
        // The same lines with and without the record of contacts.
        for without in [Instrumentation::default(), contacts(1)] {
            let plain = render_instrumented(&approval, without);
            assert!(!plain.contains("add @cut"));
            assert!(!plain.contains("--on-drop"));
            let text = render_instrumented(
                &approval,
                Instrumentation {
                    tripwire: true,
                    ..without
                },
            );
            assert_eq!(text.matches("add @cut { 0 }").count(), 1);
            assert!(!text.contains("reject"));
            let output = chain(&text, "output");
            let at = |needle: &str| output.find(needle).unwrap_or(usize::MAX);
            let order = [
                "meta mark @cut counter name \"cut\" drop",
                "ip daddr 192.0.2.1 tcp dport 443",
                "add @drop6 { ip6 daddr . meta l4proto . 0 }",
                "# --on-drop: the first packet that gets here closes all egress, and is dropped.",
                "add @cut { 0 }",
                "counter name \"dropped\"",
                "\t\tdrop",
            ];
            for pair in order.windows(2) {
                assert!(at(pair[0]) < at(pair[1]), "{pair:?} in\n{output}");
            }
            assert!(
                output.ends_with("\t\tcounter name \"dropped\"\n\t\tdrop"),
                "{output}"
            );
            // The rest is the same: only the refusal path and the size of
            // the cut set differ.
            let input = |t: &str| t[t.find("\tchain input").unwrap_or(0)..].to_owned();
            assert_eq!(input(&text), input(&plain));
            assert_eq!(
                text.matches("\tset cut {\n\t\ttype mark\n\t\tsize 65535\n\t\tflags dynamic\n\t}")
                    .count(),
                1
            );
            let stripped = text
                .replace("\t\ttype mark\n\t\tsize 65535\n", "\t\ttype mark\n")
                .replace(
                    "\t\t# --on-drop: the first packet that gets here closes all egress, and is dropped.\n\t\tadd @cut { 0 }\n",
                    "",
                )
                .replace(
                    "counter name \"dropped\"\n\t\tdrop\n",
                    "counter name \"dropped\"\n\t\treject with icmpx admin-prohibited\n",
                );
            assert_eq!(stripped, plain);
        }
    }

    #[test]
    fn end_second_rounds_down_and_stays_within_what_nft_holds() {
        let second = |end: &str| end_second(&ending(end));
        assert_eq!(second("2026-12-01T12:34:56Z"), Some(1_796_128_496));
        assert_eq!(
            second("2026-12-01T12:34:56.999999999Z"),
            Some(1_796_128_496)
        );
        assert_eq!(second("1969-12-31T23:59:59Z"), Some(0));
        assert_eq!(second("9999-12-31T23:59:59Z"), Some(LATEST_END));
        assert_eq!(end_second(&Approval::new(vec![], None)), None);
    }

    #[test]
    fn refused_after_end_sums_late_and_cut() {
        let counters = |late: Option<u64>, cut: Option<u64>| {
            let mut items = vec![serde_json::json!({"metainfo": {}})];
            if let Some(n) = late {
                items.push(serde_json::json!({"counter": {"name": "late", "packets": n}}));
            }
            if let Some(n) = cut {
                items.push(serde_json::json!({"counter": {"name": "cut", "packets": n}}));
            }
            items.push(serde_json::json!({"counter": {"name": "dropped", "packets": 99}}));
            serde_json::json!({ "nftables": items }).to_string()
        };
        assert_eq!(
            parse_refused_after_end(&counters(Some(3), Some(4)), true),
            Ok(7)
        );
        assert_eq!(
            parse_refused_after_end(&counters(None, Some(4)), false),
            Ok(4)
        );
        assert!(parse_refused_after_end(&counters(None, Some(4)), true).is_err());
        assert!(parse_refused_after_end(&counters(Some(3), Some(4)), false).is_err());
        assert!(parse_refused_after_end(&counters(Some(3), None), true).is_err());
        assert!(parse_refused_after_end(&counters(Some(u64::MAX), Some(1)), true).is_err());
        let twice = counters(None, Some(4)).replace(
            "{\"metainfo\":{}}",
            "{\"counter\":{\"name\":\"cut\",\"packets\":1}}",
        );
        assert!(parse_refused_after_end(&twice, false).is_err());
        assert!(parse_refused_after_end("{}", false).is_err());
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
        // With the contacted record, the same lines end in the goto.
        let recorded = render_instrumented(&Approval::new(rules.to_vec(), None), contacts(0));
        let goto = expected.replace(" accept\n", " goto contacted\n");
        prop_assert_eq!(recorded.matches(goto.as_str()).count(), 1);
        prop_assert_eq!(recorded.matches(" goto contacted\n").count(), rules.len());
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
