//! The destinations the command contacted through an explicit grant
//! (`--report-contacts`): the names of what the ruleset adds for it, and
//! reading the record back at teardown.
//!
//! With the option, every grant rule ends in `goto contacted` instead of
//! `accept`. The regular chain [`CHAIN`] counts the packet in [`COUNTER`],
//! adds its destination to [`SEEN4`] or [`SEEN6`], and accepts it. The
//! additions are rules of their own: when a set is full, an addition fails
//! and ends its own rule, and the accept after it still applies. In the
//! grant rule itself a failed addition would end the grant, and the packet
//! would be dropped (DESIGN.md, "Contacted destinations").

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The regular chain every grant goes to with `--report-contacts`.
pub const CHAIN: &str = "contacted";
/// Counter of the packets that reached [`CHAIN`].
pub const COUNTER: &str = "contacted";
/// The IPv4 destinations reached through a grant, with a counter each.
pub const SEEN4: &str = "seen4";
/// The IPv6 destinations reached through a grant, with a counter each.
pub const SEEN6: &str = "seen6";

/// The IPv4 sources of replies on established flows, with a counter each.
pub const ANSWERED4: &str = "answered4";
/// The IPv6 sources of replies on established flows, with a counter each.
pub const ANSWERED6: &str = "answered6";
/// The IPv4 sources of TCP replies with RST, with a counter each.
pub const RESET4: &str = "reset4";
/// The IPv6 sources of TCP replies with RST, with a counter each.
pub const RESET6: &str = "reset6";

/// One destination the command opened a flow to through an explicit grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactedDest {
    /// Destination address.
    pub address: String,
    /// `tcp` or `udp`.
    pub protocol: String,
    /// Destination port.
    pub port: u16,
    /// Packets a grant passed to this destination while their flow had no
    /// reply yet: flow starts, not volume.
    pub packets: u64,
    /// The destination sent at least one reply that is not a TCP reset: a
    /// SYN-ACK, data, or a UDP datagram. False for a destination that sent
    /// nothing, and for one that only refused (see `reset`).
    pub answered: bool,
    /// The destination sent a TCP reset: it refused at least one flow.
    pub reset: bool,
}

/// What `--report-contacts` read at teardown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contacted {
    /// Each destination once, by address, protocol and port.
    pub destinations: Vec<ContactedDest>,
    /// True when the list may leave a destination out: more destinations
    /// of one address family than a set holds, or a listing whose entries
    /// do not add up to the counter.
    pub truncated: bool,
}

/// The report fields of `--report-contacts`. A report without the option
/// has neither.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ContactFields {
    /// The record; null when the command did not run or the record could
    /// not be read.
    pub contacted: Option<Contacted>,
    /// Why the record could not be read.
    pub contacted_error: Option<String>,
}

/// The contacted destinations in `nft --json list table inet playpen`.
///
/// # Errors
/// When the JSON does not parse or the [`COUNTER`] counter is missing,
/// repeated or invalid. Anything else that is wrong with the sets makes the
/// record `truncated`.
pub fn parse(json: &str) -> Result<Contacted, String> {
    let value: Value = serde_json::from_str(json)
        .map_err(|e| format!("nft printed JSON that does not parse: {e}"))?;
    let items = value
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or("nft JSON has no \"nftables\" array")?;
    let mut total = None;
    let mut uncertain = false;
    let mut families = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut destinations = Vec::new();
    // Replies by key: all of them, and the resets among them.
    let mut replies = BTreeMap::new();
    let mut resets = BTreeMap::new();
    let mut reply_sets = BTreeSet::new();
    for item in items {
        if let Some(c) = item.get("counter")
            && c.get("name").and_then(Value::as_str) == Some(COUNTER)
        {
            if total.is_some() {
                return Err("nft JSON has duplicate contacted counters".into());
            }
            total = Some(
                c.get("packets")
                    .and_then(Value::as_u64)
                    .ok_or("invalid contacted counter")?,
            );
        }
        let Some(set) = item.get("set") else {
            continue;
        };
        let name = set.get("name").and_then(Value::as_str);
        let (v4, replies_of) = match name {
            Some(SEEN4) => (true, None),
            Some(SEEN6) => (false, None),
            Some(ANSWERED4) => (true, Some(&mut replies)),
            Some(ANSWERED6) => (false, Some(&mut replies)),
            Some(RESET4) => (true, Some(&mut resets)),
            Some(RESET6) => (false, Some(&mut resets)),
            _ => continue,
        };
        if let Some(counts) = replies_of {
            uncertain |= !reply_sets.insert(name);
            match set.get("elem") {
                None => {}
                Some(Value::Array(elems)) => {
                    for elem in elems {
                        match crate::ruleset::parse_elem(elem, v4).and_then(contacted) {
                            Some(d) => uncertain |= counts.insert(key(&d), d.packets).is_some(),
                            None => uncertain = true,
                        }
                    }
                }
                Some(_) => uncertain = true,
            }
            continue;
        }
        uncertain |= !families.insert(v4);
        match set.get("elem") {
            // nft omits elem for an empty set.
            None => {}
            Some(Value::Array(elems)) => {
                for elem in elems {
                    match crate::ruleset::parse_elem(elem, v4).and_then(contacted) {
                        Some(d)
                            if identities.insert((
                                d.address.clone(),
                                d.protocol.clone(),
                                d.port,
                            )) =>
                        {
                            destinations.push(d);
                        }
                        _ => uncertain = true,
                    }
                }
            }
            Some(_) => uncertain = true,
        }
    }
    let total = total.ok_or("nft JSON has no \"contacted\" counter")?;
    let listed = destinations
        .iter()
        .try_fold(0_u64, |sum, d| sum.checked_add(d.packets));
    uncertain |= families.len() != 2 || reply_sets.len() != 4;
    // A reply from a destination that was not contacted would mean that
    // the record misses a flow.
    let known: BTreeSet<_> = destinations.iter().map(key).collect();
    uncertain |= replies
        .keys()
        .chain(resets.keys())
        .any(|k| !known.contains(k));
    for d in &mut destinations {
        let all = replies.get(&key(d)).copied().unwrap_or(0);
        let reset = resets.get(&key(d)).copied().unwrap_or(0);
        // A reset is also a reply, so a count of replies beyond the resets
        // is an answer that is not a refusal.
        d.answered = all > reset;
        d.reset = reset > 0;
    }
    destinations
        .sort_by_cached_key(|d| (d.address.parse::<IpAddr>().ok(), d.protocol.clone(), d.port));
    Ok(Contacted {
        truncated: uncertain || listed != Some(total),
        destinations,
    })
}

/// The key of a destination in the sets: its address, protocol and port.
fn key(d: &ContactedDest) -> (String, String, u16) {
    (d.address.clone(), d.protocol.clone(), d.port)
}

/// A set entry as a contacted destination: grants are TCP and UDP only, so
/// any other protocol cannot be one.
fn contacted(d: crate::ruleset::DroppedDest) -> Option<ContactedDest> {
    if !matches!(d.protocol.as_str(), "tcp" | "udp") {
        return None;
    }
    Some(ContactedDest {
        address: d.address,
        protocol: d.protocol,
        port: d.port?,
        packets: d.packets,
        answered: false,
        reset: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(total: u64, seen4: &str, seen6: &str) -> String {
        replies(total, seen4, seen6, [""; 4])
    }

    /// A listing with the four sets of replies: answered4, answered6,
    /// reset4 and reset6.
    fn replies(total: u64, seen4: &str, seen6: &str, replies: [&str; 4]) -> String {
        let [answered4, answered6, reset4, reset6] = replies;
        format!(
            r#"{{"nftables":[{{"metainfo":{{"json_schema_version":1}}}},
            {{"counter":{{"family":"inet","name":"contacted","table":"playpen","packets":{total},"bytes":0}}}},
            {{"counter":{{"family":"inet","name":"dropped","table":"playpen","packets":7,"bytes":0}}}},
            {{"set":{{"family":"inet","name":"drop4","table":"playpen","elem":[{{"elem":{{"val":{{"concat":["192.0.2.99","tcp",1]}},"counter":{{"packets":7}}}}}}]}}}},
            {{"set":{{"family":"inet","name":"seen4","table":"playpen"{seen4}}}}},
            {{"set":{{"family":"inet","name":"seen6","table":"playpen"{seen6}}}}},
            {{"set":{{"family":"inet","name":"answered4","table":"playpen"{answered4}}}}},
            {{"set":{{"family":"inet","name":"answered6","table":"playpen"{answered6}}}}},
            {{"set":{{"family":"inet","name":"reset4","table":"playpen"{reset4}}}}},
            {{"set":{{"family":"inet","name":"reset6","table":"playpen"{reset6}}}}}]}}"#
        )
    }

    fn entry(addr: &str, proto: &str, port: u16, packets: u64) -> String {
        format!(
            r#"{{"elem":{{"val":{{"concat":["{addr}","{proto}",{port}]}},"counter":{{"packets":{packets},"bytes":60}}}}}}"#
        )
    }

    fn elems(entries: &[String]) -> String {
        format!(r#","elem":[{}]"#, entries.join(","))
    }

    #[test]
    fn reads_both_families_in_address_order_and_leaves_the_drops_out() {
        let seen4 = elems(&[
            entry("198.51.100.10", "tcp", 9557, 1),
            entry("198.51.100.7", "udp", 53, 2),
            entry("198.51.100.7", "tcp", 9558, 1),
        ]);
        let seen6 = elems(&[entry("2001:db8::1", "tcp", 443, 3)]);
        let c = parse(&listing(7, &seen4, &seen6)).unwrap_or_else(|e| panic!("{e}"));
        assert!(!c.truncated, "{c:?}");
        let got: Vec<String> = c
            .destinations
            .iter()
            .map(|d| format!("{} {} {} {}", d.address, d.protocol, d.port, d.packets))
            .collect();
        assert_eq!(
            got,
            [
                "198.51.100.7 tcp 9558 1",
                "198.51.100.7 udp 53 2",
                "198.51.100.10 tcp 9557 1",
                "2001:db8::1 tcp 443 3"
            ]
        );
        let empty = parse(&listing(0, "", "")).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(empty, Contacted::default());
    }

    /// Each destination as `ADDR PROTO PORT answered reset`.
    fn marks(c: &Contacted) -> Vec<String> {
        c.destinations
            .iter()
            .map(|d| {
                format!(
                    "{} {} {} {} {}",
                    d.address, d.protocol, d.port, d.answered, d.reset
                )
            })
            .collect()
    }

    #[test]
    fn a_destination_is_answered_refused_or_silent() {
        let seen4 = elems(&[
            entry("198.51.100.7", "tcp", 9557, 1),
            entry("198.51.100.7", "tcp", 9559, 1),
            entry("198.51.100.7", "udp", 53, 1),
            entry("198.51.100.9", "tcp", 8080, 1),
            entry("198.51.100.9", "tcp", 9557, 2),
        ]);
        let seen6 = elems(&[entry("2001:db8::1", "tcp", 443, 1)]);
        // 9557 answered; 9559 only reset; the UDP one answered; 8080 got
        // nothing; the last had one flow reset and one answered, so it has
        // more replies than resets.
        let answered4 = elems(&[
            entry("198.51.100.7", "tcp", 9557, 3),
            entry("198.51.100.7", "tcp", 9559, 1),
            entry("198.51.100.7", "udp", 53, 1),
            entry("198.51.100.9", "tcp", 9557, 4),
        ]);
        let answered6 = elems(&[entry("2001:db8::1", "tcp", 443, 1)]);
        let reset4 = elems(&[
            entry("198.51.100.7", "tcp", 9559, 1),
            entry("198.51.100.9", "tcp", 9557, 1),
        ]);
        let reset6 = elems(&[entry("2001:db8::1", "tcp", 443, 1)]);
        let c = parse(&replies(
            7,
            &seen4,
            &seen6,
            [&answered4, &answered6, &reset4, &reset6],
        ))
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(!c.truncated, "{c:?}");
        assert_eq!(
            marks(&c),
            [
                "198.51.100.7 tcp 9557 true false",
                "198.51.100.7 tcp 9559 false true",
                "198.51.100.7 udp 53 true false",
                "198.51.100.9 tcp 8080 false false",
                "198.51.100.9 tcp 9557 true true",
                "2001:db8::1 tcp 443 false true"
            ]
        );
    }

    #[test]
    fn replies_that_do_not_fit_the_record_make_it_uncertain() {
        let seen = elems(&[entry("192.0.2.1", "tcp", 80, 1)]);
        let other = elems(&[entry("192.0.2.2", "tcp", 80, 1)]);
        let same = elems(&[entry("192.0.2.1", "tcp", 80, 1)]);
        let truncated = |r: [&str; 4]| {
            parse(&replies(1, &seen, "", r))
                .unwrap_or_else(|e| panic!("{e}"))
                .truncated
        };
        assert!(!truncated([&same, "", "", ""]));
        // A reply from a destination nobody contacted.
        assert!(truncated([&other, "", "", ""]));
        assert!(truncated(["", "", &other, ""]));
        // A reply in the set of the other family.
        assert!(truncated(["", &same, "", ""]));
        // A set of replies missing.
        let missing = replies(1, &seen, "", [&same, "", "", ""]).replace("\"reset6\"", "\"x\"");
        assert!(parse(&missing).unwrap_or_default().truncated);
    }

    #[test]
    fn anything_that_does_not_add_up_is_truncated() {
        let one = elems(&[entry("192.0.2.1", "tcp", 80, 2)]);
        let truncated = |total: u64, seen4: &str, seen6: &str| {
            parse(&listing(total, seen4, seen6))
                .unwrap_or_else(|e| panic!("{e}"))
                .truncated
        };
        assert!(!truncated(2, &one, ""));
        // A full set: packets reached the chain but no entry.
        assert!(truncated(3, &one, ""));
        assert!(truncated(1, &one, ""));
        // A repeated entry, a wrong family, another protocol, no port.
        assert!(truncated(
            4,
            &elems(&vec![entry("192.0.2.1", "tcp", 80, 2); 2]),
            ""
        ));
        assert!(truncated(2, "", &one));
        assert!(truncated(2, &one.replace("\"tcp\"", "\"icmp\""), ""));
        assert!(truncated(2, &one.replace(",80]", ",\"x\"]"), ""));
        assert!(truncated(2, r#","elem":{}"#, ""));
        // A set missing, or listed twice.
        let without6 = listing(2, &one, "").replace("\"seen6\"", "\"other\"");
        assert!(parse(&without6).unwrap_or_default().truncated);
        let twice = listing(2, &one, "").replace("\"seen6\"", "\"seen4\"");
        assert!(parse(&twice).unwrap_or_default().truncated);
    }

    #[test]
    fn the_counter_is_required_once() {
        assert!(parse("not json").is_err());
        assert!(parse(r#"{"nftables":[]}"#).is_err());
        let doubled = listing(0, "", "").replace(
            r#"{"counter":{"family":"inet","name":"dropped""#,
            r#"{"counter":{"family":"inet","name":"contacted""#,
        );
        assert!(parse(&doubled).is_err());
        let invalid = listing(0, "", "").replace("\"packets\":0", "\"packets\":-1");
        assert!(parse(&invalid).is_err());
    }
}
