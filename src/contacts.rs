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

use std::collections::BTreeSet;
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
        let v4 = match set.get("name").and_then(Value::as_str) {
            Some(SEEN4) => true,
            Some(SEEN6) => false,
            _ => continue,
        };
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
    uncertain |= families.len() != 2;
    destinations
        .sort_by_cached_key(|d| (d.address.parse::<IpAddr>().ok(), d.protocol.clone(), d.port));
    Ok(Contacted {
        truncated: uncertain || listed != Some(total),
        destinations,
    })
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing(total: u64, seen4: &str, seen6: &str) -> String {
        format!(
            r#"{{"nftables":[{{"metainfo":{{"json_schema_version":1}}}},
            {{"counter":{{"family":"inet","name":"contacted","table":"playpen","packets":{total},"bytes":0}}}},
            {{"counter":{{"family":"inet","name":"dropped","table":"playpen","packets":7,"bytes":0}}}},
            {{"set":{{"family":"inet","name":"drop4","table":"playpen","elem":[{{"elem":{{"val":{{"concat":["192.0.2.99","tcp",1]}},"counter":{{"packets":7}}}}}}]}}}},
            {{"set":{{"family":"inet","name":"seen4","table":"playpen"{seen4}}}}},
            {{"set":{{"family":"inet","name":"seen6","table":"playpen"{seen6}}}}}]}}"#
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
