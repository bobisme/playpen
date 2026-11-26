//! Dropped destinations while the command runs.
//!
//! With `--events-fd`, `--live-drops` or `--on-drop`, the setup process C
//! reads the ruleset's `dropped` counter every [`INTERVAL`] while the
//! command runs. When the counter has moved since the last listing, C lists
//! the table and sends each destination it has not sent before to the
//! supervisor, one `denied` line each. The supervisor turns each line into
//! a `denied` event and, with `--live-drops`, a line on stderr. With
//! `--on-drop`, the first reading that finds the counter above zero also
//! tells the supervisor that the cut has tripped ([`LiveDrops::tripped`]).
//! The final report still comes from the readback at teardown; nothing here
//! changes it.
//!
//! This module holds what C remembers between readings and the parsing.
//! Running `nft` and the schedule are in `sandbox` (`watch_sandbox`).

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ruleset::{self, DroppedDest};

/// How often C reads the `dropped` counter while the command runs: the
/// cadence of the pass re-read.
pub const INTERVAL: Duration = crate::pass::RECHECK_INTERVAL;

/// With `--live-drops`, stderr gets a line for each of the first this many
/// destinations, then one line that says there are more.
pub const SHOWN: usize = 8;

/// Which record a `denied` line comes from. Values are stable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// The drop sets: address, protocol and port.
    #[default]
    Destination,
    /// The per-address sets: address and protocol, with `port` null. Sent
    /// only when the family's drop set is full and no line has named the
    /// address and protocol.
    Address,
}

/// One `denied` line: a dropped destination not sent before, and its
/// record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denied {
    /// The destination; `port` is null for a [`RecordKind::Address`].
    #[serde(flatten)]
    pub dest: DroppedDest,
    /// The record it comes from.
    #[serde(default)]
    pub record: RecordKind,
}

/// What C remembers between readings.
#[derive(Debug, Default)]
pub struct LiveDrops {
    /// The `dropped` counter as read just before the last listing of the
    /// table. Every packet counted by then has its destination in that
    /// listing: the ruleset adds the destination to its set before it
    /// counts the packet.
    listed_at: u64,
    /// Destinations already sent, as address, protocol and port.
    sent: HashSet<(String, String, Option<u16>)>,
    /// Addresses and protocols that a line sent has named.
    named: HashSet<(String, String)>,
    /// A failed reading has been reported.
    failure_reported: bool,
    /// The ruleset has the tripwire (`--on-drop`).
    tripwire: bool,
    /// A reading has found the cut tripped.
    tripped: bool,
}

impl LiveDrops {
    /// The state before the first reading; `tripwire` with `--on-drop`.
    #[must_use]
    pub fn new(tripwire: bool) -> Self {
        Self {
            tripwire,
            ..Self::default()
        }
    }

    /// With the tripwire: true the first time a reading finds `packets`,
    /// the `dropped` counter, above zero. Every packet counted there has
    /// tripped the cut on its way (see [`crate::tripwire`]). Always false
    /// without the tripwire.
    pub const fn tripped(&mut self, packets: u64) -> bool {
        if !self.tripwire || self.tripped || packets == 0 {
            return false;
        }
        self.tripped = true;
        true
    }

    /// Whether the table must be listed: `packets`, the `dropped` counter
    /// just read, differs from its value at the last listing.
    #[must_use]
    pub const fn moved(&self, packets: u64) -> bool {
        packets != self.listed_at
    }

    /// The destinations in `table`, a listing of the whole table made after
    /// the counter read `packets`, that were not sent before. Records them
    /// as sent, and `packets` as the counter at this listing. First the
    /// drop sets' destinations, largest packet count first; then, for a
    /// family whose drop set is full, each per-address entry whose address
    /// and protocol no line has named.
    ///
    /// # Errors
    /// When the listing does not parse; nothing is recorded then, so the
    /// next reading lists the table again.
    pub fn fresh(&mut self, packets: u64, table: &str) -> Result<Vec<Denied>, String> {
        let summary = ruleset::parse_counters(table)?;
        self.listed_at = packets;
        let mut out: Vec<Denied> = Vec::new();
        for d in summary.destinations {
            self.named.insert((d.address.clone(), d.protocol.clone()));
            if self
                .sent
                .insert((d.address.clone(), d.protocol.clone(), d.port))
            {
                out.push(Denied {
                    dest: d,
                    record: RecordKind::Destination,
                });
            }
        }
        let full = |v4: bool| {
            let name = if v4 {
                ruleset::FULL_NAMES[0]
            } else {
                ruleset::FULL_NAMES[1]
            };
            summary.full.iter().any(|f| f == name)
        };
        for a in summary.addresses.unwrap_or_default() {
            // Only a full drop set is a reason for an address to have no
            // destination there: otherwise its packet came after the drop
            // set was listed, and the next listing has it.
            let v4 = a
                .address
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_ipv4());
            if !full(v4) || !self.named.insert((a.address.clone(), a.protocol.clone())) {
                continue;
            }
            out.push(Denied {
                dest: DroppedDest {
                    address: a.address,
                    protocol: a.protocol,
                    port: None,
                    packets: a.packets,
                },
                record: RecordKind::Address,
            });
        }
        Ok(out)
    }

    /// True the first time it is called: a failed reading is reported once.
    pub const fn first_failure(&mut self) -> bool {
        let first = !self.failure_reported;
        self.failure_reported = true;
        first
    }
}

/// The packet count of the `dropped` counter in the output of `nft --json
/// list counter inet playpen dropped`.
///
/// # Errors
/// When the JSON does not parse, or the counter is missing, repeated or
/// invalid.
pub fn parse_dropped(json: &str) -> Result<u64, String> {
    parse_counter(json, "dropped")
}

/// The packet count of the counter `name` in nft's JSON: a listing of that
/// counter, or of the whole table.
///
/// # Errors
/// When the JSON does not parse, or the counter is missing, repeated or
/// invalid.
pub fn parse_counter(json: &str, name: &str) -> Result<u64, String> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| format!("nft printed JSON that does not parse: {e}"))?;
    let items = value
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or("nft JSON has no \"nftables\" array")?;
    let mut found = None;
    for counter in items.iter().filter_map(|item| item.get("counter")) {
        if counter.get("name").and_then(serde_json::Value::as_str) != Some(name) {
            continue;
        }
        if found.is_some() {
            return Err(format!("nft JSON has duplicate {name} counters"));
        }
        found = Some(
            counter
                .get("packets")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| format!("invalid {name} counter"))?,
        );
    }
    found.ok_or_else(|| format!("nft JSON has no \"{name}\" counter"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter(packets: u64) -> String {
        format!(
            r#"{{"nftables": [{{"metainfo": {{"version": "1.1.7", "json_schema_version": 1}}}}, {{"counter": {{"family": "inet", "name": "dropped", "table": "playpen", "handle": 1, "packets": {packets}, "bytes": 0}}}}]}}"#
        )
    }

    /// A table listing with the `dropped` counter at `total` and these
    /// IPv4 elements (address, protocol, port, packets).
    fn table(total: u64, v4: &[(&str, &str, u64, u64)], v6: &[(&str, &str, u64, u64)]) -> String {
        let elems = |list: &[(&str, &str, u64, u64)]| {
            list.iter()
                .map(|(a, p, port, n)| {
                    format!(
                        r#"{{"elem": {{"val": {{"concat": ["{a}", "{p}", {port}]}}, "counter": {{"packets": {n}, "bytes": 0}}}}}}"#
                    )
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            r#"{{"nftables": [{{"counter": {{"name": "dropped", "packets": {total}}}}}, {{"set": {{"name": "drop4", "elem": [{}]}}}}, {{"set": {{"name": "drop6", "elem": [{}]}}}}, {{"set": {{"name": "cut"}}}}]}}"#,
            elems(v4),
            elems(v6)
        )
    }

    fn keys(list: &[Denied]) -> Vec<(String, String, Option<u16>, u64)> {
        list.iter()
            .map(|Denied { dest: d, record }| {
                assert_eq!(*record, RecordKind::Destination);
                (d.address.clone(), d.protocol.clone(), d.port, d.packets)
            })
            .collect()
    }

    /// A table listing with the per-address sets as well: the IPv4 drop
    /// set full with UDP to ports 1 to 1024 of 203.0.113.5, and these
    /// IPv4 address entries (address, protocol, packets).
    fn flooded(total: u64, extra: &[(&str, &str, u64)]) -> String {
        let ports: Vec<String> = (1..=1024)
            .map(|port| {
                format!(
                    r#"{{"elem": {{"val": {{"concat": ["203.0.113.5", "udp", {port}]}}, "counter": {{"packets": 1, "bytes": 0}}}}}}"#
                )
            })
            .collect();
        let addrs: Vec<String> = std::iter::once(("203.0.113.5", "udp", 1024))
            .chain(extra.iter().copied())
            .map(|(a, p, n)| {
                format!(
                    r#"{{"elem": {{"val": {{"concat": ["{a}", "{p}"]}}, "counter": {{"packets": {n}, "bytes": 0}}}}}}"#
                )
            })
            .collect();
        format!(
            r#"{{"nftables": [{{"counter": {{"name": "dropped", "packets": {total}}}}}, {{"set": {{"name": "drop4", "elem": [{}]}}}}, {{"set": {{"name": "drop6"}}}}, {{"set": {{"name": "dropaddr4", "elem": [{}]}}}}, {{"set": {{"name": "dropaddr6"}}}}]}}"#,
            ports.join(","),
            addrs.join(",")
        )
    }

    #[test]
    fn past_a_full_drop_set_a_new_address_is_sent_without_its_port() {
        let mut live = LiveDrops::default();
        let first = live.fresh(1024, &flooded(1024, &[])).unwrap_or_default();
        assert_eq!(first.len(), 1024);
        assert!(first.iter().all(|d| d.record == RecordKind::Destination));
        // The decoys' address is named by their lines already; the real
        // target is not in the full drop set, and gets an address line.
        let second = live
            .fresh(1026, &flooded(1026, &[("198.51.100.66", "tcp", 2)]))
            .unwrap_or_default();
        assert_eq!(
            second,
            [Denied {
                dest: DroppedDest {
                    address: "198.51.100.66".into(),
                    protocol: "tcp".into(),
                    port: None,
                    packets: 2,
                },
                record: RecordKind::Address,
            }]
        );
        assert_eq!(
            serde_json::to_value(&second[0]).unwrap_or_default(),
            serde_json::json!({"address": "198.51.100.66", "protocol": "tcp", "port": null, "packets": 2, "record": "address"})
        );
        // Once.
        let third = live
            .fresh(1030, &flooded(1030, &[("198.51.100.66", "tcp", 6)]))
            .unwrap_or_default();
        assert_eq!(third, []);
        // An address entry without its destination while the drop set has
        // room is a packet the listing caught between the sets: the next
        // listing has its destination.
        let mut live = LiveDrops::default();
        let early = table(1, &[], &[]).replace(
            "{\"set\": {\"name\": \"cut\"}}",
            "{\"set\": {\"name\": \"dropaddr4\", \"elem\": [{\"elem\": {\"val\": {\"concat\": [\"192.0.2.2\", \"udp\"]}, \"counter\": {\"packets\": 1}}}]}}, {\"set\": {\"name\": \"dropaddr6\"}}",
        );
        assert_eq!(live.fresh(1, &early).unwrap_or_default(), []);
    }

    #[test]
    fn reads_the_dropped_counter() {
        assert_eq!(parse_dropped(&counter(0)), Ok(0));
        assert_eq!(parse_dropped(&counter(2200)), Ok(2200));
        assert!(parse_dropped("not json").is_err());
        assert!(parse_dropped(r#"{"nftables": []}"#).is_err());
        assert!(
            parse_dropped(r#"{"nftables": [{"counter": {"name": "cut", "packets": 1}}]}"#).is_err()
        );
        assert!(
            parse_dropped(r#"{"nftables": [{"counter": {"name": "dropped", "packets": -1}}]}"#)
                .is_err()
        );
        let twice = counter(1).replace(
            "{\"metainfo\"",
            "{\"counter\": {\"name\": \"dropped\", \"packets\": 1}}, {\"metainfo\"",
        );
        assert!(parse_dropped(&twice).is_err());
    }

    #[test]
    fn each_destination_is_sent_once() {
        let mut live = LiveDrops::default();
        assert!(!live.moved(0));
        assert!(live.moved(3));
        let first = live
            .fresh(
                3,
                &table(
                    3,
                    &[("192.0.2.2", "udp", 9602, 2), ("192.0.2.3", "icmp", 0, 1)],
                    &[],
                ),
            )
            .unwrap_or_default();
        assert_eq!(
            keys(&first),
            [
                ("192.0.2.2".into(), "udp".into(), Some(9602), 2),
                ("192.0.2.3".into(), "icmp".into(), None, 1),
            ]
        );
        assert!(!live.moved(3));
        // More packets to the same destinations, and one new one; nft may
        // print a protocol by number.
        assert!(live.moved(9));
        let second = live
            .fresh(
                9,
                &table(
                    9,
                    &[("192.0.2.2", "17", 9602, 6), ("192.0.2.3", "1", 0, 2)],
                    &[("2001:db8::2", "tcp", 443, 1)],
                ),
            )
            .unwrap_or_default();
        assert_eq!(
            keys(&second),
            [("2001:db8::2".into(), "tcp".into(), Some(443), 1)]
        );
        // The counter moved, but nothing new is in the sets (a full set).
        assert!(live.moved(10));
        let third = live
            .fresh(
                10,
                &table(
                    10,
                    &[("192.0.2.2", "udp", 9602, 7), ("192.0.2.3", "icmp", 0, 2)],
                    &[("2001:db8::2", "tcp", 443, 1)],
                ),
            )
            .unwrap_or_default();
        assert_eq!(keys(&third), []);
        assert!(!live.moved(10));
    }

    #[test]
    fn a_listing_that_does_not_parse_is_tried_again() {
        let mut live = LiveDrops::default();
        assert!(live.fresh(4, "not json").is_err());
        assert!(live.moved(4), "the next reading must list the table again");
        let list = live
            .fresh(4, &table(4, &[("192.0.2.2", "tcp", 80, 4)], &[]))
            .unwrap_or_default();
        assert_eq!(list.len(), 1);
        assert!(!live.moved(4));
    }

    #[test]
    fn the_trip_is_found_once_and_only_with_the_tripwire() {
        let mut plain = LiveDrops::new(false);
        assert!(!plain.tripped(0));
        assert!(!plain.tripped(5));
        let mut live = LiveDrops::new(true);
        assert!(!live.tripped(0));
        assert!(!live.tripped(0));
        assert!(live.tripped(1));
        assert!(!live.tripped(1));
        assert!(!live.tripped(7));
    }

    #[test]
    fn reads_any_counter_by_name() {
        let table = r#"{"nftables": [{"counter": {"name": "dropped", "packets": 1}}, {"counter": {"name": "cut", "packets": 37}}]}"#;
        assert_eq!(parse_counter(table, "cut"), Ok(37));
        assert_eq!(parse_counter(table, "dropped"), Ok(1));
        assert!(parse_counter(table, "late").is_err());
        let twice = table.replace("\"dropped\"", "\"cut\"");
        assert!(parse_counter(&twice, "cut").is_err());
    }

    #[test]
    fn a_failure_is_reported_once() {
        let mut live = LiveDrops::default();
        assert!(live.first_failure());
        assert!(!live.first_failure());
        assert!(!live.first_failure());
    }
}
