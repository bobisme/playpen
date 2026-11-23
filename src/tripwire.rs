//! `--on-drop`: the first packet the firewall drops closes all egress.
//!
//! With the option, the refusal path of the ruleset adds the element
//! [`crate::ruleset::CUT_MARK`] to the [`crate::ruleset::CUT_SET`] before
//! the packet is counted in `dropped`, and drops the packet. From the next
//! packet on, the cut rule refuses everything but loopback, as when playpen
//! closes egress at the end of the approval. The kernel does this itself,
//! with no polling delay.
//!
//! So every packet counted in `dropped` has tripped the cut on its way, and
//! the cut has tripped exactly when that counter is above zero, whether or
//! not playpen also added the element itself. While the command runs, the
//! setup process reads the counter every [`crate::live_drops::INTERVAL`]
//! (`read_drops_live` in `sandbox`), and the first time it is above zero it
//! tells the supervisor, with the destinations in the drop sets. With
//! [`OnDrop::Stop`] the supervisor then stops the command as at the end
//! time.
//!
//! This module has the option, what it adds to the report, and its texts.

use serde::Serialize;

use crate::ruleset::{DropSummary, DroppedDest};

/// What playpen does at the first packet the firewall drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum OnDrop {
    /// Close all egress in the firewall; the command keeps running.
    Cut,
    /// Close all egress in the firewall, and stop the command as at the end
    /// time.
    Stop,
}

impl OnDrop {
    /// The value as given on the command line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cut => "cut",
            Self::Stop => "stop",
        }
    }
}

/// What `--on-drop` adds to the full report: the keys `on_drop`,
/// `egress_cut` and `stopped_by_drop`. The report has none of them without
/// the option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OnDropReport {
    /// The option's value.
    pub on_drop: OnDrop,
    /// The cut a dropped packet tripped; `None` (null) when none did, as far
    /// as playpen could read.
    pub egress_cut: Option<EgressCut>,
    /// True when playpen stopped the command because the cut tripped.
    pub stopped_by_drop: bool,
}

/// The cut a dropped packet tripped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EgressCut {
    /// The destinations of the packets dropped before the cut closed
    /// egress: the packet that tripped it, and any sent at the same moment
    /// on another CPU. The fields of the report's `dropped` destinations.
    pub tripped_by: Vec<DroppedDest>,
    /// Packets the cut refused on their way out after it tripped (its
    /// `cut` counter); `None` when the counters could not be read.
    pub refused: Option<u64>,
}

/// What `--on-drop` adds to the shareable report: `on_drop` and
/// `stopped_by_drop`, and not the destinations.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ShareableOnDrop {
    on_drop: OnDrop,
    stopped_by_drop: bool,
}

impl From<&OnDropReport> for ShareableOnDrop {
    fn from(r: &OnDropReport) -> Self {
        Self {
            on_drop: r.on_drop,
            stopped_by_drop: r.stopped_by_drop,
        }
    }
}

/// What playpen read about the cut during and after a run with
/// `--on-drop`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Observed<'a> {
    /// The drop counters read at teardown, when they could be read.
    pub drops: Option<&'a DropSummary>,
    /// The destinations a reading sent when it found the cut tripped, if
    /// a reading did.
    pub live: Option<&'a [DroppedDest]>,
    /// The `cut` counter read at teardown.
    pub cut_packets: Option<u64>,
    /// The `late` and `cut` counters together, read at teardown
    /// (`refused_after_end` without the option).
    pub refused_after_end: Option<u64>,
}

impl OnDropReport {
    /// The report for `on_drop` before anything ran: nothing tripped.
    #[must_use]
    pub const fn new(on_drop: OnDrop) -> Self {
        Self {
            on_drop,
            egress_cut: None,
            stopped_by_drop: false,
        }
    }

    /// The report of a run with `on_drop`, and the run's
    /// `refused_after_end`.
    ///
    /// The cut tripped when a reading said so or the `dropped` counter read
    /// at teardown is above zero. The destinations that tripped it are the
    /// ones in the drop sets at teardown: nothing is added to them after
    /// the cut. Once it tripped, every packet the cut rule refused came
    /// after the trip, so the `cut` counter goes to `egress_cut.refused`
    /// and `refused_after_end` keeps the time rule's packets. Without a
    /// trip `refused_after_end` is the sum, as without the option.
    #[must_use]
    pub fn observe(on_drop: OnDrop, stopped: bool, seen: Observed<'_>) -> (Self, Option<u64>) {
        let tripped = seen.live.is_some() || seen.drops.is_some_and(|d| d.packets > 0);
        let mut report = Self::new(on_drop);
        report.stopped_by_drop = stopped;
        if !tripped {
            return (report, seen.refused_after_end);
        }
        let tripped_by = match (seen.drops, seen.live) {
            (Some(d), _) if !d.destinations.is_empty() => d.destinations.clone(),
            (_, Some(live)) => live.to_vec(),
            _ => Vec::new(),
        };
        let after_end = seen
            .refused_after_end
            .zip(seen.cut_packets)
            .and_then(|(both, cut)| both.checked_sub(cut));
        report.egress_cut = Some(EgressCut {
            tripped_by,
            refused: seen.cut_packets,
        });
        (report, after_end)
    }
}

/// The status playpen exits with, from `code`.
///
/// With `--on-drop stop`, a run whose cut tripped never exits 0. A command
/// that exited 0 (it caught SIGTERM and exited in its grace, or ended
/// before playpen learned of the trip) makes it 1; any other status is
/// kept.
#[must_use]
pub fn exit_status(report: Option<&OnDropReport>, code: i32) -> i32 {
    match report {
        Some(r) if r.on_drop == OnDrop::Stop && r.egress_cut.is_some() && code == 0 => 1,
        _ => code,
    }
}

/// A dropped destination as playpen writes it in a line: `ADDR PROTO port
/// N`, without the port for protocols other than TCP and UDP.
#[must_use]
pub fn destination(dest: &DroppedDest) -> String {
    let port = dest.port.map_or_else(String::new, |p| format!(" port {p}"));
    format!("{} {}{port}", dest.address, dest.protocol)
}

/// The destinations that tripped the cut, as a line lists them: at most
/// [`crate::live_drops::SHOWN`], then how many more.
#[must_use]
pub fn destinations(list: &[DroppedDest]) -> String {
    let shown = crate::live_drops::SHOWN;
    let mut out: Vec<String> = list.iter().take(shown).map(destination).collect();
    if list.len() > shown {
        out.push(format!("and {} more", list.len() - shown));
    }
    out.join(", ")
}

/// Why the cut tripped, as the notice, the summary and `stop_reason` say
/// it.
#[must_use]
pub fn reason(tripped_by: &[DroppedDest], on_drop: OnDrop) -> String {
    let what = match tripped_by.len() {
        0 => "a packet to an unapproved destination was dropped".to_owned(),
        1 => format!(
            "a packet to an unapproved destination was dropped: {}",
            destinations(tripped_by)
        ),
        _ => format!(
            "packets to unapproved destinations were dropped: {}",
            destinations(tripped_by)
        ),
    };
    format!("{what} (--on-drop {})", on_drop.name())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(address: &str, port: Option<u16>, packets: u64) -> DroppedDest {
        DroppedDest {
            address: address.into(),
            protocol: if port.is_some() { "udp" } else { "icmp" }.into(),
            port,
            packets,
        }
    }

    #[test]
    fn nothing_tripped_leaves_refused_after_end_as_it_is() {
        let drops = DropSummary::default();
        let (r, after) = OnDropReport::observe(
            OnDrop::Cut,
            false,
            Observed {
                drops: Some(&drops),
                live: None,
                cut_packets: Some(4),
                refused_after_end: Some(9),
            },
        );
        assert_eq!(r, OnDropReport::new(OnDrop::Cut));
        assert_eq!(after, Some(9));
        let json = serde_json::to_value(&r).unwrap_or_default();
        assert_eq!(
            json,
            serde_json::json!({"on_drop": "cut", "egress_cut": null, "stopped_by_drop": false})
        );
        assert_eq!(exit_status(Some(&r), 0), 0);
    }

    #[test]
    fn a_trip_names_the_destinations_and_takes_the_cut_counter() {
        let drops = DropSummary {
            packets: 1,
            destinations: vec![dest("198.51.100.9", Some(9563), 1)],
            destinations_truncated: false,
        };
        let seen = Observed {
            drops: Some(&drops),
            live: None,
            cut_packets: Some(37),
            refused_after_end: Some(40),
        };
        let (r, after) = OnDropReport::observe(OnDrop::Stop, true, seen);
        assert_eq!(after, Some(3));
        let json = serde_json::to_value(&r).unwrap_or_default();
        assert_eq!(
            json,
            serde_json::json!({"on_drop": "stop", "stopped_by_drop": true, "egress_cut": {
                "tripped_by": [{"address": "198.51.100.9", "protocol": "udp", "port": 9563, "packets": 1}],
                "refused": 37}})
        );
        // The teardown readback failed: what the reading saw.
        let live = [dest("192.0.2.3", None, 1)];
        let (r, after) = OnDropReport::observe(
            OnDrop::Cut,
            false,
            Observed {
                live: Some(&live),
                ..Observed::default()
            },
        );
        assert_eq!(after, None);
        let cut = r.egress_cut.unwrap_or_else(|| panic!("tripped"));
        assert_eq!(cut.tripped_by, live);
        assert_eq!(cut.refused, None);
    }

    #[test]
    fn a_stop_by_drop_never_exits_zero() {
        let drops = DropSummary {
            packets: 2,
            destinations: vec![],
            destinations_truncated: true,
        };
        let seen = Observed {
            drops: Some(&drops),
            ..Observed::default()
        };
        let (stop, _) = OnDropReport::observe(OnDrop::Stop, true, seen);
        assert_eq!(
            stop.egress_cut.as_ref().map(|c| c.tripped_by.len()),
            Some(0)
        );
        assert_eq!(exit_status(Some(&stop), 0), 1);
        assert_eq!(exit_status(Some(&stop), 3), 3);
        assert_eq!(exit_status(Some(&stop), 128 + 15), 128 + 15);
        // The command ended before playpen learned of the trip.
        let (ended, _) = OnDropReport::observe(OnDrop::Stop, false, seen);
        assert_eq!(exit_status(Some(&ended), 0), 1);
        // With cut the command's own status stands.
        let (cut, _) = OnDropReport::observe(OnDrop::Cut, false, seen);
        assert_eq!(exit_status(Some(&cut), 0), 0);
        assert_eq!(exit_status(None, 0), 0);
    }

    #[test]
    fn reasons_name_the_destinations() {
        assert_eq!(
            reason(&[], OnDrop::Stop),
            "a packet to an unapproved destination was dropped (--on-drop stop)"
        );
        assert_eq!(
            reason(&[dest("198.51.100.9", Some(53), 1)], OnDrop::Cut),
            "a packet to an unapproved destination was dropped: 198.51.100.9 udp port 53 (--on-drop cut)"
        );
        let many: Vec<_> = (0..10)
            .map(|i| dest(&format!("192.0.2.{i}"), None, 1))
            .collect();
        let text = reason(&many, OnDrop::Stop);
        assert!(
            text.starts_with("packets to unapproved destinations were dropped: 192.0.2.0 icmp, "),
            "{text}"
        );
        assert!(
            text.ends_with("192.0.2.7 icmp, and 2 more (--on-drop stop)"),
            "{text}"
        );
    }
}
