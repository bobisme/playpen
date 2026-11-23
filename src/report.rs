//! The summary playpen prints on exit and writes with `--report`.

use std::fmt::Write as _;

use serde::Serialize;

use crate::dns_stub::{self, Lookups};
use crate::ruleset::DropSummary;

/// What happened, in one word. Stable field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The command ran; `exit_code` or `signal` says how it ended.
    Ran,
    /// playpen refused by policy (bad or empty approval, time past);
    /// nothing was run. Exit status 2.
    Refused,
    /// The sandbox could not be built; nothing was run. Exit status 1.
    NotStarted,
    /// Supervision failed, and execution may have occurred. Exit status 1.
    Error,
}

/// Evidence available to a caller deciding whether a retry is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupEvidence {
    /// Refused before release, or the child explicitly reported a pre-exec error.
    NotStarted,
    /// The close-on-exec handshake completed and a normal child exit was observed.
    ExecAndExit,
    /// The available observations cannot establish whether user code executed.
    Unknown,
}

/// Result of the optional counted-drop assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DropAssertion {
    Pass,
    Violated,
    Unknown,
}

/// The JSON report. Field names are stable.
#[derive(Debug, Clone, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is a stable, independent JSON field"
)]
pub struct Report {
    /// Version of playpen that wrote this.
    pub playpen_version: &'static str,
    /// What happened.
    pub outcome: Outcome,
    /// Startup evidence for retry decisions.
    pub startup_evidence: StartupEvidence,
    /// Human-readable explanation for anything but a clean run.
    pub message: Option<String>,
    /// The command line that was (or would have been) run.
    pub command: Vec<String>,
    /// Approved destinations, as canonical specs.
    pub allowed: Vec<String>,
    /// `--host` entries as `name=addr`.
    pub hosts: Vec<String>,
    /// When the approval ends (RFC 3339, UTC), if given.
    pub until: Option<String>,
    /// When the command was released (RFC 3339, UTC); null when nothing
    /// was run.
    pub started_at: Option<String>,
    /// When playpen learned that the command had ended (RFC 3339, UTC);
    /// null when nothing was run.
    pub ended_at: Option<String>,
    /// `"pasta"` or `"none"`.
    pub network: &'static str,
    /// The command's exit code when it exited normally.
    pub exit_code: Option<i32>,
    /// The signal that killed the command, if one did.
    pub signal: Option<i32>,
    /// True when playpen stopped the command because the approval ended.
    pub stopped_by_until: bool,
    /// True when playpen stopped the command after re-reading the pass
    /// (revoked, expired, unreadable, invalid, or a destination in use
    /// edited).
    pub stopped_by_pass: bool,
    /// Why playpen stopped the command, when it did.
    pub stop_reason: Option<String>,
    /// Enforcement coverage when the pass could be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_coverage: Option<crate::pass::Coverage>,
    /// The pass, with `--pass`.
    pub pass: Option<PassReport>,
    /// The packet capture, with `--capture`, read after pasta exited;
    /// null when nothing was run.
    pub capture: Option<crate::capture::CaptureReport>,
    /// The exit status playpen itself returns.
    pub playpen_exit_status: i32,
    /// Drop counters, when they could be read.
    pub dropped: Option<DropSummary>,
    /// Packets the command sent that the firewall refused because the
    /// approval had ended (the end time, or the cut when playpen stopped
    /// the command), when the counters could be read. Not part of
    /// `dropped`, and not judged by `--fail-on-drop`.
    pub refused_after_end: Option<u64>,
    /// Optional observations for explicit accept rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_use: Option<crate::grant_use::GrantUse>,
    /// With `--report-contacts`, the fields `contacted` and
    /// `contacted_error`; neither is in the report without it. Never in the
    /// shareable report.
    #[serde(flatten)]
    pub contacts: Option<crate::contacts::ContactFields>,
    /// Result of --fail-on-drop, absent when not requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drop_assertion: Option<DropAssertion>,
    /// Why the drop counters could not be read.
    pub dropped_error: Option<String>,
    /// The names the command looked up through the DNS stub, when they
    /// could be read. Never in the shareable report.
    pub lookups: Option<Lookups>,
    /// Why the looked-up names could not be read.
    pub lookups_error: Option<String>,
    /// How host Unix sockets are kept from the command: `"landlock"`
    /// (refused wherever they are, plus the mount layer) or `"mounts_only"`
    /// (`--without-landlock`: hidden under `/run`, `/tmp`, `/var/tmp` and
    /// the runtime directory only).
    pub socket_guard: &'static str,
    /// Host paths the command was let reach (`--expose` and `--display`),
    /// canonical once checked; as typed when refused.
    pub exposed: Vec<String>,
    /// True with `--display`.
    pub display: bool,
    /// True when the command ran in its own session without a controlling
    /// terminal (`--new-session`, or a kernel that allows `TIOCSTI`).
    pub new_session: bool,
    /// True when a private controlling terminal was requested.
    pub private_tty: bool,
    /// True with `--live-drops`: new dropped destinations were printed on
    /// stderr while the command ran. `dropped` is read at the end either
    /// way.
    pub live_drops: bool,
}

/// Explicit allowlist for reports intended to be shared.
///
/// It leaves out `started_at` and `ended_at` (exact times let a reader
/// match the report to a destination's own logs, and so recover the
/// destinations it leaves out) and `capture` (the capture holds payloads).
/// See docs/spec.md, "Shareable reports".
#[derive(Serialize)]
pub struct ShareableReport {
    // An empty, fixed-size array cannot carry private diagnostic strings.
    advice: [(); 0],
    schema: &'static str,
    outcome: Outcome,
    exit_code: Option<i32>,
    signal: Option<i32>,
    playpen_exit_status: i32,
    network: &'static str,
    socket_guard: &'static str,
    stopped_by_until: bool,
    stopped_by_pass: bool,
    dropped_packets: Option<u64>,
    destinations_truncated: Option<bool>,
    drop_assertion: Option<DropAssertion>,
}

impl From<&Report> for ShareableReport {
    fn from(r: &Report) -> Self {
        Self {
            advice: [],
            schema: "playpen-shareable-v1",
            outcome: r.outcome,
            exit_code: r.exit_code,
            signal: r.signal,
            playpen_exit_status: r.playpen_exit_status,
            network: match r.network {
                "pasta" => "pasta",
                _ => "none",
            },
            socket_guard: match r.socket_guard {
                "landlock" => "landlock",
                _ => "mounts_only",
            },
            stopped_by_until: r.stopped_by_until,
            stopped_by_pass: r.stopped_by_pass,
            dropped_packets: r.dropped.as_ref().map(|d| d.packets),
            destinations_truncated: r.dropped.as_ref().map(|d| d.destinations_truncated),
            drop_assertion: r.drop_assertion,
        }
    }
}

/// The pass a run was held to. Everything but `file` is null when the pass
/// could not be loaded.
#[derive(Debug, Clone, Serialize)]
pub struct PassReport {
    /// The pass file as given.
    pub file: String,
    /// The pass id.
    pub id: Option<String>,
    /// The pass name.
    pub name: Option<String>,
    /// `approval.owner`.
    pub owner: Option<String>,
    /// `sha256:` digest of the file as loaded at start.
    pub digest: Option<String>,
    /// `approval.valid_until`, RFC 3339 UTC.
    pub valid_until: Option<String>,
    /// Labels of the destinations in use.
    pub labels: Vec<String>,
}

/// A moment as the report writes it: RFC 3339 in UTC, like `until`.
#[must_use]
pub fn stamp(at: time::OffsetDateTime) -> String {
    at.to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| at.unix_timestamp().to_string())
}

/// The closing text summary for stderr.
#[must_use]
pub fn text_summary(r: &Report) -> String {
    let mut out = String::new();
    if r.stopped_by_until {
        let _ = writeln!(
            out,
            "playpen: stopped the command because the approval ended at {}",
            r.until.as_deref().unwrap_or("?")
        );
    }
    if r.stopped_by_pass {
        let _ = writeln!(
            out,
            "playpen: stopped the command because {}",
            r.stop_reason
                .as_deref()
                .unwrap_or("the pass no longer permits it")
        );
    }
    match (r.exit_code, r.signal) {
        (Some(c), _) => {
            let _ = writeln!(out, "playpen: command exited with status {c}");
        }
        (None, Some(s)) => {
            let _ = writeln!(out, "playpen: command was killed by signal {s}");
        }
        (None, None) => {}
    }
    match (&r.dropped, &r.dropped_error) {
        (Some(d), _) if d.packets == 0 && d.destinations_truncated => {
            out.push_str("playpen: the drop counter reads zero, but the destination breakdown is incomplete or inconsistent\n");
        }
        (Some(d), _) if d.packets == 0 => {
            out.push_str("playpen: no packets to unapproved destinations were dropped\n");
        }
        (Some(d), _) => {
            let _ = writeln!(
                out,
                "playpen: ************************************************************"
            );
            let _ = writeln!(
                out,
                "playpen: WARNING: {} packet(s) to UNAPPROVED destinations were dropped.",
                d.packets
            );
            out.push_str("playpen: The command tried to reach places nobody approved:\n");
            for dest in &d.destinations {
                let port = dest.port.map_or_else(String::new, |p| format!(" port {p}"));
                let _ = writeln!(
                    out,
                    "playpen:   {} {}{port}: {} packet(s)",
                    dest.address, dest.protocol, dest.packets
                );
            }
            if d.destinations_truncated {
                out.push_str("playpen:   (destination breakdown is incomplete or inconsistent)\n");
            }
            let _ = writeln!(
                out,
                "playpen: ************************************************************"
            );
        }
        (None, Some(e)) => {
            let _ = writeln!(out, "playpen: could not read the drop counters: {e}");
        }
        (None, None) => {}
    }
    if let Some(n) = r.refused_after_end
        && (n > 0 || r.stopped_by_until || r.stopped_by_pass)
    {
        let _ = writeln!(
            out,
            "playpen: {n} packet(s) refused after the approval ended"
        );
    }
    if let Some(c) = &r.capture {
        let _ = writeln!(
            out,
            "playpen: packet capture {}: {} bytes, sha256 {}",
            c.file, c.bytes, c.sha256
        );
    }
    contacts_summary(&mut out, r);
    lookups_summary(&mut out, r);
    out
}

/// The line about the contacted destinations, with `--report-contacts`.
fn contacts_summary(out: &mut String, r: &Report) {
    let Some(fields) = &r.contacts else {
        return;
    };
    match (&fields.contacted, &fields.contacted_error) {
        (Some(c), _) => {
            let _ = writeln!(
                out,
                "playpen: the command contacted {} approved destination(s); the report lists them in contacted",
                c.destinations.len()
            );
            if c.truncated {
                out.push_str("playpen:   (the list is incomplete or inconsistent)\n");
            }
        }
        (None, Some(e)) => {
            let _ = writeln!(
                out,
                "playpen: could not read the contacted destinations: {e}"
            );
        }
        (None, None) => {}
    }
}

/// The text block for names looked up without a `--host` mapping.
fn lookups_summary(out: &mut String, r: &Report) {
    match (&r.lookups, &r.lookups_error) {
        (Some(l), _) => {
            let unmapped: Vec<_> = l.unmapped().collect();
            if !unmapped.is_empty() {
                out.push_str("playpen: The command looked up names that have no --host mapping:\n");
                for n in unmapped {
                    // Shown names are escaped already; anything else is
                    // not printed.
                    let name = if dns_stub::is_shown(&n.name) {
                        n.name.as_str()
                    } else {
                        "(a name playpen cannot show)"
                    };
                    let _ = writeln!(out, "playpen:   {name}: {} lookup(s)", n.count);
                }
                if l.truncated {
                    let _ = writeln!(
                        out,
                        "playpen:   (the list is incomplete: playpen keeps {} names)",
                        dns_stub::LIMIT
                    );
                }
                out.push_str("playpen: Each was answered \"no such name\". If the command needs one, map it with --host NAME=ADDR (ADDR must be approved).\n");
            } else if l.truncated {
                let _ = writeln!(
                    out,
                    "playpen: the command looked up more than {} names; the report lists the first {}",
                    dns_stub::LIMIT,
                    dns_stub::LIMIT
                );
            }
        }
        (None, Some(e)) => {
            let _ = writeln!(
                out,
                "playpen: could not read the names the command looked up: {e}"
            );
        }
        (None, None) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_stub::LookedUp;
    use crate::ruleset::DroppedDest;

    fn base() -> Report {
        Report {
            playpen_version: "0",
            outcome: Outcome::Ran,
            startup_evidence: StartupEvidence::ExecAndExit,
            message: None,
            command: vec!["true".into()],
            allowed: vec![],
            hosts: vec![],
            until: None,
            started_at: None,
            ended_at: None,
            network: "none",
            exit_code: Some(0),
            signal: None,
            stopped_by_until: false,
            stopped_by_pass: false,
            stop_reason: None,
            enforcement_coverage: None,
            pass: None,
            capture: None,
            playpen_exit_status: 0,
            dropped: Some(DropSummary::default()),
            refused_after_end: Some(0),
            grant_use: None,
            contacts: None,
            drop_assertion: None,
            dropped_error: None,
            lookups: Some(Lookups::default()),
            lookups_error: None,
            socket_guard: "landlock",
            exposed: vec![],
            display: false,
            new_session: false,
            private_tty: false,
            live_drops: false,
        }
    }

    #[test]
    fn shareable_is_an_explicit_allowlist() {
        let mut r = base();
        r.command = vec!["private-command".into()];
        r.hosts = vec!["private-host".into()];
        r.message = Some("private-message".into());
        r.exposed = vec!["private-path".into()];
        r.allowed = vec!["private-destination".into()];
        r.lookups = Some(Lookups {
            names: vec![LookedUp {
                name: "private-lookup".into(),
                count: 1,
                mapped: false,
            }],
            truncated: true,
        });
        r.lookups_error = Some("private-lookup-error".into());
        r.pass = Some(PassReport {
            file: "private-pass".into(),
            id: None,
            name: None,
            owner: Some("private-owner".into()),
            digest: None,
            valid_until: None,
            labels: vec!["private-label".into()],
        });
        r.contacts = Some(crate::contacts::ContactFields {
            contacted: Some(crate::contacts::Contacted {
                destinations: vec![crate::contacts::ContactedDest {
                    address: "private-contact".into(),
                    protocol: "tcp".into(),
                    port: 4242,
                    packets: 1,
                }],
                truncated: false,
            }),
            contacted_error: Some("private-contact-error".into()),
        });
        r.started_at = Some("2026-11-22T10:00:00.123456789Z".into());
        r.ended_at = Some("2026-11-22T10:00:02.5Z".into());
        r.capture = Some(crate::capture::CaptureReport {
            file: "/private-capture.pcap".into(),
            bytes: 4096,
            sha256: "private-digest".into(),
        });
        for outcome in [Outcome::Ran, Outcome::Refused, Outcome::Error] {
            r.outcome = outcome;
            let value = serde_json::to_value(ShareableReport::from(&r)).unwrap_or_default();
            let serialized = value.to_string();
            assert!(!serialized.contains("private-"), "{serialized}");
            assert!(!serialized.contains("2026-11-22"), "{serialized}");
            assert!(!serialized.contains("4096"), "{serialized}");
            assert!(!serialized.contains("4242"), "{serialized}");
            let keys: std::collections::BTreeSet<_> = value
                .as_object()
                .unwrap_or_else(|| panic!("not object"))
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                keys,
                [
                    "advice",
                    "schema",
                    "outcome",
                    "exit_code",
                    "signal",
                    "playpen_exit_status",
                    "network",
                    "socket_guard",
                    "stopped_by_until",
                    "stopped_by_pass",
                    "dropped_packets",
                    "destinations_truncated",
                    "drop_assertion"
                ]
                .into_iter()
                .collect()
            );
            assert_eq!(value["dropped_packets"], 0);
            r.dropped = None;
            assert!(serde_json::to_value(ShareableReport::from(&r)).unwrap_or_default()["dropped_packets"].is_null());
            r.dropped = Some(DropSummary::default());
        }
    }

    #[test]
    fn assertion_uses_total_and_preserves_child_status() {
        let mut r = base();
        assert_eq!(crate::cli::apply_drop_assertion(&mut r, 0, true), 0);
        r.dropped = None;
        assert_eq!(crate::cli::apply_drop_assertion(&mut r, 0, true), 1);
        assert_eq!(r.drop_assertion, Some(DropAssertion::Unknown));
        r.dropped = Some(DropSummary {
            packets: 1,
            destinations: vec![],
            destinations_truncated: true,
        });
        assert_eq!(crate::cli::apply_drop_assertion(&mut r, 0, true), 1);
        assert_eq!(r.drop_assertion, Some(DropAssertion::Violated));
        assert_eq!(r.exit_code, Some(0));
        assert_eq!(crate::cli::apply_drop_assertion(&mut r, 2, true), 2);
        assert_eq!(crate::cli::apply_drop_assertion(&mut r, 0, false), 0);
    }

    #[test]
    fn contradictory_counter_reaches_json_as_incomplete() {
        let mut report = base();
        report.dropped = Some(crate::ruleset::parse_counters(r#"{"nftables":[{"counter":{"name":"dropped","packets":2}},{"set":{"name":"drop4","elem":[{"elem":{"val":{"concat":["192.0.2.1","tcp",80]},"counter":{"packets":3}}}]}},{"set":{"name":"drop6"}}]}"#).unwrap_or_else(|e| panic!("{e}")));
        let json = serde_json::to_value(report).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(json["dropped"]["packets"], 2);
        assert_eq!(json["dropped"]["destinations_truncated"], true);
    }

    #[test]
    fn contradictory_zero_cannot_pass_ci() {
        let mut r = base();
        r.dropped = Some(DropSummary {
            packets: 0,
            destinations_truncated: true,
            destinations: vec![DroppedDest {
                address: "192.0.2.1".into(),
                protocol: "tcp".into(),
                port: Some(80),
                packets: 1,
            }],
        });
        assert_eq!(crate::cli::apply_drop_assertion(&mut r, 0, true), 1);
        assert_eq!(r.drop_assertion, Some(DropAssertion::Unknown));
        assert!(!text_summary(&r).contains("no packets"));
    }

    #[test]
    fn packets_refused_after_the_end_have_their_own_line_and_do_not_fail_drop_checks() {
        let mut r = base();
        assert!(!text_summary(&r).contains("refused after"));
        r.stopped_by_until = true;
        assert!(
            text_summary(&r).contains("playpen: 0 packet(s) refused after the approval ended\n")
        );
        r.stopped_by_until = false;
        r.refused_after_end = Some(4);
        let t = text_summary(&r);
        assert!(t.contains("playpen: 4 packet(s) refused after the approval ended\n"));
        assert!(t.contains("no packets to unapproved destinations were dropped"));
        assert!(!t.contains("WARNING"));
        assert_eq!(crate::cli::apply_drop_assertion(&mut r, 0, true), 0);
        assert_eq!(r.drop_assertion, Some(DropAssertion::Pass));
        let json = serde_json::to_value(&r).unwrap_or_default();
        assert_eq!(json["refused_after_end"], 4);
        assert_eq!(json["dropped"]["packets"], 0);
        r.refused_after_end = None;
        assert!(!text_summary(&r).contains("refused after"));
        assert!(serde_json::to_value(&r).unwrap_or_default()["refused_after_end"].is_null());
    }

    #[test]
    fn contacted_fields_only_with_the_option() {
        use crate::contacts::{ContactFields, Contacted, ContactedDest};
        let mut r = base();
        let json = serde_json::to_value(&r).unwrap_or_default();
        assert!(json.get("contacted").is_none() && json.get("contacted_error").is_none());
        assert!(!text_summary(&r).contains("contacted"));
        // Asked for, and nothing ran: both null.
        r.contacts = Some(ContactFields::default());
        let json = serde_json::to_value(&r).unwrap_or_default();
        assert!(json["contacted"].is_null() && json.get("contacted").is_some());
        assert!(json["contacted_error"].is_null() && json.get("contacted_error").is_some());
        r.contacts = Some(ContactFields {
            contacted: Some(Contacted {
                destinations: vec![ContactedDest {
                    address: "192.0.2.7".into(),
                    protocol: "udp".into(),
                    port: 53,
                    packets: 2,
                }],
                truncated: true,
            }),
            contacted_error: None,
        });
        let json = serde_json::to_value(&r).unwrap_or_default();
        assert_eq!(
            json["contacted"],
            serde_json::json!({"destinations":[{"address":"192.0.2.7","protocol":"udp","port":53,"packets":2}],"truncated":true})
        );
        let t = text_summary(&r);
        assert!(
            t.contains("playpen: the command contacted 1 approved destination(s); the report lists them in contacted\n"),
            "{t}"
        );
        assert!(
            t.contains("(the list is incomplete or inconsistent)"),
            "{t}"
        );
        r.contacts = Some(ContactFields {
            contacted: None,
            contacted_error: Some("nft could not list the table".into()),
        });
        assert!(
            text_summary(&r).contains(
                "could not read the contacted destinations: nft could not list the table"
            )
        );
        assert_eq!(
            serde_json::to_value(&r).unwrap_or_default()["contacted_error"],
            "nft could not list the table"
        );
    }

    #[test]
    fn quiet_when_nothing_dropped() {
        let t = text_summary(&base());
        assert!(t.contains("exited with status 0"));
        assert!(t.contains("no packets"));
        assert!(!t.contains("WARNING"));
        assert!(!t.contains("capture"));
    }

    #[test]
    fn times_and_capture_in_the_full_report() {
        let mut r = base();
        let at = time::macros::datetime!(2026-11-22 11:00:00.25 +01:00);
        r.started_at = Some(stamp(at));
        assert_eq!(r.started_at.as_deref(), Some("2026-11-22T10:00:00.25Z"));
        r.capture = Some(crate::capture::CaptureReport {
            file: "/w/run.pcap".into(),
            bytes: 24,
            sha256: "ab".into(),
        });
        let json = serde_json::to_value(&r).unwrap_or_default();
        assert_eq!(json["started_at"], "2026-11-22T10:00:00.25Z");
        assert!(json["ended_at"].is_null());
        assert_eq!(
            json["capture"],
            serde_json::json!({"file": "/w/run.pcap", "bytes": 24, "sha256": "ab"})
        );
        assert!(
            text_summary(&r).contains("playpen: packet capture /w/run.pcap: 24 bytes, sha256 ab\n")
        );
    }

    #[test]
    fn loud_when_something_dropped() {
        let mut r = base();
        r.dropped = Some(DropSummary {
            packets: 3,
            destinations: vec![DroppedDest {
                address: "192.0.2.9".into(),
                protocol: "tcp".into(),
                port: Some(80),
                packets: 3,
            }],
            destinations_truncated: false,
        });
        let t = text_summary(&r);
        assert!(t.contains("WARNING: 3 packet(s)"));
        assert!(t.contains("192.0.2.9 tcp port 80: 3 packet(s)"));
        let json = serde_json::to_value(&r).unwrap_or_default();
        assert_eq!(json["outcome"], "ran");
        assert_eq!(json["dropped"]["destinations"][0]["port"], 80);
    }

    #[test]
    fn unmapped_lookups_are_listed_with_the_advice_and_mapped_ones_are_not() {
        let mut r = base();
        assert!(!text_summary(&r).contains("looked up"));
        let entry = |name: &str, count, mapped| LookedUp {
            name: name.into(),
            count,
            mapped,
        };
        r.lookups = Some(Lookups {
            names: vec![
                entry("svc.example.test", 4, true),
                entry("unmapped.example", 2, false),
                // An escape sequence, as the stub writes it, and one that
                // reached the report raw (it cannot from the stub).
                entry("\\027\\0930\\059x\\007.test", 1, false),
                entry("\x1b[2J", 1, false),
            ],
            truncated: true,
        });
        let t = text_summary(&r);
        assert!(
            t.contains("playpen: The command looked up names that have no --host mapping:\n"),
            "{t}"
        );
        assert!(
            t.contains("playpen:   unmapped.example: 2 lookup(s)\n"),
            "{t}"
        );
        assert!(
            t.contains("playpen:   \\027\\0930\\059x\\007.test: 1 lookup(s)\n"),
            "{t}"
        );
        assert!(t.contains("(a name playpen cannot show)"), "{t}");
        assert!(!t.contains('\x1b'), "{t}");
        assert!(!t.contains("svc.example.test"), "{t}");
        assert!(t.contains("playpen keeps 256 names"), "{t}");
        assert!(t.contains("map it with --host NAME=ADDR"), "{t}");
        let json = serde_json::to_value(&r).unwrap_or_default();
        assert_eq!(json["lookups"]["names"][1]["name"], "unmapped.example");
        assert_eq!(json["lookups"]["names"][1]["count"], 2);
        assert_eq!(json["lookups"]["names"][0]["mapped"], true);
        assert_eq!(json["lookups"]["truncated"], true);
        r.lookups = None;
        r.lookups_error = Some("the DNS stub ended before the end of the run".into());
        assert!(text_summary(&r).contains(
            "could not read the names the command looked up: the DNS stub ended before the end of the run"
        ));
    }
}
