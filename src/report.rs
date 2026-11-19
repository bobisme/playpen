//! The summary playpen prints on exit and writes with `--report`.

use std::fmt::Write as _;

use serde::Serialize;

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
    /// Something failed after the command started. Exit status 1.
    Error,
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
    /// The pass, with `--pass`.
    pub pass: Option<PassReport>,
    /// The exit status playpen itself returns.
    pub playpen_exit_status: i32,
    /// Drop counters, when they could be read.
    pub dropped: Option<DropSummary>,
    /// Why the drop counters could not be read.
    pub dropped_error: Option<String>,
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
                out.push_str("playpen:   (more destinations than playpen could record)\n");
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::DroppedDest;

    fn base() -> Report {
        Report {
            playpen_version: "0",
            outcome: Outcome::Ran,
            message: None,
            command: vec!["true".into()],
            allowed: vec![],
            hosts: vec![],
            until: None,
            network: "none",
            exit_code: Some(0),
            signal: None,
            stopped_by_until: false,
            stopped_by_pass: false,
            stop_reason: None,
            pass: None,
            playpen_exit_status: 0,
            dropped: Some(DropSummary::default()),
            dropped_error: None,
            socket_guard: "landlock",
            exposed: vec![],
            display: false,
            new_session: false,
        }
    }

    #[test]
    fn quiet_when_nothing_dropped() {
        let t = text_summary(&base());
        assert!(t.contains("exited with status 0"));
        assert!(t.contains("no packets"));
        assert!(!t.contains("WARNING"));
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
}
