//! Reading the approval from a hallpass pass (`--pass FILE`).
//!
//! A pass is the written permission slip that hallpass reads: owner,
//! literal destinations with protocol and ports, an approval window with a
//! revocation marker, and ceilings. This module turns it into the same
//! [`Approval`] that `--allow` and `--until` produce, so the namespace code
//! does not know where the rules came from, plus a [`PassWatch`] that the
//! supervisor uses to re-read the file while the command runs.
//!
//! The pass is loaded with hallpass's own loader ([`hallpass::load`]): no
//! symbolic links, no file writable by group or others, full validation.
//! Ceilings are not used: playpen limits where packets go, not how many, so
//! it never spends from the ledger.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hallpass::{Destination, Digest, Pass};
use time::OffsetDateTime;

use crate::approval::{AllowRule, Approval, EndsAt, Net, Ports, Proto, ipv4_edges};

/// How often the supervisor re-reads the pass while the command runs.
pub const RECHECK_INTERVAL: Duration = Duration::from_secs(2);

/// The shortest re-read interval the hidden test override accepts.
pub const MIN_RECHECK_INTERVAL: Duration = Duration::from_millis(50);

/// Who approved the run, as named in the start line and the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassIdentity {
    /// The pass file as given.
    pub file: PathBuf,
    /// The pass id.
    pub id: String,
    /// The pass name.
    pub name: String,
    /// `approval.owner`.
    pub owner: String,
    /// The digest of the file's bytes at start.
    pub digest: Digest,
    /// `approval.valid_until`.
    pub valid_until: OffsetDateTime,
    /// The labels of the destinations in use, in file order.
    pub labels: Vec<String>,
}

/// A destination in use that names a host name. The name grants nothing
/// and is never resolved; the operator can map it with `--host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedDestination {
    /// The destination's label.
    pub label: String,
    /// The informational `hostname`.
    pub hostname: String,
    /// The destination's address or network, as text.
    pub destination: String,
    /// Whether the destination is a single address.
    pub single: bool,
}

/// Everything `--pass` contributes to a run.
#[derive(Debug, Clone)]
pub struct FromPass {
    /// The allow rules of the destinations in use; `ends_at` is the pass's
    /// `valid_until`.
    pub approval: Approval,
    /// Who approved it.
    pub identity: PassIdentity,
    /// Destinations in use that carry a `hostname`.
    pub named: Vec<NamedDestination>,
    /// Destinations in use that the pass approves only for listed host
    /// names, as `label (name, name)`. playpen filters addresses and
    /// ports and cannot enforce this.
    pub name_limited: Vec<String>,
    /// The handle the supervisor re-reads the pass with.
    pub watch: PassWatch,
}

/// Loads the pass at `path` and checks it at `now`.
///
/// `only` narrows the destinations to these labels (empty: all of them).
///
/// # Errors
/// A message, without the "nothing was run" suffix, when the pass cannot be
/// read, is invalid, is not valid at `now` (not yet valid, expired,
/// revoked), names an unknown label in `only`, or holds a destination
/// playpen cannot enforce.
pub fn load(path: &Path, only: &[String], now: OffsetDateTime) -> Result<FromPass, String> {
    let loaded = hallpass::load(path).map_err(|e| load_error(path, &e))?;
    from_pass(path, &loaded.pass, loaded.digest, only, now)
}

fn from_pass(
    path: &Path,
    pass: &Pass,
    digest: Digest,
    only: &[String],
    now: OffsetDateTime,
) -> Result<FromPass, String> {
    pass.check_window(now, time::Duration::ZERO)
        .map_err(|r| format!("--pass {}: {}: {r}", path.display(), r.code.as_str()))?;
    let selected = select(pass, only)?;
    let edge_addresses = pass_edges(pass);
    let mut rules = Vec::new();
    let mut in_use = Vec::new();
    let mut named = Vec::new();
    let mut name_limited = Vec::new();
    for d in &selected {
        if !d.names.is_empty() {
            let hosts: Vec<&str> = d.names.iter().map(hallpass::HostName::as_str).collect();
            name_limited.push(format!("{} ({})", d.label, hosts.join(", ")));
        }
        let converted = rules_for(d).map_err(|e| {
            format!(
                "--pass {}: destination `{}` ({}): {e}; playpen cannot enforce it. Leave it out with --only, naming the other labels",
                path.display(),
                d.label,
                d.network
            )
        })?;
        rules.extend(converted.iter().copied());
        in_use.push((d.label.clone(), converted));
        if let Some(h) = &d.hostname {
            named.push(NamedDestination {
                label: d.label.clone(),
                hostname: h.clone(),
                destination: d.network.to_string(),
                single: d.network.is_host(),
            });
        }
    }
    let identity = PassIdentity {
        file: path.to_path_buf(),
        id: pass.id.clone(),
        name: pass.name.clone(),
        owner: pass.approval.owner.clone(),
        digest,
        valid_until: pass.approval.valid_until,
        labels: selected.iter().map(|d| d.label.clone()).collect(),
    };
    let watch = PassWatch {
        path: path.to_path_buf(),
        id: pass.id.clone(),
        owner: pass.approval.owner.clone(),
        digest,
        in_use,
        edge_addresses: edge_addresses.clone(),
        interval: RECHECK_INTERVAL,
    };
    Ok(FromPass {
        approval: Approval::with_edge_scope(
            rules,
            Some(EndsAt::from_time(pass.approval.valid_until)),
            edge_addresses,
        ),
        identity,
        named,
        name_limited,
        watch,
    })
}

/// The hallpass error in words; for an invalid pass, every problem.
fn load_error(path: &Path, e: &hallpass::Error) -> String {
    let mut msg = format!("--pass {}: {}: {e}", path.display(), e.code());
    if let hallpass::Error::Invalid { problems, .. } = e {
        for p in problems {
            let _ = write!(msg, "; {}: {}", p.field, p.message);
        }
    }
    msg
}

/// The destinations named by `only`, in file order (all when empty).
fn select<'p>(pass: &'p Pass, only: &[String]) -> Result<Vec<&'p Destination>, String> {
    for label in only {
        if !pass.destinations.iter().any(|d| &d.label == label) {
            let known: Vec<&str> = pass.destinations.iter().map(|d| d.label.as_str()).collect();
            return Err(format!(
                "--only {label:?}: the pass has no destination with this label; its labels are {}",
                known.join(", ")
            ));
        }
    }
    Ok(pass
        .destinations
        .iter()
        .filter(|d| only.is_empty() || only.contains(&d.label))
        .collect())
}

fn pass_edges(pass: &Pass) -> BTreeSet<Ipv4Addr> {
    pass.destinations
        .iter()
        .filter_map(|d| ipv4_edges(d.network.addr(), d.network.prefix()))
        .flatten()
        .collect()
}

/// One allow rule per port range of the destination.
///
/// # Errors
/// When playpen cannot approve the address (it refuses loopback, which
/// hallpass accepts when listed: loopback inside the sandbox is always
/// allowed and the host's cannot be reached).
pub fn rules_for(d: &Destination) -> Result<Vec<AllowRule>, crate::approval::SpecError> {
    let net = Net::new(d.network.addr(), d.network.prefix())?;
    let proto = match d.protocol {
        hallpass::Protocol::Tcp => Proto::Tcp,
        hallpass::Protocol::Udp => Proto::Udp,
    };
    d.ports
        .ranges()
        .iter()
        .map(|&(first, last)| Ports::new(first, last).map(|ports| AllowRule { net, ports, proto }))
        .collect()
}

/// What a re-read of the pass found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recheck {
    /// Same bytes, still valid.
    Unchanged,
    /// The file was edited, but nothing in use changed and it is still
    /// valid. The run continues under the rules loaded at start; the message
    /// says so. Reported once per new digest.
    Edited(String),
    /// The command must be stopped; the message says why.
    Stop(String),
}

/// The supervisor's handle on the pass file: re-reads it and decides
/// whether the run may continue.
///
/// The rules in the kernel are fixed at start. A re-read can only stop the
/// run, never widen it.
#[derive(Debug, Clone)]
pub struct PassWatch {
    path: PathBuf,
    id: String,
    owner: String,
    digest: Digest,
    in_use: Vec<(String, Vec<AllowRule>)>,
    edge_addresses: BTreeSet<Ipv4Addr>,
    /// How often to re-read.
    pub interval: Duration,
}

impl PassWatch {
    /// Re-reads the file and judges it at `now`.
    pub fn recheck(&mut self, now: OffsetDateTime) -> Recheck {
        match hallpass::load(&self.path) {
            Ok(loaded) => self.judge(&loaded.pass, loaded.digest, now),
            Err(e) => Recheck::Stop(format!(
                "the pass can no longer be read ({}: {e})",
                e.code()
            )),
        }
    }

    /// Judges a pass read again with digest `digest` at `now`.
    pub fn judge(&mut self, pass: &Pass, digest: Digest, now: OffsetDateTime) -> Recheck {
        if let Err(r) = pass.check_window(now, time::Duration::ZERO) {
            return Recheck::Stop(format!(
                "the pass no longer permits anything ({}): {r}",
                r.code.as_str()
            ));
        }
        if digest == self.digest {
            return Recheck::Unchanged;
        }
        if pass.id != self.id {
            return Recheck::Stop(format!(
                "the pass was edited: its id changed from `{}` to `{}`, so it is no longer the approval this run started under",
                self.id, pass.id
            ));
        }
        if pass.approval.owner != self.owner {
            return Recheck::Stop(format!(
                "the pass was edited: its owner changed from `{}` to `{}`, so it is no longer the approval this run started under",
                self.owner, pass.approval.owner
            ));
        }
        for (label, rules) in &self.in_use {
            let Some(d) = pass.destinations.iter().find(|d| &d.label == label) else {
                return Recheck::Stop(format!(
                    "the pass was edited and destination `{label}`, which this run uses, was removed"
                ));
            };
            if rules_for(d).ok().as_ref() != Some(rules) {
                return Recheck::Stop(format!(
                    "the pass was edited and destination `{label}`, which this run uses, changed"
                ));
            }
        }
        if let Some(edge) = pass_edges(pass)
            .difference(&self.edge_addresses)
            .find(|&&edge| {
                self.in_use
                    .iter()
                    .flat_map(|(_, rules)| rules)
                    .any(|rule| !rule.net.is_single() && rule.net.contains(edge.into()))
            })
        {
            return Recheck::Stop(format!(
                "the pass was edited and {edge} is now a network or broadcast address within a destination this run uses"
            ));
        }
        self.digest = digest;
        Recheck::Edited(format!(
            "the pass was edited (now {digest}); nothing this run uses changed, so the command continues under the rules loaded at start. Anything the edit adds (destinations, a later valid_until) does not apply to this run; start a new run to use it"
        ))
    }
}

/// Text form of the pass in the start line: id, name, owner, digest,
/// window end and labels. Ceilings are not mentioned: playpen does not
/// count anything against them.
#[must_use]
pub fn describe(identity: &PassIdentity) -> String {
    format!(
        "pass {} ({:?}, owner {:?}, {}, window ends {}, destinations {})",
        identity.id,
        identity.name,
        identity.owner,
        identity.digest,
        hallpass::stamp(identity.valid_until),
        identity.labels.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const PASS: &str = r#"
format = 1
id = "example-1"
name = "Example"

[approval]
owner = "Pat Owner"
reference = "email"
operator = "Sam Tester"
valid_from = 2026-01-01T00:00:00Z
valid_until = 2026-01-02T00:00:00Z
revoked = false

[[destination]]
label = "web"
address = "192.0.2.10"
protocol = "tcp"
ports = [443, "8000-8001"]
hostname = "app.example.test"

[[destination]]
label = "v6"
network = "2001:db8::/120"
protocol = "udp"
ports = 5060

[ceilings]
calls = 6
"#;

    const NOW: OffsetDateTime = datetime!(2026-01-01 12:00:00 UTC);

    fn parse(text: &str) -> Pass {
        Pass::parse(text).unwrap_or_else(|p| panic!("{p:?}"))
    }

    fn watch_for(text: &str, labels: &[&str]) -> PassWatch {
        let pass = parse(text);
        let in_use = pass
            .destinations
            .iter()
            .filter(|d| labels.contains(&d.label.as_str()))
            .map(|d| (d.label.clone(), rules_for(d).unwrap_or_default()))
            .collect();
        let edge_addresses = pass_edges(&pass);
        PassWatch {
            path: PathBuf::from("unused"),
            id: pass.id,
            owner: pass.approval.owner,
            digest: Digest::of(text.as_bytes()),
            in_use,
            edge_addresses,
            interval: RECHECK_INTERVAL,
        }
    }

    fn judge(w: &mut PassWatch, text: &str, now: OffsetDateTime) -> Recheck {
        w.judge(&parse(text), Digest::of(text.as_bytes()), now)
    }

    #[test]
    fn destinations_become_one_rule_per_port_range() {
        let pass = parse(PASS);
        let web = rules_for(&pass.destinations[0]).unwrap_or_default();
        let text: Vec<String> = web.iter().map(ToString::to_string).collect();
        assert_eq!(text, ["192.0.2.10:443/tcp", "192.0.2.10:8000-8001/tcp"]);
        let v6 = rules_for(&pass.destinations[1]).unwrap_or_default();
        assert_eq!(v6[0].to_string(), "[2001:db8::/120]:5060/udp");
    }

    #[test]
    fn loopback_in_a_pass_is_refused_by_playpen() {
        let text = PASS.replace("192.0.2.10", "127.0.0.1");
        let pass = parse(&text);
        let err = rules_for(&pass.destinations[0])
            .err()
            .map(|e| e.to_string());
        assert!(err.unwrap_or_default().contains("loopback"));
    }

    #[test]
    fn unchanged_and_window_states() {
        let mut w = watch_for(PASS, &["web"]);
        assert_eq!(judge(&mut w, PASS, NOW), Recheck::Unchanged);
        let Recheck::Stop(m) = judge(&mut w, PASS, datetime!(2026-01-02 00:00:00 UTC)) else {
            panic!("expired must stop")
        };
        assert!(m.contains("expired"), "{m}");
        let revoked = PASS.replace("revoked = false", "revoked = true");
        let Recheck::Stop(m) = judge(&mut w, &revoked, NOW) else {
            panic!("revoked must stop")
        };
        assert!(m.contains("revoked"), "{m}");
        let later_start = PASS.replace(
            "valid_from = 2026-01-01T00:00:00Z",
            "valid_from = 2026-01-01T13:00:00Z",
        );
        assert!(matches!(judge(&mut w, &later_start, NOW), Recheck::Stop(_)));
    }

    #[test]
    fn harmless_edits_continue_and_never_widen() {
        let mut w = watch_for(PASS, &["web"]);
        let raised = PASS.replace("calls = 6", "calls = 60");
        let Recheck::Edited(m) = judge(&mut w, &raised, NOW) else {
            panic!("a raised ceiling is harmless")
        };
        assert!(m.contains("rules loaded at start"), "{m}");
        // The same edit seen again is no longer news.
        assert_eq!(judge(&mut w, &raised, NOW), Recheck::Unchanged);
        let later = raised.replace("2026-01-02T00:00:00Z", "2026-02-01T00:00:00Z");
        assert!(matches!(judge(&mut w, &later, NOW), Recheck::Edited(_)));
        // A change to a destination not in use is harmless too.
        let other = later.replace("ports = 5060", "ports = 5061");
        assert!(matches!(judge(&mut w, &other, NOW), Recheck::Edited(_)));
        // The hostname grants nothing; changing it changes no rule.
        let renamed = other.replace("app.example.test", "www.example.test");
        assert!(matches!(judge(&mut w, &renamed, NOW), Recheck::Edited(_)));
    }

    #[test]
    fn edits_to_destinations_in_use_stop() {
        let cases = [
            PASS.replace("ports = [443, \"8000-8001\"]", "ports = [443]"),
            PASS.replace(
                "ports = [443, \"8000-8001\"]",
                "ports = [443, \"8000-8002\"]",
            ),
            PASS.replace("192.0.2.10", "192.0.2.11"),
            PASS.replace("protocol = \"tcp\"", "protocol = \"udp\""),
            PASS.replace("label = \"web\"", "label = \"web2\""),
            PASS.replace("id = \"example-1\"", "id = \"example-2\""),
            PASS.replace("owner = \"Pat Owner\"", "owner = \"Someone Else\""),
        ];
        for text in cases {
            let mut w = watch_for(PASS, &["web"]);
            assert!(
                matches!(judge(&mut w, &text, NOW), Recheck::Stop(_)),
                "should stop for:\n{text}"
            );
        }
    }

    #[test]
    fn select_by_label() {
        let pass = parse(PASS);
        assert_eq!(select(&pass, &[]).map(|v| v.len()), Ok(2));
        let one = select(&pass, &["v6".to_owned()]).unwrap_or_default();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].label, "v6");
        let err = select(&pass, &["nope".to_owned()])
            .err()
            .unwrap_or_default();
        assert!(err.contains("web, v6"), "{err}");
    }

    #[test]
    fn description_names_the_pass_and_not_the_ceilings() {
        let pass = parse(PASS);
        let id = PassIdentity {
            file: PathBuf::from("p.toml"),
            id: pass.id.clone(),
            name: pass.name.clone(),
            owner: pass.approval.owner,
            digest: Digest::of(PASS.as_bytes()),
            valid_until: pass.approval.valid_until,
            labels: vec!["web".into()],
        };
        let d = describe(&id);
        assert!(d.contains("pass example-1"), "{d}");
        assert!(d.contains("owner \"Pat Owner\""), "{d}");
        assert!(d.contains("sha256:"), "{d}");
        assert!(d.contains("window ends 2026-01-02T00:00:00Z"), "{d}");
        assert!(!d.contains("calls"), "{d}");
    }
}

#[cfg(test)]
#[path = "pass_scope_tests.rs"]
mod scope_tests;
