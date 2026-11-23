//! `playpen suggest REPORT`: the narrowest `--allow` and `--host` options
//! that admit what one run contacted (`--report-contacts`).
//!
//! The report is read as inert data ([`crate::compare::read_report`]).
//! Nothing in it is printed unless it parses to a typed value first: an
//! allow rule built from a contacted address, protocol and port, or a host
//! entry. Every contacted destination must be one the run's own grants
//! (`allowed`) admit, so the output is never wider than they are.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::Path;

use serde_json::{Value, json};

use crate::approval::{AllowRule, Approval, Net, Ports, Proto, parse_allow};
use crate::cli::EXIT_REFUSED;
use crate::cli::discovery::{self, Format};

/// The caution every output repeats.
const CAUTION: &str =
    "this is what one run contacted. One quiet run does not show that a later run needs less.";

/// Why a run under a pass gets destinations instead of options.
const UNDER_PASS: &str = "the run was held to a pass, and --allow cannot be added beside --pass. The lines without an option are the destinations that a narrower pass from its owner would list; --only LABEL narrows the pass you have";

/// What `suggest` prints.
#[derive(Debug, PartialEq, Eq)]
struct Suggestion {
    /// The run was under `--pass`: the rules are destinations for a
    /// narrower pass, not `--allow` options.
    pass: bool,
    /// One rule per contacted destination: one address, one port, one
    /// protocol.
    rules: BTreeSet<AllowRule>,
    /// `NAME=ADDR` for each `hosts` entry whose address was contacted, in
    /// the report's order.
    hosts: Vec<String>,
    /// The destinations in `rules` that sent no reply the command could use,
    /// in the order of `rules`. They are still in `rules`.
    unanswered: Vec<(AllowRule, Unanswered)>,
}

/// What the report says about the answer of one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// The entry has no `answered`: nothing is known either way.
    Unmarked,
    /// It sent a reply that was not a reset.
    Answered,
    /// It did not answer.
    No(Unanswered),
}

/// What the record says about a destination that did not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Unanswered {
    /// It sent nothing back: no listener behind a drop, a host that is down,
    /// a flow that timed out.
    Silent,
    /// It sent a TCP reset and nothing else: a host that refused.
    Refused,
}

impl Unanswered {
    /// The name in JSON.
    const fn kind(self) -> &'static str {
        match self {
            Self::Silent => "no-reply",
            Self::Refused => "refused",
        }
    }

    /// The words in the text.
    const fn words(self) -> &'static str {
        match self {
            Self::Silent => "no reply",
            Self::Refused => "refused with a TCP reset",
        }
    }
}

/// Why `suggest` refuses: the error type for JSON, and the message.
type Refusal = (&'static str, String);

impl Suggestion {
    /// Nothing was contacted, outside a pass: `--no-network` admits the
    /// same traffic.
    fn no_network(&self) -> bool {
        !self.pass && self.rules.is_empty()
    }

    /// The text on stdout: one option (or, under a pass, one destination)
    /// per line.
    fn lines(&self) -> String {
        let option = if self.pass { "" } else { "--allow " };
        let mut out = String::new();
        for rule in &self.rules {
            let _ = writeln!(out, "{option}{rule}");
        }
        if self.no_network() {
            out.push_str("--no-network\n");
        }
        for host in &self.hosts {
            let _ = writeln!(out, "--host {host}");
        }
        out
    }

    /// The text on stderr about the destinations that did not answer.
    fn unanswered_note(&self) -> Option<String> {
        if self.unanswered.is_empty() {
            return None;
        }
        let mut text = format!(
            "{} of the destinations above got no usable answer, so the command may not have used them; they are still listed:",
            self.unanswered.len()
        );
        for (rule, why) in &self.unanswered {
            let _ = write!(text, "\nplaypen:   {rule}: {}", why.words());
        }
        Some(text)
    }

    /// What the output says besides the caution: its type for JSON, and
    /// the text.
    fn note(&self) -> Option<(&'static str, &'static str)> {
        match (self.pass, self.rules.is_empty()) {
            (true, true) => Some((
                "nothing-contacted",
                "the command contacted no destination of the pass",
            )),
            (true, false) => Some(("pass", UNDER_PASS)),
            (false, true) => Some((
                "nothing-contacted",
                "the command contacted no approved destination; --no-network admits the same traffic",
            )),
            (false, false) => None,
        }
    }
}

/// One contacted destination of the report, or `None` when the entry is
/// not exactly an address, `tcp` or `udp`, a port, a packet count, and
/// `answered` and `reset` flags when it has them. The last of the tuple is
/// what the record says about an answer.
fn destination(item: &Value) -> Option<(IpAddr, Proto, u16, Answer)> {
    let address = item["address"].as_str()?.parse().ok()?;
    let proto = match item["protocol"].as_str()? {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        _ => return None,
    };
    let port = u16::try_from(item["port"].as_u64()?).ok()?;
    item["packets"].as_u64()?;
    let answer = match (item.get("answered"), item.get("reset")) {
        (None, None) => Answer::Unmarked,
        (Some(Value::Bool(answered)), reset) => {
            let reset = match reset {
                None => false,
                Some(Value::Bool(b)) => *b,
                Some(_) => return None,
            };
            match (answered, reset) {
                (true, _) => Answer::Answered,
                (false, true) => Answer::No(Unanswered::Refused),
                (false, false) => Answer::No(Unanswered::Silent),
            }
        }
        _ => return None,
    };
    Some((address, proto, port, answer))
}

/// A text field of the report as it may be shown: quoted, with every
/// control, format and other unprintable character escaped.
fn quoted(field: &Value) -> String {
    field
        .as_str()
        .map_or_else(|| "not a string".to_owned(), |s| format!("{s:?}"))
}

/// The narrowest options for the report `v`, or why there are none.
///
/// Text from the report reaches a message only through [`quoted`], or as
/// a value parsed from it.
fn suggest(v: &Value) -> Result<Suggestion, Refusal> {
    let invalid = |m: String| ("invalid-report", m);
    let incomplete = |m: String| ("incomplete-record", m);
    if v["outcome"] != "ran" {
        return Err(incomplete(format!(
            "outcome is {}, not \"ran\": there is no record of a finished run to narrow from",
            quoted(&v["outcome"])
        )));
    }
    let Some(contacted) = v.get("contacted") else {
        return Err(incomplete(
            "the report has no contacted record; run the command with --report-contacts".into(),
        ));
    };
    if contacted.is_null() {
        return Err(incomplete(format!(
            "the record of contacted destinations is unavailable (contacted_error: {})",
            quoted(&v["contacted_error"])
        )));
    }
    if contacted["truncated"] != false {
        return Err(incomplete(
            "the record of contacted destinations is truncated or inconsistent, so a list made from it could leave out a destination the command used".into(),
        ));
    }
    let grants = v["allowed"]
        .as_array()
        .ok_or_else(|| invalid("invalid policy field allowed".into()))?
        .iter()
        .map(|spec| {
            spec.as_str()
                .ok_or_else(|| "invalid policy field allowed".to_owned())
                .and_then(|s| parse_allow(s).map_err(|e| e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?;
    let grants = Approval::new(grants, None);
    let items = contacted["destinations"]
        .as_array()
        .ok_or_else(|| invalid("contacted has no destinations array".into()))?;
    let mut rules = BTreeSet::new();
    let mut unanswered = Vec::new();
    for (n, item) in (1..).zip(items) {
        let (address, proto, port, answer) = destination(item).ok_or_else(|| {
            invalid(format!(
                "contacted destination {n} is not an address, tcp or udp, a port, a packet count and answered and reset flags"
            ))
        })?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        let rule = Net::new(address, width)
            .and_then(|net| Ports::new(port, port).map(|ports| AllowRule { net, ports, proto }))
            .map_err(|e| invalid(format!("contacted destination {n}: {e}")))?;
        // Never wider than the run's own grants: each destination must be
        // one they admitted.
        if !grants.permits_packet(address, proto, port) {
            return Err(invalid(format!(
                "contacted destination {rule} is not admitted by the run's grants (allowed); nothing is suggested from a report that does not add up"
            )));
        }
        if !rules.insert(rule) {
            return Err(invalid(format!("contacted lists {rule} twice")));
        }
        if let Answer::No(why) = answer {
            unanswered.push((rule, why));
        }
    }
    unanswered.sort();
    let addresses: BTreeSet<IpAddr> = rules.iter().map(|r| r.net.addr()).collect();
    let mut hosts = Vec::new();
    for raw in v["hosts"]
        .as_array()
        .ok_or_else(|| invalid("invalid policy field hosts".into()))?
    {
        let entry = crate::compare::host_entry(raw).map_err(invalid)?;
        let text = format!("{}={}", entry.name, entry.addr);
        if addresses.contains(&entry.addr) && !hosts.contains(&text) {
            hosts.push(text);
        }
    }
    Ok(Suggestion {
        pass: v["pass"].is_object(),
        rules,
        hosts,
        unanswered,
    })
}

/// `playpen suggest REPORT`. Exit 0 when printed, 2 when refused.
pub fn run_formatted(path: &Path, format: Format) -> i32 {
    let result = crate::compare::read_report(path)
        .map_err(|e| ("invalid-report", e))
        .and_then(|v| suggest(&v));
    let s = match result {
        Ok(s) => s,
        Err((kind, message)) => {
            return discovery::error(
                format,
                kind,
                &format!("cannot suggest from {}: {message}", path.display()),
                EXIT_REFUSED,
            );
        }
    };
    let note = s.note();
    if format == Format::Json {
        let mut advice = vec![json!({"level":"warn","type":"one-run","message":CAUTION})];
        if let Some((kind, message)) = note {
            advice.push(json!({"level":"info","type":kind,"message":message}));
        }
        if let Some(message) = s.unanswered_note() {
            advice.push(json!({"level":"warn","type":"unanswered","message":message}));
        }
        println!(
            "{}",
            json!({
                "source": if s.pass { "pass" } else { "allow" },
                "allow": s.rules.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "hosts": s.hosts,
                "unanswered": s.unanswered.iter().map(|(rule, why)| json!({"destination": rule.to_string(), "answer": why.kind()})).collect::<Vec<_>>(),
                "no_network": s.no_network(),
                "advice": advice,
            })
        );
    } else {
        // Only the options go to stdout, so it can be given to run as it is.
        print!("{}", s.lines());
        if let Some((_, message)) = note {
            eprintln!("playpen: {message}");
        }
        if let Some(message) = s.unanswered_note() {
            eprintln!("playpen: {message}");
        }
        eprintln!("playpen: caution: {CAUTION}");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Value {
        json!({
            "playpen_version": "0.1.0",
            "outcome": "ran",
            "allowed": ["198.51.100.0/24:9550-9560/tcp", "[2001:db8::/64]:53/udp"],
            "hosts": [
                "App.Example.Test=198.51.100.7",
                "idle.example.test=198.51.100.20",
                "v6.example.test=[2001:db8::5]",
                "pass.example.test=198.51.100.9 (pass: web)",
                "app.example.test=198.51.100.7"
            ],
            "pass": null,
            "contacted": {"destinations": [
                {"address": "198.51.100.9", "protocol": "tcp", "port": 9557, "packets": 1},
                {"address": "198.51.100.7", "protocol": "tcp", "port": 9558, "packets": 2},
                {"address": "2001:db8::5", "protocol": "udp", "port": 53, "packets": 4},
                {"address": "198.51.100.7", "protocol": "tcp", "port": 9557, "packets": 1}
            ], "truncated": false},
            "contacted_error": null
        })
    }

    fn refusal(v: &Value) -> Refusal {
        match suggest(v) {
            Ok(s) => panic!("suggested {s:?}"),
            Err(r) => r,
        }
    }

    #[test]
    fn one_exact_option_per_destination_and_the_hosts_that_point_at_them() {
        let s = suggest(&report()).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(
            s.lines(),
            "--allow 198.51.100.7:9557/tcp\n--allow 198.51.100.7:9558/tcp\n--allow 198.51.100.9:9557/tcp\n--allow [2001:db8::5]:53/udp\n--host app.example.test=198.51.100.7\n--host v6.example.test=2001:db8::5\n--host pass.example.test=198.51.100.9\n"
        );
        assert_eq!(s.note(), None);
        // Every suggested rule parses back to itself and is one address.
        for rule in &s.rules {
            assert_eq!(parse_allow(&rule.to_string()).ok(), Some(*rule));
            assert!(rule.net.is_single() && rule.ports.first() == rule.ports.last());
        }
    }

    #[test]
    fn nothing_wider_than_the_grants() {
        // Outside every grant: another network, port, protocol.
        for (address, protocol, port) in [
            ("198.51.101.7", "tcp", 9557),
            ("198.51.100.7", "tcp", 9561),
            ("198.51.100.7", "udp", 9557),
            ("2001:db8:1::5", "udp", 53),
        ] {
            let mut v = report();
            v["contacted"]["destinations"][0] =
                json!({"address": address, "protocol": protocol, "port": port, "packets": 1});
            let (kind, message) = refusal(&v);
            assert_eq!(kind, "invalid-report");
            assert!(
                message.contains("not admitted by the run's grants"),
                "{message}"
            );
        }
        // The broadcast address of the /24 is not a host the grant admits.
        let mut v = report();
        v["contacted"]["destinations"][0]["address"] = "198.51.100.255".into();
        assert!(refusal(&v).1.contains("not admitted"));
        // Nor an address that can never be approved.
        v["contacted"]["destinations"][0]["address"] = "127.0.0.1".into();
        assert!(refusal(&v).1.contains("loopback"));
    }

    #[test]
    fn destinations_that_did_not_answer_are_marked_and_still_listed() {
        let plain = suggest(&report()).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(plain.unanswered.is_empty() && plain.unanswered_note().is_none());
        let mut v = report();
        let entries = v["contacted"]["destinations"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("destinations"));
        for (entry, (answered, reset)) in
            entries
                .iter_mut()
                .zip([(true, false), (false, false), (false, true), (true, true)])
        {
            entry["answered"] = answered.into();
            entry["reset"] = reset.into();
        }
        let s = suggest(&v).unwrap_or_else(|e| panic!("{e:?}"));
        // The options are the same with and without the marks.
        assert_eq!(s.lines(), plain.lines());
        let note = s.unanswered_note().unwrap_or_default();
        assert_eq!(
            note,
            "2 of the destinations above got no usable answer, so the command may not have used them; they are still listed:\nplaypen:   198.51.100.7:9558/tcp: no reply\nplaypen:   [2001:db8::5]:53/udp: refused with a TCP reset"
        );
        // Only an `answered` that is not a boolean, or a `reset` alone, is wrong.
        for bad in [
            json!({"answered": 1}),
            json!({"reset": true}),
            json!({"answered": true, "reset": "no"}),
        ] {
            let mut v = report();
            for (k, x) in bad.as_object().into_iter().flatten() {
                v["contacted"]["destinations"][0][k] = x.clone();
            }
            assert_eq!(refusal(&v).0, "invalid-report", "{bad}");
        }
    }

    #[test]
    fn refuses_an_incomplete_or_missing_record() {
        let mut v = report();
        v["outcome"] = "not_started".into();
        assert_eq!(refusal(&v).0, "incomplete-record");
        let mut v = report();
        v["contacted"]["truncated"] = true.into();
        assert!(refusal(&v).1.contains("truncated"));
        v["contacted"]["truncated"] = Value::Null;
        assert!(refusal(&v).1.contains("truncated"));
        let mut v = report();
        v["contacted"] = Value::Null;
        v["contacted_error"] = "nft could not list the table\u{1b}[2J\u{9b}2J\u{202e}".into();
        let (kind, message) = refusal(&v);
        assert_eq!(kind, "incomplete-record");
        assert!(message.contains("unavailable"), "{message}");
        assert!(
            message.contains(r#""nft could not list the table\u{1b}[2J\u{9b}2J\u{202e}""#),
            "{message}"
        );
        assert!(
            !message.chars().any(|c| c.is_control() || c == '\u{202e}'),
            "{message}"
        );
        let mut v = report();
        v["outcome"] = "x\u{1b}]0;title\u{7}".into();
        let message = refusal(&v).1;
        assert!(!message.chars().any(char::is_control), "{message}");
        let mut v = report();
        v.as_object_mut().map(|o| o.remove("contacted"));
        assert!(refusal(&v).1.contains("--report-contacts"));
    }

    #[test]
    fn refuses_malformed_entries() {
        for entry in [
            json!({"address": "198.51.100.7\u{1b}[2J", "protocol": "tcp", "port": 1, "packets": 1}),
            json!({"address": "198.51.100.7", "protocol": "icmp", "port": 0, "packets": 1}),
            json!({"address": "198.51.100.7", "protocol": "tcp", "port": 70000, "packets": 1}),
            json!({"address": "198.51.100.7", "protocol": "tcp", "port": 9557}),
            json!({"address": "198.51.100.07", "protocol": "tcp", "port": 9557, "packets": 1}),
            json!({"address": "198.51.100.7", "protocol": "tcp", "port": 9558, "packets": 1}),
        ] {
            let mut v = report();
            v["contacted"]["destinations"][0] = entry.clone();
            let (kind, message) = refusal(&v);
            assert_eq!(kind, "invalid-report", "{entry}");
            assert!(!message.chars().any(char::is_control), "{message}");
        }
        let mut v = report();
        v["hosts"][0] = "evil\u{1b}]0;x=198.51.100.7".into();
        let (kind, message) = refusal(&v);
        assert_eq!(kind, "invalid-report");
        assert!(!message.chars().any(char::is_control), "{message}");
        let mut v = report();
        v["allowed"][0] = "198.51.100.0/24".into();
        assert_eq!(refusal(&v).0, "invalid-report");
    }

    #[test]
    fn a_pass_run_gets_destinations_and_nothing_contacted_gets_no_network() {
        let mut v = report();
        v["pass"] = json!({"file": "p.toml", "id": "\u{1b}[2J"});
        let s = suggest(&v).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(
            s.lines().starts_with("198.51.100.7:9557/tcp\n"),
            "{}",
            s.lines()
        );
        assert!(!s.lines().contains("--allow"));
        assert!(s.lines().contains("--host app.example.test=198.51.100.7\n"));
        assert_eq!(s.note().map(|n| n.0), Some("pass"));
        v["contacted"]["destinations"] = json!([]);
        let s = suggest(&v).unwrap_or_else(|e| panic!("{e:?}"));
        assert_eq!(s.lines(), "");
        assert_eq!(s.note().map(|n| n.0), Some("nothing-contacted"));

        let mut v = report();
        v["contacted"]["destinations"] = json!([]);
        let s = suggest(&v).unwrap_or_else(|e| panic!("{e:?}"));
        assert!(s.no_network());
        assert_eq!(s.lines(), "--no-network\n");
    }
}
