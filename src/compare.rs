//! Offline comparison of bounded, historical full reports.
use crate::cli::discovery::{self, Format};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::Read as _;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Endpoint {
    address: IpAddr,
    protocol: String,
    port: Option<u16>,
}
/// One policy field that differs between the two reports.
struct PolicyChange {
    /// The report field: `allowed`, `hosts`, `exposed`, `network`, ...
    field: &'static str,
    /// Items only in the later report; empty for a single value.
    added: Vec<String>,
    /// Items only in the earlier report; empty for a single value.
    removed: Vec<String>,
    /// For a single value, its text in the earlier and later report.
    values: Option<(String, String)>,
}
struct Comparison {
    policy: &'static str,
    policy_changes: Vec<PolicyChange>,
    evidence: &'static str,
    new_denials: Vec<Endpoint>,
    no_longer_observed: Vec<Endpoint>,
    new_unmapped_lookups: Vec<String>,
    unmapped_lookups_no_longer_observed: Vec<String>,
}
struct Input {
    policy: Vec<(&'static str, Value)>,
    endpoints: BTreeSet<Endpoint>,
    complete: bool,
    /// Names looked up without a `--host` mapping.
    unmapped: BTreeSet<String>,
    lookups_complete: bool,
}

/// One entry of a report's `hosts`. An entry from `--pass-hosts` ends in
/// ` (pass: LABEL, ...)`; the mapping is the same whichever option gave it.
pub fn host_entry(raw: &Value) -> Result<crate::resolver::HostEntry, String> {
    let raw = raw.as_str().ok_or("invalid host")?;
    let entry = raw
        .strip_suffix(')')
        .and_then(|r| r.split_once(" (pass: "))
        .map_or(raw, |(entry, _)| entry);
    crate::resolver::parse_host(entry).map_err(|e| e.to_string())
}

/// The report's `hosts` as a map from each name to its addresses.
fn host_mappings(field: &Value) -> Result<Value, String> {
    let mut mappings = std::collections::BTreeMap::<String, Vec<IpAddr>>::new();
    for raw in field.as_array().into_iter().flatten() {
        let h = host_entry(raw)?;
        mappings.entry(h.name).or_default().push(h.addr);
    }
    Ok(serde_json::json!(mappings))
}

/// The names a report says were looked up without a `--host` mapping, and
/// whether the record is complete: present, not truncated, and every entry
/// a shown name with a count, a `mapped` flag, and no repeat.
fn unmapped_lookups(lookups: &Value) -> (BTreeSet<String>, bool) {
    let mut unmapped = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut complete = lookups["truncated"] == false;
    let Some(items) = lookups["names"].as_array() else {
        return (unmapped, false);
    };
    for item in items {
        let name = item["name"]
            .as_str()
            .filter(|n| crate::dns_stub::is_shown(n));
        match (name, item["count"].as_u64(), item["mapped"].as_bool()) {
            (Some(name), Some(count), Some(mapped)) if count > 0 && seen.insert(name) => {
                if !mapped {
                    unmapped.insert(name.to_owned());
                }
            }
            _ => complete = false,
        }
    }
    (unmapped, complete)
}

/// The dropped tuples a report lists, and whether the list is complete:
/// the run ran, nothing is truncated, every entry parses, none repeats, and
/// the packet counts add up to the total.
fn dropped_endpoints(v: &Value) -> (BTreeSet<Endpoint>, bool) {
    let mut endpoints = BTreeSet::new();
    let mut complete = v["outcome"] == "ran"
        && v["dropped"]["destinations_truncated"] == false
        && v["dropped"]["packets"].is_u64();
    let mut sum = Some(0_u64);
    if let Some(items) = v["dropped"]["destinations"].as_array() {
        for item in items {
            sum = sum.and_then(|n| item["packets"].as_u64().and_then(|p| n.checked_add(p)));
            let parsed = (|| {
                let address = item["address"].as_str()?.parse().ok()?;
                let protocol = match item["protocol"].as_str()? {
                    "tcp" | "6" => "tcp",
                    "udp" | "17" => "udp",
                    "icmp" | "1" => "icmp",
                    "ipv6-icmp" | "58" => "ipv6-icmp",
                    _ => return None,
                }
                .to_owned();
                let port = if protocol == "tcp" || protocol == "udp" {
                    Some(u16::try_from(item["port"].as_u64()?).ok()?)
                } else {
                    if !item["port"].is_null() {
                        return None;
                    }
                    None
                };
                Some(Endpoint {
                    address,
                    protocol,
                    port,
                })
            })();
            if let Some(e) = parsed {
                if !endpoints.insert(e) {
                    complete = false;
                }
            } else {
                complete = false;
            }
        }
    } else {
        complete = false;
    }
    complete &= sum == v["dropped"]["packets"].as_u64();
    complete &= !cut_hid_drops(v);
    // Packets that failed at routing are not in the counters at all.
    complete &= v["uncounted"].is_null();
    (endpoints, complete)
}

/// With `--on-drop`: the cut tripped, and it refused packets after that,
/// or the count is unknown. It refuses them before the drop sets, so the
/// report does not say where they went.
fn cut_hid_drops(v: &Value) -> bool {
    match v.get("egress_cut") {
        None | Some(Value::Null) => false,
        Some(cut) => cut["refused"].as_u64() != Some(0),
    }
}

/// A full report as inert JSON: at most 1 MiB, of the 0.1.0 schema.
///
/// # Errors
/// When the file cannot be read, is too large, is not JSON, or is not a
/// full 0.1.0 report.
pub fn read_report(path: &Path) -> Result<Value, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1_048_576 {
        return Err("report exceeds 1 MiB".into());
    }
    let v: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if v["playpen_version"] != "0.1.0" {
        return Err("unsupported or reduced report schema".into());
    }
    Ok(v)
}

fn read(path: &Path) -> Result<Input, String> {
    let v = read_report(path)?;
    let mut policy = Vec::new();
    for key in [
        "allowed",
        "network",
        "hosts",
        "exposed",
        "socket_guard",
        "display",
    ] {
        let mut field = v
            .get(key)
            .cloned()
            .ok_or_else(|| format!("missing policy field {key}"))?;
        let valid = match key {
            "allowed" | "hosts" | "exposed" => field
                .as_array()
                .is_some_and(|a| a.iter().all(Value::is_string)),
            "network" => matches!(field.as_str(), Some("pasta" | "none")),
            "socket_guard" => matches!(field.as_str(), Some("landlock" | "mounts_only")),
            "display" => field.is_boolean(),
            _ => false,
        };
        if !valid {
            return Err(format!("invalid policy field {key}"));
        }
        if key == "hosts" {
            field = host_mappings(&field)?;
        } else if let Some(items) = field.as_array_mut() {
            items.sort_by_key(Value::to_string);
        }
        policy.push((key, field));
    }
    let (endpoints, complete) = dropped_endpoints(&v);
    let (unmapped, lookups_complete) = unmapped_lookups(&v["lookups"]);
    Ok(Input {
        policy,
        endpoints,
        complete,
        unmapped,
        lookups_complete: lookups_complete && v["outcome"] == "ran",
    })
}

/// The items of a policy field as text. A `hosts` map becomes `name=address`.
fn items(field: &Value) -> Vec<String> {
    if let Some(map) = field.as_object() {
        return map
            .iter()
            .flat_map(|(name, addrs)| {
                addrs
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(move |a| format!("{name}={}", a.as_str().unwrap_or_default()))
            })
            .collect();
    }
    field.as_array().map_or_else(Vec::new, |a| {
        a.iter()
            .map(|v| v.as_str().unwrap_or_default().to_owned())
            .collect()
    })
}

/// The items in `from` that `other` lacks, counting repeats.
fn missing_from(from: &[String], other: &[String]) -> Vec<String> {
    let mut rest = other.to_vec();
    let mut out: Vec<String> = from
        .iter()
        .filter(|item| {
            rest.iter()
                .position(|r| r == *item)
                .map(|i| rest.swap_remove(i))
                .is_none()
        })
        .cloned()
        .collect();
    out.sort();
    out
}

/// Each policy field that differs, with the items added and removed.
fn policy_changes(a: &[(&'static str, Value)], b: &[(&'static str, Value)]) -> Vec<PolicyChange> {
    let mut out = Vec::new();
    for ((field, before), (_, after)) in a.iter().zip(b) {
        if before == after {
            continue;
        }
        if before.is_array() || before.is_object() {
            let (x, y) = (items(before), items(after));
            out.push(PolicyChange {
                field,
                added: missing_from(&y, &x),
                removed: missing_from(&x, &y),
                values: None,
            });
        } else {
            let text = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_owned);
            out.push(PolicyChange {
                field,
                added: vec![],
                removed: vec![],
                values: Some((text(before), text(after))),
            });
        }
    }
    out
}

pub fn run_formatted(before: &Path, after: &Path, format: Format) -> i32 {
    let result = read(before)
        .map_err(|e| format!("{}: {e}", before.display()))
        .and_then(|a| {
            read(after)
                .map(|b| (a, b))
                .map_err(|e| format!("{}: {e}", after.display()))
        });
    let (a, b) = match result {
        Ok(v) => v,
        Err(e) => {
            return discovery::error(
                format,
                "invalid-report",
                &format!("cannot compare reports: {e}"),
                2,
            );
        }
    };
    let policy_changes = policy_changes(&a.policy, &b.policy);
    let policy = if a.policy == b.policy {
        "same"
    } else {
        "changed"
    };
    let evidence = if a.complete && b.complete && a.lookups_complete && b.lookups_complete {
        "complete"
    } else {
        "incomplete"
    };
    let new_denials: Vec<_> = if a.complete {
        b.endpoints.difference(&a.endpoints).cloned().collect()
    } else {
        vec![]
    };
    let no_longer_observed = if b.complete {
        a.endpoints.difference(&b.endpoints).cloned().collect()
    } else {
        vec![]
    };
    let new_unmapped_lookups: Vec<_> = if a.lookups_complete {
        b.unmapped.difference(&a.unmapped).cloned().collect()
    } else {
        vec![]
    };
    let unmapped_lookups_no_longer_observed = if b.lookups_complete {
        a.unmapped.difference(&b.unmapped).cloned().collect()
    } else {
        vec![]
    };
    let result = Comparison {
        policy,
        policy_changes,
        evidence,
        new_denials,
        no_longer_observed,
        new_unmapped_lookups,
        unmapped_lookups_no_longer_observed,
    };
    print(&result, format);
    if !result.new_denials.is_empty() || !result.new_unmapped_lookups.is_empty() {
        1
    } else if policy != "same" || evidence != "complete" {
        2
    } else {
        0
    }
}

/// The changes as JSON: one object per changed field, keyed by its name.
fn changes_json(changes: &[PolicyChange]) -> Value {
    let mut map = serde_json::Map::new();
    for c in changes {
        let v = c.values.as_ref().map_or_else(
            || serde_json::json!({"added": c.added, "removed": c.removed}),
            |(before, after)| serde_json::json!({"before": before, "after": after}),
        );
        map.insert(c.field.to_owned(), v);
    }
    Value::Object(map)
}

/// One line per change, `sep` between the words. A field that changed
/// only in the order of its addresses has no added or removed item.
fn change_lines(changes: &[PolicyChange], sep: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for c in changes {
        if let Some((before, after)) = &c.values {
            lines.push(format!(
                "changed{sep}{}{sep}{before}{sep}->{sep}{after}",
                c.field
            ));
        } else if c.added.is_empty() && c.removed.is_empty() {
            lines.push(format!("changed{sep}{}{sep}order", c.field));
        }
        for item in &c.added {
            lines.push(format!("added{sep}{}{sep}{item}", c.field));
        }
        for item in &c.removed {
            lines.push(format!("removed{sep}{}{sep}{item}", c.field));
        }
    }
    lines
}

/// Prints the comparison in `format`. Names are shown names: they hold no
/// terminal control bytes.
fn print(result: &Comparison, format: Format) {
    if format == Format::Json {
        let advice = if result.evidence == "incomplete" {
            serde_json::json!([{"level":"warn","type":"incomplete-evidence","message":"Inspect both reports for missing or partial drop counters or lookup records before drawing conclusions."}])
        } else {
            serde_json::json!([])
        };
        println!(
            "{}",
            serde_json::json!({
                "policy": result.policy,
                "policy_changes": changes_json(&result.policy_changes),
                "evidence": result.evidence,
                "new_denials": result.new_denials,
                "no_longer_observed": result.no_longer_observed,
                "new_unmapped_lookups": result.new_unmapped_lookups,
                "unmapped_lookups_no_longer_observed": result.unmapped_lookups_no_longer_observed,
                "advice": advice,
            })
        );
    } else if format == Format::Text {
        println!("policy  {}\nevidence  {}", result.policy, result.evidence);
        for line in change_lines(&result.policy_changes, "  ") {
            println!("policy-change  {line}");
        }
        for (kind, endpoints) in [
            ("new", &result.new_denials),
            ("no-longer-observed", &result.no_longer_observed),
        ] {
            for e in endpoints {
                println!(
                    "{kind}  {}  {}  {}",
                    e.address,
                    e.protocol,
                    e.port.map_or_else(|| "-".into(), |p| p.to_string())
                );
            }
        }
        for (kind, names) in [
            ("new-lookup", &result.new_unmapped_lookups),
            (
                "lookup-no-longer-observed",
                &result.unmapped_lookups_no_longer_observed,
            ),
        ] {
            for name in names {
                println!("{kind}  {name}");
            }
        }
    } else {
        println!("policy: {}; evidence: {}", result.policy, result.evidence);
        for line in change_lines(&result.policy_changes, " ") {
            println!("policy change: {line}");
        }
        for e in &result.new_denials {
            println!("new: {} {} {:?}", e.address, e.protocol, e.port);
        }
        for e in &result.no_longer_observed {
            println!(
                "no longer observed: {} {} {:?}",
                e.address, e.protocol, e.port
            );
        }
        for name in &result.new_unmapped_lookups {
            println!("new lookup without --host: {name}");
        }
        for name in &result.unmapped_lookups_no_longer_observed {
            println!("lookup without --host no longer observed: {name}");
        }
    }
}
