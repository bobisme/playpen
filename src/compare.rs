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
struct Comparison {
    policy: &'static str,
    evidence: &'static str,
    new_denials: Vec<Endpoint>,
    no_longer_observed: Vec<Endpoint>,
    new_unmapped_lookups: Vec<String>,
    unmapped_lookups_no_longer_observed: Vec<String>,
}
struct Input {
    policy: Vec<Value>,
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
    (endpoints, complete)
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
        policy.push(field);
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
