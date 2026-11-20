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
#[derive(Serialize)]
struct Comparison {
    policy: &'static str,
    evidence: &'static str,
    new_denials: Vec<Endpoint>,
    no_longer_observed: Vec<Endpoint>,
}
struct Input {
    policy: Vec<Value>,
    endpoints: BTreeSet<Endpoint>,
    complete: bool,
}

fn read(path: &Path) -> Result<Input, String> {
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
            let mut mappings = std::collections::BTreeMap::<String, Vec<IpAddr>>::new();
            for raw in field.as_array().into_iter().flatten() {
                let h = crate::resolver::parse_host(raw.as_str().ok_or("invalid host")?)
                    .map_err(|e| e.to_string())?;
                mappings.entry(h.name).or_default().push(h.addr);
            }
            field = serde_json::json!(mappings);
        } else if let Some(items) = field.as_array_mut() {
            items.sort_by_key(Value::to_string);
        }
        policy.push(field);
    }
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
    Ok(Input {
        policy,
        endpoints,
        complete,
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
    let evidence = if a.complete && b.complete {
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
    let result = Comparison {
        policy,
        evidence,
        new_denials,
        no_longer_observed,
    };
    if format == Format::Json {
        let advice = if evidence == "incomplete" {
            serde_json::json!([{"level":"warn","type":"incomplete-evidence","message":"Inspect both reports for missing or partial drop counters before drawing conclusions."}])
        } else {
            serde_json::json!([])
        };
        println!(
            "{}",
            serde_json::json!({"policy":result.policy,"evidence":result.evidence,"new_denials":result.new_denials,"no_longer_observed":result.no_longer_observed,"advice":advice})
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
    }
    if !result.new_denials.is_empty() {
        1
    } else if policy != "same" || evidence != "complete" {
        2
    } else {
        0
    }
}
