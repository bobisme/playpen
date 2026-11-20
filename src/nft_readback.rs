//! Semantic verification for the nftables JSON emitted by Playpen.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::{Value, json};

use crate::approval::{AllowRule, Approval, Proto};
use crate::ruleset::{DROP_SET_SIZE, TABLE};

#[derive(Default, Debug, PartialEq, Eq)]
struct Table {
    // Declaration order is immaterial. Expression order within a rule and
    // rule order within each chain are preserved.
    objects: BTreeMap<(String, String), Value>,
    chains: BTreeMap<String, Vec<Value>>,
}

fn object(kind: &str, name: &str, fields: Value) -> ((String, String), Value) {
    ((kind.to_owned(), name.to_owned()), fields)
}

fn meta(key: &str) -> Value {
    json!({"meta":{"key":key}})
}

fn payload(protocol: &str, field: &str) -> Value {
    json!({"payload":{"protocol":protocol,"field":field}})
}

fn matcher(op: &str, left: Value, right: Value) -> Value {
    let fields = [
        ("op".into(), json!(op)),
        ("left".into(), left),
        ("right".into(), right),
    ];
    json!({"match": fields.into_iter().collect::<serde_json::Map<_, _>>()})
}

fn members(values: impl IntoIterator<Item = Value>) -> Value {
    let mut values: Vec<_> = values.into_iter().collect();
    // Sort the JSON values by a stable spelling. Equality still requires
    // each member to have the exact expected value and type.
    values.sort_by_cached_key(Value::to_string);
    json!({"set":values})
}

fn prefix(addr: IpAddr, len: u8) -> Value {
    let width = if addr.is_ipv4() { 32 } else { 128 };
    if len == width {
        json!(addr.to_string())
    } else {
        json!({"prefix":{"addr":addr.to_string(),"len":len}})
    }
}

fn expected(approval: &Approval, grant_counters: usize) -> Table {
    let mut table = Table::default();
    table.objects.extend([
        object("table", TABLE, json!({"family":"inet","name":TABLE})),
        object(
            "counter",
            "dropped",
            json!({"family":"inet","table":TABLE,"name":"dropped"}),
        ),
    ]);
    for index in 0..grant_counters {
        let name = crate::grant_use::counter_name(index);
        table.objects.insert(
            (String::from("counter"), name.clone()),
            json!({"family":"inet","table":TABLE,"name":name}),
        );
    }
    for hook in ["output", "input", "forward"] {
        table.objects.insert(
            (String::from("chain"), hook.to_owned()),
            json!({"family":"inet","table":TABLE,"name":hook,"type":"filter","hook":hook,"prio":0,"policy":"drop"}),
        );
        table.chains.insert(hook.to_owned(), Vec::new());
    }
    for (name, kind) in [("drop4", "ipv4_addr"), ("drop6", "ipv6_addr")] {
        table.objects.insert(
            (String::from("set"), name.to_owned()),
            json!({"family":"inet","table":TABLE,"name":name,"type":[kind,"inet_proto","inet_service"],
                "size":DROP_SET_SIZE,"flags":["dynamic"],"stmt":[{"counter":null}]}),
        );
    }
    let established = json!([
        matcher("in", json!({"ct":{"key":"state"}}), [2, 4].map(Value::from).to_vec().into()),
        {"accept":null}
    ]);
    let icmp_type = |types: &[u8]| {
        matcher(
            "==",
            payload("icmpv6", "type"),
            members(types.iter().copied().map(Value::from)),
        )
    };
    let neighbour_discovery = json!([
        icmp_type(&[135, 136]),
        matcher("==", payload("ip6", "hoplimit"), json!(255)),
        {"accept":null}
    ]);
    let output = table
        .chains
        .get_mut("output")
        .expect("declared output chain");
    output.push(established.clone());
    for (family, addr, len) in [("ip", "127.0.0.0", 8), ("ip6", "::1", 128)] {
        output.push(json!([
            matcher("==", meta("oif"), json!("lo")),
            matcher("==", payload(family, "daddr"), prefix(addr.parse().expect("loopback address"), len)),
            {"accept":null}
        ]));
    }
    output.push(neighbour_discovery.clone());
    output.push(json!([
        matcher("==", payload("ip6", "daddr"), prefix("ff02::".parse().expect("multicast address"), 16)),
        icmp_type(&[131, 133, 143]),
        {"drop":null}
    ]));
    output.extend(approval.rules().iter().enumerate().map(|(index, rule)| {
        let counter = (index < grant_counters).then(|| crate::grant_use::counter_name(index));
        grant(approval, rule, counter.as_deref())
    }));
    for (family, set) in [("ip", "@drop4"), ("ip6", "@drop6")] {
        for (operation, port) in [("==", payload("th", "dport")), ("!=", json!(0))] {
            output.push(json!([
                matcher(operation, meta("l4proto"), members([json!(6), json!(17)])),
                {"set":{"op":"add","elem":{"concat":[payload(family,"daddr"),meta("l4proto"),port]},"set":set}}
            ]));
        }
    }
    output.push(json!([{"counter":"dropped"}]));
    output.push(json!([{"reject":{"type":"icmpx","expr":3}}]));
    table
        .chains
        .get_mut("input")
        .expect("declared input chain")
        .extend([
            established,
            json!([matcher("==", meta("iif"), json!("lo")), {"accept":null}]),
            neighbour_discovery,
        ]);
    table
}

fn grant(approval: &Approval, rule: &AllowRule, counter: Option<&str>) -> Value {
    let family = if rule.net.addr().is_ipv4() {
        "ip"
    } else {
        "ip6"
    };
    let mut expr = vec![matcher(
        "==",
        payload(family, "daddr"),
        prefix(rule.net.addr(), rule.net.prefix()),
    )];
    let excluded = approval.exclusions(rule);
    if !excluded.is_empty() {
        expr.push(matcher(
            "!=",
            payload(family, "daddr"),
            match excluded.as_slice() {
                [addr] => json!(addr.to_string()),
                _ => members(excluded.iter().map(|addr| json!(addr.to_string()))),
            },
        ));
    }
    let protocol = match rule.proto {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    };
    let (first, last) = (rule.ports.first(), rule.ports.last());
    let ports = if first == last {
        json!(first)
    } else {
        json!({"range":[first,last]})
    };
    expr.push(matcher("==", payload(protocol, "dport"), ports));
    if let Some(name) = counter {
        expr.push(json!({"counter":name}));
    }
    expr.push(json!({"accept":null}));
    Value::Array(expr)
}

fn symbol(value: &mut Value, names: &[(&str, u8)]) {
    if let Some(name) = value.as_str()
        && let Some(&(_, number)) = names.iter().find(|(known, _)| *known == name)
    {
        *value = json!(number);
    }
}

fn numeric_set(right: &mut Value, names: &[(&str, u8)]) {
    if let Some(set) = right.as_object_mut()
        && set.len() == 1
        && let Some(values) = set.get_mut("set").and_then(Value::as_array_mut)
    {
        for member in &mut *values {
            symbol(member, names);
        }
        values.sort_by_cached_key(Value::to_string);
    }
}

fn address(value: &mut Value) {
    if let Some(ip) = value.as_str().and_then(|s| s.parse::<IpAddr>().ok()) {
        *value = json!(ip.to_string());
    } else if let Some(obj) = value.as_object()
        && obj.len() == 1
        && let Some(body) = obj.get("prefix").and_then(Value::as_object)
        && body.len() == 2
        && let Some(ip) = body
            .get("addr")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<IpAddr>().ok())
        && let Some(len) = body
            .get("len")
            .and_then(Value::as_u64)
            .and_then(|n| u8::try_from(n).ok())
    {
        *value = prefix(ip, len);
    }
}

fn normalize_expression(expr: &mut Value) {
    // Normalize only recognized fields, preserving all other data so a
    // material addition or unfamiliar shape fails the comparison.
    if let Some(m) = expr.get_mut("match").and_then(Value::as_object_mut) {
        let left = m.get("left").cloned().unwrap_or(Value::Null);
        let Some(right) = m.get_mut("right") else {
            return;
        };
        if left == json!({"ct":{"key":"state"}}) {
            if let Some(values) = right.as_array_mut() {
                for member in &mut *values {
                    symbol(member, &[("established", 2), ("related", 4)]);
                }
                values.sort_by_cached_key(Value::to_string);
            }
        } else if left == meta("l4proto") {
            numeric_set(right, &[("tcp", 6), ("udp", 17)]);
        } else if left == payload("icmpv6", "type") {
            numeric_set(
                right,
                &[
                    ("nd-neighbor-solicit", 135),
                    ("nd-neighbor-advert", 136),
                    ("mld-listener-report", 131),
                    ("nd-router-solicit", 133),
                    ("mld2-listener-report", 143),
                ],
            );
        } else if left == payload("ip", "daddr") || left == payload("ip6", "daddr") {
            if let Some(values) = right
                .as_object_mut()
                .filter(|o| o.len() == 1)
                .and_then(|o| o.get_mut("set"))
                .and_then(Value::as_array_mut)
            {
                for value in &mut *values {
                    address(value);
                }
                values.sort_by_cached_key(Value::to_string);
                if let [single] = values.as_slice() {
                    *right = single.clone();
                }
            } else {
                address(right);
            }
        }
    }
    if let Some(reject) = expr.get_mut("reject")
        && reject.get("type").and_then(Value::as_str) == Some("icmpx")
        && let Some(code) = reject.get_mut("expr")
    {
        symbol(code, &[("admin-prohibited", 3)]);
    }
}

fn parse(mut value: Value) -> Result<Table, String> {
    let mut table = Table::default();
    let items = value
        .as_object_mut()
        .filter(|o| o.len() == 1)
        .and_then(|o| o.get_mut("nftables"))
        .and_then(Value::as_array_mut)
        .ok_or("nft JSON has no nftables array")?;
    let mut metainfo = false;
    for item in items {
        let record = item
            .as_object_mut()
            .filter(|o| o.len() == 1)
            .ok_or("expected one object per nft record")?;
        let (kind, data) = record.iter_mut().next().ok_or("empty nft record")?;
        let data = data
            .as_object_mut()
            .ok_or_else(|| format!("invalid {kind} object"))?;
        data.remove("handle");
        match kind.as_str() {
            "metainfo"
                if !metainfo
                    && data.get("json_schema_version").and_then(Value::as_u64) == Some(1) =>
            {
                metainfo = true;
            }
            "rule" => {
                let chain = data
                    .remove("chain")
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .ok_or("nft rule has no chain")?;
                let family = data.remove("family");
                let name = data.remove("table");
                if family.as_ref().and_then(Value::as_str) != Some("inet")
                    || name.as_ref().and_then(Value::as_str) != Some(TABLE)
                {
                    return Err("nft rule belongs to a different table".into());
                }
                let expressions = data
                    .remove("expr")
                    .filter(Value::is_array)
                    .ok_or("nft rule has no expression array")?;
                if !data.is_empty() {
                    return Err(format!("unexpected {chain} rule properties"));
                }
                let mut expressions = expressions;
                for expr in expressions
                    .as_array_mut()
                    .expect("checked expression array")
                {
                    normalize_expression(expr);
                }
                table.chains.entry(chain).or_default().push(expressions);
            }
            "table" | "chain" | "set" | "counter" => {
                let name = data
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or("unnamed nft object")?
                    .to_owned();
                if kind == "chain" {
                    table.chains.entry(name.clone()).or_default();
                }
                if kind == "counter" {
                    for field in ["packets", "bytes"] {
                        if let Some(value) = data.remove(field)
                            && !value.is_u64()
                        {
                            return Err(format!("invalid {field} on counter {name}"));
                        }
                    }
                }
                if kind == "set"
                    && let Some(elements) = data.remove("elem")
                    && !elements.is_array()
                {
                    return Err(format!("invalid elements on set {name}"));
                }
                if table
                    .objects
                    .insert((kind.clone(), name.clone()), json!(data))
                    .is_some()
                {
                    return Err(format!("duplicate {kind} {name}"));
                }
            }
            _ => return Err(format!("unexpected nft object {kind}")),
        }
    }
    if !metainfo {
        return Err("nft JSON has no supported schema version".into());
    }
    Ok(table)
}

/// Verify the installed table against the material policy expected from `approval`.
///
/// # Errors
/// When nft's JSON is invalid, unsupported, or differs from the approval.
pub fn verify_policy(json: &str, approval: &Approval) -> Result<(), String> {
    verify_instrumented(json, approval, 0)
}

pub fn verify_instrumented(
    json: &str,
    approval: &Approval,
    grant_counters: usize,
) -> Result<(), String> {
    let value: Value =
        serde_json::from_str(json).map_err(|e| format!("nft printed invalid JSON: {e}"))?;
    let actual = parse(value)?;
    let expected = expected(approval, grant_counters);
    if actual.objects != expected.objects {
        return Err("nft table, chains, or accounting declarations differ".into());
    }
    if actual.chains.keys().ne(expected.chains.keys()) {
        return Err("nft rules refer to unexpected chains".into());
    }
    for (name, want) in &expected.chains {
        let rules = actual
            .chains
            .get(name)
            .ok_or_else(|| format!("missing {name} rules"))?;
        if rules.len() != want.len() {
            return Err(format!(
                "{name} chain has {} rules, expected {}",
                rules.len(),
                want.len()
            ));
        }
        if let Some(index) = rules
            .iter()
            .zip(want)
            .position(|(actual, expected)| actual != expected)
        {
            return Err(format!("{name} rule {} differs", index + 1));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::parse_allow;

    const EMPTY: &str = include_str!("../tests/fixtures/nft/empty.json");
    const RULES: &str = include_str!("../tests/fixtures/nft/nonempty.json");
    const NUMERIC: &str = include_str!("../tests/fixtures/nft/numeric.json");
    const EDGES: &str = include_str!("../tests/fixtures/nft/edges.json");

    fn approval() -> Approval {
        let rules = [
            "192.0.2.0/30:8000-8002/tcp",
            "192.0.2.4:53/udp",
            "[2001:db8::/124]:80/udp",
        ]
        .map(|spec| parse_allow(spec).expect("valid fixture grant"));
        Approval::new(rules.to_vec(), None)
    }

    #[test]
    fn real_readbacks_match_approval() {
        verify_policy(EMPTY, &Approval::new(vec![], None)).expect("recorded empty policy");
        verify_policy(RULES, &approval()).expect("recorded address policy");
        verify_policy(NUMERIC, &approval()).expect("recorded numeric spellings");
    }

    #[test]
    fn readback_of_single_excluded_edge_matches() {
        let rules = [
            "192.0.2.0/28:444/tcp",
            "192.0.2.6/31:445/udp",
            "192.0.2.4/30:443/tcp",
            "[2001:db8::1]:1024/tcp",
        ]
        .map(|spec| parse_allow(spec).expect("valid fixture grant"));
        let approval = Approval::new(rules.to_vec(), None);
        verify_policy(EDGES, &approval).expect("recorded singleton exclusions");
    }

    #[test]
    fn narrower_same_length_policy_is_refused() {
        let narrower = RULES.replace("[8000, 8002]", "[8000, 8001]");
        assert_ne!(RULES, narrower);
        assert_eq!(
            verify_policy(&narrower, &approval()),
            Err("output rule 6 differs".into())
        );
    }

    #[test]
    fn unknown_expression_is_refused() {
        let unsupported = RULES.replacen("\"accept\": null", "\"unrecognized\": null", 1);
        assert_eq!(
            verify_policy(&unsupported, &approval()),
            Err("output rule 1 differs".into())
        );
    }

    #[test]
    fn rejects_changed_accounting_and_chain_metadata() {
        for (from, to) in [
            ("\"size\": 1024", "\"size\": 512"),
            ("\"prio\": 0", "\"prio\": 10"),
            ("@drop4", "@drop6"),
        ] {
            let altered = RULES.replacen(from, to, 1);
            assert_ne!(RULES, altered);
            assert!(verify_policy(&altered, &approval()).is_err());
        }
    }

    #[test]
    fn volatile_fields_and_set_member_order_are_ignored() {
        let equivalent = RULES
            .replace("\"handle\": 7", "\"handle\": 100")
            .replace("\"packets\": 0", "\"packets\": 5")
            .replace(
                "[\"192.0.2.0\", \"192.0.2.3\"]",
                "[\"192.0.2.3\", \"192.0.2.0\"]",
            );
        verify_policy(&equivalent, &approval()).expect("equivalent ruleset");
    }
}
