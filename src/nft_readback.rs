//! Semantic verification for the nftables JSON emitted by Playpen.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde_json::{Value, json};

use crate::approval::{AllowRule, Approval, Proto};
use crate::contacts;
use crate::ruleset::{
    CUT_COUNTER, CUT_MARK, CUT_SET, CUT_SET_SIZE, DROP_SET_SIZE, Instrumentation, LATE_COUNTER,
    TABLE, end_second,
};

/// The time zone `nft` is run in when it lists the table. `nft --json`
/// prints `meta time` as a wall-clock date without an offset, in the local
/// time zone of the `nft` process, with or without `--numeric`. In UTC that
/// date names one moment; `UTC0` is a POSIX zone that needs no zone files.
pub const LISTING_TZ: &str = "UTC0";

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

/// The time rule, when the approval has an end time, and the cut rule.
/// Only the output chain counts what they refuse.
fn end_rules(end: Option<i64>, output: bool) -> Vec<Value> {
    let counted = |name: &str, mut expr: Vec<Value>| {
        if output {
            expr.push(json!({"counter":name}));
        }
        expr.push(json!({"drop":null}));
        Value::Array(expr)
    };
    let mut rules = Vec::new();
    if let Some(second) = end {
        rules.push(counted(
            LATE_COUNTER,
            vec![matcher(">=", meta("time"), json!(second))],
        ));
    }
    rules.push(counted(
        CUT_COUNTER,
        vec![matcher("==", meta("mark"), json!(format!("@{CUT_SET}")))],
    ));
    rules
}

/// The table, its chains (without rules), counters and sets. With
/// `record_contacts`, also the chain, counter and sets of
/// [`crate::contacts`].
fn declarations(timed: bool, with: Instrumentation) -> Table {
    let mut table = Table::default();
    let mut counters = vec![String::from("dropped"), CUT_COUNTER.to_owned()];
    if timed {
        counters.push(LATE_COUNTER.to_owned());
    }
    counters.extend((0..with.grant_counters).map(crate::grant_use::counter_name));
    if with.record_contacts {
        counters.push(contacts::COUNTER.to_owned());
        table.objects.insert(
            (String::from("chain"), contacts::CHAIN.to_owned()),
            json!({"family":"inet","table":TABLE,"name":contacts::CHAIN}),
        );
        table.chains.insert(contacts::CHAIN.to_owned(), Vec::new());
    }
    table.objects.extend(counters.into_iter().map(|name| {
        let fields = json!({"family":"inet","table":TABLE,"name":name});
        ((String::from("counter"), name), fields)
    }));
    // An empty set: nft prints no `elem` for it (see `parse`). With
    // --on-drop it has a declared size.
    let mut cut =
        json!({"family":"inet","table":TABLE,"name":CUT_SET,"type":"mark","flags":["dynamic"]});
    if with.tripwire {
        cut["size"] = json!(CUT_SET_SIZE);
    }
    table.objects.extend([
        object("table", TABLE, json!({"family":"inet","name":TABLE})),
        object("set", CUT_SET, cut),
    ]);
    for hook in ["output", "input", "forward"] {
        table.objects.insert(
            (String::from("chain"), hook.to_owned()),
            json!({"family":"inet","table":TABLE,"name":hook,"type":"filter","hook":hook,"prio":0,"policy":"drop"}),
        );
        table.chains.insert(hook.to_owned(), Vec::new());
    }
    let mut sets = vec![("drop4", "ipv4_addr"), ("drop6", "ipv6_addr")];
    if with.record_contacts {
        // Empty at start, like the cut set (see `parse`).
        sets.extend([
            (contacts::SEEN4, "ipv4_addr"),
            (contacts::SEEN6, "ipv6_addr"),
        ]);
    }
    for (name, kind) in sets {
        table.objects.insert(
            (String::from("set"), name.to_owned()),
            json!({"family":"inet","table":TABLE,"name":name,"type":[kind,"inet_proto","inet_service"],
                "size":DROP_SET_SIZE,"flags":["dynamic"],"stmt":[{"counter":null}]}),
        );
    }
    table
}

fn expected(approval: &Approval, with: Instrumentation) -> Table {
    let end = end_second(approval);
    let mut table = declarations(end.is_some(), with);
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
    for (family, addr, len) in [("ip", "127.0.0.0", 8), ("ip6", "::1", 128)] {
        output.push(json!([
            matcher("==", meta("oif"), json!("lo")),
            matcher("==", payload(family, "daddr"), prefix(addr.parse().expect("loopback address"), len)),
            {"accept":null}
        ]));
    }
    output.push(json!([
        matcher("==", payload("ip6", "daddr"), prefix("ff02::".parse().expect("multicast address"), 16)),
        icmp_type(&[131, 133, 143]),
        {"drop":null}
    ]));
    output.extend(end_rules(end, true));
    output.push(established.clone());
    output.push(neighbour_discovery.clone());
    output.extend(approval.rules().iter().enumerate().map(|(index, rule)| {
        let counter = (index < with.grant_counters).then(|| crate::grant_use::counter_name(index));
        grant(approval, rule, counter.as_deref(), with.record_contacts)
    }));
    for (family, set) in [("ip", "@drop4"), ("ip6", "@drop6")] {
        for (operation, port) in [("==", payload("th", "dport")), ("!=", json!(0))] {
            output.push(json!([
                matcher(operation, meta("l4proto"), members([json!(6), json!(17)])),
                {"set":{"op":"add","elem":{"concat":[payload(family,"daddr"),meta("l4proto"),port]},"set":set}}
            ]));
        }
    }
    // With --on-drop: the tripwire, and a drop instead of the reject (see
    // `ruleset::render_instrumented`).
    if with.tripwire {
        output.push(json!([{"set":{"op":"add","elem":CUT_MARK,"set":format!("@{CUT_SET}")}}]));
    }
    output.push(json!([{"counter":"dropped"}]));
    output.push(if with.tripwire {
        json!([{"drop":null}])
    } else {
        json!([{"reject":{"type":"icmpx","expr":3}}])
    });
    let input = table.chains.get_mut("input").expect("declared input chain");
    input.push(json!([matcher("==", meta("iif"), json!("lo")), {"accept":null}]));
    input.extend(end_rules(end, false));
    input.extend([established, neighbour_discovery]);
    if let Some(chain) = table.chains.get_mut(contacts::CHAIN) {
        chain.push(json!([{"counter":contacts::COUNTER}]));
        for (family, set) in [("ip", contacts::SEEN4), ("ip6", contacts::SEEN6)] {
            chain.push(json!([
                {"set":{"op":"add","elem":{"concat":[payload(family,"daddr"),meta("l4proto"),payload("th","dport")]},"set":format!("@{set}")}}
            ]));
        }
        chain.push(json!([{"accept":null}]));
    }
    table
}

/// A grant rule: its matches, its counter with `--report-grant-use`, and
/// `accept`, or with `record_contacts` `goto contacted`.
fn grant(
    approval: &Approval,
    rule: &AllowRule,
    counter: Option<&str>,
    record_contacts: bool,
) -> Value {
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
    if record_contacts {
        expr.push(json!({"goto":{"target":contacts::CHAIN}}));
    } else {
        expr.push(json!({"accept":null}));
    }
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

/// The second a `meta time` date names. nft prints the date in its own
/// local time zone, which is [`LISTING_TZ`] for the listings playpen reads,
/// so the date is read as UTC. `None` for any other spelling.
fn utc_second(date: &str) -> Option<i64> {
    let format = time::macros::format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    time::PrimitiveDateTime::parse(date, format)
        .ok()
        .map(|t| t.assume_utc().unix_timestamp())
}

fn normalize_expression(expr: &mut Value) {
    // Normalize only recognized fields, preserving all other data so a
    // material addition or unfamiliar shape fails the comparison.
    if let Some(m) = expr.get_mut("match").and_then(Value::as_object_mut) {
        let left = m.get("left").cloned().unwrap_or(Value::Null);
        let Some(right) = m.get_mut("right") else {
            return;
        };
        if left == meta("time") {
            if let Some(second) = right.as_str().and_then(utc_second) {
                *right = json!(second);
            }
        } else if left == json!({"ct":{"key":"state"}}) {
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
                // An element in the cut set would close all egress from the
                // start: the run would start with a firewall that is not
                // the one rendered. One in a set of contacted destinations
                // would report a destination nothing contacted.
                if kind == "set"
                    && [CUT_SET, contacts::SEEN4, contacts::SEEN6].contains(&name.as_str())
                    && data.contains_key("elem")
                {
                    return Err(format!("the {name} set is not empty"));
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
    verify_instrumented(json, approval, Instrumentation::default())
}

/// [`verify_policy`] for the ruleset of
/// [`crate::ruleset::render_instrumented`] with the same instrumentation.
///
/// # Errors
/// As [`verify_policy`].
pub fn verify_instrumented(
    json: &str,
    approval: &Approval,
    with: Instrumentation,
) -> Result<(), String> {
    let value: Value =
        serde_json::from_str(json).map_err(|e| format!("nft printed invalid JSON: {e}"))?;
    let actual = parse(value)?;
    let expected = expected(approval, with);
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
    use crate::approval::{EndsAt, parse_allow};

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
            Err("output rule 7 differs".into())
        );
    }

    const UNTIL: &str = include_str!("../tests/fixtures/nft/until.json");
    const UNTIL_KOLKATA: &str = include_str!("../tests/fixtures/nft/until-kolkata.json");

    fn until(end: &str) -> Approval {
        let rule = parse_allow("192.0.2.0/30:8000-8002/tcp").expect("valid fixture grant");
        Approval::new(
            vec![rule],
            Some(EndsAt::parse(end).expect("valid fixture end")),
        )
    }

    #[test]
    fn time_rule_is_read_back_in_utc_to_the_second() {
        verify_policy(UNTIL, &until("2026-12-01T12:34:56Z")).expect("recorded time rule");
        // The rule starts at the end time rounded down to the second.
        verify_policy(UNTIL, &until("2026-12-01T12:34:56.900Z")).expect("same second");
        verify_policy(UNTIL, &until("2026-12-01T18:04:56+05:30")).expect("same moment");
        for other in ["2026-12-01T12:34:55Z", "2026-12-01T12:34:57Z"] {
            assert_eq!(
                verify_policy(UNTIL, &until(other)),
                Err("input rule 2 differs".into()),
                "{other}"
            );
        }
        // A dump in another time zone names another moment.
        assert_eq!(
            verify_policy(UNTIL_KOLKATA, &until("2026-12-01T12:34:56Z")),
            Err("input rule 2 differs".into())
        );
        // Without an end time the time rule and its counter are extra.
        let rule = parse_allow("192.0.2.0/30:8000-8002/tcp").expect("valid fixture grant");
        assert!(verify_policy(UNTIL, &Approval::new(vec![rule], None)).is_err());
        // With one, a ruleset without them is refused.
        assert!(verify_policy(RULES, &until("2026-12-01T12:34:56Z")).is_err());
    }

    #[test]
    fn time_rule_must_drop_and_count_in_output_only() {
        let approval = until("2026-12-01T12:34:56Z");
        let uncounted = UNTIL.replacen(
            "\"right\": \"2026-12-01 12:34:56\"}}, {\"counter\": \"late\"}, {\"drop\": null}",
            "\"right\": \"2026-12-01 12:34:56\"}}, {\"drop\": null}",
            1,
        );
        assert_ne!(UNTIL, uncounted);
        assert_eq!(
            verify_policy(&uncounted, &approval),
            Err("output rule 4 differs".into())
        );
        let accepted = UNTIL.replacen(
            "\"right\": \"2026-12-01 12:34:56\"}}, {\"drop\": null}",
            "\"right\": \"2026-12-01 12:34:56\"}}, {\"accept\": null}",
            1,
        );
        assert_ne!(UNTIL, accepted);
        assert_eq!(
            verify_policy(&accepted, &approval),
            Err("input rule 2 differs".into())
        );
        let later = UNTIL.replace("\"op\": \">=\"", "\"op\": \">\"");
        assert_ne!(UNTIL, later);
        assert!(verify_policy(&later, &approval).is_err());
    }

    #[test]
    fn cut_rule_and_empty_cut_set_are_required() {
        let approval = approval();
        let other_set = RULES.replace("\"right\": \"@cut\"", "\"right\": \"@drop4\"");
        assert_ne!(RULES, other_set);
        assert_eq!(
            verify_policy(&other_set, &approval),
            Err("input rule 2 differs".into())
        );
        let filled = RULES.replacen(
            "\"flags\": [\"dynamic\"]}}",
            "\"flags\": [\"dynamic\"], \"elem\": [0]}}",
            1,
        );
        assert_ne!(RULES, filled);
        assert_eq!(
            verify_policy(&filled, &approval),
            Err("the cut set is not empty".into())
        );
        let wider = RULES.replacen("\"type\": \"mark\"", "\"type\": \"ipv4_addr\"", 1);
        assert_ne!(RULES, wider);
        assert!(verify_policy(&wider, &approval).is_err());
    }

    const ON_DROP: &str = include_str!("../tests/fixtures/nft/on-drop.json");
    const TRIPWIRE: Instrumentation = Instrumentation {
        grant_counters: 0,
        record_contacts: false,
        tripwire: true,
    };
    const ON_DROP_NUMERIC: &str = include_str!("../tests/fixtures/nft/on-drop-numeric.json");

    #[test]
    fn tripwire_is_read_back_only_where_it_was_asked_for() {
        let approval = until("2026-12-01T12:34:56Z");
        for json in [ON_DROP, ON_DROP_NUMERIC] {
            verify_instrumented(json, &approval, TRIPWIRE).expect("recorded tripwire");
            // Without --on-drop the tripwire is extra, and the drop is not
            // the reject.
            assert!(verify_policy(json, &approval).is_err());
        }
        // With it, a ruleset without the tripwire is refused.
        assert!(verify_instrumented(UNTIL, &approval, TRIPWIRE).is_err());
        // The tripwire must add the cut mark to the cut set, nothing else.
        for (from, to) in [
            (
                "{\"set\": {\"op\": \"add\", \"elem\": 0, \"set\": \"@cut\"}}",
                "{\"set\": {\"op\": \"add\", \"elem\": 1, \"set\": \"@cut\"}}",
            ),
            (
                "{\"set\": {\"op\": \"add\", \"elem\": 0, \"set\": \"@cut\"}}",
                "{\"set\": {\"op\": \"add\", \"elem\": {\"meta\": {\"key\": \"mark\"}}, \"set\": \"@cut\"}}",
            ),
            (
                "{\"set\": {\"op\": \"add\", \"elem\": 0, \"set\": \"@cut\"}}",
                "{\"set\": {\"op\": \"delete\", \"elem\": 0, \"set\": \"@cut\"}}",
            ),
            (
                "{\"counter\": \"dropped\"}]}}",
                "{\"counter\": \"dropped\"}, {\"set\": {\"op\": \"add\", \"elem\": 0, \"set\": \"@cut\"}}]}}",
            ),
        ] {
            let altered = ON_DROP.replacen(from, to, 1);
            assert_ne!(ON_DROP, altered, "{to}");
            assert!(
                verify_instrumented(&altered, &approval, TRIPWIRE).is_err(),
                "{to}"
            );
        }
        // The tripped set fails the start check like any filled cut set.
        let filled = ON_DROP.replacen(
            "\"flags\": [\"dynamic\"]}}",
            "\"flags\": [\"dynamic\"], \"elem\": [0]}}",
            1,
        );
        assert_ne!(ON_DROP, filled);
        assert_eq!(
            verify_instrumented(&filled, &approval, TRIPWIRE),
            Err("the cut set is not empty".into())
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

    const CONTACTS: &str = include_str!("../tests/fixtures/nft/contacts.json");

    fn contacts(json: &str, grant_counters: usize) -> Result<(), String> {
        verify_instrumented(
            json,
            &approval(),
            Instrumentation {
                grant_counters,
                record_contacts: true,
                tripwire: false,
            },
        )
    }

    #[test]
    fn readback_of_the_contacted_record_matches() {
        contacts(CONTACTS, 0).expect("recorded contacted record");
        // The record is part of the policy: neither readback passes for
        // the other.
        assert!(verify_policy(CONTACTS, &approval()).is_err());
        assert!(contacts(RULES, 0).is_err());
    }

    const CONTACTS_ON_DROP: &str = include_str!("../tests/fixtures/nft/contacts-on-drop.json");

    #[test]
    fn readback_of_the_record_and_the_tripwire_together_matches() {
        let both = Instrumentation {
            grant_counters: 0,
            record_contacts: true,
            tripwire: true,
        };
        verify_instrumented(CONTACTS_ON_DROP, &approval(), both)
            .expect("recorded record and tripwire");
        // Each is part of the policy: a readback with one of them only
        // fails for both, and this one fails for either alone.
        assert!(verify_instrumented(CONTACTS, &approval(), both).is_err());
        assert!(verify_instrumented(CONTACTS_ON_DROP, &approval(), TRIPWIRE).is_err());
        assert!(contacts(CONTACTS_ON_DROP, 0).is_err());
        // The tripwire in place, but before the record's chain is taken.
        let early = CONTACTS_ON_DROP.replacen(
            "{\"goto\": {\"target\": \"contacted\"}}",
            "{\"set\": {\"op\": \"add\", \"elem\": 0, \"set\": \"@cut\"}}, {\"goto\": {\"target\": \"contacted\"}}",
            1,
        );
        assert_ne!(CONTACTS_ON_DROP, early);
        assert_eq!(
            verify_instrumented(&early, &approval(), both),
            Err("output rule 7 differs".into())
        );
    }

    #[test]
    fn grants_must_go_to_the_record_and_the_record_must_accept() {
        let accepted = CONTACTS.replacen(
            "{\"goto\": {\"target\": \"contacted\"}}",
            "{\"accept\": null}",
            1,
        );
        assert_ne!(CONTACTS, accepted);
        assert_eq!(contacts(&accepted, 0), Err("output rule 7 differs".into()));
        let elsewhere = CONTACTS.replacen("\"target\": \"contacted\"", "\"target\": \"input\"", 1);
        assert_eq!(contacts(&elsewhere, 0), Err("output rule 7 differs".into()));
        let dropped = CONTACTS.replace(
            "\"chain\": \"contacted\", \"handle\": 38, \"expr\": [{\"accept\": null}]",
            "\"chain\": \"contacted\", \"handle\": 38, \"expr\": [{\"drop\": null}]",
        );
        assert_ne!(CONTACTS, dropped);
        assert_eq!(
            contacts(&dropped, 0),
            Err("contacted rule 4 differs".into())
        );
        // The addition in the grant rule itself, as first tried: a full set
        // would end the grant and drop the packet.
        let inline = CONTACTS.replacen(
            "{\"goto\": {\"target\": \"contacted\"}}",
            "{\"set\": {\"op\": \"add\", \"elem\": {\"concat\": [{\"payload\": {\"protocol\": \"ip\", \"field\": \"daddr\"}}, {\"meta\": {\"key\": \"l4proto\"}}, {\"payload\": {\"protocol\": \"th\", \"field\": \"dport\"}}]}, \"set\": \"@seen4\"}}, {\"accept\": null}",
            1,
        );
        assert_eq!(contacts(&inline, 0), Err("output rule 7 differs".into()));
        // The sets swapped between the families.
        let swapped = CONTACTS
            .replace("\"set\": \"@seen4\"", "\"set\": \"@seenX\"")
            .replace("\"set\": \"@seen6\"", "\"set\": \"@seen4\"");
        assert_eq!(
            contacts(&swapped, 0),
            Err("contacted rule 2 differs".into())
        );
    }

    #[test]
    fn the_contacted_sets_must_start_empty() {
        let filled = CONTACTS.replacen(
            "\"name\": \"seen4\", \"table\": \"playpen\", \"type\": [\"ipv4_addr\", \"inet_proto\", \"inet_service\"], \"handle\": 10, \"size\": 1024, \"flags\": [\"dynamic\"]",
            "\"name\": \"seen4\", \"table\": \"playpen\", \"type\": [\"ipv4_addr\", \"inet_proto\", \"inet_service\"], \"handle\": 10, \"size\": 1024, \"flags\": [\"dynamic\"], \"elem\": []",
            1,
        );
        assert_ne!(CONTACTS, filled);
        assert_eq!(
            contacts(&filled, 0),
            Err("the seen4 set is not empty".into())
        );
        let smaller = CONTACTS.replacen(
            "\"handle\": 11, \"size\": 1024",
            "\"handle\": 11, \"size\": 2",
            1,
        );
        assert_ne!(CONTACTS, smaller);
        assert!(contacts(&smaller, 0).is_err());
    }

    #[test]
    fn a_grant_counter_comes_before_the_goto() {
        let counter = "{\"counter\": {\"family\": \"inet\", \"name\": \"grant_1\", \"table\": \"playpen\", \"handle\": 99, \"packets\": 0, \"bytes\": 0}},\n  {\"set\": {\"family\": \"inet\", \"name\": \"drop4\"";
        let declared = CONTACTS.replacen(
            "{\"set\": {\"family\": \"inet\", \"name\": \"drop4\"",
            counter,
            1,
        );
        let goto = "{\"goto\": {\"target\": \"contacted\"}}";
        let before = declared.replacen(goto, &format!("{{\"counter\": \"grant_1\"}}, {goto}"), 1);
        contacts(&before, 1).expect("counter, then goto");
        let after = declared.replacen(goto, &format!("{goto}, {{\"counter\": \"grant_1\"}}"), 1);
        assert_eq!(contacts(&after, 1), Err("output rule 7 differs".into()));
        assert!(contacts(&before, 0).is_err());
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
