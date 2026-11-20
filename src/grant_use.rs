//! Bounded first-match observations for explicit grants.

use serde::Serialize;
use serde_json::Value;

use crate::approval::{AllowRule, Approval};
use crate::ruleset::TABLE;

/// At most this many accept rules get counters in a single run.
pub const LIMIT: usize = 256;

/// The staged nft object name and its stable report identifier.
pub fn counter_name(index: usize) -> String {
    format!("grant_{}", index + 1)
}

pub fn counter_count(approval: &Approval, enabled: bool) -> usize {
    if enabled {
        approval.rules().len().min(LIMIT)
    } else {
        0
    }
}

pub fn read_packets(json: &str, count: usize) -> Vec<Option<u64>> {
    let Ok(value) = serde_json::from_str::<Value>(json) else {
        return vec![None; count];
    };
    let mut packets = vec![None; count];
    let mut seen = vec![false; count];
    for counter in value["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("counter"))
    {
        if counter["family"] != "inet" || counter["table"] != TABLE {
            continue;
        }
        let Some(index) = counter["name"].as_str().and_then(|name| {
            let index = name
                .strip_prefix("grant_")?
                .parse::<usize>()
                .ok()?
                .checked_sub(1)?;
            (index < count && counter_name(index) == name).then_some(index)
        }) else {
            continue;
        };
        packets[index] = if seen[index] {
            None
        } else {
            counter["packets"].as_u64()
        };
        seen[index] = true;
    }
    packets
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantUse {
    /// Observations in the same order as the loaded grants.
    pub grants: Vec<GrantObservation>,
    /// Rules after the instrumented prefix are omitted.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantObservation {
    /// Stable within the same ordered policy.
    pub id: String,
    /// Canonical rule specification, including its port range.
    pub rule: String,
    /// Source label when the grant came from a pass.
    pub label: Option<String>,
    pub packets: Option<u64>,
    pub state: GrantState,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    Observed,
    NoObservedMatch,
    ShadowedOrAmbiguous,
    Unavailable,
}

impl GrantUse {
    pub fn summarize(rules: &[AllowRule], labels: &[String], counters: &[Option<u64>]) -> Self {
        let grants = rules
            .iter()
            .take(LIMIT)
            .enumerate()
            .map(|(index, rule)| {
                let packets = counters.get(index).copied().flatten();
                let state = match packets {
                    None => GrantState::Unavailable,
                    Some(0) if rules[..index].iter().any(|earlier| overlap(rule, earlier)) => {
                        GrantState::ShadowedOrAmbiguous
                    }
                    Some(0) => GrantState::NoObservedMatch,
                    Some(_) => GrantState::Observed,
                };
                GrantObservation {
                    id: counter_name(index),
                    rule: rule.to_string(),
                    label: labels.get(index).cloned(),
                    packets,
                    state,
                }
            })
            .collect();
        Self {
            grants,
            truncated: rules.len() > LIMIT,
        }
    }
}

fn overlap(a: &AllowRule, b: &AllowRule) -> bool {
    // Ignore edge exclusions here to classify conservatively.
    let first = a.ports.first().max(b.ports.first());
    let last = a.ports.last().min(b.ports.last());
    a.proto == b.proto && first <= last && a.net.overlaps(b.net)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::parse_allow;

    #[test]
    fn observation_and_counter_installation_are_bounded() {
        let grant = parse_allow("192.0.2.1:9101/tcp").expect("valid grant");
        let approval = Approval::new(vec![grant; LIMIT + 1], None);
        assert_eq!(counter_count(&approval, false), 0);
        assert_eq!(counter_count(&approval, true), LIMIT);
        let report = GrantUse::summarize(approval.rules(), &[], &[]);
        assert!(report.truncated);
        assert_eq!(report.grants.len(), LIMIT);
        assert_eq!(report.grants[LIMIT - 1].id, counter_name(LIMIT - 1));
    }
}
