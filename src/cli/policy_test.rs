//! Offline assertions about the outbound application tuple filter.
use super::{EXIT_REFUSED, Format, ONLY_WITHOUT_PASS, PASS_AND_ALLOW, discovery};
use crate::approval::{Approval, Proto, parse_allow, parse_literal_addr};
use crate::pass;
use clap::Args;
use serde::Deserialize;
use std::io::Read as _;
use std::net::IpAddr;
use std::path::PathBuf;
use time::OffsetDateTime;

#[derive(Debug, Args)]
pub(super) struct PolicyTestArgs {
    /// JSON file containing an array of cases.
    cases: PathBuf,
    /// Approved literal grant, repeatable.
    #[arg(long)]
    allow: Vec<String>,
    /// A hallpass pass.
    #[arg(long)]
    pass: Option<PathBuf>,
    /// Narrow the pass to selected labels.
    #[arg(long)]
    only: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: Option<String>,
    address: String,
    protocol: String,
    port: u16,
    expect: String,
}

fn evaluate(args: &PolicyTestArgs, format: Format) -> Result<bool, String> {
    let policy = if let Some(path) = &args.pass {
        if !args.allow.is_empty() {
            return Err(PASS_AND_ALLOW.into());
        }
        pass::load(path, &args.only, OffsetDateTime::now_utc())?.approval
    } else {
        if !args.only.is_empty() {
            return Err(ONLY_WITHOUT_PASS.into());
        }
        if args.allow.is_empty() {
            return Err("give --pass or at least one --allow".into());
        }
        Approval::new(
            args.allow
                .iter()
                .map(|s| parse_allow(s).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?,
            None,
        )
    };
    let file = std::fs::File::open(&args.cases).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 1_048_576 {
        return Err("cases exceed 1 MiB".into());
    }
    let cases: Vec<Case> = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if cases.is_empty() {
        return Err("at least one case is required".into());
    }
    let mut checked = Vec::new();
    let mut invalid = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        match check(case) {
            Ok(c) => checked.push(c),
            Err(e) => invalid.push(format!("case {} {e}", index + 1)),
        }
    }
    if !invalid.is_empty() {
        return Err(invalid.join("; "));
    }
    let mut results = Vec::new();
    let mut matched_count = 0_usize;
    for (index, (case, (ip, proto, expected))) in cases.iter().zip(&checked).enumerate() {
        let (ip, proto, expected) = (*ip, *proto, *expected);
        let (actual, reason) = if ip.is_loopback() {
            (
                true,
                "the sandbox's own loopback, always allowed".to_string(),
            )
        } else {
            let matched = policy.matching_grant(ip, proto, case.port);
            let excluded = || {
                policy
                    .rules()
                    .iter()
                    .find(|r| r.proto == proto && r.ports.contains(case.port) && r.net.contains(ip))
            };
            let reason = match (matched, excluded()) {
                (Some(r), _) => format!("granted by {r}"),
                (_, Some(r)) => format!("excluded network/broadcast address in {r}"),
                _ => "no matching grant".into(),
            };
            (matched.is_some(), reason)
        };
        let verdict = if actual { "allow" } else { "deny" };
        let ok = actual == expected;
        matched_count += usize::from(ok);
        if format == Format::Json {
            results.push(serde_json::json!({"index":index + 1, "name":case.name, "address":ip, "port":case.port, "protocol":case.protocol, "expect":case.expect, "actual":verdict, "ok":ok, "reason":reason}));
        } else {
            let label = case
                .name
                .clone()
                .unwrap_or_else(|| format!("case {}", index + 1));
            if ok {
                outln!("{label}: ok, {verdict} ({reason})");
            } else {
                outln!(
                    "{label}: expected {}, got {verdict} ({reason})",
                    case.expect
                );
            }
        }
    }
    let total = cases.len();
    if format == Format::Json {
        outln!(
            "{}",
            serde_json::json!({"ok":matched_count == total,"matched":matched_count,"mismatched":total - matched_count,"total":total,"cases":results,"advice":[]})
        );
    } else {
        outln!("{matched_count} of {total} cases matched");
    }
    Ok(matched_count != total)
}

/// Validate one case: its address, protocol, port and expectation.
fn check(case: &Case) -> Result<(IpAddr, Proto, bool), String> {
    // An IPv4-mapped IPv6 address is sent as IPv4, so test the IPv4 address.
    let ip = parse_literal_addr(&case.address)
        .map_err(|e| format!("has an invalid address: {e}"))?
        .to_canonical();
    if ip.is_unspecified() || ip.is_multicast() || case.port == 0 {
        return Err("is outside outbound application tuples (unspecified, multicast and port 0 cannot be tested)".into());
    }
    let proto = match case.protocol.as_str() {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        other => return Err(format!("has invalid protocol {other:?} (use tcp or udp)")),
    };
    let expected = match case.expect.as_str() {
        "allow" => true,
        "deny" => false,
        other => {
            return Err(format!(
                "has invalid expectation {other:?} (use allow or deny)"
            ));
        }
    };
    Ok((ip, proto, expected))
}
pub(super) fn run(args: &PolicyTestArgs, format: Format) -> i32 {
    match evaluate(args, format) {
        Ok(false) => 0,
        Ok(true) => 1,
        Err(e) => discovery::error(
            format,
            "invalid-policy-test",
            &format!("invalid policy test: {e}"),
            EXIT_REFUSED,
        ),
    }
}
