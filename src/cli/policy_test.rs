//! Offline assertions about the outbound application tuple filter.
use super::{EXIT_REFUSED, ONLY_WITHOUT_PASS, PASS_AND_ALLOW};
use crate::approval::{Approval, Proto, parse_allow, parse_literal_addr};
use crate::pass;
use clap::Args;
use serde::Deserialize;
use std::io::Read as _;
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

fn evaluate(args: &PolicyTestArgs) -> Result<bool, String> {
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
    let mut failed = false;
    for (index, case) in cases.iter().enumerate() {
        let ip = parse_literal_addr(&case.address).map_err(|e| e.to_string())?;
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || case.port == 0 {
            return Err(format!(
                "case {} is outside outbound application tuples",
                index + 1
            ));
        }
        let proto = match case.protocol.as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => return Err(format!("case {} has invalid protocol", index + 1)),
        };
        let expected = match case.expect.as_str() {
            "allow" => true,
            "deny" => false,
            _ => return Err(format!("case {} has invalid expectation", index + 1)),
        };
        let matched = policy.matching_grant(ip, proto, case.port);
        let actual = matched.is_some();
        if actual != expected {
            failed = true;
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
            println!(
                "{}: expected {}, got {} ({reason})",
                case.name.as_deref().unwrap_or("unnamed"),
                case.expect,
                if actual { "allow" } else { "deny" }
            );
        }
    }
    Ok(failed)
}
pub(super) fn run(args: &PolicyTestArgs) -> i32 {
    match evaluate(args) {
        Ok(false) => 0,
        Ok(true) => 1,
        Err(e) => {
            eprintln!("playpen: invalid policy test: {e}");
            EXIT_REFUSED
        }
    }
}
