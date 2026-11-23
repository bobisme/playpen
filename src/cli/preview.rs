//! The reviewed launch configuration. Preserve Unix strings without losing bytes.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;

use serde_json::{Value, json};

use super::{Checked, EXIT_REFUSED, Format, RunArgs, check, enforce_coverage};
use crate::approval::EndsAt;

fn unix_string(value: &OsStr) -> Value {
    value
        .to_str()
        .map_or_else(|| json!({"unix_bytes": value.as_bytes()}), |s| json!(s))
}

pub(super) fn scope(args: &RunArgs, checked: &Checked) -> Result<Value, String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot resolve working directory: {e}"))?;
    let mut grants = checked.approval.rules().to_vec();
    grants.sort();
    grants.dedup();
    let paths = |v: &[std::path::PathBuf]| {
        v.iter()
            .map(|p| unix_string(p.as_os_str()))
            .collect::<Vec<_>>()
    };
    let pass = checked.from_pass.as_ref().map(|p| {
        json!({
            "file": unix_string(p.identity.file.as_os_str()), "id": p.identity.id,
            "digest": p.identity.digest.to_string(), "labels": p.identity.labels,
            "recheck_ms": p.watch.interval.as_millis(),
            "name_limits": p.name_limited, "coverage": p.coverage,
        })
    });
    let mut scope = json!({
        "schema": "playpen.plan.v1",
        "fixture": checked.fixture,
        "fail_on_drop": args.fail_on_drop,
        "instrumented_grants": args.report_grant_use.then(|| checked.approval.rules().iter()
            .take(crate::grant_use::counter_count(&checked.approval, true))
            .map(ToString::to_string).collect::<Vec<_>>()), "require_enforced": args.require_enforced,
        "command": args.command.iter().map(|a| unix_string(a)).collect::<Vec<_>>(),
        "cwd": unix_string(cwd.as_os_str()), "pass": pass,
        "allowed": grants.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "hosts": checked.host_texts(),
        "until": checked.approval.ends_at.map(EndsAt::to_rfc3339),
        "network": if args.no_network { "none" } else { "pasta" },
        "loopback_addresses": checked.lo_addrs,
        "hide": paths(&args.hide), "expose": paths(&checked.exposed),
        "display": args.display, "display_paths": paths(&checked.display),
        "socket_guard": if args.without_landlock { "mounts_only" } else { "landlock" },
        "new_session": checked.new_session,
    });
    // Keep pre-existing plan digests valid for unchanged terminal behavior.
    if args.private_tty {
        scope["private_tty"] = json!(true);
    }
    // Likewise for runs without --pass-hosts; its entries are in `hosts`.
    if args.pass_hosts {
        scope["pass_hosts"] = json!(true);
    }
    // The same for runs without a packet capture.
    if let Some(path) = &args.capture {
        scope["capture"] = unix_string(path.as_os_str());
    }
    Ok(scope)
}

fn digest(value: &Value) -> hallpass::Digest {
    hallpass::Digest::of(value.to_string().as_bytes())
}

pub(super) fn match_pin(args: &RunArgs, checked: &Checked) -> Result<(), String> {
    if let Some(expected) = args.expect_plan {
        let actual = digest(&scope(args, checked)?);
        if actual != expected {
            return Err(format!(
                "reviewed plan {expected} differs from current scope {actual}; review a new plan"
            ));
        }
    }
    Ok(())
}

pub(super) fn print(args: &RunArgs, format: Format) -> i32 {
    let scope = match check(args).and_then(|checked| {
        enforce_coverage(args, &checked)?;
        scope(args, &checked)
    }) {
        Ok(scope) => scope,
        Err(e) => {
            return super::discovery::error(
                format,
                "refused",
                &format!("refused: {e}"),
                EXIT_REFUSED,
            );
        }
    };
    let at_launch = "Helper availability, namespace setup, live pass validity and installation of the firewall are checked at launch.";
    let digest = digest(&scope);
    match format {
        Format::Json => println!(
            "{}",
            json!({"advice":[], "plan":scope, "digest":digest.to_string(), "at_launch":at_launch})
        ),
        Format::Text | Format::Pretty => {
            let sep = if format == Format::Pretty { ": " } else { "  " };
            for (key, value) in scope.as_object().into_iter().flatten() {
                println!("{key}{sep}{value}");
            }
            println!("digest{sep}{digest}");
            println!("{at_launch}");
        }
    }
    0
}
