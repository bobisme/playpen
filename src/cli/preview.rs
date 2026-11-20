//! The reviewed launch configuration. Preserve Unix strings without losing bytes.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt as _;

use serde_json::{Value, json};

use super::{Checked, EXIT_REFUSED, Format, RunArgs, check};
use crate::approval::EndsAt;

fn unix_string(value: &OsStr) -> Value {
    value
        .to_str()
        .map_or_else(|| json!({"unix_bytes": value.as_bytes()}), |s| json!(s))
}

pub(super) fn scope(args: &RunArgs, checked: &Checked) -> Result<Value, String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("cannot resolve working directory: {e}"))?;
    let mut grants = checked.approval.rules.clone();
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
            "name_limits": p.name_limited,
        })
    });
    Ok(json!({
        "schema": "playpen.plan.v1",
        "command": args.command.iter().map(|a| unix_string(a)).collect::<Vec<_>>(),
        "cwd": unix_string(cwd.as_os_str()), "pass": pass,
        "allowed": grants.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "hosts": checked.hosts.iter().map(|h| format!("{}={}",h.name,h.addr)).collect::<Vec<_>>(),
        "until": checked.approval.ends_at.map(EndsAt::to_rfc3339),
        "network": if args.no_network { "none" } else { "pasta" },
        "loopback_addresses": checked.lo_addrs,
        "hide": paths(&args.hide), "expose": paths(&checked.exposed),
        "display": args.display, "display_paths": paths(&checked.display),
        "socket_guard": if args.without_landlock { "mounts_only" } else { "landlock" },
        "new_session": checked.new_session,
    }))
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

pub(super) fn print(args: &RunArgs) -> i32 {
    let scope = match check(args).and_then(|checked| scope(args, &checked)) {
        Ok(scope) => scope,
        Err(e) => {
            eprintln!("playpen: refused: {e}");
            return EXIT_REFUSED;
        }
    };
    let at_launch = "Helper availability, namespace setup, live pass validity and installation of the firewall are checked at launch.";
    let digest = digest(&scope);
    match args.format {
        Format::Json => println!(
            "{}",
            json!({"plan":scope, "digest":digest.to_string(), "at_launch":at_launch})
        ),
        Format::Text => {
            for (key, value) in scope.as_object().into_iter().flatten() {
                println!("{key}: {value}");
            }
            println!("digest: {digest}");
            println!("{at_launch}");
        }
    }
    0
}
