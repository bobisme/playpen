//! `playpen resolve`: print the options that approve what names resolve to now.
use std::collections::BTreeSet;
use std::net::{IpAddr, ToSocketAddrs as _};

use clap::Args;
use serde_json::json;

use super::{EXIT_ERROR, EXIT_REFUSED, Format, discovery};
use crate::approval::parse_allow;
use crate::resolver::{parse_host, valid_hostname};

const CAUTION: &str = "these are the addresses the names have now, from this host's resolver. They change, and the resolver is trusted: check that they belong to the service before you approve them.";

#[derive(Debug, Args)]
pub(super) struct ResolveArgs {
    /// Host names to look up with this host's resolver.
    #[arg(required = true, value_name = "NAME")]
    names: Vec<String>,
    /// TCP port for the --allow lines.
    #[arg(long, value_name = "PORT", default_value_t = 443)]
    port: u16,
    /// Print IPv4 addresses only, which keeps the output short.
    #[arg(long)]
    ipv4: bool,
}

/// What the lookups gave: the options, the names that gave nothing, and notes.
#[derive(Default)]
struct Found {
    allow: Vec<String>,
    hosts: Vec<String>,
    unresolved: Vec<String>,
    notes: Vec<String>,
}

fn addresses(name: &str, port: u16) -> Result<BTreeSet<IpAddr>, String> {
    (name, port)
        .to_socket_addrs()
        .map(|found| found.map(|a| a.ip()).collect())
        .map_err(|e| e.to_string())
}

fn lookup(args: &ResolveArgs) -> Result<Found, String> {
    if args.port == 0 {
        return Err("--port 0 cannot be approved".into());
    }
    let mut found = Found::default();
    let mut allow = BTreeSet::new();
    for name in &args.names {
        if !valid_hostname(name) {
            return Err(format!(
                "{name:?} is not a plain host name (letters, digits, '-' and '.')"
            ));
        }
        let name = name.to_ascii_lowercase();
        let mut usable = 0;
        match addresses(&name, args.port) {
            Ok(set) => {
                for ip in set.into_iter().filter(|ip| !args.ipv4 || ip.is_ipv4()) {
                    let spec = if ip.is_ipv6() {
                        format!("[{ip}]:{}/tcp", args.port)
                    } else {
                        format!("{ip}:{}/tcp", args.port)
                    };
                    // Both checks are the ones run applies, so what is printed is accepted.
                    match (parse_allow(&spec), parse_host(&format!("{name}={ip}"))) {
                        (Ok(_), Ok(_)) => {
                            usable += 1;
                            allow.insert((ip, spec));
                            found.hosts.push(format!("{name}={ip}"));
                        }
                        (Err(e), _) | (_, Err(e)) => {
                            found.notes.push(format!("{name}: skipped {ip}: {e}"));
                        }
                    }
                }
            }
            Err(e) => found.notes.push(format!("{name}: {e}")),
        }
        if usable == 0 {
            found.unresolved.push(name);
        }
    }
    found.allow = allow.into_iter().map(|(_, spec)| spec).collect();
    Ok(found)
}

pub(super) fn run(args: &ResolveArgs, format: Format) -> i32 {
    let found = match lookup(args) {
        Ok(found) => found,
        Err(e) => {
            return discovery::error(
                format,
                "invalid-resolve",
                &format!("refused: {e}"),
                EXIT_REFUSED,
            );
        }
    };
    let status = if found.unresolved.is_empty() {
        0
    } else {
        EXIT_ERROR
    };
    if format == Format::Json {
        let mut advice = vec![json!({"level":"warn","type":"changes","message":CAUTION})];
        advice.extend(
            found
                .notes
                .iter()
                .map(|n| json!({"level":"info","type":"lookup","message":n})),
        );
        outln!(
            "{}",
            json!({
                "allow": found.allow, "hosts": found.hosts,
                "unresolved": found.unresolved, "advice": advice,
            })
        );
    } else {
        // Only the options go to stdout, so it can be given to run as it is.
        for spec in &found.allow {
            outln!("--allow {spec}");
        }
        for host in &found.hosts {
            outln!("--host {host}");
        }
        for note in &found.notes {
            sayln!("playpen: {note}");
        }
        for name in &found.unresolved {
            sayln!("playpen: {name} gave no address that can be approved");
        }
        sayln!("playpen: caution: {CAUTION}");
    }
    status
}
