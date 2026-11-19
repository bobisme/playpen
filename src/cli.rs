//! Command-line interface.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::approval::{Approval, EndsAt, parse_allow, parse_literal_addr};
use crate::report::{Outcome, Report, text_summary};
use crate::resolver::{HostEntry, check_hosts, parse_host};
use crate::sandbox::{self, CommandStatus, Events, Plan, RunError};

/// Exit status when playpen refuses by policy.
pub const EXIT_REFUSED: i32 = 2;
/// Exit status for any other playpen error.
pub const EXIT_ERROR: i32 = 1;

/// Run a command with its network egress limited to approved literal addresses.
#[derive(Debug, Parser)]
#[command(name = "playpen", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run COMMAND with egress limited to the --allow destinations.
    Run(RunArgs),
    /// Print the nftables ruleset that would be loaded; sends and creates nothing.
    Rules {
        /// Approved destination: ADDR:PORT/PROTO, ADDR:FROM-TO/PROTO or NET/PREFIX:PORTS/PROTO.
        #[arg(long = "allow", value_name = "SPEC")]
        allow: Vec<String>,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Check that this machine can run playpen, and say exactly what is missing.
    Doctor {
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Checks run inside the sandbox by doctor and the tests.
    #[command(hide = true)]
    Probe {
        #[command(subcommand)]
        what: ProbeCmd,
    },
}

#[derive(Debug, Subcommand)]
enum ProbeCmd {
    /// Start listeners, then try to reach targets.
    Reach {
        #[arg(long = "serve")]
        serve: Vec<String>,
        #[arg(long = "try")]
        tries: Vec<String>,
    },
    /// Try everything the command must not be able to do.
    Privs {
        #[arg(long, default_value = "nft")]
        nft: String,
    },
    /// Resolve a name with the system resolver.
    Resolve { name: String },
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    /// Approved destination: ADDR:PORT/PROTO, ADDR:FROM-TO/PROTO or
    /// NET/PREFIX:PORTS/PROTO; IPv6 in brackets. Repeatable.
    #[arg(long = "allow", value_name = "SPEC")]
    allow: Vec<String>,
    /// Make NAME resolve to ADDR inside the sandbox (ADDR must be approved). Repeatable.
    #[arg(long = "host", value_name = "NAME=ADDR")]
    host: Vec<String>,
    /// When the approval ends (RFC 3339 with offset); the command is stopped then.
    #[arg(long, value_name = "RFC3339")]
    until: Option<String>,
    /// No network at all: only loopback inside the sandbox.
    #[arg(long)]
    no_network: bool,
    /// Also hide this host path from the command (sockets/files: bound to
    /// /dev/null; directories: an empty read-only tmpfs). Repeatable.
    #[arg(long = "hide", value_name = "PATH")]
    hide: Vec<PathBuf>,
    /// Summary format; json requires --report.
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Write the JSON summary to FILE (for every outcome, refusals included).
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,
    /// Test aid: add ADDR to the sandbox's lo before the ruleset loads.
    #[arg(long = "lo-addr", hide = true, value_name = "ADDR")]
    lo_addr: Vec<String>,
    /// The command to run, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<OsString>,
}

/// Entry point; returns the process exit status.
#[must_use]
pub fn main() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() { EXIT_REFUSED } else { 0 };
            let _ = e.print();
            return code;
        }
    };
    match cli.command {
        Cmd::Run(args) => run(&args),
        Cmd::Rules { allow, format } => rules(&allow, format),
        Cmd::Doctor { format } => crate::doctor::run(format == Format::Json),
        Cmd::Probe { what } => probe(what),
    }
}

fn rules(allow: &[String], format: Format) -> i32 {
    let mut parsed = Vec::new();
    for spec in allow {
        match parse_allow(spec) {
            Ok(r) => parsed.push(r),
            Err(e) => {
                eprintln!("playpen: refused: {e}");
                return EXIT_REFUSED;
            }
        }
    }
    let text = crate::ruleset::render(&parsed);
    match format {
        Format::Text => print!("{text}"),
        Format::Json => println!(
            "{}",
            serde_json::json!({
                "allowed": parsed.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "ruleset": text,
            })
        ),
    }
    0
}

fn probe(what: ProbeCmd) -> i32 {
    match what {
        ProbeCmd::Reach { serve, tries } => {
            let parse = |v: &[String]| -> Result<Vec<_>, String> {
                v.iter().map(|s| crate::probe::parse_target(s)).collect()
            };
            let result = parse(&serve)
                .and_then(|s| parse(&tries).map(|t| (s, t)))
                .and_then(|(s, t)| crate::probe::reach(&s, &t));
            match result {
                Ok(lines) => {
                    for l in lines {
                        println!("{l}");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("probe: {e}");
                    EXIT_ERROR
                }
            }
        }
        ProbeCmd::Privs { nft } => {
            println!("{}", crate::probe::privs(&nft));
            0
        }
        ProbeCmd::Resolve { name } => {
            println!("{}", crate::probe::resolve(&name));
            0
        }
    }
}

/// Validated run request.
struct Checked {
    approval: Approval,
    hosts: Vec<HostEntry>,
    lo_addrs: Vec<IpAddr>,
}

fn check(args: &RunArgs) -> Result<Checked, String> {
    let mut rules = Vec::new();
    for spec in &args.allow {
        rules.push(parse_allow(spec).map_err(|e| e.to_string())?);
    }
    if args.no_network && !rules.is_empty() {
        return Err("--no-network and --allow contradict each other; give one or the other".into());
    }
    if !args.no_network && rules.is_empty() {
        return Err(
            "no --allow was given. An empty allow list is almost always a mistake: give the approved destinations with --allow ADDR:PORT/PROTO, or use --no-network to run with loopback only"
                .into(),
        );
    }
    let ends_at = args
        .until
        .as_deref()
        .map(EndsAt::parse)
        .transpose()
        .map_err(|e| e.to_string())?;
    let approval = Approval { rules, ends_at };
    approval
        .check_active(time::OffsetDateTime::now_utc())
        .map_err(|e| e.to_string())?;
    let mut hosts = Vec::new();
    for h in &args.host {
        hosts.push(parse_host(h).map_err(|e| e.to_string())?);
    }
    check_hosts(&hosts, &approval).map_err(|e| e.to_string())?;
    let mut lo_addrs = Vec::new();
    for a in &args.lo_addr {
        lo_addrs.push(parse_literal_addr(a).map_err(|e| format!("--lo-addr {a:?}: {e}"))?);
    }
    if args.format == Format::Json && args.report.is_none() {
        return Err(
            "--format json writes the summary to a file; give it with --report FILE".into(),
        );
    }
    Ok(Checked {
        approval,
        hosts,
        lo_addrs,
    })
}

struct StderrEvents {
    start_line: String,
    until: Option<String>,
}

impl Events for StderrEvents {
    fn starting(&mut self) {
        eprintln!("{}", self.start_line);
    }
    fn until_reached(&mut self) {
        eprintln!(
            "playpen: the approval ended at {}; sending SIGTERM to the command (SIGKILL in {} s)",
            self.until.as_deref().unwrap_or("?"),
            sandbox::GRACE.as_secs()
        );
    }
}

fn start_line(c: &Checked, network: bool) -> String {
    let until = c.approval.ends_at.map_or_else(
        || "with no time limit".to_owned(),
        |e| format!("until {}", e.to_rfc3339()),
    );
    let names = if c.hosts.is_empty() {
        "no DNS".to_owned()
    } else {
        let list: Vec<String> = c
            .hosts
            .iter()
            .map(|h| format!("{}={}", h.name, h.addr))
            .collect();
        format!("no DNS, names {}", list.join(", "))
    };
    if network {
        let list: Vec<String> = c.approval.rules.iter().map(ToString::to_string).collect();
        format!(
            "playpen: allowing only {} {until} ({names}); everything else is dropped",
            list.join(", ")
        )
    } else {
        format!("playpen: no network, loopback only, {until} ({names})")
    }
}

fn base_report(args: &RunArgs) -> Report {
    Report {
        playpen_version: env!("CARGO_PKG_VERSION"),
        outcome: Outcome::Refused,
        message: None,
        command: args
            .command
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect(),
        allowed: args.allow.clone(),
        hosts: args.host.clone(),
        until: args.until.clone(),
        network: if args.no_network { "none" } else { "pasta" },
        exit_code: None,
        signal: None,
        stopped_by_until: false,
        playpen_exit_status: EXIT_REFUSED,
        dropped: None,
        dropped_error: None,
    }
}

fn write_report(file: Option<&mut File>, report: &Report) {
    if let Some(f) = file {
        let text = serde_json::to_string_pretty(report).unwrap_or_default();
        if let Err(e) = f
            .write_all(text.as_bytes())
            .and_then(|()| f.write_all(b"\n"))
        {
            eprintln!("playpen: could not write the report: {e}");
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "a linear sequence of steps, each mapping to a report field"
)]
fn run(args: &RunArgs) -> i32 {
    let mut report = base_report(args);
    let mut report_file = match &args.report {
        Some(p) => match File::create(p) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!(
                    "playpen: refused: cannot create the report file {}: {e}; nothing was run",
                    p.display()
                );
                return EXIT_REFUSED;
            }
        },
        None => None,
    };
    let checked = match check(args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("playpen: refused: {e}");
            if !e.contains("nothing was run") {
                eprintln!("playpen: nothing was run");
            }
            report.message = Some(e);
            write_report(report_file.as_mut(), &report);
            return EXIT_REFUSED;
        }
    };
    report.allowed = checked
        .approval
        .rules
        .iter()
        .map(ToString::to_string)
        .collect();
    report.until = checked.approval.ends_at.map(EndsAt::to_rfc3339);
    let fail = |report: &mut Report, file: Option<&mut File>, outcome, msg: String| {
        eprintln!("playpen: {msg}");
        report.outcome = outcome;
        report.message = Some(msg);
        report.playpen_exit_status = EXIT_ERROR;
        write_report(file, report);
        EXIT_ERROR
    };
    let Some(nft) = crate::tools::nft() else {
        return fail(
            &mut report,
            report_file.as_mut(),
            Outcome::NotStarted,
            "nft (nftables) was not found; install it or set PLAYPEN_NFT; nothing was run".into(),
        );
    };
    let pasta = if args.no_network {
        PathBuf::from("pasta")
    } else if let Some(p) = crate::tools::pasta() {
        p
    } else {
        return fail(
            &mut report,
            report_file.as_mut(),
            Outcome::NotStarted,
            "pasta (from the passt package) was not found; install it, set PLAYPEN_PASTA, or use --no-network; nothing was run".into(),
        );
    };
    let mut events = StderrEvents {
        start_line: start_line(&checked, !args.no_network),
        until: report.until.clone(),
    };
    let plan = Plan {
        approval: checked.approval,
        hosts: checked.hosts,
        network: !args.no_network,
        lo_addrs: checked.lo_addrs,
        hide: args.hide.clone(),
        command: args.command.clone(),
        nft,
        pasta,
    };
    let result = match sandbox::run(&plan, &mut events) {
        Ok(r) => r,
        Err(e @ RunError::NotStarted(_)) => {
            return fail(
                &mut report,
                report_file.as_mut(),
                Outcome::NotStarted,
                e.to_string(),
            );
        }
        Err(e @ RunError::Failed(_)) => {
            return fail(
                &mut report,
                report_file.as_mut(),
                Outcome::Error,
                e.to_string(),
            );
        }
    };
    report.outcome = Outcome::Ran;
    report.stopped_by_until = result.stopped_by_until;
    let code = match result.status {
        CommandStatus::Exited(c) => {
            report.exit_code = Some(c);
            c
        }
        CommandStatus::Signaled(s) => {
            report.signal = Some(s);
            128 + s
        }
    };
    report.playpen_exit_status = code;
    match result.drops {
        Ok(d) => report.dropped = Some(d),
        Err(e) => report.dropped_error = Some(e),
    }
    eprint!("{}", text_summary(&report));
    write_report(report_file.as_mut(), &report);
    code
}
