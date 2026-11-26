//! Public help is generated from the same command tree that parses invocations.
use std::ffi::{OsStr, OsString};
use std::io::IsTerminal as _;

use clap::{ColorChoice, Command, CommandFactory, FromArgMatches, ValueEnum, error::ErrorKind};
use serde_json::json;

use super::{Cli, EXIT_REFUSED};

pub(super) const ROOT: &str = "Examples
  playpen doctor --mode offline
  playpen plan --no-network -- printf hello
  playpen run --no-network -- printf hello

Agent workflow
  Start with playpen help run --format json. Check the host with doctor, review the command and grants with plan, then pass its digest to run --expect-plan. Arguments after -- belong to the workload.
  Use --format json for machine output. For run, read startup_evidence before retrying. A child can itself exit 1 or 2.";
pub(super) const RUN: &str = "Examples
  playpen run --no-network -- printf hello
  playpen run --format json --no-network -- printf hello
  playpen run --no-network --private-tty -- bash -i
  playpen run --allow 192.0.2.10:443/tcp --report run.json -- true
  playpen run --pass ~/passes/engagement.pass.toml --pass-hosts -- curl -sS https://app.example.test/
  playpen run --allow 192.0.2.10:443/tcp --capture run.pcap --report run.json -- true
  playpen run --allow 192.0.2.10:443/tcp --live-drops --events-fd 3 -- ./scan 3> >(jq -c .)
  playpen run --allow 192.0.2.0/24:8000-8099/tcp --report-contacts --report wide.json -- true
  playpen run --allow 192.0.2.10:443/tcp --on-drop stop --report run.json -- ./scan

Agent workflow
  Choose --no-network, explicit --allow grants, or --pass FILE. Use plan with the same command and policy first, then pass its digest to --expect-plan.
  Nothing is resolved: there is no DNS inside. With --pass, --pass-hosts maps the hostname of each selected single-address destination to its address. --host NAME=ADDR maps any other name to an approved address.
  Keep a pass in a directory of its own, outside the working directory: playpen hides that directory from the command, or makes it read-only when it holds other files, so the command cannot put back a pass the owner revoked. A pass in or above the working directory, or inside an --expose path, is refused (exit 2). --pass-dir-writable runs anyway, with a NOTE.
  In JSON mode the final report goes to stdout and workload output streams to stderr. With --report FILE, the file gets the report and stdout belongs to the workload.
  To learn of a refused destination while the command runs, read --events-fd: one denied record per new dropped destination, within about 2 s. --live-drops also prints the first 8 on stderr. The report's dropped field remains the complete record.
  --on-drop cut makes the first dropped packet close all egress but loopback in the firewall itself; --on-drop stop also stops the command within about 2 s plus the 3 s grace and never exits 0. The report's egress_cut names the destination. mDNS, LLMNR, a client's own DNS server, a cloud metadata probe and IPv6 attempts trip it too, so try a run without it first.
  --capture FILE keeps a pcap of what crossed the sandbox's outside interface, and the report gives its size and sha256. It holds payloads, credentials sent in clear included: keep it like the pass.
  --report-contacts lists in the report each address, protocol and port the command reached through a grant. playpen suggest REPORT turns that list into the narrowest --allow and --host options.
  Read startup_evidence before retrying a job with side effects. not_started permits a retry after fixing the cause. unknown requires investigation.
  --fail-on-drop counts each packet to another host that no grant allows, with --no-network too. Loopback, lookups the DNS stub answered and host Unix sockets are not counted. If the report's dropped_error or uncounted is set, the count is incomplete and drop_assertion is unknown.
  A policy refusal exits 2, a setup error exits 1, and a launched command normally supplies its own exit status. --fail-on-drop and --on-drop stop can turn child success into exit 1.";
pub(super) const PLAN: &str = "Examples
  playpen plan --no-network -- printf hello
  playpen plan --format json --allow 192.0.2.10:443/tcp -- true

Agent workflow
  Read plan and digest from stdout, then use playpen run --expect-plan DIGEST with the same policy and argv. Planning starts no workload, probes no host capabilities and writes no report. Exit 0 means the plan validated. Invalid policy exits 2.";
pub(super) const RULES: &str = "Examples
  playpen rules --allow 192.0.2.10:443/tcp
  playpen rules --allow 192.0.2.0/24:8000-8099/tcp --report-contacts
  playpen rules --allow 192.0.2.10:443/tcp --on-drop cut
  playpen rules --format json

Agent workflow
  Inspect allowed and ruleset before a launch. Empty grants show the baseline firewall. Use plan to bind grants to a specific command. Exit 0 means rendered. Invalid grants exit 2. `rules --pass FILE` is the check for a hand-written pass: it lists each problem on its own line.";
pub(super) const POLICY: &str = r#"Examples
  printf '%s\n' '[{"address":"192.0.2.10","port":443,"protocol":"tcp","expect":"allow"}]' > cases.json
  playpen policy-test cases.json --allow 192.0.2.10:443/tcp --format json

Agent workflow
  Supply a JSON array of literal address, port, protocol (tcp or udp), expect (allow or deny), and optional name. Inspect cases for individual decisions. The check sends no packets. Exit 0 means all matched, 1 means a mismatch, and 2 means invalid inputs."#;
pub(super) const COMPARE: &str = "Examples
  playpen run --no-network --report before.json -- true
  playpen run --no-network --report after.json -- true
  playpen compare before.json after.json --format json

Agent workflow
  Supply two full private run reports. Read policy, evidence, new_denials and new_unmapped_lookups together. Exit 1 means new denials or new lookups of names without a --host mapping. Otherwise exit 2 means policy changed, evidence was incomplete or input was invalid. Exit 0 means comparable policy with complete evidence and nothing new.";
pub(super) const SUGGEST: &str = "Examples
  playpen run --allow 192.0.2.0/24:8000-8099/tcp --report-contacts --report wide.json -- ./scan
  playpen suggest wide.json
  playpen suggest wide.json --format json

Agent workflow
  Supply one full private report of a run with --report-contacts. Text output prints one option per line on stdout, ready for playpen run, and the caution on stderr. In JSON, read source, allow, hosts and no_network: each allow entry is one contacted address, port and protocol, never wider than the run's own grants. With source pass the entries are destinations for a narrower pass from its owner, not --allow options. One quiet run does not show that a later run needs less: review the list before narrowing an approval.
  Exit 0 means printed. Exit 2 means the report's outcome is not ran, the record is missing, truncated or unavailable, or the report is invalid.";
pub(super) const DOCTOR: &str = "Examples
  playpen doctor --mode offline --format json
  playpen doctor --mode egress

Agent workflow
  Check the mode your command needs. Offline requires nft and exercises private loopback. Egress also needs pasta. Read capability.status and probes before scheduling. Exit 0 means available and 1 means unavailable or a check failed.";
pub(super) const QUALIFY: &str = "Examples
  playpen qualify --list --format json
  playpen qualify --require offline-command --format json
  playpen qualify --source . --require terminal-pty-input --format json

Agent workflow
  Read scenarios for IDs, prerequisites, evidence and status. Repeat --require for every scenario your job needs. Give --source only for a trusted Playpen checkout whose Cargo tests you want to execute.
  Exit 0 means requirements met, 1 means a failed check or unsupported required scenario, and 2 means an invalid request.";
pub(super) const VERSION: &str = "Examples
  playpen version --format json

Agent workflow
  Include version in bug reports and host qualification records. Exit 0 means the version was printed.";
pub(super) const HELP: &str = "Examples
  playpen help
  playpen help plan --format json

Agent workflow
  Read commands from root help, then request a command by name to see its arguments, examples and workflow. Exit 2 means an unknown topic.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Text,
    Pretty,
    Json,
}

impl Format {
    pub(super) fn resolve(explicit: Option<Self>, json: bool) -> Result<Self, String> {
        if json {
            return Ok(Self::Json);
        }
        if let Some(format) = explicit {
            return Ok(format);
        }
        match std::env::var_os("FORMAT") {
            Some(value) => Self::from_str(&value.to_string_lossy(), false).map_err(|_| {
                format!(
                    "invalid FORMAT={}; choose text, pretty or json, or override it with --format",
                    value.display()
                )
            }),
            None if std::io::stdout().is_terminal() => Ok(Self::Pretty),
            None => Ok(Self::Text),
        }
    }
}

pub fn error(format: Format, kind: &str, message: &str, status: i32) -> i32 {
    if format == Format::Json {
        // A refusal that lists problems gives the heading as the message and
        // the problems, one string each, as an array.
        let (heading, problems) = crate::pass::split_problems(message);
        let mut error = json!({"type":kind,"message":heading});
        if !problems.is_empty() {
            error["problems"] = json!(problems);
        }
        sayln!("{}", json!({"error":error,"exit_code":status,"advice":[]}));
    } else {
        sayln!("playpen: {message}");
    }
    status
}

// Clap short-circuits on help, version and parse errors without returning
// matches. Read only presentation flags on the playpen side of the delimiter.
fn presentation(argv: &[OsString]) -> (Option<Format>, bool, bool) {
    let mut tokens = argv
        .iter()
        .skip(1)
        .map(OsString::as_os_str)
        .take_while(|s| *s != "--");
    let (mut format, mut json, mut plain) = (None, false, false);
    while let Some(arg) = tokens.next() {
        match arg.to_str() {
            Some("--json") => json = true,
            Some("--no-color") => plain = true,
            Some("--format") => {
                format = tokens
                    .next()
                    .and_then(OsStr::to_str)
                    .and_then(|s| Format::from_str(s, false).ok());
            }
            Some(s) if s.starts_with("--format=") => format = Format::from_str(&s[9..], false).ok(),
            _ => {}
        }
    }
    (format, json, plain)
}

/// Removes the hidden subcommands from the suggestions of an unknown
/// subcommand: clap offers them, and the operator is not told they exist.
fn drop_hidden_suggestions(e: &mut clap::Error) {
    use clap::error::{ContextKind, ContextValue};
    if e.kind() != ErrorKind::InvalidSubcommand {
        return;
    }
    let root = Cli::command();
    let Some(ContextValue::Strings(list)) = e.get(ContextKind::SuggestedSubcommand) else {
        return;
    };
    let kept: Vec<String> = list
        .iter()
        .filter(|name| {
            root.find_subcommand(name.as_str())
                .is_none_or(|c| !c.is_hide_set())
        })
        .cloned()
        .collect();
    if kept.len() == list.len() {
        return;
    }
    if kept.is_empty() {
        e.remove(ContextKind::SuggestedSubcommand);
        // Clap starts a tips paragraph even for an empty list of tips, which
        // leaves a second blank line once the suggestion is gone.
        if matches!(e.get(ContextKind::Suggested), Some(ContextValue::StyledStrs(t)) if t.is_empty())
        {
            e.remove(ContextKind::Suggested);
        }
    } else {
        e.insert(
            ContextKind::SuggestedSubcommand,
            ContextValue::Strings(kept),
        );
    }
}

pub(super) fn parse(argv: &[OsString]) -> Result<Cli, i32> {
    let (explicit, json, plain) = presentation(argv);
    let mut app = Cli::command();
    if plain
        || std::env::var_os("NO_COLOR").is_some()
        || std::env::var_os("TERM").as_deref() == Some(OsStr::new("dumb"))
    {
        app = app.color(ColorChoice::Never);
    }
    let result = app
        .try_get_matches_from(argv)
        .and_then(|mut matches| Cli::from_arg_matches_mut(&mut matches));
    result.map_err(|mut e| {
        let format = Format::resolve(explicit, json).unwrap_or(Format::Text);
        drop_hidden_suggestions(&mut e);
        match e.kind() {
            ErrorKind::DisplayVersion => version(format),
            ErrorKind::DisplayHelp if format == Format::Json => {
                // Clap has already validated the command path up to the help flag.
                // Global format values cannot be public subcommand names.
                let tree = Cli::command();
                let topic = argv
                    .iter()
                    .skip(1)
                    .map(OsString::as_os_str)
                    .take_while(|token| *token != "--help" && *token != "-h" && *token != "--")
                    .filter_map(OsStr::to_str)
                    .find(|token| tree.find_subcommand(token).is_some());
                help(topic, format)
            }
            ErrorKind::DisplayHelp => {
                let _ = e.print();
                0
            }
            _ if format == Format::Json => error(
                format,
                "invalid-arguments",
                &e.render().to_string(),
                EXIT_REFUSED,
            ),
            _ => {
                let _ = e.print();
                EXIT_REFUSED
            }
        }
    })
}

pub(super) fn help(topic: Option<&str>, format: Format) -> i32 {
    let mut root = Cli::command().color(ColorChoice::Never);
    root.build();
    let mut cmd = match topic {
        None => root,
        Some(name) => match root.find_subcommand(name).filter(|c| !c.is_hide_set()) {
            Some(command) => command.clone(),
            None => {
                return error(
                    format,
                    "unknown-command",
                    &format!("unknown help topic {name:?}; run playpen help for public commands"),
                    EXIT_REFUSED,
                );
            }
        },
    };
    if format == Format::Json {
        let options: Vec<_> = cmd
            .get_arguments()
            .filter(|arg| !arg.is_hide_set())
            .map(argument_description)
            .collect();
        let commands: Vec<_> = cmd
            .get_subcommands()
            .filter(|c| !c.is_hide_set())
            .map(command_description)
            .collect();
        let guide = cmd
            .get_after_help()
            .map_or_else(String::new, ToString::to_string);
        let (examples, workflow) = guide
            .split_once("\n\nAgent workflow\n")
            .unwrap_or((&guide, ""));
        let examples: Vec<_> = examples.lines().skip(1).map(str::trim).collect();
        let usage = cmd.render_usage().to_string();
        let document = json!({
            "command": cmd.get_bin_name().unwrap_or_else(|| cmd.get_name()),
            "description": cmd.get_about().map(ToString::to_string),
            "usage": usage,
            "arguments": options,
            "commands": commands,
            "examples": examples,
            "workflow": workflow.trim(),
            "advice": [],
        });
        outln!("{document}");
    } else {
        out!("{}", cmd.render_long_help());
    }
    0
}

fn argument_description(arg: &clap::Arg) -> serde_json::Value {
    let values: Vec<_> = arg
        .get_possible_values()
        .into_iter()
        .filter(|v| !v.is_hide_set())
        .map(|v| v.get_name().to_owned())
        .collect();
    json!({
        "name": arg.get_id().as_str(),
        "long": arg.get_long(),
        "short": arg.get_short(),
        "required": arg.is_required_set(),
        "takes_value": arg.get_action().takes_values(),
        "repeatable": matches!(arg.get_action(), clap::ArgAction::Append | clap::ArgAction::Count),
        "after_delimiter": arg.is_last_set(),
        "value_names": arg.get_value_names().unwrap_or_default().iter().map(clap::builder::Str::as_str).collect::<Vec<_>>(),
        "help": arg.get_help().map(ToString::to_string),
        "values": values,
        "defaults": arg.get_default_values().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>(),
    })
}

fn command_description(cmd: &Command) -> serde_json::Value {
    json!({"name":cmd.get_name(),"description":cmd.get_about().map(ToString::to_string)})
}

pub(super) fn version(format: Format) -> i32 {
    let version = env!("CARGO_PKG_VERSION");
    if format == Format::Json {
        outln!(
            "{}",
            json!({"name":"playpen","version":version,"advice":[]})
        );
    } else {
        outln!("playpen {version}");
    }
    0
}
