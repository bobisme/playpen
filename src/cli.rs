//! Command-line interface.

pub(crate) mod discovery;
mod event_pipe;
mod policy_test;
mod preview;
mod resolve;
use event_pipe::EventPipe;

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use discovery::Format;
use time::OffsetDateTime;

use crate::approval::{Approval, EndsAt, parse_allow, parse_literal_addr};
use crate::capture::Capture;
use crate::pass::{
    self, FromPass, MIN_RECHECK_INTERVAL, NamedDestination, PassHosts, RECHECK_INTERVAL,
};
use crate::report::{Outcome, PassReport, Report, StartupEvidence, text_summary};
use crate::report_file::ReportFile;
use crate::resolver::{HostEntry, check_hosts, parse_host};
use crate::ruleset::Instrumentation;
use crate::sandbox::{self, CommandStatus, Events, Plan, RunError};
use crate::sockets;
use crate::tripwire::{self, OnDrop, OnDropReport};

/// Why `--pass` and `--allow` cannot be combined.
const PASS_AND_ALLOW: &str = "--pass and --allow cannot be combined: the pass lists every destination its owner approved in writing, and an --allow beside it would add a destination the owner did not approve. Add the destination to the pass (with the owner's written approval), or use --only LABEL to narrow the pass";

/// Exit status when playpen refuses by policy.
pub const EXIT_REFUSED: i32 = 2;
/// Exit status for any other playpen error.
pub const EXIT_ERROR: i32 = 1;

/// Run a command with its network egress limited to approved literal addresses.
#[derive(Debug, Parser)]
#[command(name = "playpen", version, about, disable_help_subcommand = true, after_help = discovery::ROOT)]
struct Cli {
    /// Output format. Defaults to FORMAT, then pretty on a terminal or text in a pipe.
    #[arg(long, global = true, value_enum)]
    format: Option<Format>,
    #[arg(long, global = true, hide = true, conflicts_with = "format")]
    json: bool,
    /// Disable color in CLI output.
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Test expected packet decisions without loading a firewall.
    #[command(display_order = 5, after_help = discovery::POLICY)]
    PolicyTest(policy_test::PolicyTestArgs),
    /// Compare two full reports without executing either command.
    #[command(display_order = 6, after_help = discovery::COMPARE)]
    Compare { before: PathBuf, after: PathBuf },
    /// Print the --allow and --host options for what host names resolve to now.
    #[command(display_order = 8, after_help = discovery::RESOLVE)]
    Resolve(resolve::ResolveArgs),
    /// Print the narrowest --allow and --host options for what one run contacted.
    #[command(display_order = 7, after_help = discovery::SUGGEST)]
    Suggest {
        /// A full private report of a run with --report-contacts.
        report: PathBuf,
    },
    /// Run COMMAND with egress limited to a pass's destinations or the --allow ones.
    #[command(display_order = 3, after_help = discovery::RUN)]
    Run(RunArgs),
    /// Preview the validated run without starting helpers or writing a report.
    #[command(display_order = 2, after_help = discovery::PLAN)]
    Plan(RunArgs),
    /// Print the nftables ruleset that would be loaded; sends and creates nothing.
    #[command(display_order = 4, after_help = discovery::RULES)]
    Rules {
        /// Approved destination: ADDR:PORT/PROTO, ADDR:FROM-TO/PROTO or NET/PREFIX:PORTS/PROTO.
        #[arg(long = "allow", value_name = "SPEC")]
        allow: Vec<String>,
        /// Take the destinations from this hallpass pass instead of --allow.
        #[arg(long, value_name = "FILE")]
        pass: Option<PathBuf>,
        /// With --pass: only the destination with this label. Repeatable.
        #[arg(long = "only", value_name = "LABEL")]
        only: Vec<String>,
        /// With --pass: accepted as by run. Host names change no rule, so the
        /// output is the same.
        #[arg(long, requires = "pass")]
        pass_hosts: bool,
        /// When the approval ends (RFC 3339 with offset), as with run: adds the
        /// rule that refuses all but loopback from then. With --pass it can only
        /// be earlier than the pass's window end.
        #[arg(long, value_name = "RFC3339")]
        until: Option<String>,
        /// The ruleset run loads with --report-contacts: each grant goes to a
        /// chain that records its destination, then accepts.
        #[arg(long)]
        report_contacts: bool,
        /// As with run: the first refused packet closes all egress, and is
        /// dropped instead of rejected. cut and stop load the same ruleset.
        #[arg(long, value_enum, value_name = "ACTION")]
        on_drop: Option<OnDrop>,
    },
    /// Check that this machine can run playpen, and say exactly what is missing.
    #[command(display_order = 1, after_help = discovery::DOCTOR)]
    Doctor {
        /// Capability to demonstrate (offline avoids the pasta dependency).
        #[arg(long, value_enum, default_value = "egress")]
        mode: crate::doctor::Mode,
    },
    /// Run native sandbox qualification scenarios and report what executed.
    #[command(display_order = 9, after_help = discovery::QUALIFY)]
    Qualify {
        /// List scenario IDs and prerequisites without executing any probes or tests.
        #[arg(long, conflicts_with_all = ["source", "required"])]
        list: bool,
        /// Explicit trusted source tree for integration-test scenarios.
        #[arg(long, value_name = "PATH")]
        source: Option<PathBuf>,
        /// A scenario that this qualification job requires to execute.
        #[arg(long = "require", value_name = "SCENARIO")]
        required: Vec<String>,
    },
    /// Show usage, examples and the suggested workflow for a public command.
    #[command(display_order = 10, after_help = discovery::HELP)]
    Help { command: Option<String> },
    /// Print the installed Playpen version.
    #[command(display_order = 11, after_help = discovery::VERSION)]
    Version,
    /// Checks run inside the sandbox by doctor and the tests.
    #[command(hide = true)]
    Probe {
        #[command(subcommand)]
        what: ProbeCmd,
    },
}

#[derive(Debug, Subcommand)]
enum ProbeCmd {
    /// Serve the private HTTP fixture passed on standard input.
    HttpFixture,
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
    /// Send one DNS message, given in hex, to the stub at 127.0.0.1 port
    /// 53 and describe the reply.
    Dns {
        #[arg(long)]
        tcp: bool,
        message: String,
    },
    /// Listen on Unix sockets, then connect to Unix sockets (@NAME:
    /// abstract) and close at once.
    Unix {
        #[arg(long = "listen")]
        listen: Vec<String>,
        #[arg(long = "try")]
        tries: Vec<String>,
    },
    /// Send one datagram by address to a Unix datagram socket.
    UnixSend { path: String },
    /// Rename and hard-link a file, and rename a directory, into another
    /// directory below DIR (default: the temporary directory).
    Reparent { dir: Option<PathBuf> },
    /// Take a descriptor passed over the Unix socket at PATH and send a
    /// datagram to ADDR:PORT through it.
    UnixRecvFd { path: String, to: String },
    /// Try to point the socket on standard output at TARGET instead;
    /// the result goes to standard error.
    StdoutReconnect { target: String },
    /// List the open file descriptors.
    Fds,
    /// List interfaces visible in this network namespace.
    Interfaces,
    /// Read this network namespace's VSOCK mode, create an `AF_VSOCK` socket
    /// and, with --try PORT, connect it to CID 1 at PORT.
    Vsock {
        #[arg(long = "try", value_name = "PORT")]
        port: Option<u32>,
    },
    /// Try TIOCSTI on standard input and opening /dev/tty.
    Tty,
    /// Count deliveries of SIGUSR1 until SIGTERM.
    Signals,
    /// Listen on ADDR:PORT/tcp (or /udp) for MS milliseconds; print the
    /// connections (or datagrams, with the wall-clock time).
    Listen {
        target: String,
        #[arg(long, default_value_t = 5000)]
        ms: u64,
    },
    /// Send a numbered datagram to ADDR:PORT/udp every MS milliseconds
    /// until killed; print each result with the wall-clock time.
    Send {
        target: String,
        #[arg(long, default_value_t = 50)]
        every_ms: u64,
    },
}

#[derive(Debug, clap::Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent command-line switches"
)]
struct RunArgs {
    /// Load a Hallpass approval. Stop on expiry, revocation, or withdrawal of a selected grant.
    /// Cannot be combined with --allow.
    #[arg(help_heading = "Network policy", long, value_name = "FILE")]
    pass: Option<PathBuf>,
    /// With --pass: use only the destination with this label. Repeatable.
    #[arg(help_heading = "Network policy", long = "only", value_name = "LABEL")]
    only: Vec<String>,
    /// Approved destination: ADDR:PORT/PROTO, ADDR:FROM-TO/PROTO or
    /// NET/PREFIX:PORTS/PROTO; IPv6 in brackets. Repeatable.
    #[arg(help_heading = "Network policy", long = "allow", value_name = "SPEC")]
    allow: Vec<String>,
    /// Make NAME resolve to ADDR inside the sandbox (ADDR must be approved). Repeatable.
    #[arg(
        help_heading = "Network policy",
        long = "host",
        value_name = "NAME=ADDR"
    )]
    host: Vec<String>,
    /// With --pass: make the hostname of each selected single-address destination
    /// resolve to its address inside the sandbox. Looks nothing up, grants nothing;
    /// --host for the same name wins.
    #[arg(help_heading = "Network policy", long, requires = "pass")]
    pass_hosts: bool,
    /// With --pass: leave the pass's directory writable by the command. By
    /// default it is read-only inside (hidden if it holds only the pass), and
    /// a pass in or above the working directory is refused. With this, an edit
    /// that saves a new pass lets the command put back an unrevoked one.
    #[arg(help_heading = "Network policy", long, requires = "pass")]
    pass_dir_writable: bool,
    /// With --pass: serve the pass to the command over one Unix socket, path in
    /// `PLAYPEN_PASS_BROKER` (protocol pass-broker-v1). playpen reads the pass and
    /// records the command's spends in its ledger and the hallpass witness; the
    /// command gets no write access to the pass, ledger, witness or state directory,
    /// which is hidden.
    #[arg(
        help_heading = "Network policy",
        long,
        requires = "pass",
        conflicts_with = "pass_dir_writable"
    )]
    pass_broker: bool,
    /// When the approval ends (RFC 3339 with offset); the command is stopped
    /// then. With --pass it can only be earlier than the pass's window end.
    #[arg(help_heading = "Network policy", long, value_name = "RFC3339")]
    until: Option<String>,
    /// Allow only private loopback. No DNS or external network: a packet to
    /// any other host is dropped and counted, as with a network.
    #[arg(help_heading = "Network policy", long)]
    no_network: bool,
    /// At the first packet the firewall drops, close all egress but loopback:
    /// cut lets the command run on, stop also stops it (SIGTERM, 3 s, SIGKILL;
    /// learned within 2 s). Off by default: mDNS and LLMNR lookups, a client's
    /// own DNS server, a cloud metadata probe or an IPv6 try trip it too.
    #[arg(
        help_heading = "Network policy",
        long,
        value_enum,
        value_name = "ACTION"
    )]
    on_drop: Option<OnDrop>,
    /// Serve one literal HTTP fixture on private loopback in offline mode.
    #[arg(
        help_heading = "Launch and reporting",
        long,
        requires = "no_network",
        value_name = "FILE"
    )]
    fixture: Option<PathBuf>,
    /// Also hide this host path from the command (sockets/files: bound to
    /// /dev/null; directories: an empty read-only tmpfs). Repeatable.
    #[arg(help_heading = "Host access", long = "hide", value_name = "PATH")]
    hide: Vec<PathBuf>,
    /// Let the command reach this host socket, or every socket below this
    /// directory. Host Unix sockets are unreachable otherwise. Repeatable.
    #[arg(help_heading = "Host access", long = "expose", value_name = "PATH")]
    expose: Vec<PathBuf>,
    /// Let graphical programs reach the display: expose the Wayland and X11
    /// sockets the environment names, and the X authority file. An X11
    /// server lets any client type into other windows; off by default.
    #[arg(help_heading = "Host access", long)]
    display: bool,
    /// Run on a kernel without Landlock ABI 9: hide host sockets by mounts
    /// only (under /run, /tmp, /var/tmp and the runtime directory). Sockets
    /// elsewhere, and ones created after the start, stay reachable.
    #[arg(help_heading = "Host access", long)]
    without_landlock: bool,
    /// Run the command in a new session with no controlling terminal, so
    /// it cannot type into the caller's terminal. Automatic on kernels that
    /// allow TIOCSTI; then Ctrl-C still reaches the command, but programs
    /// cannot open /dev/tty.
    #[arg(help_heading = "Host access", long)]
    new_session: bool,
    /// Give the command a private controlling terminal with job control and one
    /// signal route. Requires exclusive keyboard input from a foreground controlling
    /// terminal. Stdin can come from a pipe or file.
    #[arg(help_heading = "Host access", long, conflicts_with = "new_session")]
    private_tty: bool,
    /// Write lifecycle JSON lines to an inherited pipe above stderr.
    #[arg(help_heading = "Launch and reporting", long, value_name = "FD")]
    events_fd: Option<i32>,
    /// Refuse pass terms that require an external enforcer.
    #[arg(help_heading = "Network policy", long)]
    require_enforced: bool,
    /// Require the effective scope to match the digest from playpen plan.
    #[arg(help_heading = "Launch and reporting", long, value_name = "SHA256")]
    expect_plan: Option<hallpass::Digest>,
    /// Exit 1 if the firewall dropped a packet, or cannot say. It counts each
    /// packet to another host that no grant allows, --no-network included;
    /// loopback, lookups the DNS stub answered and host Unix sockets are not
    /// counted. Unreadable counters or a family with no route make it unknown.
    #[arg(help_heading = "Launch and reporting", long)]
    fail_on_drop: bool,
    /// Print each new dropped destination on stderr while the command runs
    /// (read every 2 s; the first 8, then one line that says there are more,
    /// then the first 8 new addresses after that).
    /// --events-fd gets a denied record for each, with or without this option.
    #[arg(help_heading = "Launch and reporting", long)]
    live_drops: bool,
    /// Include bounded first-match grant packet counts in the private report.
    #[arg(
        help_heading = "Launch and reporting",
        long,
        conflicts_with = "shareable_report"
    )]
    report_grant_use: bool,
    /// Record each address, protocol and port the command opened a flow to
    /// through a grant, in the private report's contacted (1024 per address
    /// family), for playpen suggest.
    #[arg(
        help_heading = "Launch and reporting",
        long,
        conflicts_with = "shareable_report"
    )]
    report_contacts: bool,
    /// Write only the shareable allowlisted fields to the report.
    #[arg(help_heading = "Launch and reporting", long)]
    shareable_report: bool,
    /// Write the JSON summary to FILE (for every outcome, refusals included).
    #[arg(help_heading = "Launch and reporting", long, value_name = "FILE")]
    report: Option<PathBuf>,
    /// Write a pcap of every packet that crosses the sandbox's outside
    /// interface to FILE, a new file (mode 0600). It holds what was sent,
    /// credentials sent in clear included. Not with --no-network.
    #[arg(help_heading = "Launch and reporting", long, value_name = "FILE")]
    capture: Option<PathBuf>,
    /// Test aid: add ADDR to the sandbox's lo before the ruleset loads.
    #[arg(long = "lo-addr", hide = true, value_name = "ADDR")]
    lo_addr: Vec<String>,
    /// Test aid: re-read the pass every MS milliseconds (50 up to the
    /// default interval; never longer).
    #[arg(long = "pass-recheck-ms", hide = true, value_name = "MS")]
    pass_recheck_ms: Option<u64>,
    /// The command to run, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<OsString>,
}

/// Entry point; returns the process exit status.
#[must_use]
pub fn main() -> i32 {
    let argv: Vec<_> = std::env::args_os().collect();
    let cli = match discovery::parse(&argv) {
        Ok(cli) => cli,
        Err(status) => return status,
    };
    // Internal subprocess protocols have a fixed wire format of their own.
    if let Some(Cmd::Probe { what }) = cli.command {
        return probe(what);
    }
    let format = match Format::resolve(cli.format, cli.json) {
        Ok(format) => format,
        Err(message) => {
            return discovery::error(Format::Text, "invalid-format", &message, EXIT_REFUSED);
        }
    };
    cli.command.map_or_else(
        || discovery::help(None, format),
        |cmd| dispatch(cmd, format),
    )
}

fn dispatch(cmd: Cmd, format: Format) -> i32 {
    match cmd {
        Cmd::Help { command } => discovery::help(command.as_deref(), format),
        Cmd::Version => discovery::version(format),
        Cmd::Run(args) => run(&args, format),
        Cmd::PolicyTest(args) => policy_test::run(&args, format),
        Cmd::Plan(args) => preview::print(&args, format),
        Cmd::Resolve(args) => resolve::run(&args, format),
        Cmd::Compare { before, after } => crate::compare::run_formatted(&before, &after, format),
        Cmd::Suggest { report } => crate::suggest::run_formatted(&report, format),
        Cmd::Rules {
            allow,
            pass,
            only,
            until,
            report_contacts,
            on_drop,
            ..
        } => rules(
            &allow,
            pass.as_deref(),
            &only,
            until.as_deref(),
            report_contacts,
            on_drop,
            format,
        ),
        Cmd::Doctor { mode } => crate::doctor::run_formatted(mode, format),
        Cmd::Qualify { list: true, .. } => crate::qualification::list(format),
        Cmd::Qualify {
            source, required, ..
        } => crate::qualification::run_formatted(&required, source.as_deref(), format),
        Cmd::Probe { what } => probe(what),
    }
}

fn rules(
    allow: &[String],
    pass_file: Option<&Path>,
    only: &[String],
    until: Option<&str>,
    report_contacts: bool,
    on_drop: Option<OnDrop>,
    format: Format,
) -> i32 {
    let refuse =
        |e: &str| discovery::error(format, "refused", &format!("refused: {e}"), EXIT_REFUSED);
    let now = OffsetDateTime::now_utc();
    let until = match until.map(EndsAt::parse).transpose() {
        Ok(until) => until,
        Err(e) => return refuse(&e.to_string()),
    };
    let mut notes = Vec::new();
    let (mut approval, identity) = if let Some(path) = pass_file {
        if !allow.is_empty() {
            return refuse(PASS_AND_ALLOW);
        }
        match pass::load(path, only, now) {
            Ok(p) => {
                notes = pass::unenforced_notes(&p);
                (p.approval, Some(p.identity))
            }
            Err(e) => return refuse(&e),
        }
    } else {
        if !only.is_empty() {
            return refuse(ONLY_WITHOUT_PASS);
        }
        let parsed = match allow
            .iter()
            .map(|spec| parse_allow(spec))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(parsed) => parsed,
            Err(e) => return refuse(&e.to_string()),
        };
        (Approval::new(parsed, None), None)
    };
    if let Some(until) = until {
        if let Some(id) = &identity
            && let Err(e) = check_until_in_pass(until, id.valid_until)
        {
            return refuse(&e);
        }
        approval.ends_at = Some(until);
    }
    if let Err(e) = approval.check_active(now) {
        return refuse(&e.to_string());
    }
    let with = Instrumentation {
        record_contacts: report_contacts,
        tripwire: on_drop.is_some(),
        ..Instrumentation::default()
    };
    let text = crate::ruleset::render_instrumented(&approval, with);
    match format {
        Format::Text | Format::Pretty => {
            for note in &notes {
                sayln!("playpen: NOTE: {note}");
            }
            out!("{text}");
        }
        Format::Json => {
            let mut out = serde_json::json!({
                "allowed": approval.rules().iter().map(ToString::to_string).collect::<Vec<_>>(),
                "pass": identity.as_ref().map(pass_report),
                "until": approval.ends_at.map(EndsAt::to_rfc3339),
                "ruleset": text, "notes": notes, "advice": [],
            });
            if let Some(on_drop) = on_drop {
                out["on_drop"] = serde_json::json!(on_drop);
            }
            outln!("{out}");
        }
    }
    0
}

const ONLY_WITHOUT_PASS: &str = "--only narrows the destinations of a pass; it needs --pass FILE";

fn pass_report(id: &pass::PassIdentity) -> PassReport {
    PassReport {
        file: id.file.display().to_string(),
        id: Some(id.id.clone()),
        name: Some(id.name.clone()),
        owner: Some(id.owner.clone()),
        digest: Some(id.digest.to_string()),
        valid_until: Some(hallpass::stamp(id.valid_until)),
        labels: id.labels.clone(),
        directory: None,
        broker: None,
    }
}

fn print_probe_lines(result: Result<Vec<serde_json::Value>, String>) -> i32 {
    match result {
        Ok(lines) => {
            for line in lines {
                outln!("{line}");
            }
            0
        }
        Err(e) => {
            sayln!("probe: {e}");
            EXIT_ERROR
        }
    }
}

fn probe(what: ProbeCmd) -> i32 {
    match what {
        ProbeCmd::HttpFixture => match crate::fixture::serve() {
            Ok(()) => 0,
            Err(e) => {
                sayln!("fixture: {e}");
                EXIT_ERROR
            }
        },
        ProbeCmd::Reach { serve, tries } => {
            let parse = |v: &[String]| -> Result<Vec<_>, String> {
                v.iter().map(|s| crate::probe::parse_target(s)).collect()
            };
            let result = parse(&serve)
                .and_then(|s| parse(&tries).map(|t| (s, t)))
                .and_then(|(s, t)| crate::probe::reach(&s, &t));
            print_probe_lines(result)
        }
        ProbeCmd::Privs { nft } => {
            outln!("{}", crate::probe::privs(&nft));
            0
        }
        ProbeCmd::Resolve { name } => {
            outln!("{}", crate::probe::resolve(&name));
            0
        }
        ProbeCmd::Dns { tcp, message } => {
            outln!("{}", crate::probe::dns(&message, tcp));
            0
        }
        ProbeCmd::Unix { listen, tries } => print_probe_lines(crate::probe::unix(&listen, &tries)),
        ProbeCmd::Fds => {
            outln!("{}", crate::probe::fds());
            0
        }
        ProbeCmd::Interfaces => {
            outln!("{}", crate::probe::interfaces());
            0
        }
        ProbeCmd::Vsock { port } => {
            outln!("{}", crate::probe::vsock(port));
            0
        }
        ProbeCmd::UnixSend { path } => {
            outln!("{}", crate::probe::unix_send(&path));
            0
        }
        ProbeCmd::Reparent { dir } => {
            outln!("{}", crate::probe::reparent(dir.as_deref()));
            0
        }
        ProbeCmd::UnixRecvFd { path, to } => match to.parse() {
            Ok(to) => {
                outln!("{}", crate::probe::unix_recv_fd(&path, to));
                0
            }
            Err(e) => {
                sayln!("probe: {to:?}: {e}");
                EXIT_ERROR
            }
        },
        ProbeCmd::StdoutReconnect { target } => {
            sayln!("{}", crate::probe::stdout_reconnect(&target));
            0
        }
        ProbeCmd::Tty => {
            outln!("{}", crate::probe::tty());
            0
        }
        ProbeCmd::Signals => match crate::probe::signals() {
            Ok(v) => {
                outln!("{v}");
                0
            }
            Err(e) => {
                sayln!("probe: {e}");
                EXIT_ERROR
            }
        },
        traffic @ (ProbeCmd::Listen { .. } | ProbeCmd::Send { .. }) => probe_traffic(traffic),
    }
}

/// `probe listen` and `probe send`: traffic to or from a fixture.
fn probe_traffic(what: ProbeCmd) -> i32 {
    let result = match what {
        ProbeCmd::Listen { target, ms } => crate::probe::parse_target(&target).and_then(|t| {
            if t.udp {
                crate::probe::listen_udp(t, ms)
            } else {
                crate::probe::listen_tcp(t, ms)
            }
        }),
        ProbeCmd::Send { target, every_ms } => crate::probe::parse_target(&target)
            .and_then(|t| {
                if t.udp {
                    crate::probe::send_udp(t, Duration::from_millis(every_ms))
                } else {
                    Err(format!("{target:?}: probe send sends UDP only"))
                }
            })
            .map(|never| match never {}),
        _ => Err("not a traffic probe".into()),
    };
    match result {
        Ok(v) => {
            outln!("{v}");
            0
        }
        Err(e) => {
            sayln!("probe: {e}");
            EXIT_ERROR
        }
    }
}

/// Validated run request.
struct Checked {
    fixture: Option<crate::fixture::Fixture>,
    new_session: bool,
    approval: Approval,
    /// `--host`.
    hosts: Vec<HostEntry>,
    /// What `--pass-hosts` takes from the pass; `None` without it.
    pass_hosts: Option<PassHosts>,
    lo_addrs: Vec<IpAddr>,
    from_pass: Option<FromPass>,
    /// With `--pass`: what the command can do in the pass's directory.
    pass_dir: Option<PassDirView>,
    /// With `--pass-broker`: the hallpass state directory.
    broker: Option<BrokerView>,
    /// Every exposed path, canonical (`--expose` and `--display`).
    exposed: Vec<PathBuf>,
    /// The display sockets among them.
    display: Vec<PathBuf>,
}

/// With `--pass-broker`: the hallpass state directory the broker writes
/// the witness in, which the command must not reach.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BrokerView {
    /// As the environment names it (`.../hallpass`).
    state: PathBuf,
    /// Hidden already, by `--hide` or the mount layer: nothing is added.
    hidden_already: bool,
}

/// The hallpass state directory for `--pass-broker`, or why the run is
/// refused: the directory is, or holds, the working directory, or lies in
/// an `--expose` path, so playpen cannot hide it.
fn broker_view(args: &RunArgs, exposed: &[PathBuf]) -> Result<BrokerView, String> {
    let state = crate::broker::StateGuard::path_from_env()?;
    let resolved = std::fs::canonicalize(&state).unwrap_or_else(|_| state.clone());
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|c| std::fs::canonicalize(c).ok());
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let covers: Vec<PathBuf> = sockets::covers(nix::unistd::getuid(), runtime_dir.as_deref())
        .into_iter()
        .map(|c| c.path)
        .collect();
    let hidden_already = dir_hidden(&resolved, &args.hide, &covers, exposed, cwd.as_deref());
    let shown = state.display();
    let risk = "the command could change or remove the witness the broker writes there";
    if !hidden_already {
        if let Some(c) = cwd.as_ref().filter(|c| c.starts_with(&resolved)) {
            return Err(format!(
                "--pass-broker: the hallpass state directory, {shown}, is or holds the working directory {}: {risk}, and playpen cannot hide the directory a command works in. Run from another directory, or set XDG_STATE_HOME to a directory outside it",
                c.display()
            ));
        }
        if let Some(e) = exposed.iter().find(|e| resolved.starts_with(e)) {
            return Err(format!(
                "--pass-broker: the hallpass state directory, {shown}, is inside --expose {}: {risk}. Expose less",
                e.display()
            ));
        }
    }
    Ok(BrokerView {
        state,
        hidden_already,
    })
}

/// What the command can do in the pass's directory (docs/DESIGN.md, "The
/// command and the pass file"). Each path is canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PassDirView {
    /// Hidden already, by `--hide` or by the mount layer: nothing is added.
    Hidden,
    /// It holds only the pass and playpen's own files: playpen hides it.
    HiddenByPlaypen(PathBuf),
    /// It holds other files too: playpen makes it read-only.
    ReadOnly(PathBuf),
    /// `--pass-dir-writable`: left as it is, with a NOTE.
    Writable(PathBuf),
}

impl PassDirView {
    /// The mount playpen adds, if any.
    fn guard(&self) -> Option<sandbox::DirGuard> {
        match self {
            Self::HiddenByPlaypen(dir) => Some(sandbox::DirGuard::Hidden(dir.clone())),
            Self::ReadOnly(dir) => Some(sandbox::DirGuard::ReadOnly(dir.clone())),
            Self::Hidden | Self::Writable(_) => None,
        }
    }

    /// The report's `pass.directory`.
    const fn report(&self) -> &'static str {
        match self {
            Self::Hidden | Self::HiddenByPlaypen(_) => "hidden",
            Self::ReadOnly(_) => "read_only",
            Self::Writable(_) => "writable",
        }
    }

    /// The start-line clause; none when the operator hid the directory.
    fn clause(&self) -> Option<String> {
        let (dir, what) = match self {
            Self::Hidden => return None,
            Self::HiddenByPlaypen(dir) => (dir, "hidden from the command"),
            Self::ReadOnly(dir) => (dir, "read-only for the command"),
            Self::Writable(dir) => (dir, "writable by the command, --pass-dir-writable"),
        };
        Some(format!("pass directory: {} ({what})", dir.display()))
    }
}

impl Checked {
    /// The entries from `--pass-hosts` (none without it).
    fn pass_entries(&self) -> &[pass::PassHost] {
        self.pass_hosts.as_ref().map_or(&[], |p| &p.entries)
    }

    /// Every name that resolves inside: the `--host` entries, then those
    /// from `--pass-hosts`.
    fn all_hosts(&self) -> Vec<HostEntry> {
        self.hosts
            .iter()
            .cloned()
            .chain(self.pass_entries().iter().map(|p| p.entry.clone()))
            .collect()
    }

    /// The same as text for the start line and the plan: `NAME=ADDR`, and
    /// `NAME=ADDR (pass: LABEL, ...)` for an entry from the pass.
    fn host_texts(&self) -> Vec<String> {
        self.hosts
            .iter()
            .map(|h| format!("{}={}", h.name, h.addr))
            .chain(self.pass_entries().iter().map(ToString::to_string))
            .collect()
    }
}

/// `--expose` and `--display`, checked: every path exists, none lies in a
/// `--hide` path.
fn check_exposed(args: &RunArgs) -> Result<(Vec<PathBuf>, Vec<PathBuf>), String> {
    let mut exposed = Vec::new();
    for p in &args.expose {
        exposed.push(sockets::check_expose(p)?);
    }
    let mut display = Vec::new();
    if args.display {
        let env = |k: &str| std::env::var(k).ok();
        let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        for p in sockets::display_paths(
            env("WAYLAND_DISPLAY").as_deref(),
            env("DISPLAY").as_deref(),
            env("XAUTHORITY").as_deref(),
            runtime_dir.as_deref(),
        )? {
            display.push(sockets::check_expose(&p)?);
        }
    }
    exposed.extend(display.iter().cloned());
    exposed.sort();
    exposed.dedup();
    for h in &args.hide {
        let Ok(hidden) = std::fs::canonicalize(h) else {
            continue;
        };
        if let Some(e) = exposed.iter().find(|e| e.starts_with(&hidden)) {
            return Err(format!(
                "{} is both exposed and inside --hide {}; give one or the other",
                e.display(),
                h.display()
            ));
        }
    }
    Ok((exposed, display))
}

/// The approval from `--pass`, narrowed by `--only` and `--until`.
fn check_pass(args: &RunArgs, path: &Path, now: OffsetDateTime) -> Result<FromPass, String> {
    if !args.allow.is_empty() {
        return Err(PASS_AND_ALLOW.into());
    }
    if args.no_network {
        return Err(
            "--no-network and --pass contradict each other: --no-network allows no destination at all; give one or the other"
                .into(),
        );
    }
    let mut from_pass = pass::load(path, &args.only, now)?;
    if let Some(text) = &args.until {
        let until = EndsAt::parse(text).map_err(|e| e.to_string())?;
        check_until_in_pass(until, from_pass.identity.valid_until)?;
        from_pass.approval.ends_at = Some(until);
    }
    from_pass.watch.require_enforced = args.require_enforced;
    from_pass.watch.pass_hosts = args.pass_hosts;
    if let Some(ms) = args.pass_recheck_ms {
        from_pass.watch.interval =
            Duration::from_millis(ms).clamp(MIN_RECHECK_INTERVAL, RECHECK_INTERVAL);
    }
    Ok(from_pass)
}

/// Refuses an `--until` later than the pass's `valid_until`.
fn check_until_in_pass(until: EndsAt, valid_until: OffsetDateTime) -> Result<(), String> {
    if until.at() > valid_until {
        return Err(format!(
            "--until {} is later than the pass's valid_until {}; --until can only end the run earlier than the window the owner approved. Leave --until out to run until {}",
            until.to_rfc3339(),
            hallpass::stamp(valid_until),
            hallpass::stamp(valid_until)
        ));
    }
    Ok(())
}

/// Every `--host` address, and every address `--pass-hosts` took from the
/// pass, must be in a destination of the pass that is in use. A host name
/// the pass mentions grants nothing. `pass_hosts`: the option was given, so
/// the refusal does not suggest it.
fn check_pass_hosts(
    hosts: &[HostEntry],
    from_pass: &FromPass,
    pass_hosts: bool,
) -> Result<(), String> {
    for h in hosts {
        if !from_pass.approval.covers_addr(h.addr) {
            return Err(format!(
                "--host {}={}: {} is not in any destination of the pass in use ({}), for any port, so the name would lead to an address nobody approved; map the name to an address the pass lists{}{}",
                h.name,
                h.addr,
                h.addr,
                from_pass.identity.labels.join(", "),
                from_pass.approval.edge_hint(h.addr),
                hostname_hint(&from_pass.named, &[], !pass_hosts)
            ));
        }
    }
    Ok(())
}

/// Names the pass mentions that no `--host` maps: they are not resolved.
/// With `suggest_pass_hosts`, also says that `--pass-hosts` maps the ones
/// on a single address.
fn hostname_hint(
    named: &[NamedDestination],
    hosts: &[HostEntry],
    suggest_pass_hosts: bool,
) -> String {
    let unmapped: Vec<&NamedDestination> = named
        .iter()
        .filter(|n| {
            !hosts
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case(&n.hostname))
        })
        .collect();
    if unmapped.is_empty() {
        return String::new();
    }
    let list: Vec<String> = unmapped
        .iter()
        .map(|n| {
            let addr = if n.address.is_some() {
                n.destination.clone()
            } else {
                format!("ADDR-IN-{}", n.destination)
            };
            format!("--host {}={addr} (destination {})", n.hostname, n.label)
        })
        .collect();
    let option = if suggest_pass_hosts && unmapped.iter().any(|n| n.address.is_some()) {
        "; --pass-hosts maps the name of each single-address destination to its address"
    } else {
        ""
    };
    format!(
        "; host names in the pass grant nothing and are not resolved; if the tool needs them, map them with {}{option}",
        list.join(", ")
    )
}

fn check(args: &RunArgs) -> Result<Checked, String> {
    if args.capture.is_some() && args.no_network {
        return Err(
            "--capture and --no-network contradict each other: without a network there is no pasta and no outside interface to capture; give one or the other"
                .into(),
        );
    }
    let now = OffsetDateTime::now_utc();
    let mut from_pass = None;
    let approval = if let Some(path) = &args.pass {
        let p = check_pass(args, path, now)?;
        let approval = p.approval.clone();
        from_pass = Some(p);
        approval
    } else {
        if !args.only.is_empty() {
            return Err(ONLY_WITHOUT_PASS.into());
        }
        let mut rules = Vec::new();
        for spec in &args.allow {
            rules.push(parse_allow(spec).map_err(|e| e.to_string())?);
        }
        if args.no_network && !rules.is_empty() {
            return Err(
                "--no-network and --allow contradict each other; give one or the other".into(),
            );
        }
        if !args.no_network && rules.is_empty() {
            return Err(
                "no --allow or --pass was given. An empty allow list is almost always a mistake: give the approved destinations with --pass FILE or --allow ADDR:PORT/PROTO, or use --no-network to run with loopback only"
                    .into(),
            );
        }
        let ends_at = args
            .until
            .as_deref()
            .map(EndsAt::parse)
            .transpose()
            .map_err(|e| e.to_string())?;
        Approval::new(rules, ends_at)
    };
    approval.check_active(now).map_err(|e| e.to_string())?;
    let mut hosts = Vec::new();
    for h in &args.host {
        hosts.push(parse_host(h).map_err(|e| e.to_string())?);
    }
    let mut pass_hosts = None;
    match &from_pass {
        Some(p) => {
            check_pass_hosts(&hosts, p, args.pass_hosts)?;
            if args.pass_hosts {
                let taken = pass::pass_hosts(&p.named, &hosts);
                let entries: Vec<HostEntry> =
                    taken.entries.iter().map(|h| h.entry.clone()).collect();
                check_pass_hosts(&entries, p, true)?;
                pass_hosts = Some(taken);
            }
        }
        None => check_hosts(&hosts, &approval).map_err(|e| e.to_string())?,
    }
    let mut lo_addrs = Vec::new();
    for a in &args.lo_addr {
        lo_addrs.push(parse_literal_addr(a).map_err(|e| format!("--lo-addr {a:?}: {e}"))?);
    }
    let (exposed, display) = check_exposed(args)?;
    let pass_dir = from_pass
        .as_ref()
        .map(|p| pass_dir_view(args, p, &exposed))
        .transpose()?;
    let broker = if args.pass_broker {
        Some(broker_view(args, &exposed)?)
    } else {
        None
    };
    sandbox::check_stdio(!args.without_landlock)?;
    Ok(Checked {
        fixture: args
            .fixture
            .as_deref()
            .map(crate::fixture::Fixture::load)
            .transpose()?,
        new_session: new_session(args),
        approval,
        hosts,
        pass_hosts,
        lo_addrs,
        from_pass,
        pass_dir,
        broker,
        exposed,
        display,
    })
}

/// How the command will see the pass's directory, or why the run is
/// refused: the directory is, or holds, the working directory, or an
/// `--expose` path gives the command the real directory. The command could
/// write there, and after an owner's edit that saves a new file it could
/// read the new pass and put an unrevoked one in its place.
fn pass_dir_view(
    args: &RunArgs,
    from_pass: &FromPass,
    exposed: &[PathBuf],
) -> Result<PassDirView, String> {
    let held = from_pass.watch.dir();
    let given = from_pass.identity.file.display();
    let dir = std::fs::canonicalize(held.path()).map_err(|e| {
        format!(
            "--pass {given}: cannot resolve the pass's directory {}: {e}",
            held.path().display()
        )
    })?;
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|c| std::fs::canonicalize(c).ok());
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let covers: Vec<PathBuf> = sockets::covers(nix::unistd::getuid(), runtime_dir.as_deref())
        .into_iter()
        .map(|c| c.path)
        .collect();
    if dir_hidden(&dir, &args.hide, &covers, exposed, cwd.as_deref()) {
        return Ok(PassDirView::Hidden);
    }
    if args.pass_dir_writable {
        return Ok(PassDirView::Writable(dir));
    }
    let shown = dir.display();
    let risk = "the command could write there, and after an edit that saves a new pass (sed -i and most editors do) read it and put an unrevoked one in its place before the next re-read";
    let accept = "or give --pass-dir-writable to run with that risk";
    let cwd_why = match cwd {
        Some(c) if c == dir => Some(String::from("is the working directory")),
        Some(c) if c.starts_with(&dir) => {
            Some(format!("holds the working directory {}", c.display()))
        }
        _ => None,
    };
    if let Some(why) = cwd_why {
        return Err(format!(
            "--pass {given}: the pass's directory, {shown}, {why}: {risk}. playpen cannot make the directory a command works in read-only or hide it. Move the pass to a directory of its own outside the working directory (playpen then makes that directory read-only for the command, or hides it), {accept}"
        ));
    }
    if let Some(e) = exposed.iter().find(|e| dir.starts_with(e)) {
        return Err(format!(
            "--pass {given}: the pass's directory, {shown}, is inside --expose {}: {risk}. playpen does not narrow what --expose gives the command. Move the pass to a directory of its own outside {}, hide its directory with --hide {shown}, {accept}",
            e.display(),
            e.display()
        ));
    }
    let file = held.file();
    let mut own: Vec<OsString> = vec![
        held.name().to_owned(),
        hallpass::ledger_path(&file)
            .file_name()
            .unwrap_or_default()
            .to_owned(),
    ];
    for p in [&args.report, &args.capture].into_iter().flatten() {
        if let Ok(p) = std::path::absolute(p)
            && let (Some(parent), Some(name)) = (p.parent(), p.file_name())
            && std::fs::canonicalize(parent).is_ok_and(|parent| parent == dir)
        {
            own.push(name.to_owned());
        }
    }
    Ok(if only_entries(&dir, &own) {
        PassDirView::HiddenByPlaypen(dir)
    } else {
        PassDirView::ReadOnly(dir)
    })
}

/// Whether every entry of `dir` has one of the `names`; false when it
/// cannot be listed.
fn only_entries(dir: &Path, names: &[OsString]) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries
            .map(|e| e.map(|e| e.file_name()))
            .all(|name| name.is_ok_and(|n| names.contains(&n)))
    })
}

fn enforce_coverage(args: &RunArgs, checked: &Checked) -> Result<(), String> {
    let Some(pass) = checked.from_pass.as_ref().filter(|_| args.require_enforced) else {
        return Ok(());
    };
    let c = &pass.coverage;
    if c.fully_enforced() {
        return Ok(());
    }
    let mut what = Vec::new();
    if !c.external_names.is_empty() {
        what.push(format!(
            "name restrictions on destinations: {}",
            c.external_names.join(", ")
        ));
    }
    if !c.external_ceilings.is_empty() {
        what.push(format!(
            "application ceilings: {}",
            c.external_ceilings.join(", ")
        ));
    }
    Err(format!(
        "--require-enforced: selected names or application ceilings require an external enforcer ({})",
        what.join("; ")
    ))
}

struct StderrEvents<'a> {
    pipe: &'a EventPipe,
    args: &'a RunArgs,
    start_line: StartLine,
    until: Option<String>,
    /// When the command was released.
    started_at: Option<OffsetDateTime>,
    /// When the supervisor learned that the command had ended.
    ended_at: Option<OffsetDateTime>,
    /// With `--live-drops`: destinations printed so far.
    live_shown: usize,
    /// With `--live-drops`: the addresses and protocols seen so far, and
    /// how many new ones were printed past the first lines.
    live_addresses: std::collections::BTreeSet<(String, String)>,
    live_new_addresses: usize,
    /// The sandbox's VSOCK mode, once C has found it.
    vsock: Option<crate::vsock::Mode>,
}

impl Events for StderrEvents<'_> {
    fn in_setup_child(&mut self) {
        self.pipe.close();
    }
    fn before_start(&mut self) -> Result<(), String> {
        if self.args.expect_plan.is_some() || self.args.require_enforced {
            let current = check(self.args)?;
            enforce_coverage(self.args, &current)?;
            preview::match_pin(self.args, &current)?;
        }
        Ok(())
    }

    fn starting(&mut self) {
        self.pipe.send("starting", &serde_json::Value::Null);
        sayln!("{}", self.start_line.render(self.vsock));
    }
    fn vsock(&mut self, mode: crate::vsock::Mode) {
        self.vsock = Some(mode);
    }
    fn released(&mut self, at: OffsetDateTime) {
        self.started_at = Some(at);
    }
    fn ended(&mut self, at: OffsetDateTime) {
        self.ended_at = Some(at);
    }
    fn until_reached(&mut self, cut: &sandbox::Cut) {
        self.pipe.send(
            "stopping",
            &serde_json::json!({"reason":"expiry","egress_closed":*cut == sandbox::Cut::Closed}),
        );
        sayln!(
            "playpen: the approval ended at {}; {}",
            self.until.as_deref().unwrap_or("?"),
            stopping(cut)
        );
    }
    fn own_addresses(&mut self, addresses: &[std::net::IpAddr]) {
        let list: Vec<String> = addresses.iter().map(ToString::to_string).collect();
        let (verb, it) = if list.len() == 1 {
            ("is", "it")
        } else {
            ("are", "them")
        };
        sayln!(
            "playpen: NOTE: {} {verb} approved, but the sandbox has the same address on its own interface (it gets this host's addresses), so connections to {it} stay inside the sandbox and do not reach this host. A service on this host is reachable only at an address the sandbox does not have (docs/DESIGN.md, \"The host's own addresses\")",
            list.join(", ")
        );
    }
    fn uncounted(&mut self, why: &str) {
        sayln!(
            "playpen: NOTE: {why}. The drop counts of this run are incomplete: --fail-on-drop says unknown, and --on-drop and --live-drops do not see these packets"
        );
    }
    fn pass_edited(&mut self, message: &str) {
        sayln!("playpen: {message}");
    }
    fn pass_withdrawn(&mut self, reason: &str, cut: &sandbox::Cut) {
        self.pipe.send(
            "stopping",
            &serde_json::json!({"reason":"pass_withdrawn","egress_closed":*cut == sandbox::Cut::Closed}),
        );
        sayln!("playpen: {reason}; {}", stopping(cut));
    }
    fn denied(&mut self, denied: &crate::live_drops::Denied) {
        let dest = &denied.dest;
        self.pipe.send(
            "denied",
            &serde_json::json!({"address": dest.address, "protocol": dest.protocol,
                "port": dest.port, "packets": dest.packets, "record": denied.record}),
        );
        if !self.args.live_drops {
            return;
        }
        let shown = crate::live_drops::SHOWN;
        let port = match denied.record {
            crate::live_drops::RecordKind::Destination => "",
            crate::live_drops::RecordKind::Address => ", port not recorded",
        };
        let new_address = self
            .live_addresses
            .insert((dest.address.clone(), dest.protocol.clone()));
        self.live_shown += 1;
        if self.live_shown <= shown {
            sayln!(
                "playpen: dropped: {}{port} (not approved)",
                tripwire::destination(dest)
            );
            return;
        }
        if self.live_shown == shown + 1 {
            sayln!("playpen: dropped: more than {shown} destinations; see the summary at the end");
        }
        // Past the first lines, a new address still gets one: a sweep of
        // one address's ports cannot hide another address from stderr.
        if new_address {
            self.live_new_addresses += 1;
            if self.live_new_addresses <= shown {
                sayln!(
                    "playpen: dropped: {}{port} (not approved; a new address)",
                    tripwire::destination(dest)
                );
            } else if self.live_new_addresses == shown + 1 {
                sayln!(
                    "playpen: dropped: more than {shown} further addresses; see the summary at the end"
                );
            }
        }
    }
    fn denied_unreadable(&mut self, why: &str) {
        if self.args.live_drops {
            sayln!(
                "playpen: could not read the drop counter while the command runs: {why}; playpen tries again every {} s, and the summary at the end reports the drops as usual",
                crate::live_drops::INTERVAL.as_secs()
            );
        }
    }
    fn tripped(&mut self, tripped_by: &[crate::ruleset::DroppedDest], cut: Option<&sandbox::Cut>) {
        let on_drop = self.args.on_drop.unwrap_or(OnDrop::Cut);
        let reason = tripwire::reason(tripped_by, on_drop);
        match cut {
            Some(cut) => {
                self.pipe.send(
                    "stopping",
                    &serde_json::json!({"reason":"drop","egress_closed":*cut == sandbox::Cut::Closed}),
                );
                sayln!("playpen: {reason}; {}", stopping(cut));
            }
            None => sayln!(
                "playpen: {reason}; the firewall now refuses all traffic but loopback, and the command keeps running"
            ),
        }
    }
}

/// The rest of the notice that the command is being stopped.
fn stopping(cut: &sandbox::Cut) -> String {
    match cut {
        sandbox::Cut::Closed => format!(
            "the firewall now refuses all traffic but loopback; sending SIGTERM to the command (SIGKILL in {} s)",
            sandbox::GRACE.as_secs()
        ),
        sandbox::Cut::Failed(why) => format!(
            "egress could not be closed in the firewall ({why}), so the command is killed now with SIGKILL, without the grace"
        ),
    }
}

fn paths(list: &[PathBuf]) -> String {
    list.iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The clause groups about host Unix sockets and paths, one per line:
/// the socket guard, `--expose`, `--hide`, and the display sockets.
///
/// `--capture` adds its file to the hidden paths, but that file is not
/// listed under `hidden:`. The `packet capture:` clause already names it,
/// and the operator did not ask to hide it. The same holds for the pass,
/// its ledger and the `--report` file: playpen always hides them, the
/// operator did not ask, and `hidden:` stays the list the operator typed,
/// as in the plan.
fn sockets_clauses(c: &Checked, args: &RunArgs) -> Vec<String> {
    let mut out = vec![if args.without_landlock {
        String::from(
            "host Unix sockets: hidden under /run, /tmp, /var/tmp and the runtime directory only (--without-landlock); sockets elsewhere stay reachable",
        )
    } else if c.exposed.is_empty() && c.broker.is_some() {
        String::from("host Unix sockets: none reachable but the pass broker's")
    } else if c.exposed.is_empty() {
        String::from("host Unix sockets: none reachable")
    } else if c.broker.is_some() {
        String::from("host Unix sockets: only the exposed ones and the pass broker's")
    } else {
        String::from("host Unix sockets: only the exposed ones")
    }];
    let other: Vec<PathBuf> = c
        .exposed
        .iter()
        .filter(|p| !c.display.contains(p))
        .cloned()
        .collect();
    if !other.is_empty() {
        out.push(format!("exposed: {}", paths(&other)));
    }
    if !args.hide.is_empty() {
        out.push(format!("hidden: {}", paths(&args.hide)));
    }
    if !c.display.is_empty() {
        out.push(format!("display exposed: {}", paths(&c.display)));
    }
    out
}

/// What a listening program at `path` lets a client do, when that is to run
/// programs on the host or take it over; `None` for any other path.
///
/// The name and the directory decide: these daemons keep their sockets at
/// fixed places, and a copy under another name is not known.
fn escape_kind(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_str()?;
    let parent = path.parent()?;
    let parent_name = parent.file_name().and_then(|n| n.to_str());
    let in_user_runtime = |dir: &Path| dir.parent().is_some_and(|p| p.ends_with("run/user"));
    match name {
        "bus" if in_user_runtime(parent) => Some("the D-Bus session bus"),
        "system_bus_socket" if parent_name == Some("dbus") => Some("the D-Bus system bus"),
        "private" if parent_name == Some("systemd") => Some("systemd's private socket"),
        "docker.sock" => Some("the Docker daemon's socket"),
        "podman.sock" => Some("the Podman socket"),
        "containerd.sock" => Some("the containerd socket"),
        _ => None,
    }
}

/// The places where the sockets of `escape_kind` live, for the user whose
/// runtime directory is `runtime`.
fn escape_candidates(runtime: Option<&Path>) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [
        "/run/dbus/system_bus_socket",
        "/run/systemd/private",
        "/run/docker.sock",
        "/run/podman/podman.sock",
        "/run/containerd/containerd.sock",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if let Some(r) = runtime {
        for rel in [
            "bus",
            "systemd/private",
            "docker.sock",
            "podman/podman.sock",
        ] {
            v.push(r.join(rel));
        }
    }
    v
}

/// The NOTE lines for `--expose` paths that let the command run programs on
/// the host: a known socket (`escape_kind`), or a directory that is, or
/// holds, the runtime directory or one of those sockets. `runtime` is the
/// caller's runtime directory.
fn expose_notes(exposed: &[PathBuf], runtime: Option<&Path>) -> Vec<String> {
    let candidates = escape_candidates(runtime);
    let mut out = Vec::new();
    for e in exposed {
        if let Some(kind) = escape_kind(e) {
            out.push(format!(
                "NOTE: --expose {} gives the command {kind}. A program that talks to it can start programs on the host, outside the network filter, the hidden paths and Landlock; expose it only to a command you would also trust with a host shell",
                e.display()
            ));
        } else if e.is_dir()
            && (runtime.is_some_and(|r| r.starts_with(e))
                || candidates.iter().any(|c| c.starts_with(e) && c.exists()))
        {
            out.push(format!(
                "NOTE: --expose {} gives the command every socket in that directory, and it holds or leads to sockets that can start programs on the host (the D-Bus buses, systemd's private socket, docker.sock, podman.sock, containerd). Expose the one socket you need instead",
                e.display()
            ));
        }
    }
    out
}

/// The start line, built before the sandbox and printed once it is ready:
/// a short first line, then one `playpen:   ` line for each further clause
/// group, then the NOTE lines. A CI log filtered by the `playpen:` prefix
/// keeps every line.
struct StartLine {
    /// The first line, then the clause groups.
    lines: Vec<String>,
    /// The NOTE lines, each starting with a newline.
    notes: String,
}

impl StartLine {
    /// The start line as printed. The clause about VM sockets comes last:
    /// C finds the sandbox's VSOCK mode only once the sandbox's namespace
    /// exists, after the rest was built.
    fn render(&self, vsock: Option<crate::vsock::Mode>) -> String {
        let mut lines = self.lines.clone();
        if let Some(mode) = vsock {
            lines.push(mode.clause().to_owned());
        }
        let mut out = String::new();
        for (i, line) in lines.iter().enumerate() {
            if i > 0 {
                let _ = write!(out, "\n{CLAUSE_PREFIX}");
            }
            out.push_str(line);
        }
        out.push_str(&self.notes);
        out
    }
}

/// The start line without the clause about VM sockets (see
/// [`StartLine::render`]).
fn start_line(
    c: &Checked,
    args: &RunArgs,
    capture: Option<&Path>,
    broker: Option<&crate::broker::Broker>,
) -> StartLine {
    let mut lines = start_line_net(c, !args.no_network);
    if let Some(p) = capture {
        lines.push(format!("packet capture: {}", p.display()));
    }
    if args.live_drops {
        lines.push(format!(
            "dropped destinations printed while the command runs (the first {})",
            crate::live_drops::SHOWN
        ));
    }
    if args.report_contacts {
        lines.push("contacted destinations recorded".to_owned());
    }
    // What is recorded first, then what the first drop does.
    match args.on_drop {
        None => {}
        Some(OnDrop::Cut) => lines.push(
            "at the first dropped packet the firewall itself refuses all traffic but loopback, and the command runs on (--on-drop cut)".to_owned(),
        ),
        Some(OnDrop::Stop) => lines.push(
            "at the first dropped packet the firewall itself refuses all traffic but loopback, and playpen stops the command (--on-drop stop)".to_owned(),
        ),
    }
    if args.private_tty {
        lines.push("private controlling terminal".to_owned());
    } else if c.new_session {
        lines
            .push("the command runs in its own session, without a controlling terminal".to_owned());
    }
    lines.extend(sockets_clauses(c, args));
    lines.extend(c.pass_dir.as_ref().and_then(PassDirView::clause));
    if let (Some(b), Some(view)) = (broker, &c.broker) {
        lines.extend(broker_clauses(b, view));
    }
    StartLine {
        lines,
        notes: start_notes(c),
    }
}

/// The start-line clauses of `--pass-broker`: the socket, the only path it
/// adds, and the state directory the command cannot reach.
fn broker_clauses(b: &crate::broker::Broker, view: &BrokerView) -> Vec<String> {
    let hidden = if view.hidden_already {
        "hidden from the command already"
    } else {
        "hidden from the command"
    };
    vec![
        format!(
            "pass broker: {} ({}, in {}; hallpass {}); the only path it exposes. The command reads the pass and spends from its ledger through it, with no write access to the pass, the ledger or the witness",
            b.socket().display(),
            crate::broker::PROTOCOL,
            crate::broker::ENV,
            &crate::broker::HALLPASS_REVISION[..12]
        ),
        format!(
            "hallpass state directory: {} ({hidden}; the broker writes the witness there)",
            view.state.display()
        ),
    ]
}

/// The prefix of each start-line clause after the first line.
const CLAUSE_PREFIX: &str = "playpen:   ";

/// The cloud instance metadata addresses (AWS, GCP, Azure and others use the
/// IPv4 one; AWS also serves the IPv6 one).
const METADATA_ADDRS: [IpAddr; 2] = [
    IpAddr::V4(std::net::Ipv4Addr::new(169, 254, 169, 254)),
    IpAddr::V6(std::net::Ipv6Addr::new(
        0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254,
    )),
];

/// The NOTE for each cloud metadata address that a grant covers.
///
/// A grant covers the address when its network contains it and it allows
/// TCP on some port. `--allow` takes link-local addresses because the
/// operator typed them; a pass does not (docs/DESIGN.md).
fn metadata_notes(approval: &Approval) -> Vec<String> {
    METADATA_ADDRS
        .into_iter()
        .filter(|a| {
            approval
                .rules()
                .iter()
                .any(|r| r.proto == crate::approval::Proto::Tcp && r.covers_addr(*a))
        })
        .map(|a| {
            format!(
                "NOTE: the allow list includes {a}, the cloud instance metadata address; a command that reaches it may read this machine's cloud credentials"
            )
        })
        .collect()
}

/// The NOTE lines that follow the start line, each starting with a newline.
fn start_notes(c: &Checked) -> String {
    let mut out = String::new();
    for note in metadata_notes(&c.approval) {
        let _ = write!(out, "\nplaypen: {note}");
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            Some(PathBuf::from(format!(
                "/run/user/{}",
                nix::unistd::getuid()
            )))
        })
        .and_then(|p| std::fs::canonicalize(p).ok());
    for note in expose_notes(&c.exposed, runtime.as_deref()) {
        let _ = write!(out, "\nplaypen: {note}");
    }
    for note in c.from_pass.iter().flat_map(pass::unenforced_notes) {
        let _ = write!(out, "\nplaypen: NOTE: {note}");
    }
    if c.broker.is_some()
        && c.from_pass
            .iter()
            .any(|p| !p.coverage.external_ceilings.is_empty())
    {
        out.push_str("\nplaypen: NOTE: with --pass-broker the broker refuses a spend over a ceiling and records the ones it allows, but it counts only what the command asks it to spend: the firewall does not count requests");
    }
    for note in c.pass_hosts.iter().flat_map(|p| &p.notes) {
        let _ = write!(out, "\nplaypen: NOTE: {note}");
    }
    if let Some(PassDirView::Writable(dir)) = &c.pass_dir {
        let _ = write!(
            out,
            "\nplaypen: NOTE: the pass's directory, {}, is writable by the command (--pass-dir-writable). Inside, the pass is /dev/null until it is replaced: an edit that writes a new file (sed -i and most editors do) makes the new pass visible there, and the command can read it and put another in its place before the next re-read. Keep the pass in a directory of its own, outside the working directory, and leave out --pass-dir-writable: playpen then makes that directory read-only for the command, or hides it",
            dir.display()
        );
    }
    out
}

/// Whether the command cannot reach `dir`: it is at or below a `hide`
/// directory, or one of the `covers` the mount layer replaces, that is not
/// the working directory `cwd` and does not hold it. An `exposed` path
/// brings back what a cover hides when it is at or above `dir` and at or
/// below the cover: the exposed paths are bound back after the covers, the
/// `--hide` paths are mounted after both (and `--expose` refuses a path
/// inside a `--hide` one). A process that starts in a hidden directory, or
/// below it, keeps reaching the real one through relative paths.
fn dir_hidden(
    dir: &Path,
    hide: &[PathBuf],
    covers: &[PathBuf],
    exposed: &[PathBuf],
    cwd: Option<&Path>,
) -> bool {
    let canonical = |p: &Path| std::fs::canonicalize(p).ok();
    let Some(dir) = canonical(dir) else {
        return false;
    };
    let cwd = cwd.and_then(canonical);
    let hides = |h: &PathBuf| {
        h.is_dir() && dir.starts_with(h) && !cwd.as_ref().is_some_and(|c| c.starts_with(h))
    };
    hide.iter().filter_map(|h| canonical(h)).any(|h| hides(&h))
        || covers
            .iter()
            .filter_map(|c| canonical(c))
            .filter(hides)
            .any(|c| {
                !exposed
                    .iter()
                    .any(|e| dir.starts_with(e) && e.starts_with(&c))
            })
}

/// The first line (the grant summary, the end time and what is dropped),
/// then the pass identity, the names and the end-of-egress clauses.
fn start_line_net(c: &Checked, network: bool) -> Vec<String> {
    let until = c.approval.ends_at.map_or_else(
        || "with no time limit".to_owned(),
        |e| format!("until {}", e.to_rfc3339()),
    );
    let mut names = String::from("no DNS");
    let list = c.host_texts();
    if !list.is_empty() {
        names.push_str(", names ");
        names.push_str(&list.join(", "));
    }
    for r in c.pass_hosts.iter().flat_map(|p| &p.replaced) {
        let _ = write!(names, "; --host {} replaces {r}", r.entry.name);
    }
    names.push_str("; lookups recorded");
    if !network {
        return vec![
            format!("playpen: no network, loopback only, {until}; everything else is dropped"),
            names,
        ];
    }
    let list: Vec<String> = c.approval.rules().iter().map(ToString::to_string).collect();
    let mut lines = vec![format!(
        "playpen: allowing only {} {until}; everything else is dropped",
        list.join(", ")
    )];
    if let Some(p) = &c.from_pass {
        lines.push(format!("under {}", pass::describe(&p.identity)));
    }
    lines.push(names);
    if let Some(p) = &c.from_pass {
        // With --pass-hosts the notes below say why a name is not mapped.
        if c.pass_hosts.is_none() {
            let hint = hostname_hint(&p.named, &c.hosts, true);
            if let Some(hint) = hint.strip_prefix("; ") {
                lines.push(hint.to_owned());
            }
        }
    }
    let ends = ends_clause(c);
    if let Some(ends) = ends.strip_prefix("; ") {
        lines.push(ends.to_owned());
    }
    lines
}

/// What the start line says about the end of egress in the firewall: from
/// the end second (the end time rounded down), and with a pass also when a
/// re-read withdraws it.
fn ends_clause(c: &Checked) -> String {
    let Some(second) = crate::ruleset::end_second(&c.approval) else {
        return String::new();
    };
    let at = OffsetDateTime::from_unix_timestamp(second)
        .map_or_else(|_| String::new(), |t| EndsAt::from_time(t).to_rfc3339());
    let or_pass = if c.from_pass.is_some() {
        ", or once a re-read withdraws the pass,"
    } else {
        ""
    };
    format!("; from {at}{or_pass} the firewall itself refuses all traffic but loopback")
}

fn base_report(args: &RunArgs) -> Report {
    Report {
        playpen_version: env!("CARGO_PKG_VERSION"),
        outcome: Outcome::Refused,
        startup_evidence: StartupEvidence::NotStarted,
        message: None,
        command: args
            .command
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect(),
        allowed: args.allow.clone(),
        hosts: args.host.clone(),
        until: args.until.clone(),
        started_at: None,
        ended_at: None,
        network: if args.no_network { "none" } else { "pasta" },
        exit_code: None,
        signal: None,
        stopped_by_until: false,
        stopped_by_pass: false,
        stop_reason: None,
        enforcement_coverage: None,
        pass: args.pass.as_ref().map(|p| PassReport {
            file: p.display().to_string(),
            id: None,
            name: None,
            owner: None,
            digest: None,
            valid_until: None,
            labels: Vec::new(),
            directory: None,
            broker: None,
        }),
        capture: None,
        playpen_exit_status: EXIT_REFUSED,
        dropped: None,
        refused_after_end: None,
        grant_use: None,
        contacts: args
            .report_contacts
            .then(crate::contacts::ContactFields::default),
        drop_assertion: None,
        dropped_error: None,
        uncounted: None,
        lookups: None,
        lookups_error: None,
        socket_guard: if args.without_landlock {
            "mounts_only"
        } else {
            "landlock"
        },
        vsock: None,
        exposed: args
            .expose
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        display: args.display,
        new_session: new_session(args),
        private_tty: args.private_tty,
        live_drops: args.live_drops,
        on_drop: args.on_drop.map(OnDropReport::new),
    }
}

/// Whether the workload runs without a controlling terminal.
fn new_session(args: &RunArgs) -> bool {
    !args.private_tty && (args.new_session || sandbox::tiocsti_allowed())
}

/// The report as written to the file or stdout: pretty JSON and a newline.
fn render_report(report: &Report, shareable: bool) -> std::io::Result<Vec<u8>> {
    let mut out = if shareable {
        serde_json::to_vec_pretty(&crate::report::ShareableReport::from(report))?
    } else {
        let mut value = serde_json::to_value(report)?;
        value["advice"] = if report.startup_evidence == StartupEvidence::Unknown {
            serde_json::json!([{"level":"warn","type":"uncertain-startup","message":"Check for side effects before retrying this command."}])
        } else {
            serde_json::json!([])
        };
        serde_json::to_vec_pretty(&value)?
    };
    out.push(b'\n');
    Ok(out)
}

/// Writes the report: to the `--report` file, or to stdout with
/// `stdout_report`. When the command replaced the report file (see
/// [`ReportFile::replaced`]), playpen's exit status becomes 1 if it was 0,
/// `message` says so, and the report is written to the path again.
fn write_report(
    file: Option<&mut ReportFile>,
    report: &mut Report,
    shareable: bool,
    stdout_report: bool,
) -> Result<(), String> {
    let replaced = file.as_deref().and_then(|f| {
        f.replaced()
            .map(|why| (why, f.shown().display().to_string()))
    });
    if let Some((why, _)) = &replaced {
        if report.playpen_exit_status == 0 {
            report.playpen_exit_status = EXIT_ERROR;
        }
        let note = format!(
            "the report file was replaced while the command ran ({why}); playpen wrote this report to its path again"
        );
        report.message = Some(match report.message.take() {
            Some(m) => format!("{m}; {note}"),
            None => note,
        });
    }
    let written = render_report(report, shareable).and_then(|bytes| match file {
        Some(f) if replaced.is_some() => f.write_again(&bytes),
        Some(f) => f.write(&bytes),
        None if stdout_report => {
            let mut out = std::io::stdout().lock();
            match out.write_all(&bytes).and_then(|()| out.flush()) {
                // Nobody reads stdout any more: the report is lost, but
                // the run and playpen's exit status are not changed.
                Err(e) if crate::say::stdout_reader_gone(&e) => {
                    crate::say::stdout_lost();
                    sayln!("playpen: the report was not written: stdout is closed ({e})");
                    Ok(())
                }
                other => other,
            }
        }
        None => Ok(()),
    });
    match (written, replaced) {
        (Ok(()), None) => Ok(()),
        (Ok(()), Some((why, shown))) => {
            sayln!(
                "playpen: WARNING: the report file {shown} was replaced while the command ran ({why}); playpen wrote its report there again, and exits with status {}",
                report.playpen_exit_status
            );
            Ok(())
        }
        (Err(e), None) => Err(format!("could not write the final report: {e}")),
        (Err(e), Some((why, shown))) => Err(format!(
            "the report file {shown} was replaced while the command ran ({why}), and playpen could not write its report there again: {e}"
        )),
    }
}

/// playpen's own files besides the capture, which the command must not
/// read or replace: the pass, its ledger when it exists, and the report
/// when it is a regular file. Inside the sandbox each is `/dev/null`.
fn own_files(from_pass: Option<&pass::FromPass>, report: Option<&ReportFile>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(p) = from_pass {
        let file = p.watch.dir().file();
        let ledger = hallpass::ledger_path(&file);
        out.push(file);
        if std::fs::symlink_metadata(&ledger).is_ok_and(|m| m.is_file()) {
            out.push(ledger);
        }
    }
    out.extend(report.and_then(ReportFile::hidden).map(Path::to_path_buf));
    out
}

#[expect(
    clippy::too_many_lines,
    reason = "a linear sequence of steps, each mapping to a report field"
)]
fn run(args: &RunArgs, format: Format) -> i32 {
    let stdout_report = format == Format::Json && args.report.is_none();
    if (args.shareable_report || args.report_grant_use || args.report_contacts)
        && args.report.is_none()
        && !stdout_report
    {
        return discovery::error(
            format,
            "missing-report",
            "choose --report FILE or --format json for this report option; nothing was run",
            EXIT_REFUSED,
        );
    }
    let pipe = match EventPipe::open(args.events_fd) {
        Ok(p) => p,
        Err(e) => {
            return discovery::error(
                format,
                "invalid-events-fd",
                &format!("refused: {e}; nothing was run"),
                EXIT_REFUSED,
            );
        }
    };
    let mut report = base_report(args);
    let finish = |file: Option<&mut ReportFile>, report: &mut Report| {
        if let Err(e) = write_report(file, report, args.shareable_report, stdout_report) {
            if report.playpen_exit_status == 0 {
                report.playpen_exit_status = EXIT_ERROR;
            }
            discovery::error(
                format,
                "report-write-failed",
                &e,
                report.playpen_exit_status,
            );
        }
        pipe.terminal(report);
        report.playpen_exit_status
    };
    if args.fail_on_drop {
        report.drop_assertion = Some(crate::report::DropAssertion::Unknown);
    }
    let mut report_file = match &args.report {
        Some(p) => match ReportFile::create(p) {
            Ok(f) => Some(f),
            Err(e) => {
                let message = format!(
                    "refused: cannot create the report file {}: {e}; nothing was run",
                    p.display()
                );
                pipe.terminal(&report);
                return discovery::error(format, "report-unwritable", &message, EXIT_REFUSED);
            }
        },
        None => None,
    };
    let checked = match check(args).and_then(|c| {
        preview::match_pin(args, &c)?;
        Ok(c)
    }) {
        Ok(c) => c,
        Err(e) => {
            sayln!("playpen: refused: {e}");
            if !e.contains("nothing was run") {
                sayln!("playpen: nothing was run");
            }
            report.message = Some(e);
            return finish(report_file.as_mut(), &mut report);
        }
    };
    report.enforcement_coverage = checked.from_pass.as_ref().map(|p| p.coverage.clone());
    if let Err(e) = enforce_coverage(args, &checked) {
        sayln!("playpen: refused: {e}; nothing was run");
        report.message = Some(e);
        return finish(report_file.as_mut(), &mut report);
    }
    // Created before anything is built, so that a name that is taken, a
    // link or a directory that cannot be used is a refusal.
    let capture = match args.capture.as_deref().map(Capture::create).transpose() {
        Ok(c) => c.map(Arc::new),
        Err(e) => {
            sayln!("playpen: refused: {e}; nothing was run");
            report.message = Some(e);
            return finish(report_file.as_mut(), &mut report);
        }
    };
    // When nothing was run, the capture file playpen created goes again.
    let discard = || {
        if let Some(c) = &capture {
            c.discard();
        }
    };
    // The socket and the state directory, before anything is built: an
    // unusable state directory is a refusal.
    let broker = match checked
        .broker
        .as_ref()
        .map(|_| crate::broker::StateGuard::open().and_then(crate::broker::Broker::create))
    {
        Some(Ok(b)) => Some(Arc::new(b)),
        Some(Err(e)) => {
            discard();
            sayln!("playpen: refused: {e}; nothing was run");
            report.message = Some(e);
            return finish(report_file.as_mut(), &mut report);
        }
        None => None,
    };
    pipe.send("validated", &serde_json::Value::Null);
    report.allowed = checked
        .approval
        .rules()
        .iter()
        .map(ToString::to_string)
        .collect();
    report
        .hosts
        .extend(checked.pass_entries().iter().map(ToString::to_string));
    for path in &args.hide {
        if explicitly_missing(path) {
            sayln!(
                "playpen: NOTE: --hide path {} does not exist; nothing was hidden there",
                path.display()
            );
        }
    }
    report.until = checked.approval.ends_at.map(EndsAt::to_rfc3339);
    if let Some(p) = &checked.from_pass {
        report.pass = Some(PassReport {
            directory: checked.pass_dir.as_ref().map(PassDirView::report),
            broker: checked
                .broker
                .as_ref()
                .map(|_| crate::report::BrokerReport {
                    protocol: crate::broker::PROTOCOL,
                    hallpass_revision: crate::broker::HALLPASS_REVISION,
                    socket: broker.as_ref().map(|b| b.socket().display().to_string()),
                    state_directory: broker
                        .as_ref()
                        .map(|b| b.state().path().display().to_string()),
                    state_directory_view: Some("hidden"),
                    activity: None,
                }),
            ..pass_report(&p.identity)
        });
    }
    let fail = |report: &mut Report, file: Option<&mut ReportFile>, outcome, msg: String| {
        sayln!("playpen: {msg}");
        report.outcome = outcome;
        if outcome == Outcome::Error {
            report.startup_evidence = StartupEvidence::Unknown;
        }
        report.message = Some(msg);
        report.playpen_exit_status = EXIT_ERROR;
        finish(file, report)
    };
    let Some(nft) = crate::tools::nft() else {
        discard();
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
        discard();
        return fail(
            &mut report,
            report_file.as_mut(),
            Outcome::NotStarted,
            "pasta (from the passt package) was not found; install it, set PLAYPEN_PASTA, or use --no-network; nothing was run".into(),
        );
    };
    report.exposed = checked
        .exposed
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    report.new_session = checked.new_session;
    let mut events = StderrEvents {
        pipe: &pipe,
        args,
        start_line: start_line(
            &checked,
            args,
            capture.as_deref().map(Capture::path),
            broker.as_deref(),
        ),
        until: report.until.clone(),
        started_at: None,
        ended_at: None,
        live_shown: 0,
        live_addresses: std::collections::BTreeSet::new(),
        live_new_addresses: 0,
        vsock: None,
    };
    let grant_labels = if args.report_grant_use {
        checked
            .from_pass
            .as_ref()
            .map_or_else(Vec::new, pass::FromPass::rule_labels)
    } else {
        Vec::new()
    };
    let grant_counters = crate::grant_use::counter_count(&checked.approval, args.report_grant_use);
    let hosts = checked.all_hosts();
    let mut hide = args.hide.clone();
    // The command cannot open the capture: inside it is /dev/null.
    hide.extend(capture.as_deref().map(|c| c.path().to_path_buf()));
    // Nor the pass, its ledger or the report.
    hide.extend(own_files(checked.from_pass.as_ref(), report_file.as_ref()));
    let mut exposed = checked.exposed;
    let mut state_dir = None;
    let mut watch = checked.from_pass.map(|p| p.watch);
    if let (Some(b), Some(w)) = (&broker, watch.as_mut()) {
        // P stops the run when the state directory is moved, as for the
        // pass's directory.
        w.held.push(b.state().held());
    }
    let pinned = sandbox::pinned_dirs(
        watch
            .as_ref()
            .map(|w| w.dir().path())
            .into_iter()
            .chain(broker.as_ref().map(|b| b.state().canonical())),
    );
    if let (Some(b), Some(view)) = (&broker, &checked.broker) {
        // Canonical, as every exposed path is.
        exposed
            .push(std::fs::canonicalize(b.socket()).unwrap_or_else(|_| b.socket().to_path_buf()));
        exposed.sort();
        if !view.hidden_already {
            state_dir = Some(sandbox::DirGuard::Hidden(
                b.state().canonical().to_path_buf(),
            ));
        }
    }
    let plan = Plan {
        fixture: checked.fixture,
        approval: checked.approval,
        hosts,
        network: !args.no_network,
        grant_counters,
        report_contacts: args.report_contacts,
        lo_addrs: checked.lo_addrs,
        hide,
        exposed,
        landlock: !args.without_landlock,
        new_session: checked.new_session,
        command: args.command.clone(),
        nft,
        pasta,
        capture: capture.clone(),
        watch,
        pass_dir: checked.pass_dir.as_ref().and_then(PassDirView::guard),
        pinned,
        watch_drops: args.events_fd.is_some() || args.live_drops || args.on_drop.is_some(),
        on_drop: args.on_drop,
        broker,
        state_dir,
    };
    let outcome = sandbox::run_with_output(&plan, &mut events, stdout_report, args.private_tty);
    report.started_at = events.started_at.map(crate::report::stamp);
    report.ended_at = events.ended_at.map(crate::report::stamp);
    report.vsock = events.vsock.map(crate::vsock::Mode::name);
    if let Some(c) = &capture {
        // pasta has exited: the file is complete.
        if report.started_at.is_none() {
            c.discard();
        } else {
            match c.summary() {
                Ok(s) => report.capture = Some(s),
                Err(e) => {
                    sayln!("playpen: {e}");
                    report.message.get_or_insert(e);
                }
            }
        }
    }
    let result = match outcome {
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
    if result.stopped_by_until {
        report.stop_reason = Some(format!(
            "the approval ended at {}",
            report.until.as_deref().unwrap_or("?")
        ));
    }
    if let Some(why) = result.stopped_by_pass {
        report.stopped_by_pass = true;
        report.stop_reason = Some(why);
    }
    let code = match result.status {
        CommandStatus::Exited(c) => {
            report.startup_evidence = StartupEvidence::ExecAndExit;
            report.exit_code = Some(c);
            c
        }
        CommandStatus::Signaled(s) => {
            report.startup_evidence = StartupEvidence::Unknown;
            report.signal = Some(s);
            128 + s
        }
    };
    if args.report_grant_use {
        report.grant_use = Some(crate::grant_use::GrantUse::summarize(
            plan.approval.rules(),
            &grant_labels,
            &result.grant_packets,
        ));
    }
    match result.drops {
        Ok(d) => report.dropped = Some(d),
        Err(e) => report.dropped_error = Some(e),
    }
    match result.lookups {
        Ok(l) => report.lookups = Some(l),
        Err(e) => report.lookups_error = Some(e),
    }
    if let (Some(fields), Some(read)) = (report.contacts.as_mut(), result.contacts) {
        match read {
            Ok(c) => fields.contacted = Some(c),
            Err(e) => fields.contacted_error = Some(e),
        }
    }
    report.refused_after_end = result.refused_after_end;
    report.uncounted = result.uncounted;
    if let Some(b) = report.pass.as_mut().and_then(|p| p.broker.as_mut()) {
        b.activity = result.broker;
    }
    if let Some(on_drop) = args.on_drop {
        let seen = tripwire::Observed {
            drops: report.dropped.as_ref(),
            live: result.tripped_by.as_deref(),
            cut_packets: result.cut_packets,
            refused_after_end: result.refused_after_end,
        };
        let (on, after_end) = OnDropReport::observe(on_drop, result.stopped_by_drop, seen);
        if let Some(cut) = on.egress_cut.as_ref().filter(|_| on.stopped_by_drop) {
            report.stop_reason = Some(tripwire::reason(&cut.tripped_by, on_drop));
        }
        report.on_drop = Some(on);
        report.refused_after_end = after_end;
    }
    let code = apply_drop_assertion(&mut report, code, args.fail_on_drop);
    let code = tripwire::exit_status(report.on_drop.as_ref(), code);
    report.playpen_exit_status = code;
    say!("{}", text_summary(&report));
    finish(report_file.as_mut(), &mut report)
}

pub(crate) fn apply_drop_assertion(report: &mut Report, code: i32, enabled: bool) -> i32 {
    if !enabled {
        return code;
    }
    let assertion = match &report.dropped {
        Some(d) if d.packets > 0 => crate::report::DropAssertion::Violated,
        Some(d)
            if d.destinations.iter().any(|entry| entry.packets > 0)
                || d.addresses.iter().flatten().any(|entry| entry.packets > 0) =>
        {
            crate::report::DropAssertion::Unknown
        }
        // Packets that failed at routing may have gone uncounted.
        Some(_) if report.uncounted.is_some() => crate::report::DropAssertion::Unknown,
        Some(_) => crate::report::DropAssertion::Pass,
        None => crate::report::DropAssertion::Unknown,
    };
    report.drop_assertion = Some(assertion);
    if code == 0
        && (assertion != crate::report::DropAssertion::Pass
            || report.stopped_by_until
            || report.stopped_by_pass)
    {
        1
    } else {
        code
    }
}

/// An explicit hide target that is absent, including a dangling symlink.
/// Other metadata errors are left for the mount operation to report.
fn explicitly_missing(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Ok(meta) if meta.file_type().is_symlink() => {
            matches!(std::fs::metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_escape_sockets_are_named_by_place_and_others_are_not() {
        let kind = |p: &str| escape_kind(Path::new(p));
        assert_eq!(kind("/run/user/1000/bus"), Some("the D-Bus session bus"));
        assert_eq!(
            kind("/run/dbus/system_bus_socket"),
            Some("the D-Bus system bus")
        );
        assert_eq!(
            kind("/run/systemd/private"),
            Some("systemd's private socket")
        );
        assert_eq!(
            kind("/run/user/1000/systemd/private"),
            Some("systemd's private socket")
        );
        assert_eq!(kind("/run/docker.sock"), Some("the Docker daemon's socket"));
        assert_eq!(
            kind("/run/user/1000/podman/podman.sock"),
            Some("the Podman socket")
        );
        assert_eq!(
            kind("/run/containerd/containerd.sock"),
            Some("the containerd socket")
        );
        assert_eq!(kind("/run/user/1000/wayland-0"), None);
        assert_eq!(kind("/tmp/bus"), None);
        assert_eq!(kind("/run/user/1000/other/private"), None);
    }

    #[test]
    fn expose_notes_cover_the_socket_and_a_directory_that_holds_it() {
        let root = std::env::temp_dir().join(format!("playpen-notes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let runtime = root.join("run/user/1000");
        std::fs::create_dir_all(runtime.join("sub")).unwrap_or_else(|e| panic!("{e}"));
        let notes = |e: &[PathBuf]| expose_notes(e, Some(&runtime));
        let bus = runtime.join("bus");
        assert!(notes(&[bus])[0].contains("the D-Bus session bus"));
        // The runtime directory, and a directory above it.
        assert!(
            notes(std::slice::from_ref(&runtime))[0].contains("every socket in that directory")
        );
        assert!(notes(&[root.join("run")])[0].contains("every socket in that directory"));
        // A directory that holds neither, and a plain socket.
        assert_eq!(notes(&[runtime.join("sub")]).len(), 0);
        assert_eq!(notes(&[runtime.join("wayland-0")]).len(), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A directory tree for [`dir_hidden`]: `root/sealed/pass`,
    /// `root/work` and a link `root/link` to `sealed`.
    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("playpen-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["sealed/pass", "work"] {
            std::fs::create_dir_all(root.join(d)).unwrap_or_else(|e| panic!("{e}"));
        }
        std::os::unix::fs::symlink(root.join("sealed"), root.join("link"))
            .unwrap_or_else(|e| panic!("{e}"));
        root
    }

    #[test]
    fn a_pass_directory_is_hidden_only_below_a_hidden_directory_that_does_not_hold_the_cwd() {
        let root = tree("hidden");
        let pass = root.join("sealed/pass");
        let work = root.join("work");
        let hide = |h: &[&str]| -> Vec<PathBuf> { h.iter().map(|p| root.join(p)).collect() };
        // Each check twice: with the directory given as `--hide`, and as a
        // directory the mount layer replaces.
        let hidden = |h: &[&str], exposed: &[PathBuf], cwd: &Path| {
            let by_hide = dir_hidden(&pass, &hide(h), &[], exposed, Some(cwd));
            let by_cover = dir_hidden(&pass, &[], &hide(h), exposed, Some(cwd));
            (by_hide, by_cover)
        };
        // Nothing hidden.
        assert!(!dir_hidden(&pass, &[], &[], &[], Some(&work)));
        // The directory itself, or one above it, through a link or not.
        assert_eq!(hidden(&["sealed/pass"], &[], &work), (true, true));
        assert_eq!(hidden(&["sealed"], &[], &work), (true, true));
        assert_eq!(hidden(&["link"], &[], &work), (true, true));
        // A sibling is not enough.
        assert_eq!(hidden(&["work"], &[], &work), (false, false));
        // A hidden directory that holds the working directory is still
        // reachable through relative paths.
        assert_eq!(hidden(&["sealed"], &[], &pass), (false, false));
        assert_eq!(
            hidden(&["sealed"], &[], &root.join("sealed")),
            (false, false)
        );
        assert_eq!(hidden(&[""], &[], &work), (false, false));
        // An exposed path at or above the directory and at or below a
        // cover brings it back; a `--hide` directory is mounted after the
        // exposed paths, so nothing brings that back.
        let canonical = |p: &str| std::fs::canonicalize(root.join(p)).unwrap_or_default();
        let sealed = [canonical("sealed")];
        assert_eq!(hidden(&["sealed"], &sealed, &work), (true, false));
        assert_eq!(hidden(&["sealed/pass"], &sealed, &work), (true, true));
        assert_eq!(hidden(&["sealed"], &[canonical("")], &work), (true, true));
        // The directory itself, exposed, comes back from a cover; a path
        // below it does not bring it back.
        let itself = [canonical("sealed/pass")];
        std::fs::create_dir_all(root.join("sealed/pass/sock")).unwrap_or_else(|e| panic!("{e}"));
        let below = [canonical("sealed/pass/sock")];
        assert_eq!(hidden(&["sealed"], &itself, &work), (true, false));
        assert_eq!(hidden(&["sealed"], &below, &work), (true, true));
        // A hidden file is not a hidden directory.
        std::fs::write(root.join("file"), "").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(hidden(&["file"], &[], &work), (false, false));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn only_entries_lists_the_directory_and_refuses_what_it_cannot_list() {
        let root = tree("entries");
        let dir = root.join("sealed/pass");
        let names = |n: &[&str]| -> Vec<OsString> { n.iter().map(OsString::from).collect() };
        assert!(only_entries(&dir, &names(&[])));
        std::fs::write(dir.join("p.toml"), "").unwrap_or_else(|e| panic!("{e}"));
        assert!(only_entries(&dir, &names(&["p.toml", "p.toml.ledger"])));
        std::fs::write(dir.join("notes"), "").unwrap_or_else(|e| panic!("{e}"));
        assert!(!only_entries(&dir, &names(&["p.toml", "p.toml.ledger"])));
        assert!(!only_entries(&root.join("missing"), &names(&[])));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_vm_socket_clause_comes_after_the_other_clauses_and_before_the_notes() {
        let line = StartLine {
            lines: vec![
                "playpen: first".into(),
                "host Unix sockets: none reachable".into(),
            ],
            notes: "\nplaypen: NOTE: a note".into(),
        };
        assert_eq!(
            line.render(Some(crate::vsock::Mode::Local)),
            format!(
                "playpen: first\n{CLAUSE_PREFIX}host Unix sockets: none reachable\n{CLAUSE_PREFIX}{}\nplaypen: NOTE: a note",
                crate::vsock::Mode::Local.clause()
            )
        );
        assert_eq!(
            line.render(None),
            format!(
                "playpen: first\n{CLAUSE_PREFIX}host Unix sockets: none reachable\nplaypen: NOTE: a note"
            )
        );
    }
}
