//! Command-line interface.

mod event_pipe;
mod policy_test;
mod preview;
use event_pipe::EventPipe;

use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use time::OffsetDateTime;

use crate::approval::{Approval, EndsAt, parse_allow, parse_literal_addr};
use crate::pass::{self, FromPass, MIN_RECHECK_INTERVAL, NamedDestination, RECHECK_INTERVAL};
use crate::report::{Outcome, PassReport, Report, StartupEvidence, text_summary};
use crate::resolver::{HostEntry, check_hosts, parse_host};
use crate::sandbox::{self, CommandStatus, Events, Plan, RunError};
use crate::sockets;

/// Why `--pass` and `--allow` cannot be combined.
const PASS_AND_ALLOW: &str = "--pass and --allow cannot be combined: the pass lists every destination its owner approved in writing, and an --allow beside it would add a destination the owner did not approve. Add the destination to the pass (with the owner's written approval), or use --only LABEL to narrow the pass";

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
    /// Test expected packet decisions without loading a firewall.
    PolicyTest(policy_test::PolicyTestArgs),
    /// Compare two full reports without executing either command.
    Compare {
        before: PathBuf,
        after: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Run COMMAND with egress limited to a pass's destinations or the --allow ones.
    Run(RunArgs),
    /// Preview the validated run without starting helpers or writing a report.
    Plan(RunArgs),
    /// Print the nftables ruleset that would be loaded; sends and creates nothing.
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
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Check that this machine can run playpen, and say exactly what is missing.
    Doctor {
        /// Capability to demonstrate (offline avoids the pasta dependency).
        #[arg(long, value_enum, default_value = "egress")]
        mode: crate::doctor::Mode,
        /// Output format.
        #[arg(long, value_enum, default_value = "text")]
        format: Format,
    },
    /// Run native sandbox qualification scenarios and report what executed.
    Qualify {
        /// Explicit trusted source tree for integration-test scenarios.
        #[arg(long, value_name = "PATH")]
        source: Option<PathBuf>,
        /// A scenario that this qualification job requires to execute.
        #[arg(long = "require", value_name = "SCENARIO")]
        required: Vec<String>,
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
    /// Try TIOCSTI on standard input and opening /dev/tty.
    Tty,
    /// Count deliveries of SIGUSR1 until SIGTERM.
    Signals,
    /// Listen on ADDR:PORT/tcp for MS milliseconds; print the connections.
    Listen {
        target: String,
        #[arg(long, default_value_t = 5000)]
        ms: u64,
    },
}

#[derive(Debug, clap::Args)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent command-line switches"
)]
struct RunArgs {
    /// A hallpass pass: allow exactly its destinations until its approval
    /// window end, and stop the command if it is revoked or edited.
    /// Cannot be combined with --allow.
    #[arg(long, value_name = "FILE")]
    pass: Option<PathBuf>,
    /// With --pass: use only the destination with this label. Repeatable.
    #[arg(long = "only", value_name = "LABEL")]
    only: Vec<String>,
    /// Approved destination: ADDR:PORT/PROTO, ADDR:FROM-TO/PROTO or
    /// NET/PREFIX:PORTS/PROTO; IPv6 in brackets. Repeatable.
    #[arg(long = "allow", value_name = "SPEC")]
    allow: Vec<String>,
    /// Make NAME resolve to ADDR inside the sandbox (ADDR must be approved). Repeatable.
    #[arg(long = "host", value_name = "NAME=ADDR")]
    host: Vec<String>,
    /// When the approval ends (RFC 3339 with offset); the command is stopped
    /// then. With --pass it can only be earlier than the pass's window end.
    #[arg(long, value_name = "RFC3339")]
    until: Option<String>,
    /// No network at all: only loopback inside the sandbox.
    #[arg(long)]
    no_network: bool,
    /// Serve one literal HTTP fixture on private loopback in offline mode.
    #[arg(long, requires = "no_network", value_name = "JSON")]
    fixture: Option<PathBuf>,
    /// Also hide this host path from the command (sockets/files: bound to
    /// /dev/null; directories: an empty read-only tmpfs). Repeatable.
    #[arg(long = "hide", value_name = "PATH")]
    hide: Vec<PathBuf>,
    /// Let the command reach this host socket, or every socket below this
    /// directory. Host Unix sockets are unreachable otherwise. Repeatable.
    #[arg(long = "expose", value_name = "PATH")]
    expose: Vec<PathBuf>,
    /// Let graphical programs reach the display: expose the Wayland and X11
    /// sockets the environment names, and the X authority file. An X11
    /// server lets any client type into other windows; off by default.
    #[arg(long)]
    display: bool,
    /// Run on a kernel without Landlock ABI 9: hide host sockets by mounts
    /// only (under /run, /tmp, /var/tmp and the runtime directory). Sockets
    /// elsewhere, and ones created after the start, stay reachable.
    #[arg(long)]
    without_landlock: bool,
    /// Run the command in a new session with no controlling terminal, so
    /// it cannot type into the caller's terminal. Automatic on kernels that
    /// allow TIOCSTI; then Ctrl-C still reaches the command, but programs
    /// cannot open /dev/tty.
    #[arg(long)]
    new_session: bool,
    /// Write lifecycle JSON lines to an inherited pipe above stderr.
    #[arg(long, value_name = "FD")]
    events_fd: Option<i32>,
    /// Refuse pass terms that require an external enforcer.
    #[arg(long)]
    require_enforced: bool,
    /// Require the effective scope to match the digest from playpen plan.
    #[arg(long, value_name = "SHA256")]
    expect_plan: Option<hallpass::Digest>,
    /// Fail if any dropped packets were counted, or counters are unavailable.
    #[arg(long)]
    fail_on_drop: bool,
    /// Include bounded first-match grant packet counts in the private report.
    #[arg(long, requires = "report", conflicts_with = "shareable_report")]
    report_grant_use: bool,
    /// Summary format; json requires --report.
    #[arg(long, value_enum, default_value = "text")]
    format: Format,
    /// Write only the shareable allowlisted fields to the report.
    #[arg(long, requires = "report")]
    shareable_report: bool,
    /// Write the JSON summary to FILE (for every outcome, refusals included).
    #[arg(long, value_name = "FILE")]
    report: Option<PathBuf>,
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
        Cmd::PolicyTest(args) => policy_test::run(&args),
        Cmd::Plan(args) => preview::print(&args),
        Cmd::Compare {
            before,
            after,
            format,
        } => crate::compare::run(&before, &after, format == Format::Json),
        Cmd::Rules {
            allow,
            pass,
            only,
            format,
        } => rules(&allow, pass.as_deref(), &only, format),
        Cmd::Doctor { mode, format } => crate::doctor::run(mode, format == Format::Json),
        Cmd::Qualify {
            source,
            required,
            format,
        } => crate::qualification::run(&required, source.as_deref(), format == Format::Json),
        Cmd::Probe { what } => probe(what),
    }
}

fn rules(allow: &[String], pass_file: Option<&Path>, only: &[String], format: Format) -> i32 {
    let refuse = |e: &str| {
        eprintln!("playpen: refused: {e}");
        EXIT_REFUSED
    };
    let (approval, identity) = if let Some(path) = pass_file {
        if !allow.is_empty() {
            return refuse(PASS_AND_ALLOW);
        }
        match pass::load(path, only, OffsetDateTime::now_utc()) {
            Ok(p) => (p.approval, Some(p.identity)),
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
    let text = crate::ruleset::render_approval(&approval);
    match format {
        Format::Text => print!("{text}"),
        Format::Json => println!(
            "{}",
            serde_json::json!({
                "allowed": approval.rules().iter().map(ToString::to_string).collect::<Vec<_>>(),
                "pass": identity.as_ref().map(pass_report),
                "ruleset": text,
            })
        ),
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
    }
}

fn print_probe_lines(result: Result<Vec<serde_json::Value>, String>) -> i32 {
    match result {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            0
        }
        Err(e) => {
            eprintln!("probe: {e}");
            EXIT_ERROR
        }
    }
}

fn probe(what: ProbeCmd) -> i32 {
    match what {
        ProbeCmd::HttpFixture => match crate::fixture::serve() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("fixture: {e}");
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
            println!("{}", crate::probe::privs(&nft));
            0
        }
        ProbeCmd::Resolve { name } => {
            println!("{}", crate::probe::resolve(&name));
            0
        }
        ProbeCmd::Unix { listen, tries } => print_probe_lines(crate::probe::unix(&listen, &tries)),
        ProbeCmd::Fds => {
            println!("{}", crate::probe::fds());
            0
        }
        ProbeCmd::Interfaces => {
            println!("{}", crate::probe::interfaces());
            0
        }
        ProbeCmd::UnixSend { path } => {
            println!("{}", crate::probe::unix_send(&path));
            0
        }
        ProbeCmd::UnixRecvFd { path, to } => match to.parse() {
            Ok(to) => {
                println!("{}", crate::probe::unix_recv_fd(&path, to));
                0
            }
            Err(e) => {
                eprintln!("probe: {to:?}: {e}");
                EXIT_ERROR
            }
        },
        ProbeCmd::StdoutReconnect { target } => {
            eprintln!("{}", crate::probe::stdout_reconnect(&target));
            0
        }
        ProbeCmd::Tty => {
            println!("{}", crate::probe::tty());
            0
        }
        ProbeCmd::Signals => match crate::probe::signals() {
            Ok(v) => {
                println!("{v}");
                0
            }
            Err(e) => {
                eprintln!("probe: {e}");
                EXIT_ERROR
            }
        },
        ProbeCmd::Listen { target, ms } => {
            match crate::probe::parse_target(&target).and_then(|t| crate::probe::listen_tcp(t, ms))
            {
                Ok(v) => {
                    println!("{v}");
                    0
                }
                Err(e) => {
                    eprintln!("probe: {e}");
                    EXIT_ERROR
                }
            }
        }
    }
}

/// Validated run request.
struct Checked {
    fixture: Option<crate::fixture::Fixture>,
    new_session: bool,
    approval: Approval,
    hosts: Vec<HostEntry>,
    lo_addrs: Vec<IpAddr>,
    from_pass: Option<FromPass>,
    /// Every exposed path, canonical (`--expose` and `--display`).
    exposed: Vec<PathBuf>,
    /// The display sockets among them.
    display: Vec<PathBuf>,
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
        if until.at() > from_pass.identity.valid_until {
            return Err(format!(
                "--until {} is later than the pass's valid_until {}; --until can only end the run earlier than the window the owner approved. Leave --until out to run until {}",
                until.to_rfc3339(),
                hallpass::stamp(from_pass.identity.valid_until),
                hallpass::stamp(from_pass.identity.valid_until)
            ));
        }
        from_pass.approval.ends_at = Some(until);
    }
    from_pass.watch.require_enforced = args.require_enforced;
    if let Some(ms) = args.pass_recheck_ms {
        from_pass.watch.interval =
            Duration::from_millis(ms).clamp(MIN_RECHECK_INTERVAL, RECHECK_INTERVAL);
    }
    Ok(from_pass)
}

/// Every `--host` address must be in a destination of the pass that is in
/// use. A host name the pass mentions grants nothing.
fn check_pass_hosts(hosts: &[HostEntry], from_pass: &FromPass) -> Result<(), String> {
    for h in hosts {
        if !from_pass.approval.covers_addr(h.addr) {
            return Err(format!(
                "--host {}={}: {} is not in any destination of the pass in use ({}), for any port, so the name would lead to an address nobody approved; map the name to an address the pass lists{}{}",
                h.name,
                h.addr,
                h.addr,
                from_pass.identity.labels.join(", "),
                from_pass.approval.edge_hint(h.addr),
                hostname_hint(&from_pass.named, &[])
            ));
        }
    }
    Ok(())
}

/// Names the pass mentions that no `--host` maps: they are not resolved.
fn hostname_hint(named: &[NamedDestination], hosts: &[HostEntry]) -> String {
    let unmapped: Vec<String> = named
        .iter()
        .filter(|n| {
            !hosts
                .iter()
                .any(|h| h.name.eq_ignore_ascii_case(&n.hostname))
        })
        .map(|n| {
            let addr = if n.single {
                n.destination.clone()
            } else {
                format!("ADDR-IN-{}", n.destination)
            };
            format!("--host {}={addr} (destination {})", n.hostname, n.label)
        })
        .collect();
    if unmapped.is_empty() {
        String::new()
    } else {
        format!(
            "; host names in the pass grant nothing and are not resolved; if the tool needs them, map them with {}",
            unmapped.join(", ")
        )
    }
}

fn check(args: &RunArgs) -> Result<Checked, String> {
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
    match &from_pass {
        Some(p) => check_pass_hosts(&hosts, p)?,
        None => check_hosts(&hosts, &approval).map_err(|e| e.to_string())?,
    }
    let mut lo_addrs = Vec::new();
    for a in &args.lo_addr {
        lo_addrs.push(parse_literal_addr(a).map_err(|e| format!("--lo-addr {a:?}: {e}"))?);
    }
    let (exposed, display) = check_exposed(args)?;
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
        lo_addrs,
        from_pass,
        exposed,
        display,
    })
}

fn enforce_coverage(args: &RunArgs, checked: &Checked) -> Result<(), String> {
    if args.require_enforced
        && checked
            .from_pass
            .as_ref()
            .is_some_and(|p| !p.coverage.fully_enforced())
    {
        return Err("--require-enforced: selected names or application ceilings require an external enforcer".into());
    }
    Ok(())
}

struct StderrEvents<'a> {
    pipe: &'a EventPipe,
    args: &'a RunArgs,
    start_line: String,
    until: Option<String>,
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
        eprintln!("{}", self.start_line);
    }
    fn until_reached(&mut self) {
        self.pipe
            .send("stopping", &serde_json::json!({"reason":"expiry"}));
        eprintln!(
            "playpen: the approval ended at {}; sending SIGTERM to the command (SIGKILL in {} s)",
            self.until.as_deref().unwrap_or("?"),
            sandbox::GRACE.as_secs()
        );
    }
    fn pass_edited(&mut self, message: &str) {
        eprintln!("playpen: {message}");
    }
    fn pass_withdrawn(&mut self, reason: &str) {
        self.pipe
            .send("stopping", &serde_json::json!({"reason":"pass_withdrawn"}));
        eprintln!(
            "playpen: {reason}; sending SIGTERM to the command (SIGKILL in {} s)",
            sandbox::GRACE.as_secs()
        );
    }
}

fn paths(list: &[PathBuf]) -> String {
    list.iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// What the start line says about host Unix sockets.
fn sockets_clause(c: &Checked, landlock: bool) -> String {
    let mut out = if landlock {
        String::from("; host Unix sockets: none reachable")
    } else {
        String::from(
            "; host Unix sockets: hidden under /run, /tmp, /var/tmp and the runtime directory only (--without-landlock); sockets elsewhere stay reachable",
        )
    };
    let other: Vec<PathBuf> = c
        .exposed
        .iter()
        .filter(|p| !c.display.contains(p))
        .cloned()
        .collect();
    if !other.is_empty() {
        out.push_str("; exposed: ");
        out.push_str(&paths(&other));
    }
    if !c.display.is_empty() {
        out.push_str("; display exposed: ");
        out.push_str(&paths(&c.display));
    }
    out
}

fn start_line(c: &Checked, network: bool, landlock: bool, new_session: bool) -> String {
    let line = start_line_net(c, network);
    let session = if new_session {
        "; the command runs in its own session, without a controlling terminal"
    } else {
        ""
    };
    format!("{line}{}{session}", sockets_clause(c, landlock))
}

fn start_line_net(c: &Checked, network: bool) -> String {
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
        let list: Vec<String> = c.approval.rules().iter().map(ToString::to_string).collect();
        let (under, hint) = c.from_pass.as_ref().map_or_else(Default::default, |p| {
            (
                format!("under {}: ", pass::describe(&p.identity)),
                hostname_hint(&p.named, &c.hosts),
            )
        });
        let limited = c
            .from_pass
            .as_ref()
            .filter(|p| !p.name_limited.is_empty())
            .map_or_else(String::new, |p| {
                format!(
                    "\nplaypen: NOTE: the pass approves these destinations only for the listed host names: {}. playpen filters addresses and ports and cannot see the name inside a request, so it does NOT enforce this; the command must send only those names",
                    p.name_limited.join("; ")
                )
            });
        format!(
            "playpen: {under}allowing only {} {until} ({names}); everything else is dropped{hint}{limited}",
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
        }),
        playpen_exit_status: EXIT_REFUSED,
        dropped: None,
        grant_use: None,
        drop_assertion: None,
        dropped_error: None,
        socket_guard: if args.without_landlock {
            "mounts_only"
        } else {
            "landlock"
        },
        exposed: args
            .expose
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        display: args.display,
        new_session: new_session(args),
    }
}

/// Whether the command gets its own session.
fn new_session(args: &RunArgs) -> bool {
    args.new_session || sandbox::tiocsti_allowed()
}

fn write_report(file: Option<&mut File>, report: &Report, shareable: bool) {
    if let Some(f) = file {
        let text = if shareable {
            serde_json::to_string_pretty(&crate::report::ShareableReport::from(report))
        } else {
            serde_json::to_string_pretty(report)
        }
        .unwrap_or_default();
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
    let pipe = match EventPipe::open(args.events_fd) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("playpen: refused: {e}");
            return EXIT_REFUSED;
        }
    };
    let mut report = base_report(args);
    if args.format == Format::Json && args.report.is_none() {
        eprintln!(
            "playpen: refused: --format json writes the summary to a file; give it with --report FILE"
        );
        pipe.terminal(&report);
        return EXIT_REFUSED;
    }
    if args.fail_on_drop {
        report.drop_assertion = Some(crate::report::DropAssertion::Unknown);
    }
    let mut report_file = match &args.report {
        Some(p) => match File::create(p) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!(
                    "playpen: refused: cannot create the report file {}: {e}; nothing was run",
                    p.display()
                );
                pipe.terminal(&report);
                return EXIT_REFUSED;
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
            eprintln!("playpen: refused: {e}");
            if !e.contains("nothing was run") {
                eprintln!("playpen: nothing was run");
            }
            report.message = Some(e);
            write_report(report_file.as_mut(), &report, args.shareable_report);
            pipe.terminal(&report);
            return EXIT_REFUSED;
        }
    };
    report.enforcement_coverage = checked.from_pass.as_ref().map(|p| p.coverage.clone());
    if let Err(e) = enforce_coverage(args, &checked) {
        eprintln!("playpen: refused: {e}; nothing was run");
        report.message = Some(e);
        pipe.terminal(&report);
        write_report(report_file.as_mut(), &report, args.shareable_report);
        return EXIT_REFUSED;
    }
    pipe.send("validated", &serde_json::Value::Null);
    report.allowed = checked
        .approval
        .rules()
        .iter()
        .map(ToString::to_string)
        .collect();
    for path in &args.hide {
        if explicitly_missing(path) {
            eprintln!(
                "playpen: NOTE: --hide path {} does not exist; nothing was hidden there",
                path.display()
            );
        }
    }
    report.until = checked.approval.ends_at.map(EndsAt::to_rfc3339);
    if let Some(p) = &checked.from_pass {
        report.pass = Some(pass_report(&p.identity));
    }
    let fail = |report: &mut Report, file: Option<&mut File>, outcome, msg: String| {
        eprintln!("playpen: {msg}");
        report.outcome = outcome;
        if outcome == Outcome::Error {
            report.startup_evidence = StartupEvidence::Unknown;
        }
        report.message = Some(msg);
        report.playpen_exit_status = EXIT_ERROR;
        pipe.terminal(report);
        write_report(file, report, args.shareable_report);
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
            !args.no_network,
            !args.without_landlock,
            checked.new_session,
        ),
        until: report.until.clone(),
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
    let plan = Plan {
        fixture: checked.fixture,
        approval: checked.approval,
        hosts: checked.hosts,
        network: !args.no_network,
        grant_counters,
        lo_addrs: checked.lo_addrs,
        hide: args.hide.clone(),
        exposed: checked.exposed,
        landlock: !args.without_landlock,
        new_session: checked.new_session,
        command: args.command.clone(),
        nft,
        pasta,
        watch: checked.from_pass.map(|p| p.watch),
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
    let code = apply_drop_assertion(&mut report, code, args.fail_on_drop);
    report.playpen_exit_status = code;
    pipe.terminal(&report);
    eprint!("{}", text_summary(&report));
    write_report(report_file.as_mut(), &report, args.shareable_report);
    code
}

pub(crate) fn apply_drop_assertion(report: &mut Report, code: i32, enabled: bool) -> i32 {
    if !enabled {
        return code;
    }
    let assertion = match &report.dropped {
        Some(d) if d.packets > 0 => crate::report::DropAssertion::Violated,
        Some(d) if d.destinations.iter().any(|entry| entry.packets > 0) => {
            crate::report::DropAssertion::Unknown
        }
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
