//! `playpen doctor`: checks this machine without changing anything, except
//! that, like every run, it loads the `vsock` module where it is not loaded
//! (see [`crate::vsock`]).
//!
//! Besides looking for the tools and kernel settings, it runs the real
//! mechanism once: a sandbox whose only reachable destinations are
//! documentation addresses added to the sandbox's own `lo`, so no packet can
//! leave the machine even if something were wrong. It also checks that
//! every address family has a default route in the sandbox, so that a
//! packet to any address reaches the firewall (see [`crate::routes`]), and
//! that the command's VM sockets reach only the sandbox's own.

use crate::cli::discovery::Format;
use std::path::Path;
use std::process::Command;

use clap::ValueEnum;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Offline,
    Egress,
}

impl Mode {
    const fn name(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Egress => "egress",
        }
    }
}

#[derive(Debug, Serialize)]
struct ProbeResult {
    name: &'static str,
    status: &'static str,
    ok: Option<bool>,
    detail: String,
}

#[derive(Debug, Serialize)]
struct Capability {
    mode: &'static str,
    status: &'static str,
    detail: String,
}

fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

fn apparmor_userns_check(value: &str) -> Check {
    Check {
        name: "AppArmor user namespace restriction",
        ok: true,
        detail: if value == "0" {
            "kernel.apparmor_restrict_unprivileged_userns = 0".into()
        } else {
            format!(
                "kernel.apparmor_restrict_unprivileged_userns = {value}; the live namespace probe will determine whether an AppArmor profile permits playpen"
            )
        },
    }
}

fn userns_checks(out: &mut Vec<Check>) {
    let max = read_sysctl("/proc/sys/user/max_user_namespaces");
    out.push(match max.as_deref() {
        Some("0") => Check {
            name: "user namespaces",
            ok: false,
            detail: "user.max_user_namespaces is 0; an administrator must raise it".into(),
        },
        Some(v) => Check {
            name: "user namespaces",
            ok: true,
            detail: format!("user.max_user_namespaces = {v}"),
        },
        None => Check {
            name: "user namespaces",
            ok: false,
            detail: "the kernel has no user namespace support (/proc/sys/user/max_user_namespaces missing)".into(),
        },
    });
    if let Some(v) = read_sysctl("/proc/sys/kernel/unprivileged_userns_clone") {
        out.push(Check {
            name: "unprivileged user namespaces",
            ok: v == "1",
            detail: if v == "1" {
                "kernel.unprivileged_userns_clone = 1".into()
            } else {
                format!("kernel.unprivileged_userns_clone = {v}; an administrator must set it to 1")
            },
        });
    }
    if let Some(v) = read_sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
        out.push(apparmor_userns_check(&v));
    }
}

fn tool_check(name: &'static str, found: Option<&Path>, hint: &str) -> Check {
    let Some(path) = found else {
        return Check {
            name,
            ok: false,
            detail: format!("not found; {hint}"),
        };
    };
    match Command::new(path).arg("--version").output() {
        Ok(o) if o.status.success() => Check {
            name,
            ok: true,
            detail: format!(
                "{} ({})",
                path.display(),
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
            ),
        },
        Ok(o) => Check {
            name,
            ok: false,
            detail: format!("{} --version failed: {}", path.display(), o.status),
        },
        Err(e) => Check {
            name,
            ok: false,
            detail: format!("cannot run {}: {e}", path.display()),
        },
    }
}

/// Runs `playpen run ARGS -- playpen probe PROBE...` and returns stdout.
fn self_run(run_args: &[&str], probe: &[&str]) -> Result<String, String> {
    let me = std::env::current_exe().map_err(|e| format!("cannot find own binary: {e}"))?;
    let out = Command::new(&me)
        .args(["run", "--format", "text"])
        .args(run_args)
        .arg("--")
        .arg(&me)
        .arg("probe")
        .args(probe)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", me.display()))?;
    if !out.status.success() {
        return Err(format!(
            "exit status {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .replace('\n', " | ")
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("invalid probe stdout: {e}"))
}

fn self_command(run_args: &[&str], command: &[&str]) -> Check {
    let name = "offline command";
    let Some((executable, arguments)) = command.split_first() else {
        return Check {
            name,
            ok: false,
            detail: "no command was configured".into(),
        };
    };
    let me = match std::env::current_exe() {
        Ok(me) => me,
        Err(e) => {
            return Check {
                name,
                ok: false,
                detail: format!("cannot find own binary: {e}"),
            };
        }
    };
    let out = Command::new(&me)
        .args(["run", "--format", "text"])
        .args(run_args)
        .arg("--")
        .arg(executable)
        .args(arguments)
        .output();
    match out {
        Ok(o) if o.status.success() => Check {
            name,
            ok: true,
            detail: "a real --no-network command ran successfully".into(),
        },
        Ok(o) => Check {
            name,
            ok: false,
            detail: format!(
                "exit status {}: {}",
                o.status,
                String::from_utf8_lossy(&o.stderr)
                    .trim()
                    .replace('\n', " | ")
            ),
        },
        Err(e) => Check {
            name,
            ok: false,
            detail: format!("cannot run {}: {e}", me.display()),
        },
    }
}

/// Runs `playpen run --format json ARGS -- playpen probe PROBE...` and
/// returns the run's report, which JSON mode prints on stdout.
fn self_report(run_args: &[&str], probe: &[&str]) -> Result<serde_json::Value, String> {
    let me = std::env::current_exe().map_err(|e| format!("cannot find own binary: {e}"))?;
    let out = Command::new(&me)
        .args(["run", "--format", "json"])
        .args(run_args)
        .arg("--")
        .arg(&me)
        .arg("probe")
        .args(probe)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", me.display()))?;
    serde_json::from_slice(&out.stdout).map_err(|e| {
        format!(
            "no report ({e}), exit status {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .replace('\n', " | ")
        )
    })
}

/// The interface names and the default routes `probe interfaces` printed.
fn interfaces_and_routes(out: &str) -> (Vec<String>, crate::routes::DefaultRoutes) {
    let value = serde_json::from_str::<serde_json::Value>(out.trim()).unwrap_or_default();
    let list = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    let routes = &value["default_routes"];
    (
        list(&value["interfaces"]),
        crate::routes::DefaultRoutes {
            ipv4: list(&routes["ipv4"]),
            ipv6: list(&routes["ipv6"]),
        },
    )
}

/// The offline sandbox has `lo` and the discard interface, both default
/// routes lead to the discard interface, and a packet to another host is
/// refused and counted.
fn offline_interfaces_check() -> Check {
    let name = "offline loopback only";
    let fail = |detail: String| Check {
        name,
        ok: false,
        detail,
    };
    let out = match self_run(&["--no-network"], &["interfaces"]) {
        Ok(out) => out,
        Err(e) => return fail(e),
    };
    let discard = crate::routes::DISCARD;
    let (names, routes) = interfaces_and_routes(&out);
    if names != ["lo", discard] {
        return fail(format!(
            "expected lo and {discard}, found {}",
            names.join(", ")
        ));
    }
    if routes.ipv4 != [discard] || routes.ipv6 != [discard] {
        return fail(format!(
            "expected the IPv4 and IPv6 default routes on {discard}, found {routes:?}"
        ));
    }
    // Documentation addresses: refused before they reach the discard
    // interface, and so before anything could leave.
    let tries = ["192.0.2.1:9/tcp", "[2001:db8::1]:9/udp"];
    let report = match self_report(
        &["--no-network"],
        &["reach", "--try", tries[0], "--try", tries[1]],
    ) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let counted = |address: &str, protocol: &str| {
        report["dropped"]["destinations"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|d| d["address"] == address && d["protocol"] == protocol && d["port"] == 9)
    };
    if !counted("192.0.2.1", "tcp")
        || !counted("2001:db8::1", "udp")
        || !report["uncounted"].is_null()
    {
        return fail(format!(
            "attempts to {} were not all refused and counted: dropped {}, uncounted {}",
            tries.join(" and "),
            report["dropped"],
            report["uncounted"]
        ));
    }
    Check {
        name,
        ok: true,
        detail: format!(
            "the sandbox has its loopback interface and {discard}, which discards what is sent to it; both default routes lead to {discard}, and IPv4 and IPv6 attempts to other hosts were refused and counted"
        ),
    }
}

/// Every address family has a default route in a sandbox with pasta, and
/// says which ones playpen added because this host has none.
fn routes_check() -> Check {
    let name = "default routes";
    let out = match self_run(SANDBOX, &["interfaces"]) {
        Ok(out) => out,
        Err(e) => {
            return Check {
                name,
                ok: false,
                detail: e,
            };
        }
    };
    let (_, inside) = interfaces_and_routes(&out);
    let host = crate::routes::DefaultRoutes::read().unwrap_or_default();
    let mut said = Vec::new();
    let mut ok = true;
    for family in crate::netlink::Family::BOTH {
        let f = family.name();
        said.push(match (host.of(family).is_empty(), inside.of(family).is_empty()) {
            (_, true) => {
                ok = false;
                format!("{f}: the sandbox has no default route, so {f} attempts fail at routing and are not counted")
            }
            (false, false) => format!("{f}: this host's default route"),
            (true, false) => format!(
                "{f}: this host has no default route, so playpen adds one into pasta's interface; {f} attempts are refused and counted, and approved {f} destinations are reachable only where this host has a route to them"
            ),
        });
    }
    Check {
        name,
        ok,
        detail: said.join("; "),
    }
}

const SANDBOX: &[&str] = &[
    "--allow",
    "192.0.2.1:9101/tcp",
    "--allow",
    "192.0.2.1:9102/udp",
    "--allow",
    "[2001:db8::1]:9101/tcp",
    "--lo-addr",
    "192.0.2.1",
    "--lo-addr",
    "192.0.2.2",
    "--lo-addr",
    "2001:db8::1",
    "--lo-addr",
    "2001:db8::2",
];

fn reach_check() -> Check {
    let probe = [
        "reach",
        "--serve",
        "192.0.2.1:9101/tcp",
        "--serve",
        "192.0.2.1:9103/tcp",
        "--serve",
        "192.0.2.2:9101/tcp",
        "--serve",
        "192.0.2.1:9102/udp",
        "--serve",
        "192.0.2.2:9102/udp",
        "--serve",
        "[2001:db8::1]:9101/tcp",
        "--serve",
        "[2001:db8::2]:9101/tcp",
        "--try",
        "192.0.2.1:9101/tcp",
        "--try",
        "192.0.2.1:9103/tcp",
        "--try",
        "192.0.2.2:9101/tcp",
        "--try",
        "192.0.2.1:9102/udp",
        "--try",
        "192.0.2.2:9102/udp",
        "--try",
        "[2001:db8::1]:9101/tcp",
        "--try",
        "[2001:db8::2]:9101/tcp",
    ];
    let expected = [true, false, false, true, false, true, false];
    let name = "allowed reached, others blocked";
    let out = match self_run(SANDBOX, &probe) {
        Ok(o) => o,
        Err(e) => {
            return Check {
                name,
                ok: false,
                detail: e,
            };
        }
    };
    let got: Vec<(String, bool)> = out
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .map(|v| {
            (
                v["target"].as_str().unwrap_or("").to_owned(),
                v["reached"].as_bool().unwrap_or(true),
            )
        })
        .collect();
    let wrong: Vec<String> = got
        .iter()
        .zip(expected)
        .filter(|((_, r), want)| r != want)
        .map(|((t, r), _)| format!("{t} {}", if *r { "was reached" } else { "was not reached" }))
        .collect();
    if got.len() != expected.len() || !wrong.is_empty() {
        return Check {
            name,
            ok: false,
            detail: format!("unexpected results: {}", wrong.join(", ")),
        };
    }
    Check {
        name,
        ok: true,
        detail: "TCP, UDP and IPv6 to in-sandbox addresses: approved reached, others dropped"
            .into(),
    }
}

fn privs_check(nft: &Path, offline: bool) -> Check {
    let name = "command cannot change the network";
    let nft_s = nft.display().to_string();
    let run_args: &[&str] = if offline { &["--no-network"] } else { SANDBOX };
    let out = match self_run(run_args, &["privs", "--nft", &nft_s]) {
        Ok(o) => o,
        Err(e) => {
            return Check {
                name,
                ok: false,
                detail: e,
            };
        }
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(out.trim()) else {
        return Check {
            name,
            ok: false,
            detail: format!("unexpected probe output: {out}"),
        };
    };
    let allowed: Vec<String> = v
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, val)| val.as_str() == Some("ALLOWED"))
        .map(|(k, _)| k.clone())
        .collect();
    if allowed.is_empty()
        && v["cap_eff"]
            .as_str()
            .is_some_and(|c| c.bytes().all(|b| b == b'0'))
    {
        Check {
            name,
            ok: true,
            detail: "nft, netlink address, link and route changes, raw and packet sockets, binding port 53 all denied; no capabilities".into(),
        }
    } else {
        Check {
            name,
            ok: false,
            detail: format!("the command could: {}", allowed.join(", ")),
        }
    }
}

fn landlock_check() -> Check {
    let name = "Landlock (host Unix sockets)";
    match crate::landlock::abi() {
        Some(v) if v >= crate::landlock::RESOLVE_UNIX_ABI => Check {
            name,
            ok: true,
            detail: format!("ABI {v}: connections to host Unix sockets can be refused"),
        },
        _ => Check {
            name,
            ok: false,
            detail: crate::sandbox::landlock_missing(),
        },
    }
}

fn terminal_check() -> Check {
    Check {
        name: "terminal input injection (TIOCSTI)",
        ok: true,
        detail: if crate::sandbox::tiocsti_allowed() {
            "this kernel allows TIOCSTI: the default workload has no controlling terminal".into()
        } else {
            "refused by the kernel (dev.tty.legacy_tiocsti = 0): the default workload keeps the terminal and job control".into()
        },
    }
}

fn prerequisites_ok(checks: &[Check]) -> bool {
    checks.iter().all(|check| check.ok)
}

/// A host socket (in a fresh private directory) and a host abstract
/// socket must not be connectable from inside.
fn sockets_check() -> Check {
    let name = "host Unix sockets unreachable";
    let fail = |detail: String| Check {
        name,
        ok: false,
        detail,
    };
    let dir = match crate::sandbox::private_dir() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let path = dir.join("doctor.sock");
    let abstract_name = format!("playpen-doctor-{}", std::process::id());
    let listeners = (|| {
        use std::os::linux::net::SocketAddrExt as _;
        let a = std::os::unix::net::UnixListener::bind(&path)?;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(abstract_name.as_bytes())?;
        let b = std::os::unix::net::UnixListener::bind_addr(&addr)?;
        Ok::<_, std::io::Error>((a, b))
    })();
    let path_s = path.display().to_string();
    let at = format!("@{abstract_name}");
    let control = format!("{at}-inside");
    let result = match listeners {
        Ok(_held) => self_run(
            &["--no-network"],
            &[
                "unix", "--listen", &control, "--try", &path_s, "--try", &at, "--try", &control,
            ],
        )
        .and_then(|out| crate::probe::connected_unix_paths(&out, &[&path_s, &at, &control])),
        Err(e) => Err(format!("cannot create the test sockets: {e}")),
    };
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
    match result {
        Ok(connected) if connected == [control.as_str()] => Check {
            name,
            ok: true,
            detail:
                "private control socket reached; host pathname and abstract sockets unreachable"
                    .into(),
        },
        Ok(connected) => fail(format!(
            "expected only the private control {control:?} to connect; reached {connected:?}"
        )),
        Err(e) => fail(e),
    }
}

/// A VM-socket listener of the caller in the caller's network namespace, on
/// a port the kernel picks: the socket and the port. Creating it loads the
/// `vsock` module where it is not loaded, as `playpen run` does.
fn vsock_listener() -> Result<(std::os::fd::OwnedFd, u32), nix::errno::Errno> {
    use nix::sys::socket::{
        AddressFamily, Backlog, SockFlag, SockType, VsockAddr, bind, getsockname, listen, socket,
    };
    use std::os::fd::AsRawFd as _;
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    bind(
        fd.as_raw_fd(),
        &VsockAddr::new(libc::VMADDR_CID_ANY, libc::VMADDR_PORT_ANY),
    )?;
    listen(&fd, Backlog::new(4)?)?;
    let port = getsockname::<VsockAddr>(fd.as_raw_fd())?.port();
    Ok((fd, port))
}

/// VM sockets (`AF_VSOCK`): inside a sandbox, the command reads VSOCK mode
/// `local`, and cannot connect over the loopback transport (CID 1) to a
/// listener doctor holds outside; or the kernel offers no VM sockets.
fn vsock_check(run_args: &[&str]) -> Check {
    let name = "VM sockets (AF_VSOCK)";
    let fail = |detail: String| Check {
        name,
        ok: false,
        detail,
    };
    // Held until the probe has tried it; a connection that got through
    // waits in its backlog.
    let listener = vsock_listener();
    let port = listener.as_ref().ok().map(|(_, port)| port.to_string());
    let mut probe = vec!["vsock"];
    if let Some(port) = port.as_deref() {
        probe.extend(["--try", port]);
    }
    let out = match self_run(run_args, &probe) {
        Ok(out) => out,
        Err(e) => return fail(e),
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(out.trim()) else {
        return fail(format!("unexpected probe output: {out}"));
    };
    let socket = v["socket"].as_str().unwrap_or_default();
    match v["ns_mode"].as_str() {
        Some("local") => match (&v["connect"]["connected"], port) {
            (serde_json::Value::Bool(false), Some(port)) => Check {
                name,
                ok: true,
                detail: format!(
                    "the sandbox has VSOCK mode local: the command's VM sockets reach only the sandbox's own; a listener outside at CID 1 port {port} was not reachable ({})",
                    v["connect"]["error"].as_str().unwrap_or("refused")
                ),
            },
            (serde_json::Value::Bool(true), Some(port)) => fail(format!(
                "the sandbox has VSOCK mode local, but the command connected to a listener outside at CID 1 port {port}"
            )),
            _ => fail(format!(
                "the sandbox has VSOCK mode local, but the reach of its VM sockets could not be tried: {}",
                listener.err().map_or_else(
                    || format!("the probe could not connect ({socket})"),
                    |e| format!("no listener outside ({e})")
                )
            )),
        },
        Some(other) => fail(format!(
            "the sandbox has VSOCK mode {other}: the command's VM sockets reach the hypervisor, this machine's VMs and VM-socket listeners"
        )),
        None if socket == "created" => fail(
            "not confined: this kernel has no VSOCK namespace mode (Linux 7.0 has it), so the command's VM sockets reach the hypervisor, this machine's VMs and VM-socket listeners; --hide /dev/vhost-vsock at least keeps it from acting as a VM".into(),
        ),
        None => Check {
            name,
            ok: true,
            detail: format!("the command cannot create VM sockets ({socket})"),
        },
    }
}

/// Runs every check and prints the result. Returns the exit status.
#[must_use]
pub fn run(mode: Mode, json: bool) -> i32 {
    run_formatted(mode, if json { Format::Json } else { Format::Pretty })
}

pub(crate) fn run_formatted(mode: Mode, format: Format) -> i32 {
    let mut checks = Vec::new();
    userns_checks(&mut checks);
    let nft = crate::tools::nft();
    checks.push(tool_check(
        "nft",
        nft.as_deref(),
        "install nftables (it provides /usr/bin/nft) or set PLAYPEN_NFT",
    ));
    if matches!(mode, Mode::Egress) {
        let found = crate::tools::pasta();
        checks.push(tool_check(
            "pasta",
            found.as_deref(),
            "install passt (it provides /usr/bin/pasta) or set PLAYPEN_PASTA",
        ));
    }
    checks.push(landlock_check());
    checks.push(terminal_check());

    let prereq_end = checks.len() - 1; // terminal behavior is informational
    let prereqs_ok = prerequisites_ok(&checks[..prereq_end]);
    let prereq_detail = checks[..prereq_end]
        .iter()
        .filter(|c| !c.ok)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect::<Vec<_>>()
        .join("; ");
    let mut probes = Vec::new();

    if prereqs_ok && let Some(nft) = nft.as_deref() {
        let executed = match mode {
            Mode::Offline => vec![
                self_command(&["--no-network"], &["true"]),
                offline_interfaces_check(),
                privs_check(nft, true),
                sockets_check(),
                vsock_check(&["--no-network"]),
            ],
            Mode::Egress => vec![
                reach_check(),
                routes_check(),
                privs_check(nft, false),
                sockets_check(),
                vsock_check(SANDBOX),
            ],
        };
        for check in executed {
            probes.push(ProbeResult {
                name: check.name,
                status: "executed",
                ok: Some(check.ok),
                detail: check.detail.clone(),
            });
            checks.push(check);
        }
    }

    if probes.is_empty() {
        let skipped: &[&str] = match mode {
            Mode::Offline => &[
                "offline command",
                "offline loopback only",
                "command cannot change the network",
                "host Unix sockets unreachable",
                "VM sockets (AF_VSOCK)",
            ],
            Mode::Egress => &[
                "allowed reached, others blocked",
                "default routes",
                "command cannot change the network",
                "host Unix sockets unreachable",
                "VM sockets (AF_VSOCK)",
            ],
        };
        for name in skipped {
            probes.push(ProbeResult {
                name,
                status: "untested",
                ok: None,
                detail: format!("not run because prerequisites are unavailable: {prereq_detail}"),
            });
        }
        checks.push(Check {
            name: "namespace self-test",
            ok: false,
            detail: format!("untested; prerequisites are unavailable: {prereq_detail}"),
        });
    }

    let ok = checks.iter().all(|c| c.ok);
    let capability = capability(mode, prereqs_ok, prereq_detail, &probes);
    print_result(mode, ok, &capability, &checks, &probes, format);
    i32::from(!ok)
}

fn capability(
    mode: Mode,
    prereqs_ok: bool,
    prereq_detail: String,
    probes: &[ProbeResult],
) -> Capability {
    let probe_ok = probes.iter().all(|p| p.ok == Some(true));
    Capability {
        mode: mode.name(),
        status: if !prereqs_ok {
            "unavailable"
        } else if probe_ok {
            "available"
        } else {
            "failed"
        },
        detail: if prereqs_ok {
            if probe_ok {
                format!(
                    "{} mode was demonstrated by every requested probe",
                    mode.name()
                )
            } else {
                format!(
                    "{} mode has one or more failed executed probes",
                    mode.name()
                )
            }
        } else {
            prereq_detail
        },
    }
}

fn print_result(
    mode: Mode,
    ok: bool,
    capability: &Capability,
    checks: &[Check],
    probes: &[ProbeResult],
    format: Format,
) {
    if format == Format::Json {
        outln!(
            "{}",
            serde_json::json!({
                "ok": ok,
                "mode": mode,
                "capability": capability,
                "probes": probes,
                "checks": checks, "advice": [],
            })
        );
    } else if format == Format::Text {
        outln!("{}  {}", mode.name(), capability.status);
        for c in checks {
            outln!(
                "{}  {}  {}",
                c.name,
                if c.ok { "ok" } else { "failed" },
                c.detail
            );
        }
        for p in probes.iter().filter(|p| p.status == "untested") {
            outln!("{}  untested  {}", p.name, p.detail);
        }
    } else {
        for c in checks {
            outln!(
                "{} {}: {}",
                if c.ok { "ok  " } else { "FAIL" },
                c.name,
                c.detail
            );
        }
        for probe in probes {
            if probe.status == "untested" {
                outln!("untested {}: {}", probe.name, probe.detail);
            }
        }
        outln!(
            "{}",
            if ok {
                format!("playpen {} mode is available.", mode.name())
            } else {
                format!(
                    "playpen {} mode is not available until the FAIL lines are fixed.",
                    mode.name()
                )
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{Check, apparmor_userns_check, prerequisites_ok};

    #[test]
    fn unavailable_shared_prerequisite_blocks_either_mode() {
        let checks = [
            Check {
                name: "user namespaces",
                ok: false,
                detail: "unavailable in this simulated host".into(),
            },
            Check {
                name: "nft",
                ok: true,
                detail: "available".into(),
            },
            Check {
                name: "Landlock (host Unix sockets)",
                ok: true,
                detail: "available".into(),
            },
        ];
        assert!(!prerequisites_ok(&checks));
    }

    #[test]
    fn restricted_but_profile_permitted_apparmor_does_not_block_live_probes() {
        let checks = [
            Check {
                name: "user namespaces",
                ok: true,
                detail: "namespaces are enabled".into(),
            },
            Check {
                name: "nft",
                ok: true,
                detail: "available".into(),
            },
            Check {
                name: "Landlock (host Unix sockets)",
                ok: true,
                detail: "available".into(),
            },
            apparmor_userns_check("1"),
        ];
        assert!(checks[3].detail.contains("live namespace probe"));
        assert!(prerequisites_ok(&checks));
    }
}
