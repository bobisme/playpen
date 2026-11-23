//! `playpen doctor`: checks this machine without changing anything.
//!
//! Besides looking for the tools and kernel settings, it runs the real
//! mechanism once: a sandbox whose only reachable destinations are
//! documentation addresses added to the sandbox's own `lo`, so no packet can
//! leave the machine even if something were wrong.

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

fn offline_interfaces_check() -> Check {
    let name = "offline loopback only";
    let out = match self_run(&["--no-network"], &["interfaces"]) {
        Ok(out) => out,
        Err(e) => {
            return Check {
                name,
                ok: false,
                detail: e,
            };
        }
    };
    let interfaces = serde_json::from_str::<serde_json::Value>(out.trim())
        .ok()
        .and_then(|value| value["interfaces"].as_array().cloned())
        .unwrap_or_default();
    let names = interfaces
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect::<Vec<_>>();
    if names == ["lo"] {
        Check {
            name,
            ok: true,
            detail: "the sandbox exposes only its loopback interface".into(),
        }
    } else {
        Check {
            name,
            ok: false,
            detail: format!("expected only lo, found {}", names.join(", ")),
        }
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
            detail: "nft, netlink address/link changes, raw and packet sockets, binding port 53 all denied; no capabilities".into(),
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
            ],
            Mode::Egress => vec![reach_check(), privs_check(nft, false), sockets_check()],
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
            ],
            Mode::Egress => &[
                "allowed reached, others blocked",
                "command cannot change the network",
                "host Unix sockets unreachable",
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
        println!(
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
        println!("{}  {}", mode.name(), capability.status);
        for c in checks {
            println!(
                "{}  {}  {}",
                c.name,
                if c.ok { "ok" } else { "failed" },
                c.detail
            );
        }
        for p in probes.iter().filter(|p| p.status == "untested") {
            println!("{}  untested  {}", p.name, p.detail);
        }
    } else {
        for c in checks {
            println!(
                "{} {}: {}",
                if c.ok { "ok  " } else { "FAIL" },
                c.name,
                c.detail
            );
        }
        for probe in probes {
            if probe.status == "untested" {
                println!("untested {}: {}", probe.name, probe.detail);
            }
        }
        println!(
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
