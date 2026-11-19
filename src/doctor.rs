//! `playpen doctor`: checks this machine without changing anything.
//!
//! Besides looking for the tools and kernel settings, it runs the real
//! mechanism once: a sandbox whose only reachable destinations are
//! documentation addresses added to the sandbox's own `lo`, so no packet can
//! leave the machine even if something were wrong.

use std::path::Path;
use std::process::Command;

use serde::Serialize;

#[derive(Debug, Serialize)]
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

fn read_sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
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
        out.push(Check {
            name: "AppArmor user namespace restriction",
            ok: v == "0",
            detail: if v == "0" {
                "kernel.apparmor_restrict_unprivileged_userns = 0".into()
            } else {
                format!(
                    "kernel.apparmor_restrict_unprivileged_userns = {v}; unprivileged namespaces get no capabilities unless an AppArmor profile allows them for playpen"
                )
            },
        });
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
        .arg("run")
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
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
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

fn privs_check(nft: &Path) -> Check {
    let name = "command cannot change the network";
    let nft_s = nft.display().to_string();
    let out = match self_run(SANDBOX, &["privs", "--nft", &nft_s]) {
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
            detail: "nft, netlink address/link changes, raw and packet sockets all denied; no capabilities".into(),
        }
    } else {
        Check {
            name,
            ok: false,
            detail: format!("the command could: {}", allowed.join(", ")),
        }
    }
}

/// Runs every check and prints the result. Returns the exit status.
#[must_use]
pub fn run(json: bool) -> i32 {
    let mut checks = Vec::new();
    userns_checks(&mut checks);
    let nft = crate::tools::nft();
    let pasta = crate::tools::pasta();
    checks.push(tool_check(
        "nft",
        nft.as_deref(),
        "install nftables (it provides /usr/bin/nft) or set PLAYPEN_NFT",
    ));
    checks.push(tool_check(
        "pasta",
        pasta.as_deref(),
        "install passt (it provides /usr/bin/pasta) or set PLAYPEN_PASTA; without it only --no-network works",
    ));
    let basics_ok = checks.iter().all(|c| c.ok);
    if basics_ok && let Some(nft) = &nft {
        checks.push(reach_check());
        checks.push(privs_check(nft));
    } else {
        checks.push(Check {
            name: "namespace self-test",
            ok: false,
            detail: "skipped because a check above failed".into(),
        });
    }
    let ok = checks.iter().all(|c| c.ok);
    if json {
        println!("{}", serde_json::json!({"ok": ok, "checks": checks}));
    } else {
        for c in &checks {
            println!(
                "{} {}: {}",
                if c.ok { "ok  " } else { "FAIL" },
                c.name,
                c.detail
            );
        }
        println!(
            "{}",
            if ok {
                "playpen can run here."
            } else {
                "playpen cannot run here until the FAIL lines are fixed."
            }
        );
    }
    i32::from(!ok)
}
