//! Opt-in, machine-readable qualification of native sandbox scenarios.

use crate::cli::discovery::{self, Format};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Copy)]
struct Scenario {
    id: &'static str,
    mode: &'static str,
    check: ScenarioCheck,
    prerequisites: &'static [&'static str],
}

#[derive(Clone, Copy)]
enum ScenarioCheck {
    DoctorProbe(&'static str),
    RoutedPeer,
    IntegrationTest {
        suite: &'static str,
        test: &'static str,
    },
}

const COMMON: &[&str] = &[
    "user namespaces available to this user",
    "working nft executable",
    "Landlock ABI 9 or later",
];

const SCENARIOS: &[Scenario] = &[
    Scenario {
        id: "offline-command",
        mode: "offline",
        check: ScenarioCheck::DoctorProbe("offline command"),
        prerequisites: COMMON,
    },
    Scenario {
        id: "offline-loopback",
        mode: "offline",
        check: ScenarioCheck::DoctorProbe("offline loopback only"),
        prerequisites: COMMON,
    },
    Scenario {
        id: "network-privileges",
        mode: "offline",
        check: ScenarioCheck::DoctorProbe("command cannot change the network"),
        prerequisites: COMMON,
    },
    Scenario {
        id: "unix-socket-guard",
        mode: "offline",
        check: ScenarioCheck::DoctorProbe("host Unix sockets unreachable"),
        prerequisites: COMMON,
    },
    Scenario {
        id: "cross-directory-rename",
        mode: "offline",
        check: ScenarioCheck::DoctorProbe("renames and links across directories"),
        prerequisites: COMMON,
    },
    Scenario {
        id: "socket-runtime-directory",
        mode: "offline",
        check: ScenarioCheck::IntegrationTest {
            suite: "sockets",
            test: "the_runtime_directory_is_private_empty_and_usable",
        },
        prerequisites: &[
            "user namespaces available to this user",
            "working nft executable",
            "Landlock ABI 9 or later",
            "cargo and cached integration-test dependencies",
        ],
    },
    Scenario {
        id: "egress-filter",
        mode: "egress",
        check: ScenarioCheck::DoctorProbe("allowed reached, others blocked"),
        prerequisites: &[
            "user namespaces available to this user",
            "working nft executable",
            "pasta executable",
            "Landlock ABI 9 or later",
        ],
    },
    Scenario {
        id: "run-loopback",
        mode: "egress",
        check: ScenarioCheck::IntegrationTest {
            suite: "run",
            test: "loopback_inside_the_sandbox_works",
        },
        prerequisites: &[
            "user namespaces available to this user",
            "working nft executable",
            "pasta executable (required by the run suite preflight)",
            "cargo and cached integration-test dependencies",
        ],
    },
    Scenario {
        id: "pass-egress",
        mode: "egress",
        check: ScenarioCheck::IntegrationTest {
            suite: "pass",
            test: "pass_destinations_are_reachable_and_nothing_else_and_the_report_names_the_pass",
        },
        prerequisites: &[
            "user namespaces available to this user",
            "working nft executable",
            "pasta executable",
            "cargo and cached integration-test dependencies",
        ],
    },
    Scenario {
        id: "gateway-host-loopback",
        mode: "egress",
        check: ScenarioCheck::IntegrationTest {
            suite: "gateway",
            test: "the_gateway_is_not_the_host_loopback",
        },
        prerequisites: &[
            "user namespaces available to this user",
            "working nft executable",
            "pasta executable",
            "unshare and ip with dummy-interface support",
            "cargo and cached integration-test dependencies",
        ],
    },
    Scenario {
        id: "routed-peer",
        mode: "egress",
        check: ScenarioCheck::RoutedPeer,
        prerequisites: &[
            "trusted source tree containing tests/routed_peer.py",
            "python3, ip, unshare, curl, nft and pasta",
            "nested user and network namespaces, IPv6, dummy interface and Landlock ABI 9",
        ],
    },
    Scenario {
        id: "terminal-pty-input",
        mode: "offline",
        check: ScenarioCheck::IntegrationTest {
            suite: "terminal",
            test: "the_command_reads_from_the_terminal",
        },
        prerequisites: &[
            "user namespaces available to this user",
            "working nft executable",
            "Landlock ABI 9 or later",
            "bash and a working pseudoterminal",
            "cargo and cached integration-test dependencies",
        ],
    },
    Scenario {
        id: "private-tty-signals",
        mode: "offline",
        check: ScenarioCheck::IntegrationTest {
            suite: "terminal",
            test: "private_tty_delivers_each_supervisor_and_group_signal_once",
        },
        prerequisites: &[
            "user namespaces available to this user",
            "working nft executable",
            "Landlock ABI 9 or later",
            "bash and a working pseudoterminal",
            "cargo and cached integration-test dependencies",
        ],
    },
];

#[derive(Debug, Serialize)]
struct ScenarioResult {
    id: &'static str,
    mode: &'static str,
    required: bool,
    prerequisites: &'static [&'static str],
    evidence: &'static str,
    source: Option<String>,
    status: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
struct Qualification {
    ok: bool,
    scenarios: Vec<ScenarioResult>,
}

fn results_ok(scenarios: &[ScenarioResult]) -> bool {
    scenarios.iter().all(|scenario| {
        scenario.status != "failed" && (!scenario.required || scenario.status == "executed")
    })
}

fn doctor(mode: &str) -> Result<Value, String> {
    let executable = std::env::current_exe().map_err(|e| format!("cannot locate playpen: {e}"))?;
    let output = Command::new(&executable)
        .args(["doctor", "--mode", mode, "--format", "json"])
        .output()
        .map_err(|e| format!("cannot run {}: {e}", executable.display()))?;
    serde_json::from_slice(&output.stdout).map_err(|e| {
        format!(
            "doctor {mode} returned invalid JSON ({}): {e}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })
}

fn integration_test(source: Option<&Path>, suite: &str, test: &str) -> (&'static str, String) {
    let Some(source) = source else {
        return (
            "unsupported",
            "integration-test scenario needs an explicit trusted --source PATH".into(),
        );
    };
    let manifest = source.join("Cargo.toml");
    let output = Command::new("cargo")
        .env_remove("FORMAT")
        .args(["test", "--locked", "--offline", "--manifest-path"])
        .arg(&manifest)
        .args(["--test", suite, test, "--", "--exact", "--nocapture"])
        .current_dir(source)
        .output();
    let output = match output {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ("unsupported", format!("cargo is unavailable: {e}"));
        }
        Err(e) => return ("failed", format!("cannot run cargo test: {e}")),
    };
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    classify_test_output(suite, test, output.status.success(), &combined)
}

fn routed_peer(source: Option<&Path>) -> (&'static str, String) {
    let Some(source) = source else {
        return (
            "unsupported",
            "routed-peer needs an explicit trusted --source PATH".into(),
        );
    };
    let script = source.join("tests/routed_peer.py");
    if !script.is_file() {
        return (
            "unsupported",
            format!("fixture {} is unavailable", script.display()),
        );
    }
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(e) => return ("failed", format!("cannot locate playpen: {e}")),
    };
    let output = match Command::new("python3")
        .arg(&script)
        .arg("--playpen")
        .arg(exe)
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ("unsupported", format!("python3 unavailable: {e}"));
        }
        Err(e) => return ("failed", format!("cannot run routed-peer fixture: {e}")),
    };
    let detail = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .trim()
    .to_owned();
    match output.status.code() {
        Some(0) if detail.contains("EXECUTED: routed-peer") => ("executed", detail),
        Some(77) => ("unsupported", detail),
        _ => ("failed", detail),
    }
}

fn classify_test_output(
    suite: &str,
    test: &str,
    success: bool,
    output: &str,
) -> (&'static str, String) {
    if output.contains(&format!("test {test} ... FAILED")) {
        return ("failed", output.trim().to_owned());
    }
    if !success {
        if [
            "no matching package named",
            "failed to download",
            "no such command",
        ]
        .iter()
        .any(|marker| output.contains(marker))
        {
            return (
                "unsupported",
                format!(
                    "integration-test prerequisites unavailable: {}",
                    output.trim()
                ),
            );
        }
        return ("failed", output.trim().to_owned());
    }
    if output.contains("SKIPPED:") {
        let reason = output
            .lines()
            .find(|line| line.contains("SKIPPED:"))
            .unwrap_or("SKIPPED: host prerequisite unavailable")
            .trim()
            .to_owned();
        return ("unsupported", reason);
    }
    if output.contains(&format!("test {test} ... ok")) {
        return (
            "executed",
            format!("cargo test --test {suite} {test}: passed"),
        );
    }
    (
        "failed",
        format!(
            "cargo test exited without reporting {test}: {}",
            output.trim()
        ),
    )
}

fn validate_source(source: &Path) -> Result<PathBuf, String> {
    let source = source
        .canonicalize()
        .map_err(|e| format!("cannot resolve source path {}: {e}", source.display()))?;
    if !source.is_dir() {
        return Err(format!(
            "source path {} is not a directory",
            source.display()
        ));
    }
    for required_file in ["Cargo.toml", "Cargo.lock"] {
        if !source.join(required_file).is_file() {
            return Err(format!(
                "source path {} has no {required_file}",
                source.display()
            ));
        }
    }
    let manifest = std::fs::read_to_string(source.join("Cargo.toml"))
        .map_err(|e| format!("cannot read source manifest: {e}"))?;
    let mut package = false;
    let name = manifest.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('[') {
            package = line == "[package]";
        }
        package
            .then(|| line.strip_prefix("name ="))
            .flatten()
            .map(|name| name.trim().trim_matches('"').to_owned())
    });
    if name.as_deref() != Some("playpen") {
        return Err(format!(
            "source path {} is not the playpen package",
            source.display()
        ));
    }
    Ok(source)
}

fn probe_result(report: Result<&Value, &String>, name: &str) -> (&'static str, String) {
    let report = match report {
        Ok(report) => report,
        Err(error) => return ("failed", error.clone()),
    };
    let Some(probe) = report["probes"]
        .as_array()
        .and_then(|probes| probes.iter().find(|probe| probe["name"] == name))
    else {
        return ("failed", format!("doctor did not report probe {name:?}"));
    };
    let detail = probe["detail"].as_str().unwrap_or("no detail reported");
    match probe["status"].as_str() {
        Some("untested") => ("unsupported", detail.to_owned()),
        Some("executed") if probe["ok"] == true => ("executed", detail.to_owned()),
        Some("executed") => ("failed", detail.to_owned()),
        _ => ("failed", format!("unexpected probe result: {probe}")),
    }
}

pub(crate) fn list(format: Format) -> i32 {
    let mut scenarios = Vec::new();
    for scenario in SCENARIOS {
        let source = match scenario.check {
            ScenarioCheck::DoctorProbe(_) => "installed_binary",
            ScenarioCheck::IntegrationTest { .. } | ScenarioCheck::RoutedPeer => "source_tree",
        };
        if format == Format::Json {
            scenarios.push(serde_json::json!({"id":scenario.id,"mode":scenario.mode,"evidence":source,"prerequisites":scenario.prerequisites}));
        } else {
            outln!(
                "{}  {}  {}  {}",
                scenario.id,
                scenario.mode,
                source,
                scenario.prerequisites.join(", ")
            );
        }
    }
    if format == Format::Json {
        outln!("{}", serde_json::json!({"scenarios":scenarios,"advice":[]}));
    }
    0
}

/// Runs all scenarios, marking required scenarios and failing if one could not
/// execute. Assertions that ran and failed always make the qualification fail.
#[must_use]
pub fn run(required: &[String], source: Option<&Path>, json: bool) -> i32 {
    run_formatted(
        required,
        source,
        if json { Format::Json } else { Format::Pretty },
    )
}

pub(crate) fn run_formatted(required: &[String], source: Option<&Path>, format: Format) -> i32 {
    let unknown: Vec<&str> = required
        .iter()
        .filter(|id| !SCENARIOS.iter().any(|scenario| scenario.id == id.as_str()))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        let message = format!(
            "unknown qualification scenario(s): {}; available: {}",
            unknown.join(", "),
            SCENARIOS
                .iter()
                .map(|scenario| scenario.id)
                .collect::<Vec<_>>()
                .join(", ")
        );
        return discovery::error(format, "unknown-scenario", &message, 2);
    }

    let source = match source.map(validate_source).transpose() {
        Ok(source) => source,
        Err(e) => {
            return discovery::error(
                format,
                "invalid-source",
                &format!("invalid --source: {e}"),
                2,
            );
        }
    };
    let source_str = source.as_ref().map(|path| path.display().to_string());

    let offline = doctor("offline");
    let egress = doctor("egress");
    let scenarios = SCENARIOS
        .iter()
        .map(|scenario| {
            let report = match scenario.mode {
                "offline" => offline.as_ref(),
                "egress" => egress.as_ref(),
                _ => unreachable!("scenario mode is defined in this module"),
            };
            let (status, detail, evidence, scenario_source) = match scenario.check {
                ScenarioCheck::DoctorProbe(probe) => {
                    let (status, detail) = probe_result(report, probe);
                    (status, detail, "installed_binary", None)
                }
                source_check => match report {
                    Ok(report) if report["capability"]["status"] != "unavailable" => {
                        let (status, detail) = match source_check {
                            ScenarioCheck::RoutedPeer => routed_peer(source.as_deref()),
                            ScenarioCheck::IntegrationTest { suite, test } => {
                                integration_test(source.as_deref(), suite, test)
                            }
                            ScenarioCheck::DoctorProbe(_) => unreachable!("handled above"),
                        };
                        (status, detail, "source_tree", source_str.clone())
                    }
                    Ok(report) => (
                        "unsupported",
                        report["capability"]["detail"]
                            .as_str()
                            .unwrap_or("required mode prerequisites are unavailable")
                            .to_owned(),
                        "source_tree",
                        source_str.clone(),
                    ),
                    Err(e) => ("failed", e.clone(), "source_tree", source_str.clone()),
                },
            };
            ScenarioResult {
                id: scenario.id,
                mode: scenario.mode,
                required: required.iter().any(|id| id == scenario.id),
                prerequisites: scenario.prerequisites,
                evidence,
                source: scenario_source,
                status,
                detail,
            }
        })
        .collect::<Vec<_>>();
    let ok = results_ok(&scenarios);
    let qualification = Qualification { ok, scenarios };

    print_qualification(&qualification, format);
    i32::from(!qualification.ok)
}

fn print_qualification(qualification: &Qualification, format: Format) {
    if format == Format::Json {
        outln!(
            "{}",
            serde_json::json!({"ok":qualification.ok,"scenarios":qualification.scenarios,"advice":[]})
        );
    } else if format == Format::Text {
        for scenario in &qualification.scenarios {
            outln!(
                "{}  {}  {}  {}",
                scenario.id,
                scenario.status,
                scenario.evidence,
                scenario.detail
            );
        }
    } else {
        for scenario in &qualification.scenarios {
            outln!(
                "{} {}{} (requires {}): {}",
                scenario.status,
                scenario.id,
                if scenario.required { " [required]" } else { "" },
                scenario.prerequisites.join(", "),
                scenario.detail
            );
        }
        outln!(
            "{}",
            if qualification.ok {
                "playpen qualification requirements met."
            } else {
                "playpen qualification failed."
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{ScenarioResult, classify_test_output, integration_test, results_ok, routed_peer};

    #[test]
    fn routed_peer_requires_trusted_source() {
        let (status, detail) = routed_peer(None);
        assert_eq!(status, "unsupported");
        assert!(detail.contains("trusted --source"));
    }

    fn result(status: &'static str, required: bool) -> ScenarioResult {
        ScenarioResult {
            id: "scenario",
            mode: "offline",
            required,
            prerequisites: &[],
            evidence: "installed_binary",
            source: None,
            status,
            detail: String::new(),
        }
    }

    #[test]
    fn required_unsupported_fails_but_optional_unsupported_does_not() {
        assert!(results_ok(&[
            result("executed", true),
            result("unsupported", false)
        ]));
        assert!(!results_ok(&[result("unsupported", true)]));
        assert!(!results_ok(&[result("failed", false)]));
    }

    #[test]
    fn a_test_failure_keeps_failed_status_even_if_it_printed_skipped() {
        let output = "SKIPPED: later setup step unavailable\ntest selected_case ... FAILED";
        let (status, _) = classify_test_output("run", "selected_case", false, output);
        assert_eq!(status, "failed");
    }

    #[test]
    fn source_suite_without_explicit_source_is_unsupported() {
        let (status, reason) = integration_test(None, "run", "selected_case");
        assert_eq!(status, "unsupported");
        assert!(reason.contains("--source PATH"));
    }
}
