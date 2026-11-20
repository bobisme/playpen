use std::io::{BufRead as _, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

fn recipe(name: &str, body: &str) -> std::path::PathBuf {
    let file = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("http-{name}-{}.json", std::process::id()));
    std::fs::write(
        &file,
        serde_json::json!({"method":"POST","path":"/items","status":201,"body":body}).to_string(),
    )
    .expect("recipe");
    file
}

#[test]
fn concurrent_clients_get_private_routes_and_real_statuses() {
    let mut children = Vec::new();
    for body in ["first", "second"] {
        let file = recipe(body, body);
        let request = r#"
            curl -qsS --noproxy '*' -d hello -w ':%{http_code}' "$PLAYPEN_FIXTURE_URL/items"
            curl -qsS --noproxy '*' -o /dev/null -w ':%{http_code}' "$PLAYPEN_FIXTURE_URL/missing"
        "#;
        let child = Command::new(BIN)
            .args(["run", "--no-network", "--fixture"])
            .arg(file)
            .args(["--", "sh", "-ec", request])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("client");
        children.push((body, child));
    }
    for (body, child) in children {
        let out = child.wait_with_output().expect("wait");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{body}:201:404")
        );
    }
}

fn descendants(pid: u32) -> Vec<u32> {
    let mut pending = vec![pid];
    let mut found = Vec::new();
    while let Some(p) = pending.pop() {
        let raw =
            std::fs::read_to_string(format!("/proc/{p}/task/{p}/children")).unwrap_or_default();
        for child in raw.split_whitespace().filter_map(|n| n.parse::<u32>().ok()) {
            pending.push(child);
            found.push(child);
        }
    }
    found
}

#[test]
fn fixture_is_reaped_after_exit_signal_expiry_and_supervisor_death() {
    for mode in ["exit", "signal", "expiry", "death"] {
        check_cleanup(mode);
    }
}

fn check_cleanup(mode: &str) {
    let file = recipe("teardown", "ok");
    let mut cmd = Command::new(BIN);
    cmd.args(["run", "--no-network", "--fixture"]).arg(file);
    if mode == "expiry" {
        let until = time::OffsetDateTime::now_utc() + time::Duration::seconds(2);
        cmd.args(["--until", &hallpass::stamp(until)]);
    }
    let script = if mode == "exit" {
        "printf 'ready\\n'; read done"
    } else {
        "printf 'ready\\n'; exec sleep 20"
    };
    let mut child = cmd
        .args(["--", "sh", "-ec", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut ready = String::new();
    BufReader::new(child.stdout.take().expect("pipe"))
        .read_line(&mut ready)
        .expect("read");
    assert_eq!(ready, "ready\n");
    let procs = descendants(child.id());
    let helper = procs.iter().copied().find(|p| {
        std::fs::read(format!("/proc/{p}/cmdline"))
            .unwrap_or_default()
            .windows(b"http-fixture\0".len())
            .any(|v| v == b"http-fixture\0")
    });
    match mode {
        "exit" => {
            use std::io::Write as _;
            writeln!(child.stdin.take().expect("stdin"), "done").expect("release command");
        }
        "signal" => {
            let pid = nix::unistd::Pid::from_raw(i32::try_from(child.id()).expect("pid"));
            nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM).expect("signal child");
        }
        "death" => child.kill().expect("terminate supervisor"),
        _ => {}
    }
    child.wait().expect("wait supervisor");
    let end = Instant::now() + Duration::from_secs(5);
    let helper = helper.expect("fixture pid");
    let path = format!("/proc/{helper}/status");
    while Path::new(&path).exists() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!Path::new(&path).exists(), "helper still present");
}

#[test]
fn malformed_recipe_refuses_without_running_the_client() {
    let file = recipe("malformed", "x");
    std::fs::write(&file, b"{}").expect("invalid fixture");
    let marker = file.with_extension("marker");
    let out = Command::new(BIN)
        .args(["run", "--no-network", "--fixture"])
        .arg(file)
        .args(["--", "touch"])
        .arg(&marker)
        .output()
        .expect("refusal");
    assert_eq!(out.status.code(), Some(2));
    assert!(!marker.exists());
}
