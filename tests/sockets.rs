//! Integration tests for host Unix sockets, IPC and `/proc`: what the
//! command can reach on the host machine without the network.
//!
//! Connecting to a local daemon's socket and closing it at once sends
//! nothing off the machine; nothing is ever written into a connected
//! socket. All sandboxes here use `--no-network`.

use std::os::linux::net::SocketAddrExt as _;
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_playpen");

fn skip_reason() -> Option<String> {
    let max = std::fs::read_to_string("/proc/sys/user/max_user_namespaces").unwrap_or_default();
    if max.trim().is_empty() || max.trim() == "0" {
        return Some("user namespaces are not available".into());
    }
    let nft = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        .iter()
        .any(|d| Path::new(d).join("nft").exists());
    if !nft {
        return Some("nft is not installed".into());
    }
    None
}

macro_rules! require_sandbox {
    () => {
        if let Some(why) = skip_reason() {
            eprintln!("SKIPPED: {why}");
            return;
        }
    };
}

fn landlock_ok() -> bool {
    playpen::landlock::resolve_unix_supported()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn tmpdir(name: &str) -> PathBuf {
    let dir =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("sock-{name}-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

struct PrivateDir(PathBuf);

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn private_dir(root: &Path, label: &str) -> PrivateDir {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = root.join(format!("pp-{label}-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
    PrivateDir(path)
}

fn private_home_dir(label: &str) -> Option<PrivateDir> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    if ["/run", "/tmp", "/var/tmp", "/dev/shm"]
        .iter()
        .any(|root| home.starts_with(root))
    {
        return None;
    }
    Some(private_dir(&home, label))
}

struct RuntimeDir(PrivateDir);

thread_local! {
    // The test thread owns this fallback, and its Drop removes the private
    // directory after all fixtures owned by that test have been dropped.
    static FALLBACK_RUNTIME: RuntimeDir = {
        let home = std::env::var_os("HOME").map(PathBuf::from)
            .expect("HOME is required for a private runtime fixture when XDG_RUNTIME_DIR is unset");
        RuntimeDir(private_dir(&home, "runtime"))
    };
}

fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || FALLBACK_RUNTIME.with(|dir| dir.0.0.clone()),
        PathBuf::from,
    )
}

/// Runs `playpen run --no-network EXTRA -- ARGS`.
fn sandbox(extra: &[&str], args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("run")
        .arg("--no-network")
        .args(extra)
        .arg("--")
        .args(args)
        // playpen and its child must agree on the runtime directory even on
        // hosts whose test environment has no login-session variable.
        .env("XDG_RUNTIME_DIR", runtime_dir())
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("cannot run playpen: {e}"))
}

/// Connects to each Unix socket from inside a sandbox; returns the paths
/// that connected.
fn connectable_inside(extra: &[&str], listen: &[&str], tries: &[String]) -> (Vec<String>, Output) {
    let mut args = vec![BIN, "probe", "unix"];
    for l in listen {
        args.extend_from_slice(&["--listen", l]);
    }
    for t in tries {
        args.extend_from_slice(&["--try", t]);
    }
    let out = sandbox(extra, &args);
    let connected = observed_connections(&out, tries);
    (connected, out)
}

fn observed_connections(out: &Output, paths: &[impl AsRef<str>]) -> Vec<String> {
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = std::str::from_utf8(&out.stdout).expect("UTF-8 Unix probe output");
    playpen::probe::connected_unix_paths(stdout, paths).unwrap_or_else(|e| panic!("{e}: {stdout}"))
}

/// A listening socket at `path`, removed again on drop.
struct Listening {
    path: PathBuf,
    _l: UnixListener,
}

impl Drop for Listening {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn listen(path: &Path) -> Listening {
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path).unwrap_or_else(|e| panic!("bind {}: {e}", path.display()));
    Listening {
        path: path.to_path_buf(),
        _l: l,
    }
}

/// Every socket below `root`, at most `depth` levels down, not following
/// symbolic links and not entering `skip`.
fn sockets_below(root: &Path, depth: usize, skip: &[PathBuf], out: &mut Vec<PathBuf>) {
    if depth == 0 || skip.iter().any(|s| root.starts_with(s)) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.filter_map(Result::ok) {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_socket() {
            out.push(e.path());
        } else if ft.is_dir() {
            sockets_below(&e.path(), depth - 1, skip, out);
        }
    }
}

/// The usual places host sockets live.
fn host_sockets(with_home: bool) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let target = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let mut roots = vec![
        (runtime_dir(), 8),
        (PathBuf::from("/run"), 8),
        (PathBuf::from("/var/run"), 8),
        (PathBuf::from("/tmp"), 8),
        (PathBuf::from("/var/tmp"), 8),
        (PathBuf::from("/dev/shm"), 8),
    ];
    if with_home && let Some(home) = std::env::var_os("HOME") {
        roots.push((PathBuf::from(home), 4));
    }
    for (root, depth) in roots {
        // The test's own sockets are checked separately.
        sockets_below(&root, depth, std::slice::from_ref(&target), &mut found);
    }
    found.sort();
    found.dedup();
    found
}

fn strings(paths: &[PathBuf]) -> Vec<String> {
    paths.iter().map(|p| p.display().to_string()).collect()
}

#[test]
fn no_host_socket_is_connectable_from_inside() {
    require_sandbox!();
    if !landlock_ok() {
        eprintln!("SKIPPED: this kernel lacks Landlock ABI 9");
        return;
    }
    // Sockets of our own in each kind of place, so there is always
    // something connectable on the host.
    let dir = tmpdir("all");
    let own = [
        listen(&dir.join("home.sock")),
        listen(&runtime_dir().join(format!("playpen-test-{}.sock", std::process::id()))),
        listen(Path::new(&format!(
            "/tmp/playpen-test-{}.sock",
            std::process::id()
        ))),
    ];
    let mut all = host_sockets(true);
    all.extend(own.iter().map(|l| l.path.clone()));
    for l in &own {
        assert!(
            UnixStream::connect(&l.path).is_ok(),
            "{} not connectable on the host",
            l.path.display()
        );
    }
    all.sort();
    all.dedup();
    let tries = strings(&all);
    let (connected, out) = connectable_inside(&[], &[], &tries);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        connected.is_empty(),
        "host sockets reachable from inside: {connected:?}"
    );
    assert!(
        text(&out.stderr).contains("host Unix sockets: none reachable"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn without_landlock_the_mount_layer_still_hides_the_usual_places() {
    require_sandbox!();
    let Some(home_fixture) = private_home_dir("mount-only") else {
        eprintln!("SKIPPED: HOME is unavailable or inside a mount-hidden temporary root");
        return;
    };
    let in_home = listen(&home_fixture.0.join("home.sock"));
    let own = [
        listen(&runtime_dir().join(format!("playpen-test-m-{}.sock", std::process::id()))),
        listen(Path::new(&format!(
            "/tmp/playpen-test-m-{}.sock",
            std::process::id()
        ))),
    ];
    let mut usual = host_sockets(false);
    usual.extend(own.iter().map(|l| l.path.clone()));
    usual.sort();
    usual.dedup();
    let tries = strings(&usual);
    let (connected, out) = connectable_inside(&["--without-landlock"], &[], &tries);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        connected.is_empty(),
        "sockets in the usual places reachable: {connected:?}"
    );
    // What stays open in this mode: a socket elsewhere, here in the home
    // directory. Landlock is what closes it.
    let (connected, out) = connectable_inside(
        &["--without-landlock"],
        &[],
        &strings(std::slice::from_ref(&in_home.path)),
    );
    assert_eq!(connected.len(), 1, "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("--without-landlock"));
}

#[test]
fn abstract_sockets_of_the_host_are_not_reachable() {
    require_sandbox!();
    let name = format!("playpen-test-abstract-{}", std::process::id());
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
    let _l = UnixListener::bind_addr(&addr).unwrap_or_else(|e| panic!("{e}"));
    assert!(UnixStream::connect_addr(&addr).is_ok());
    let at = format!("@{name}");
    let mut modes: Vec<&[&str]> = vec![&["--without-landlock"]];
    if landlock_ok() {
        modes.push(&[]);
    }
    for extra in modes {
        let (connected, out) = connectable_inside(extra, &[], std::slice::from_ref(&at));
        assert!(connected.is_empty(), "{extra:?}: {}", text(&out.stderr));
    }
    // The command's own abstract sockets work.
    let own = format!("@playpen-inside-{}", std::process::id());
    let (connected, out) = connectable_inside(&[], &[&own], std::slice::from_ref(&own));
    assert_eq!(connected, vec![own], "{}", text(&out.stderr));
}

#[test]
fn expose_lets_exactly_the_named_socket_or_directory_through() {
    require_sandbox!();
    let Some(expose_fixture) = private_home_dir("expose") else {
        eprintln!("SKIPPED: HOME is unavailable or inside a mount-hidden temporary root");
        return;
    };
    let dir = &expose_fixture.0;
    let exposed_sock = listen(&dir.join("a.sock"));
    let sibling = listen(&dir.join("b.sock"));
    let sub = dir.join("sub");
    let _ = std::fs::create_dir_all(&sub);
    let in_dir_1 = listen(&sub.join("c.sock"));
    let in_dir_2 = listen(&sub.join("d.sock"));
    let rt_name = format!("playpen-test-x-{}.sock", std::process::id());
    let rt = listen(&runtime_dir().join(&rt_name));
    let rt_other =
        listen(&runtime_dir().join(format!("playpen-test-y-{}.sock", std::process::id())));
    let all = strings(&[
        exposed_sock.path.clone(),
        sibling.path.clone(),
        in_dir_1.path.clone(),
        in_dir_2.path.clone(),
        rt.path.clone(),
        rt_other.path.clone(),
    ]);
    let s = |p: &Path| p.display().to_string();
    let (ap, sp, rp) = (s(&exposed_sock.path), s(&sub), s(&rt.path));
    let rep = dir.join("report.json");
    let reps = s(&rep);
    let mut modes: Vec<Vec<&str>> = vec![vec!["--without-landlock"]];
    if landlock_ok() {
        modes.push(vec![]);
    }
    for mode in modes {
        let mut extra = mode.clone();
        extra.extend_from_slice(&["--expose", &ap, "--expose", &sp, "--expose", &rp]);
        extra.extend_from_slice(&["--report", &reps]);
        let (mut connected, out) = connectable_inside(&extra, &[], &all);
        connected.sort();
        let mut want = vec![
            s(&exposed_sock.path),
            s(&in_dir_1.path),
            s(&in_dir_2.path),
            s(&rt.path),
        ];
        // With Landlock only the exposed ones connect. Without it, the
        // sibling in the home directory is the residual.
        if !mode.is_empty() {
            want.push(s(&sibling.path));
        }
        want.sort();
        let err = text(&out.stderr);
        assert_eq!(connected, want, "{err}");
        assert!(err.contains("exposed: "), "{err}");
        assert!(err.contains(&ap) && err.contains(&rp), "{err}");
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&rep).unwrap_or_default())
                .unwrap_or_default();
        let listed: Vec<&str> = json["exposed"].as_array().map_or_else(Vec::new, |v| {
            v.iter().filter_map(serde_json::Value::as_str).collect()
        });
        assert!(
            listed.contains(&ap.as_str()) && listed.contains(&sp.as_str()),
            "{json}"
        );
        assert_eq!(json["display"], false);
        let guard = if mode.is_empty() {
            "landlock"
        } else {
            "mounts_only"
        };
        assert_eq!(json["socket_guard"], guard);
    }
}

/// What DESIGN.md lists as open by design: the peer of a socket the
/// operator exposed can pass the command a descriptor (`SCM_RIGHTS`), and a
/// socket passed that way belongs to the host's network, outside the
/// filter. Shown with a UDP socket of the test's own and a receiver on the
/// host's loopback; nothing leaves the machine. Without `--expose` the
/// command cannot connect, so nothing can be passed.
#[test]
fn the_peer_of_an_exposed_socket_can_pass_a_host_network_socket() {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    use std::os::fd::AsRawFd as _;
    require_sandbox!();
    if !landlock_ok() {
        eprintln!("SKIPPED: no Landlock ABI 9");
        return;
    }
    let dir = tmpdir("scm");
    let path = dir.join("giver.sock");
    let _ = std::fs::remove_file(&path);
    let giver = UnixListener::bind(&path).unwrap_or_else(|e| panic!("{e}"));
    let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap_or_else(|e| panic!("{e}"));
    receiver
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .unwrap_or_else(|e| panic!("{e}"));
    let to = receiver
        .local_addr()
        .unwrap_or_else(|e| panic!("{e}"))
        .to_string();
    // The "daemon": gives every client a UDP socket of the host's network.
    std::thread::spawn(move || {
        for conn in giver.incoming().flatten() {
            let Ok(gift) = std::net::UdpSocket::bind("127.0.0.1:0") else {
                continue;
            };
            let fds = [gift.as_raw_fd()];
            let _ = sendmsg::<()>(
                conn.as_raw_fd(),
                &[std::io::IoSlice::new(b"x")],
                &[ControlMessage::ScmRights(&fds)],
                MsgFlags::empty(),
                None,
            );
        }
    });
    let p = path.display().to_string();
    let arrived = |receiver: &std::net::UdpSocket| {
        let mut buf = [0u8; 64];
        receiver
            .recv_from(&mut buf)
            .is_ok_and(|(n, _)| &buf[..n] == b"playpen-probe")
    };
    let probe = [BIN, "probe", "unix-recv-fd", p.as_str(), to.as_str()];

    // Not exposed: no connection, no descriptor, nothing arrives; and the
    // sandbox itself cannot send to the host's loopback.
    let out = sandbox(&[], &probe);
    let line = text(&out.stdout);
    assert!(line.contains("\"received\":false"), "{line}");
    assert!(line.contains("Permission denied"), "{line}");
    assert!(!arrived(&receiver));

    // Exposed: the start line names the socket, the descriptor crosses,
    // and a datagram sent through it arrives on the host's loopback.
    let out = sandbox(&["--expose", &p], &probe);
    let line = text(&out.stdout);
    let err = text(&out.stderr);
    assert!(err.contains(&format!("exposed: {p}")), "{err}");
    assert!(line.contains("\"received\":true"), "{line} {err}");
    assert!(line.contains("\"sent\":\"ALLOWED\""), "{line}");
    assert!(
        arrived(&receiver),
        "the passed socket did not reach the host's loopback: {line}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_datagram_sent_by_address_to_a_host_socket_is_refused() {
    require_sandbox!();
    if !landlock_ok() {
        eprintln!("SKIPPED: this kernel lacks Landlock ABI 9");
        return;
    }
    let dir = tmpdir("dgram");
    let path = dir.join("log.sock");
    let _ = std::fs::remove_file(&path);
    let sock = std::os::unix::net::UnixDatagram::bind(&path).unwrap_or_else(|e| panic!("{e}"));
    sock.set_nonblocking(true).unwrap_or_else(|e| panic!("{e}"));
    let p = path.display().to_string();
    // From the host it arrives: the probe works.
    let direct = Command::new(BIN)
        .args(["probe", "unix-send", &p])
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        text(&direct.stdout).contains("ALLOWED"),
        "{}",
        text(&direct.stdout)
    );
    let mut buf = [0u8; 64];
    assert!(sock.recv(&mut buf).is_ok());
    let out = sandbox(&[], &[BIN, "probe", "unix-send", &p]);
    assert!(
        text(&out.stdout).contains("denied: EACCES"),
        "{}",
        text(&out.stdout)
    );
    assert!(sock.recv(&mut buf).is_err(), "the datagram arrived");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn expose_refuses_missing_paths_and_root() {
    for (args, expect) in [
        (
            vec!["--expose", "/nonexistent/playpen.sock"],
            "only an existing path",
        ),
        (vec!["--expose", "/"], "every host socket"),
    ] {
        let out = sandbox(&args, &["true"]);
        let err = text(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{err}");
        assert!(err.contains(expect), "{err}");
        assert!(err.contains("nothing was run"), "{err}");
    }
}

#[test]
fn display_exposes_the_wayland_socket_and_is_off_by_default() {
    require_sandbox!();
    let dir = tmpdir("display");
    let wl = listen(&dir.join("wayland-test"));
    let wls = wl.path.display().to_string();
    let run = |extra: &[&str]| {
        Command::new(BIN)
            .args(["run", "--no-network"])
            .args(extra)
            .args(["--", BIN, "probe", "unix", "--try", &wls])
            .env("WAYLAND_DISPLAY", &wl.path)
            .env_remove("DISPLAY")
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("{e}"))
    };
    let off = run(&[]);
    assert_eq!(observed_connections(&off, &[&wls]), Vec::<String>::new());
    assert!(!text(&off.stderr).contains("display exposed"));
    let on = run(&["--display"]);
    assert_eq!(observed_connections(&on, &[&wls]), [wls.as_str()]);
    assert!(
        text(&on.stderr).contains(&format!("display exposed: {wls}")),
        "{}",
        text(&on.stderr)
    );
    // No display at all: refused.
    let none = Command::new(BIN)
        .args(["run", "--no-network", "--display", "--", "true"])
        .env_remove("WAYLAND_DISPLAY")
        .env("DISPLAY", "host.example.test:0")
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(none.status.code(), Some(2));
    assert!(
        text(&none.stderr).contains("network"),
        "{}",
        text(&none.stderr)
    );
}

/// A private, headless X server for a test: `Xvnc` on a display number it
/// picks itself, Unix sockets only (no TCP for X, none for VNC), with a
/// cookie clients must present.
struct XServer {
    child: std::process::Child,
    display: String,
    authority: PathBuf,
}

impl XServer {
    /// `None` when `Xvnc` is not installed or does not come up.
    fn start(dir: &Path) -> Option<Self> {
        use std::io::{BufRead as _, Read as _};
        // An authority file whose one entry matches every display
        // (family "wild", no address, no number).
        let mut cookie = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut cookie))
            .ok()?;
        let mut entry = vec![0xff, 0xff];
        for field in [&b""[..], b"", b"MIT-MAGIC-COOKIE-1", &cookie] {
            entry.extend_from_slice(&u16::try_from(field.len()).ok()?.to_be_bytes());
            entry.extend_from_slice(field);
        }
        // In the runtime directory, which is private inside the sandbox,
        // so the file is only there if playpen brings it back.
        let home = Some(runtime_dir()).filter(|d| d.is_dir());
        let authority = home
            .as_deref()
            .unwrap_or(dir)
            .join(format!("playpen-test-xauth-{}", std::process::id()));
        std::fs::write(&authority, entry).ok()?;
        let mut child = Command::new("Xvnc")
            .args(["-displayfd", "1", "-nolisten", "tcp", "-rfbport", "-1"])
            .arg("-rfbunixpath")
            .arg(dir.join("vnc.sock"))
            .args(["-SecurityTypes", "None", "-auth"])
            .arg(&authority)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut number = String::new();
        let _ = std::io::BufReader::new(child.stdout.take()?).read_line(&mut number);
        let mut server = Self {
            child,
            display: format!(":{}", number.trim()),
            authority,
        };
        if number.trim().is_empty() || number.trim().bytes().any(|b| !b.is_ascii_digit()) {
            server.display.clear();
            return None;
        }
        Some(server)
    }

    /// Runs an X client that connects, authenticates and asks one question.
    fn client(&self, playpen: Option<&[&str]>, authority: Option<&Path>) -> Output {
        let mut cmd = Command::new(if playpen.is_some() { BIN } else { "xdotool" });
        if let Some(extra) = playpen {
            cmd.args(["run", "--no-network"])
                .args(extra)
                .args(["--", "xdotool"]);
        }
        cmd.arg("getdisplaygeometry")
            .env("DISPLAY", &self.display)
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("XAUTHORITY")
            .stdin(Stdio::null());
        if let Some(a) = authority {
            cmd.env("XAUTHORITY", a);
        }
        cmd.output().unwrap_or_else(|e| panic!("{e}"))
    }
}

impl Drop for XServer {
    fn drop(&mut self) {
        // SIGTERM, so the server removes its socket and lock file in /tmp.
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.authority);
    }
}

/// `--display` with a real X server and a real client: the socket in
/// `/tmp/.X11-unix` is bound back over the private directory, the client
/// falls back to it from the abstract socket (which the sandbox's network
/// namespace does not have), and the authority file is there to read.
#[test]
fn display_works_with_a_real_x_server_and_is_off_by_default() {
    require_sandbox!();
    let on_path = |tool: &str| {
        ["/usr/bin", "/usr/local/bin", "/bin"]
            .iter()
            .any(|d| Path::new(d).join(tool).exists())
    };
    if !on_path("Xvnc") || !on_path("xdotool") {
        eprintln!("SKIPPED: Xvnc and xdotool are not both installed");
        return;
    }
    let dir = tmpdir("xserver");
    let Some(x) = XServer::start(&dir) else {
        eprintln!("SKIPPED: Xvnc did not start");
        return;
    };
    let auth = Some(x.authority.as_path());
    let socket = format!("/tmp/.X11-unix/X{}", &x.display[1..]);
    // The server and the client work, and the server insists on the cookie.
    let direct = x.client(None, auth);
    assert_eq!(direct.status.code(), Some(0), "{}", text(&direct.stderr));
    let geometry = text(&direct.stdout);
    assert_eq!(x.client(None, None).status.code(), Some(1));

    let mut modes: Vec<Vec<&str>> = vec![vec!["--without-landlock"]];
    if landlock_ok() {
        modes.push(vec![]);
    }
    for mode in modes {
        // Off by default: the client cannot reach the server.
        let off = x.client(Some(&mode), auth);
        assert_eq!(off.status.code(), Some(1), "{}", text(&off.stderr));
        assert!(!text(&off.stderr).contains("display exposed"));
        // With --display: the same answer as outside.
        let mut extra = mode.clone();
        extra.push("--display");
        let on = x.client(Some(&extra), auth);
        let err = text(&on.stderr);
        assert_eq!(on.status.code(), Some(0), "{err}");
        assert_eq!(text(&on.stdout), geometry, "{err}");
        assert!(
            err.contains(&format!(
                "display exposed: {socket}, {}",
                x.authority.display()
            )),
            "{err}"
        );
        // The socket alone is not enough: the server still wants the
        // cookie, as outside.
        let no_cookie = x.client(Some(&extra), None);
        assert_eq!(
            no_cookie.status.code(),
            Some(1),
            "{}",
            text(&no_cookie.stderr)
        );
    }
    drop(x);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_runtime_directory_is_private_empty_and_usable() {
    require_sandbox!();
    let marker = runtime_dir().join(format!("playpen-test-file-{}", std::process::id()));
    std::fs::write(&marker, "host").unwrap_or_else(|e| panic!("{e}"));
    let inside = runtime_dir().join("made-inside");
    let script = format!(
        "set -e; d=\"$XDG_RUNTIME_DIR\"; test -d \"$d\"; test -w \"$d\"; \
         test \"$(stat -c %a \"$d\")\" = 700; test \"$(stat -c %u \"$d\")\" = \"$(id -u)\"; \
         test -z \"$(ls -A \"$d\")\"; test ! -e {}; echo x > {}; \
         {BIN} probe unix --listen \"$d/own.sock\" --try \"$d/own.sock\"",
        marker.display(),
        inside.display()
    );
    let out = sandbox(&[], &["sh", "-c", &script]);
    let _ = std::fs::remove_file(&marker);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let own = runtime_dir().join("own.sock").display().to_string();
    assert_eq!(observed_connections(&out, &[&own]), [own]);
    assert!(!inside.exists(), "a file made inside appeared on the host");
}

#[test]
fn common_programs_work() {
    require_sandbox!();
    let dir = tmpdir("programs");
    let repo = dir.join("repo");
    let _ = std::fs::remove_dir_all(&repo);
    let tmp_out = format!("/tmp/playpen-test-out-{}", std::process::id());
    let _ = std::fs::remove_file(&tmp_out);
    let py = "import socket, os, tempfile\n\
              p = os.path.join(os.environ['XDG_RUNTIME_DIR'], 'py.sock')\n\
              s = socket.socket(socket.AF_UNIX); s.bind(p); s.listen()\n\
              c = socket.socket(socket.AF_UNIX); c.connect(p)\n\
              with tempfile.NamedTemporaryFile() as f: pass\n\
              print('python-ok')\n";
    let cases: Vec<(Vec<String>, &str)> = vec![
        (
            vec!["sh".into(), "-c".into(), "echo shell-ok".into()],
            "shell-ok",
        ),
        (vec!["curl".into(), "--version".into()], "curl"),
        (
            vec!["python3".into(), "-I".into(), "-c".into(), py.into()],
            "python-ok",
        ),
        (
            vec![
                "sh".into(),
                "-c".into(),
                format!(
                    "git init -q {} && git -C {} status --short && echo git-ok",
                    repo.display(),
                    repo.display()
                ),
            ],
            "git-ok",
        ),
        (
            vec!["sh".into(), "-c".into(), "ssh -V 2>&1".into()],
            "OpenSSH",
        ),
        (
            vec![
                "sh".into(),
                "-c".into(),
                format!("echo tmp-ok > {tmp_out} && cat {tmp_out}"),
            ],
            "tmp-ok",
        ),
    ];
    for (cmd, expect) in cases {
        let args: Vec<&str> = cmd.iter().map(String::as_str).collect();
        let out = sandbox(&[], &args);
        assert_eq!(out.status.code(), Some(0), "{cmd:?}: {}", text(&out.stderr));
        assert!(
            text(&out.stdout).contains(expect),
            "{cmd:?}: {}",
            text(&out.stdout)
        );
    }
    // /tmp is the host's: a file written there is there afterwards.
    assert_eq!(
        std::fs::read_to_string(&tmp_out).unwrap_or_default(),
        "tmp-ok\n"
    );
    let _ = std::fs::remove_file(&tmp_out);
}

#[test]
fn host_ipc_and_shared_memory_are_not_reachable() {
    require_sandbox!();
    let pid = std::process::id();
    // POSIX shared memory lives in /dev/shm.
    let shm = PathBuf::from(format!("/dev/shm/playpen-test-{pid}"));
    std::fs::write(&shm, "host").unwrap_or_else(|e| panic!("{e}"));
    // A POSIX message queue, created through the host's mqueue mount.
    let mq = PathBuf::from(format!("/dev/mqueue/playpen-test-{pid}"));
    let have_mq = std::fs::File::create(&mq).is_ok();
    // A System V shared memory segment.
    let key = i32::try_from(0x5070_0000_u32 | (pid & 0xffff)).unwrap_or(0x5070_0001);
    // SAFETY: plain syscall wrapper with integer arguments.
    let id = unsafe { libc::shmget(key, 4096, libc::IPC_CREAT | 0o600) };
    assert!(id >= 0, "shmget failed");
    let host_ipcs = Command::new("ipcs").arg("-m").output();
    let key_hex = format!("0x{key:08x}");
    let script = format!(
        "test ! -e {}; test ! -e {}; ipcs -m; echo shm-checked",
        shm.display(),
        mq.display()
    );
    let out = sandbox(&[], &["sh", "-c", &script]);
    let _ = std::fs::remove_file(&shm);
    let _ = std::fs::remove_file(&mq);
    // SAFETY: removes the segment created above; null buffer for IPC_RMID.
    unsafe { libc::shmctl(id, libc::IPC_RMID, std::ptr::null_mut()) };
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(stdout.contains("shm-checked"), "{stdout}");
    if let Ok(h) = host_ipcs {
        assert!(
            text(&h.stdout).contains(&key_hex),
            "the test segment is not visible on the host"
        );
    }
    assert!(
        !stdout.contains(&key_hex),
        "host segment visible inside: {stdout}"
    );
    let _ = have_mq;
}

#[test]
fn host_processes_are_not_visible_in_proc() {
    require_sandbox!();
    let me = std::process::id();
    let script = format!(
        "test ! -e /proc/{me}; ls /proc | grep -E '^[0-9]+$' | sort -n | tail -n 1; cat /proc/1/cmdline | tr '\\0' ' '"
    );
    let out = sandbox(&[], &["sh", "-c", &script]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let highest: u32 = stdout
        .lines()
        .next()
        .and_then(|l| l.trim().parse().ok())
        .unwrap_or(u32::MAX);
    // Only the sandbox's own handful of processes.
    assert!(highest < 100, "{stdout}");
    assert!(
        stdout.contains("playpen"),
        "PID 1 is not playpen's init: {stdout}"
    );
}
