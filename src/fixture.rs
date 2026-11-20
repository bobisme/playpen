//! One literal HTTP response on private loopback for offline runs.
use std::fs::File;
use std::io::{BufRead as _, BufReader, Read, Write as _};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

const LIMIT: usize = 64 * 1024;

/// The literal route and response. Unknown fields are refused to surface typos.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    method: String,
    path: String,
    status: u16,
    body: String,
}

impl Fixture {
    fn read(source: impl Read) -> Result<Self, String> {
        let mut bytes = Vec::new();
        source
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > LIMIT {
            return Err("fixture exceeds 64 KiB".into());
        }
        let value: Self =
            serde_json::from_slice(&bytes).map_err(|e| format!("invalid fixture: {e}"))?;
        if !matches!(
            value.method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
        ) || !value.path.starts_with('/')
            || value.path.len() > 2048
            || !value.path.bytes().all(|b| b.is_ascii_graphic())
            || !(200..=599).contains(&value.status)
            || (matches!(value.status, 204 | 205 | 304) && !value.body.is_empty())
        {
            return Err(
                "fixture requires an HTTP method, an ASCII /path, and a status from 200 to 599"
                    .into(),
            );
        }
        Ok(value)
    }

    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        Self::read(File::open(path).map_err(|e| format!("fixture {}: {e}", path.display()))?)
    }

    /// Start the helper after X has acquired the workload's full restrictions.
    /// The only descriptor the helper returns data on is its private ready pipe.
    pub(crate) fn start(&self) -> Result<String, String> {
        let (io, peer) = UnixStream::pair().map_err(|e| e.to_string())?;
        let timeout = Some(Duration::from_secs(5));
        io.set_read_timeout(timeout).map_err(|e| e.to_string())?;
        io.set_write_timeout(timeout).map_err(|e| e.to_string())?;
        let input = peer.try_clone().map_err(|e| e.to_string())?;
        let mut cmd = Command::new("/proc/self/exe");
        cmd.args(["probe", "http-fixture"])
            .stdin(Stdio::from(OwnedFd::from(input)))
            .stdout(Stdio::from(OwnedFd::from(peer)))
            .stderr(Stdio::null());
        adopt_into_namespace_init(&mut cmd);
        let mut launcher = cmd
            .spawn()
            .map_err(|e| format!("cannot start HTTP fixture: {e}"))?;
        drop(cmd);
        launcher.wait().map_err(|e| e.to_string())?;
        serde_json::to_writer(&io, self).map_err(|e| e.to_string())?;
        io.shutdown(Shutdown::Write).map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(io)
            .take(32)
            .read_line(&mut line)
            .map_err(|e| format!("fixture readiness: {e}"))?;
        let port = line
            .strip_suffix('\n')
            .and_then(|p| p.parse::<u16>().ok())
            .filter(|p| *p > 0)
            .ok_or("HTTP fixture did not report a listening port")?;
        Ok(format!("http://127.0.0.1:{port}"))
    }

    fn handle(&self, mut stream: TcpStream) -> std::io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut reader = BufReader::new(&stream).take(8192);
        let mut request = String::new();
        reader.read_line(&mut request)?;
        let mut words = request.split_ascii_whitespace();
        let matched = request.ends_with('\n')
            && words.next() == Some(self.method.as_str())
            && words.next() == Some(self.path.as_str())
            && matches!(words.next(), Some("HTTP/1.0" | "HTTP/1.1"))
            && words.next().is_none();
        let mut length = None;
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Ok(());
            }
            if line == "\r\n" || line == "\n" {
                break;
            }
            let Some((key, value)) = line.split_once(':') else {
                return Ok(());
            };
            if key.eq_ignore_ascii_case("content-length") {
                let Some(n) = value
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .filter(|&n| n <= LIMIT as u64)
                else {
                    return Ok(());
                };
                if length.replace(n).is_some() {
                    return Ok(());
                }
            } else if key.eq_ignore_ascii_case("transfer-encoding") {
                return Ok(());
            }
        }
        let n = length.unwrap_or(0);
        let copied = std::io::copy(&mut reader.into_inner().take(n), &mut std::io::sink())?;
        if copied != n {
            return Ok(());
        }
        let (status, body) = if matched {
            (self.status, self.body.as_str())
        } else {
            (404, "route not found\n")
        };
        if matches!(status, 204 | 304) {
            return write!(
                stream,
                "HTTP/1.1 {status} Fixture\r\nConnection: close\r\n\r\n"
            );
        }
        write!(
            stream,
            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }
}

fn adopt_into_namespace_init(cmd: &mut Command) {
    // SAFETY: fork and _exit are async-signal-safe. The intermediate child
    // exits immediately; namespace init adopts the helper. The workload
    // can then wait for its own children without waiting for the fixture.
    unsafe {
        cmd.pre_exec(|| match libc::fork() {
            -1 => Err(std::io::Error::last_os_error()),
            0 => Ok(()),
            _ => libc::_exit(0),
        });
    }
}

/// Private helper entry point inside the offline sandbox.
pub(crate) fn serve() -> Result<(), String> {
    let fixture = Fixture::read(std::io::stdin().lock())?;
    let listener =
        TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    writeln!(std::io::stdout().lock(), "{port}").map_err(|e| e.to_string())?;
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let _ = fixture.handle(s);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}
