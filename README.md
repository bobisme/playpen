# playpen

![PLAYPEN — A firewall for a single command. A faceless, cloaked figure kneels on flagstones to complete a circle of salt.](docs/images/playpen-cover.webp)

playpen runs a command and its children with a firewall that restricts
outbound IP traffic to the addresses, ports and protocols you approve.
It works without root on Linux and reports attempts to reach other
destinations.

It is a guard for tools that do not police themselves. A tool that follows
a redirect, resolves a name to an unexpected address, or was configured
with the wrong target cannot reach anywhere else.

A [Hallpass](https://github.com/bobisme/hallpass) file records the
owner, approved destinations and time window. playpen loads those
destinations into the firewall at startup. It checks the pass every
2 seconds and starts shutting down the command when it detects revocation
or the deadline passes. The command can still reach approved destinations
during detection and shutdown. See [how a pass-backed run ends](#how-a-pass-backed-run-ends)
for the timing, including what happens if playpen itself is paused.
For a quick run, supply destinations directly with `--allow`.

- [docs/spec.md](docs/spec.md): what playpen does, exactly: every command,
  option, exit code and report field. Start here.
- [docs/DESIGN.md](docs/DESIGN.md): why it is built this way, and the leaks
  considered and how each is closed or not.

## Two-minute example

```console
$ git clone https://github.com/bobisme/playpen.git
$ cd playpen
$ cargo build --release --locked
$ export PATH="$PWD/target/release:$PATH"
$ ./target/release/playpen doctor --mode egress
ok   user namespaces: user.max_user_namespaces = 512098
ok   unprivileged user namespaces: kernel.unprivileged_userns_clone = 1
ok   nft: /usr/bin/nft (nftables v1.1.7 (Commodore Bullmoose #8))
ok   pasta: /usr/bin/pasta (pasta 2026_09_25.df90211)
ok   Landlock (host Unix sockets): ABI 10: connections to host Unix sockets can be refused
ok   terminal input injection (TIOCSTI): refused by the kernel (dev.tty.legacy_tiocsti = 0): the command keeps the terminal and job control
ok   allowed reached, others blocked: TCP, UDP and IPv6 to in-sandbox addresses: approved reached, others dropped
ok   command cannot change the network: nft, netlink address/link changes, raw and packet sockets all denied; no capabilities
ok   host Unix sockets unreachable: a host socket and a host abstract socket were not reachable from inside
playpen egress mode is available.

$ cat engagement.pass.toml          # written with hallpass init, mode 0600
format = 1
id = "example-2026-11"
name = "Example web app"

[approval]
owner = "Pat Owner, Example Corp"
reference = "email of 2026-11-18"
operator = "Sam Tester"
valid_from = 2026-11-19T08:00:00Z
valid_until = 2026-11-19T17:00:00Z
revoked = false

[[destination]]
label = "app"
address = "192.0.2.10"
protocol = "tcp"
ports = 443
hostname = "app.example.test"     # informational: grants nothing

$ playpen run --pass engagement.pass.toml \
              --host app.example.test=192.0.2.10 \
              -- curl -sS https://app.example.test/
playpen: under pass example-2026-11 ("Example web app", owner "Pat Owner, Example Corp", sha256:3f1c..., window ends 2026-11-19T17:00:00Z, destinations app): allowing only 192.0.2.10:443/tcp until 2026-11-19T17:00:00Z (no DNS, names app.example.test=192.0.2.10); everything else is dropped; host Unix sockets: none reachable
...curl output...
playpen: command exited with status 0
playpen: no packets to unapproved destinations were dropped
```

playpen refuses to start (exit 2, "nothing was run") when the pass is
invalid, unreadable, a symbolic link, writable by others, not yet valid,
expired or revoked. `--only LABEL` narrows the pass to some destinations;
`--until` can end the run earlier than the window, never later. The pass's
host names are never resolved for you; map them with `--host`.

Pass restrictions on destination names and application ceilings need a separate
application-level enforcer. Use `--require-enforced` to refuse a pass with
such applicable terms when playpen must enforce every restriction itself.

### How a pass-backed run ends

If the owner sets `revoked = true`, playpen normally detects it at the
next pass check. The supervisor schedules checks 2 seconds apart. It sends the command `SIGTERM` and
gives it 3 seconds to exit before killing the remaining sandbox. The same
shutdown applies when the deadline passes, the file disappears or becomes
invalid, or a destination in use changes. The original firewall stays in
force throughout. Granting more destinations or extending the deadline
only affects future runs.

If the supervisor is stopped directly or gets stuck, it cannot check the
pass or enforce the deadline. After 5 seconds without a heartbeat, a
watchdog inside the sandbox starts freezing its processes. When the
supervisor resumes, it checks the deadline and re-reads the pass if due.
Time spent in system suspend counts toward the deadline. Poll intervals,
grace periods and watchdog actions depend on Linux scheduling the supervisor
and the sandbox init. A signal request and the final process exit can occur
at different times.

For CI jobs that signal the whole process group, use `playpen run --new-session`
to deliver each signal to the command once. The default shared group preserves
interactive shell job control, and a group signal can reach the command twice.
With `--new-session`, stdin still works, but the command has no controlling
terminal for `/dev/tty` prompts or nested shell job control.

### Run with a command-line allow list

```console
$ playpen run --allow 192.0.2.10:443/tcp \
              --host app.example.test=192.0.2.10 \
              --until 2026-11-19T18:00:00+01:00 \
              -- curl -sS https://app.example.test/
playpen: allowing only 192.0.2.10:443/tcp until 2026-11-19T17:00:00Z (no DNS, names app.example.test=192.0.2.10); everything else is dropped; host Unix sockets: none reachable
```

`--pass` and `--allow` cannot be combined: an `--allow` beside a pass would
add a destination the owner did not approve.

The command also cannot reach daemons on the host through their Unix
sockets: a host daemon has the host's network (a session bus, a container
engine, an SSH or browser automation agent). The command's runtime
directory (`$XDG_RUNTIME_DIR`) is a fresh, empty, private one; `/tmp` is
the host's. Bring a socket back deliberately with `--expose`; graphical
programs need `--display`. Both are listed on the start line and in the
report:

```console
$ playpen run --pass engagement.pass.toml --expose "$SSH_AUTH_SOCK" \
              -- ssh admin@192.0.2.10
playpen: under pass ...; everything else is dropped; host Unix sockets: none reachable; exposed: /home/sam/.ssh/agent.sock
```

Upgrading from v0.1? The spec lists the [changes](docs/spec.md#changes-since-v01):
the runtime directory is empty, and the session bus, `ssh-agent`, syslog
and others are not reachable without `--expose`.

If the tool tries to go somewhere else, the connection fails at once
("No route to host" for TCP over IPv4, "Permission denied" for TCP over
IPv6, "Operation not permitted" for UDP), and
playpen says so loudly on exit:

```text
playpen: ************************************************************
playpen: WARNING: 3 packet(s) to UNAPPROVED destinations were dropped.
playpen: The command tried to reach places nobody approved:
playpen:   198.51.100.7 tcp port 80: 2 packet(s)
playpen:   198.51.100.7 udp port 53: 1 packet(s)
playpen: ************************************************************
```

To see the firewall rules without running anything:

```console
$ playpen rules --pass engagement.pass.toml
$ playpen rules --allow 192.0.2.10:443/tcp --allow '[2001:db8::10]:443/tcp'
```

For scripts, `run --format json` writes the final report to stdout and sends
workload output to stderr. Give `--report FILE` to keep workload stdout in
a pipeline and save the JSON report, including refusals. The report's
`outcome` field tells a command
that exited with status 2 (`"ran"`, `exit_code: 2`) apart from playpen
refusing to start it (`"refused"`).

### Discover the CLI from an agent

```sh
playpen help --format json | jq -r '.commands[].name'
playpen help run --format json | jq '{usage, examples, workflow}'
playpen qualify --list --format json | jq -r '.scenarios[].id'
```

Every public command accepts `--format text|pretty|json` before or after the
command name. An explicit flag overrides `FORMAT`. By default a terminal gets
pretty output and a pipe gets text. JSON results are objects with an `advice`
array. Invalid CLI syntax in JSON mode produces a structured error on stderr.
Pass the workload and its flags after `--`.

### Review a command before launch

```sh
playpen plan --no-network -- printf hello
digest=$(playpen plan --format json --no-network -- printf hello | jq -er .digest)
playpen run --expect-plan "$digest" --no-network -- printf hello
```

The digest binds the reviewed arguments and effective settings, including
the pass bytes when present. The command reads executable and file contents
at run time.

### Check dropped traffic in CI

For CI, fail a successful command if it sends a counted denied packet:

```sh
playpen run --allow 192.0.2.1:443/tcp --fail-on-drop --report report.json -- ./check
```

Unavailable counters also fail the assertion. The report keeps the child
status separately from playpen's exit status.

### Run an HTTP client offline

Save one response in a fixture file, then run a client against it:

```sh
printf '%s\n' '{"method":"GET","path":"/items","status":200,"body":"[]"}' > items.json
playpen run --no-network --fixture items.json -- sh -c 'curl -qsS --noproxy "*" "$PLAYPEN_FIXTURE_URL/items"'
```

The client prints `[]`. Each run has a private listener and an ephemeral port.

## Requirements

- Linux with unprivileged user namespaces enabled (the default on most
  distributions; `playpen doctor` checks). On distributions that restrict
  them with AppArmor (Ubuntu 24.04 and later, for example), an
  administrator must allow playpen; DESIGN.md shows a profile.
- Landlock ABI 9 or later, to refuse host Unix sockets. On older kernels
  `--without-landlock` runs with weaker, mount-only hiding.
- `nft` (nftables) and `pasta` (from the passt package). `--no-network`
  needs only `nft`.
- No root, no setuid helper, no subuid/subgid ranges, no change to host
  settings. playpen refuses to run as root.

Build with a stable Rust toolchain: `cargo build --release`. Run the tests
with `cargo test`; they need the same requirements and send nothing to any
other host.

Rootless Podman workloads that require a nested mount setup or subordinate
UID/GID mappings are outside the supported configuration. Playpen runs the
command with no new privileges and applies Landlock by default. Use the
guarded offline invocation above to check ordinary command support.

### Check this host

Offline mode runs a real command with only the sandbox loopback interface.
It checks the command’s network privileges and access to host Unix sockets.
Egress mode also uses pasta and tests allowed and denied TCP, UDP and IPv6
destinations. Both modes require user namespaces, nft and Landlock ABI 9 or later.

```console
$ playpen doctor --mode offline --format json | jq -r .capability.status
available
$ playpen doctor --mode egress --format json | jq -r .capability.status
available
```

A missing prerequisite produces `unavailable` and marks the affected probes
`untested`. A probe that ran and found unexpected behavior produces `failed`.
A machine without pasta can still demonstrate offline mode.

For CI, name the native scenarios the job requires. The command reports
every scenario and exits unsuccessfully if a required scenario could not
run or any scenario failed.

```sh
playpen qualify --require offline-command --require unix-socket-guard --format json
playpen qualify --source "$PWD" --require terminal-pty-input --format json
```

Direct probes exercise the running Playpen binary. An explicit trusted
`--source` checkout enables named Cargo tests from the run, pass, sockets,
gateway and terminal suites. They use `--locked --offline`. Each result
identifies its evidence source, prerequisites and outcome. See the
[native qualification reference](docs/spec.md#441-playpen-qualify) for details.

## Threat model

playpen guards against:

- accidents and misconfigured tools: a wrong target, a forgotten default
  host, a tool reaching for updates or telemetry;
- tools that follow redirects, or resolve names, to places nobody approved:
  there is no DNS inside, and only literal approved addresses are reachable;
- children and background processes of the command: they stay in the same
  sandbox and are killed when the command exits;
- the command trying to undo the guard: it cannot change the firewall,
  add addresses or interfaces, open raw sockets, or join another network
  namespace (each is tested);
- side doors to the host's network: host daemons reached through Unix
  sockets anywhere in the file system (refused unless you `--expose`
  them), host abstract sockets, descriptors inherited from the caller, a
  network (TCP, UDP) socket as standard input or output, host IPC and
  shared memory, the display server (unless `--display`), and pushing
  input into your terminal for your shell to run later. Each is tested;
  DESIGN.md has the list, with what stays open.

playpen does not guard against:

- non-IP transports provided by the host or hypervisor. In particular,
  VM sockets (AF_VSOCK) have their own namespace rules and fall outside
  playpen's IP filter and drop counts;
- a kernel exploit, or a bug in nftables, pasta or Landlock;
- processes started outside playpen;
- whatever the daemon behind a socket you exposed does for the command;
- host processes acting on files the command writes (a sync client
  watching your home directory, a print spooler), and network file
  systems: playpen does not confine files;
- on kernels without Landlock ABI 9 (`--without-landlock`), host sockets
  outside `/run`, `/tmp`, `/var/tmp` and the runtime directory;
- the approved destination itself forwarding traffic elsewhere (an approved
  proxy is a way out to wherever that proxy goes);
- what is sent: playpen limits where packets go, not how many or what they
  contain (so it does not enforce a pass's ceilings);
- traffic to approved destinations during the [revocation and shutdown
  window](#how-a-pass-backed-run-ends), or someone who can restore the pass
  file between checks.

## License

[MIT License](LICENSE).
