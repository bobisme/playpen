# playpen

![PLAYPEN — A firewall for a single command. A faceless, cloaked figure kneels on flagstones to complete a circle of salt.](docs/images/playpen-cover.webp)

playpen runs a command and its children with a firewall that restricts
outbound IP traffic to the addresses, ports and protocols you approve.
It works without root on Linux and reports packets the firewall drops.

It is a guard for tools that do not police themselves. If an HTTP client follows a redirect,
the new connection must also match the allow list. The command keeps its own
loopback. An approved server can forward traffic, so choose destinations you trust.

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
$ playpen doctor --mode offline --format json | jq -r .capability.status
available
$ playpen run --no-network --format json -- printf 'hello\n' | jq '{outcome, exit_code}'
```

The command's `hello` and playpen's diagnostics go to stderr. The pipe receives
one JSON report with `outcome: "ran"` and `exit_code: 0`.
This example needs no network destination, pass file or pasta. For a run with
outbound access, check `playpen doctor --mode egress` first.

### Run under a Hallpass approval

Use a current pass from the owner. For example, if the pass approves
`192.0.2.10:443/tcp`, the invocation below gives curl a local name for that
address. Substitute the address and hostname from your own engagement.

```sh
playpen run --pass engagement.pass.toml \
  --host app.example.test=192.0.2.10 \
  -- curl -sS https://app.example.test/
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

For a headless job (no controlling terminal), send signals to the playpen PID
or its process group. Playpen forwards them to the workload group. Redirecting
stdio alone does not make a terminal job headless.

At a terminal, the default preserves shell pipelines, `fg`/`bg` and
`/dev/tty`. Send signals to the playpen PID or to its process group; the
command gets one copy either way. `killall playpen` also delivers one copy.

### Run an interactive shell with single signal delivery

From a foreground terminal, run:

```sh
playpen run --no-network --private-tty -- bash -i
```

The shell gets its own controlling terminal for prompts and job control.
Send a forwarded signal such as SIGTERM or SIGUSR1 to the playpen PID or
its process group. Either way, the private terminal’s foreground job gets
one copy. Use this mode when playpen has exclusive use of terminal input.
A pipe or file can supply stdin while the command reads a password or
confirmation from `/dev/tty`. For a pipeline with another stage that reads
the keyboard, use the default terminal behavior.

### Run with a command-line allow list

```sh
playpen run --allow 192.0.2.10:443/tcp \
  --host app.example.test=192.0.2.10 \
  -- curl -sS https://app.example.test/
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
$ playpen run --allow 192.0.2.10:22/tcp --expose "$SSH_AUTH_SOCK" \
              -- ssh admin@192.0.2.10
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
command name. Use `--json` as a shorthand for `--format json`. An explicit
flag overrides `FORMAT`. By default a terminal gets pretty output and a pipe
gets text. JSON results are objects with an `advice`
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

### Reach a test service on this machine

The sandbox gets this host's network address, so a service listening on
that address is not reachable from inside: the connection stays in the
sandbox, and playpen prints a NOTE that says so. Give the service an
address the sandbox does not have. Without privileges, build a throwaway
host and run both in it:

```sh
unshare --user --map-root-user --net sh -c '
  ip link set lo up
  ip link add host0 type dummy && ip addr add 192.0.2.10/24 dev host0
  ip link set host0 up && ip route add default via 192.0.2.1
  ip link add svc0 type dummy && ip addr add 198.51.100.7/32 dev svc0
  ip link set svc0 up
  my-test-service --listen 198.51.100.7:8080 &
  unshare --user --map-user='"$(id -u)"' --map-group='"$(id -g)"' \
    playpen run --allow 198.51.100.7:8080/tcp -- my-client http://198.51.100.7:8080/
'
```

Nothing leaves the machine: a dummy interface discards what is sent to it.
Do not run playpen inside `playpen run`; the inner one cannot start.

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
It checks the command’s network privileges and verifies that a private Unix socket
connects while the host pathname and abstract sockets are unreachable.
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
playpen qualify --source "$PWD" --require routed-peer --format json
```

Direct probes exercise the running Playpen binary. An explicit trusted
`--source` checkout enables named Cargo tests from the run, pass, sockets,
gateway and terminal suites. They use `--locked --offline`. Each result
identifies its evidence source, prerequisites and outcome. The `routed-peer`
scenario runs a Python fixture against the qualifying binary. It follows an
HTTP redirect with and without a grant for the second server, then sends UDP
to approved and denied ports over IPv4 and IPv6. The listeners record which
requests arrived, and playpen reports which packets it dropped.

| Tested Linux configuration | nftables | pasta | Landlock | Checks that ran |
| --- | --- | --- | --- | --- |
| Arch host, 7.2.8-arch1-2 | 1.1.7 | 2026_09_25.df90211 | ABI 10 | All 12 qualification scenarios, including private-terminal signal delivery |
| Isolated Arch guest, 7.1.4-arch1-1 | 1.1.6 | 2026_07_28.f8df3f1 | ABI 9 | Egress doctor, offline command and routed-peer fixture |

The guest had no external network interface. Its test servers ran inside the
guest. See the [guest qualification record](docs/qualification-second-linux.md)
and the [qualification command reference](docs/spec.md#441-playpen-qualify).

## Threat model

playpen guards against:

- accidents and misconfigured tools: a wrong target, a forgotten default
  host, a tool reaching for updates or telemetry;
- tools that follow redirects, or resolve names, to places nobody approved:
  the system resolver uses the sandbox hosts file. A client that implements
  its own DNS still needs permission to reach the resolver;
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
