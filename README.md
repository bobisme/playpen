# playpen

playpen runs a command (a scanner, a proxy, a browser, a shell) so that its
network traffic can reach only the literal addresses, ports and protocols you
approved. Everything else is dropped and counted. It works without root on
Linux.

It is a guard for tools that do not police themselves. A tool that follows
a redirect, resolves a name to an unexpected address, or was configured
with the wrong target cannot reach anywhere else.

The approval normally comes from a [hallpass](../hallpass) pass: the
owner's written permission as a file (owner, literal destinations, a time
window, a revocation marker). playpen allows exactly the pass's
destinations until the window ends, and stops the command if the pass is
revoked while it runs. For a quick run you can give the destinations on the
command line with `--allow` instead.

- [docs/spec.md](docs/spec.md): what playpen does, exactly: every command,
  option, exit code and report field. Start here.
- [docs/DESIGN.md](docs/DESIGN.md): why it is built this way, and the leaks
  considered and how each is closed or not.

## Two-minute example

```console
$ cargo build --release
$ ./target/release/playpen doctor
ok   user namespaces: user.max_user_namespaces = 512098
ok   unprivileged user namespaces: kernel.unprivileged_userns_clone = 1
ok   nft: /usr/bin/nft (nftables v1.1.7 (Commodore Bullmoose #8))
ok   pasta: /usr/bin/pasta (pasta 2026_09_25.df90211)
ok   allowed reached, others blocked: TCP, UDP and IPv6 to in-sandbox addresses: approved reached, others dropped
ok   command cannot change the network: nft, netlink address/link changes, raw and packet sockets all denied; no capabilities
playpen can run here.

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
playpen: under pass example-2026-11 ("Example web app", owner "Pat Owner, Example Corp", sha256:3f1c..., window ends 2026-11-19T17:00:00Z, destinations app): allowing only 192.0.2.10:443/tcp until 2026-11-19T17:00:00Z (no DNS, names app.example.test=192.0.2.10); everything else is dropped
...curl output...
playpen: command exited with status 0
playpen: no packets to unapproved destinations were dropped
```

playpen refuses to start (exit 2, "nothing was run") when the pass is
invalid, unreadable, a symbolic link, writable by others, not yet valid,
expired or revoked. `--only LABEL` narrows the pass to some destinations;
`--until` can end the run earlier than the window, never later. The pass's
host names are never resolved for you; map them with `--host`.

While the command runs, playpen re-reads the pass every 2 seconds. If the
owner revokes it (`revoked = true`), the window ends, the file disappears
or stops validating, or a destination in use is changed, playpen stops the
command (SIGTERM, then SIGKILL after 3 seconds) and says why. Other edits
(a raised ceiling, a later end) do not stop it, and do not apply to the
running command either: the rules are fixed at start and never widened.
playpen does not use the pass's ceilings; it limits where packets go, not
how many.

The quick form, without a pass:

```console
$ playpen run --allow 192.0.2.10:443/tcp \
              --host app.example.test=192.0.2.10 \
              --until 2026-11-19T18:00:00+01:00 \
              -- curl -sS https://app.example.test/
playpen: allowing only 192.0.2.10:443/tcp until 2026-11-19T17:00:00Z (no DNS, names app.example.test=192.0.2.10); everything else is dropped
```

`--pass` and `--allow` cannot be combined: an `--allow` beside a pass would
add a destination the owner did not approve.

If the tool tries to go somewhere else, the connection fails at once
("No route to host" for TCP, "Operation not permitted" for UDP), and
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

For scripts, `--report FILE` writes a JSON summary (for refusals too), and
`--format json` requires it. The report's `outcome` field tells a command
that exited with status 2 (`"ran"`, `exit_code: 2`) apart from playpen
refusing to start it (`"refused"`).

## Requirements

- Linux with unprivileged user namespaces enabled (the default on most
  distributions; `playpen doctor` checks).
- `nft` (nftables) and `pasta` (from the passt package). `--no-network`
  needs only `nft`.
- No root, no setuid helper, no subuid/subgid ranges, no change to host
  settings. playpen refuses to run as root.

Build with a stable Rust toolchain: `cargo build --release`. Run the tests
with `cargo test`; they need the same requirements and send nothing to any
other host.

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
  namespace (each is tested).

playpen does not guard against:

- a kernel exploit, or a bug in nftables or pasta;
- processes started outside playpen, or a host daemon that the command
  reaches through a filesystem socket and that acts on the host's network
  for it. playpen hides the ones it knows (D-Bus buses, systemd, resolvers,
  container engines, dirmngr, PulseAudio; see the spec) and `--hide PATH`
  hides more, but it cannot know every such socket on your machine;
- the approved destination itself forwarding traffic elsewhere (an approved
  proxy is a way out to wherever that proxy goes);
- what is sent: playpen limits where packets go, not how many or what they
  contain (so it does not enforce a pass's ceilings);
- the few seconds between a pass being revoked and the command being
  stopped (the next re-read, up to 2 s, plus the 3 s grace), and anyone who
  can write the pass file.

## License

MIT OR Apache-2.0.
