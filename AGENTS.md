# playpen

**playpen** runs a command (a scanner, a proxy, a browser, a shell) so that its
network traffic can reach only the literal addresses, ports and protocols you
approved. Everything else is dropped and counted. It works without root on
Linux.

It is a guard for tools that do not police themselves. A tool that follows
a redirect, resolves a name to an unexpected address, or was configured
with the wrong target cannot reach anywhere else

## Workflow

- Use bones (`bn --help`) to track all goals, tasks, and bugs.
- All work should be done in maw workspaces (`maw --help`).
  - Use ephemeral workspaces that get destroyed when merged.
