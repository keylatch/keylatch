# The daemon socket

`keylatchd serve` owns the vault, the signing keys and the policy. The `keylatch` client holds no key
material: `status`, `list`, `doctor`, `describe`, `explain`, `call`, `run` and `key` go to the daemon over an
owner-only Unix socket (`$XDG_RUNTIME_DIR/keylatch/keylatchd.sock`, `KEYLATCH_SOCKET`), so they work by bare
name inside a sandbox that hides Keylatch state and exposes only the socket.

## Who is asking

The daemon decides the caller kind itself and never trusts the client to say. One classifier serves the
control socket, the ssh-agent socket, key operations and the mint policy.

| Kind | Evidence |
|------|----------|
| `agent` | a signal the client reports, a valid session ticket, or a known harness among the peer's ancestors (Linux: the `/proc/<pid>/stat` parent chain with each process's executable and command line; macOS: the kernel process table) |
| `host` | none of the above, but the peer is outside the daemon's namespaces, or is `keylatch-relay` |
| `service` | a process the service manager started (local checks only) |
| `human` | same user, same namespaces, no agent evidence |

Evidence only moves a caller away from `human`. A client can add signals and cannot remove what the daemon
sees: an agent that sends nothing and runs outside every sandbox is still `agent` while a harness is among its
ancestors. An agent that also hides its ancestry (for example by double-forking out of the harness's process
tree) is `host` at best, so policy should allow `host` only where that is acceptable. Constrained callers
(`agent`, `host`, `service`) are refused `get`, `export`, `backup` and `mint`.

## Streaming

Served verbs stream. Output reaches the caller as the verb produces it, in frames of at most 32 KiB, and
standard input is forwarded the same way, so `keylatch call ... < body.json` and interactive verbs behave as
they do locally. There is no limit on total output; a slow reader slows the verb instead of growing a buffer.
A verb that runs longer than five minutes is stopped.

## Audit

Every decision on the socket writes one value-free event, whether it allows or refuses:

- `run.decided`: `op`, `verb`, `connection`, `tier`, `child_location` (`caller` when the client starts the child,
  `daemon` when the daemon does), `caller_kind`, `harness`, `argv_sha256`, `cwd_sha256`, `hosts`, `run_id`, and
  `reason` for a refusal.
- `run.exited`: `run_id`, `exit`, `duration_ms` and `bytes_relayed`. For a session the client started, the exit
  status is what the client reports; a run whose client never reports is closed as `expired`.
- `approval.requested`, `approval.granted` and `approval.denied` are reserved for decisions that wait on an
  approval; the daemon serves none yet.

Argv and cwd appear only as SHA-256 digests; tokens, placeholders and credentials never appear. When the audit
log cannot record a decision, the daemon refuses it: `keylatchd serve` does not start without an audit log.

## `keylatch-relay`

Some harness sandboxes cannot reach a Unix socket at all. For those, `keylatch-relay` is a separate, tiny binary
meant to be run outside the sandbox as the harness's excluded command. It copies its standard input to the
daemon socket and the reply to its standard output. It ignores its arguments, holds no key material, never
starts a process and links no code that can. What a caller sends through it is the daemon's to decide, and the
daemon classifies the relay's callers as `agent` or `host`, never `human`.

The relay connects to `$XDG_RUNTIME_DIR/keylatch/keylatchd.sock`, or to the path fixed at build time with
`-ldflags "-X github.com/keylatch/keylatch/internal/socketrelay.DefaultSocket=<path>"`. `KEYLATCH_SOCKET` is
honored only for a socket owned by the same user inside a directory only that user can write; the daemon must
also run as that user.

Install it root- or package-owned, so that nothing running as you can replace a command the harness runs
outside its sandbox:

```
sudo install -o root -m 0755 keylatch-relay /usr/local/bin/keylatch-relay
```

`keylatch doctor` warns when the relay on your `PATH` is writable by your user. Then list it as the excluded
command for the harness:

- **Claude Code**: add `keylatch-relay:*` to `sandbox.excludedCommands` in `settings.json`, and leave
  `keylatch` out of that list.
- **Other harnesses**: use the harness's equivalent of an unsandboxed command allowlist, with the absolute path
  of the installed relay and nothing broader.
