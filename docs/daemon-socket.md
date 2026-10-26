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
- A contained run (tier D5, see [contained-runtime.md](contained-runtime.md)) is decided and recorded the same
  way, with `child_location` `daemon`, `sandbox_sha256` (a digest of the command, project, paths, hosts and
  limits, never of the environment) and `approval_id` when an approval was collected. Its `run.exited` adds the
  number of redactions, and `egress.denied`, `contained.leak_suspected` and `sandbox.degraded` events record what
  the sandbox refused or could not apply.

## Contained runs

A client asks for tier D5 with one `contained` request that stays open for the run. The daemon answers with a
first frame that says the run started, then streams the child's output in frames, and the client sends frames
for standard input, terminal resizes and signals. The final frame carries the exit status. The daemon starts the
child in its own sandbox, so the client holds no value and the host sandbox around the client needs no change.

Argv and cwd appear only as SHA-256 digests; tokens, placeholders and credentials never appear. When the audit
log cannot record a decision, the daemon refuses it: `keylatchd serve` does not start without an audit log.

## The system broker socket

On Linux, `sudo keylatch broker install` adds a second daemon, `keylatchd broker`, under the `keylatch` OS user
(see [the broker guide](guides/broker-linux.md)). It listens on `/run/keylatch/broker.sock` (`KEYLATCH_BROKER_SOCKET`),
which systemd creates with mode 0666: any local user may connect, and the daemon decides who is admitted.

The protocol is the one above, with broker operations added. For each connection the daemon reads the peer's uid, pid and a
pidfd from the kernel, the process start time and the control group, admits only ordinary users, and serves the
user from a private partition under `/var/lib/keylatch/users/<uid>/`. It checks the pidfd again once it has read the
request, so a request that arrives from a recycled PID is refused.

When the socket exists, the client prefers it to the user-level socket (unless `KEYLATCH_SOCKET` names one), accepts it
only when it is owned by root (socket activation) or by `keylatch`, and refuses to fall back to local key files if
nothing answers. The caller kinds differ from the user-level daemon: a peer with no agent evidence is `host`, because
`human` means a presence proof bound to the request, and a peer inside a registered agent scope or carrying a
daemon-signed ticket is `agent`.

The broker also serves `approval.list` and `approval.decide`. Listing returns the connected user's pending requests,
their complete plan summaries and review digests. A decision carries `approval: {token, digest, decision, reason}`,
where `decision` is `approve` or `deny`. The broker reloads the request, compares the digest, and asks its trusted OS
presence method to authenticate that exact plan for the socket peer. Agent callers cannot open a prompt. A changed
request, expired approval, departed peer, invalid policy or failed audit leaves the request unsigned.

Broker decisions use an Ed25519 key derived separately for each user from the protected key hierarchy. The run
approver pins that user's public key and consumes an approved decision once. A copied decision cannot authorize a
different user or command. Standalone daemon approvals continue to use the locally configured approver passphrase.
Shell arguments in review summaries retain newline and control bytes as visible escapes.

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
