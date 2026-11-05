# Contained runtime (tier D5)

Tier D5 hands a command the real secret value, and it is the only tier that does so for an agent.
The daemon, not the caller's client, starts the command inside a Keylatch sandbox. The client relays
the terminal or the standard streams over the control socket; it never sees the value.

```bash
keylatch run --tier D5 stripe -- pnpm test
keylatch doctor --sandbox
```

Use D5 when a tool needs the value as a raw environment variable and sends it to a host the proxy
cannot substitute for: proprietary protocols, files a tool reads, signing. Prefer D3 whenever the
template declares host bindings; the secret then never enters the child at all.

## What the sandbox is

On Linux the daemon re-executes the `keylatch` binary as the sandbox's init. No external helper is
required.

| Layer | What it does |
|---|---|
| user, mount, PID, IPC, UTS, cgroup and network namespaces | The child is PID 2 of its own PID namespace, root only inside its own user namespace, and sees a private root. Everything it started dies with it. |
| private root | Read-only `/usr`, `/bin`, `/lib*`, a small part of `/etc` (users, groups, the trust store, the linker cache) and the project directory read-write. `/tmp`, `$HOME`, `/run` and `/dev` are private tmpfs. Keylatch state, `~/.ssh`, cloud credentials, browser profiles, agent configuration and the D-Bus socket are not mounted at all. |
| Landlock | A second filesystem layer that mirrors the mounts, plus, on kernels with ABI 4 or newer, a rule that lets TCP connect only to the forwarder's port. |
| seccomp | Refuses `ptrace`, `process_vm_readv/writev`, `keyctl`, `add_key`, `request_key`, `bpf`, `perf_event_open`, `userfaultfd`, `mount` and the new mount API, `pivot_root`, `chroot`, `unshare`, `setns`, `clone` with a namespace flag, `clone3`, module, kexec and reboot calls and `io_uring`. A foreign architecture kills the process. |
| capabilities | The bounding, permitted, effective, inheritable and ambient sets are emptied and `no_new_privs` is set before the command starts. |
| cgroup v2 | One leaf per run for kill-all and, when the host delegates the controllers, memory, process and CPU limits. |
| network | The namespace has only `lo`. A forwarder on `127.0.0.1:3128` connects each connection to the daemon's egress proxy over a Unix socket. |

The value travels to the sandbox over an inherited pipe and appears only in the command's
environment block. Nothing is on argv and the daemon's own environment never holds it.

## Egress

The egress proxy is the only exit. It allows a destination only when the policy names it: the hosts
the connection's template binds the credential to, plus `egress.allow` from the policy. It resolves
names itself and dials the address it checked, so a rebinding answer cannot move a connection to an
internal address. IP literals, loopback, private, link-local (including the cloud metadata
address), shared and multicast ranges are refused unless the policy names them. Every refusal writes
an `egress.denied` audit event.

`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and `NODE_USE_ENV_PROXY` point at the forwarder. A tool that
ignores them simply cannot connect.

## Output and files

Standard output and error pass through an exact-value redactor that also catches the base64,
base64url, hex, URL-encoded and JSON-escaped forms of every value, across chunk boundaries. After the
run, files written under the project are scanned for the same patterns. A hit makes `run` exit 3
and writes a `contained.leak_suspected` audit event with the number of files.

A command that holds a value can still encode it in a way no scanner recognizes, for example by
XORing it with a constant before printing it. That is why D5 asks for approval by default.

## Canaries

Every contained run, and every D3 session, carries decoys: a `KEYLATCH_CANARY_<PROVIDER>` variable and,
in a contained run, honey files in the empty home (`~/.aws/credentials`, `~/.config/gh/hosts.yml`,
`~/.npmrc`) whose keys look real and are worthless. Nothing legitimate sends them anywhere. The
egress proxy and the D3 proxy look for them, in any common encoding, in the request target, the
head and (for plain HTTP and the D3 proxy's terminated TLS) the body. The first request that
carries one is refused, the session is suspended or the contained run ended, and a `canary.tripped`
audit event records the host and where it was seen, never the decoy. A tunnel's contents are
opaque, so a decoy inside a pass-through TLS connection is not seen; the target name is.

`keylatch scan [path...]` applies the same idea to text: it reports the lines of a file or standard
input that hold a known credential format or a Keylatch canary, without printing them, and exits 2
when it finds any. `--redact` writes the text with the findings replaced instead, so a hook can
filter a prompt or a tool result before it reaches a model.

## Approval

A human caller runs D5 under the connection's policy. An agent or host caller needs an approval
unless the policy pre-approves the exact command (`approval: auto`). The approval is bound to the
argv digest, the tier, the host set and the lifetime; an approval for one run never applies to
another. Without an approver the daemon refuses the run and says why.

The daemon opens a signed approval request that carries the plan (connection, tier, caller, project,
argv, hosts, lifetime) and prints the token to the caller before it starts anything. The person runs
`keylatch approve <token>` in their own terminal, which shows the plan and asks for presence bound to
the request hash. The daemon starts the run only when the signed decision names that plan; a
decision is used once and expires with the request.

Changes that widen what a secret can reach need a person at a terminal even when the caller is a
human: creating or widening a custom connection's hosts (`binding.change`, bound to the hosts before
and after), and weakening a local-only delivery mode (`local_only.weaken`). Narrowing needs nothing.
Key-operation allowlists are not yet presence-gated.

## Requirements and limits

- Linux with unprivileged user namespaces, Landlock (Linux 5.13 or newer) and seccomp.
  `keylatch doctor --sandbox` reports each capability and exits 2 when D5 cannot run, 1 when only an
  optional layer (TCP rules, cgroup limits) is missing. D5 never falls back to an uncontained run.
- Ubuntu 24.04 and newer restrict unprivileged user namespaces with AppArmor
  (`kernel.apparmor_restrict_unprivileged_userns`). The daemon's profile or the sysctl must allow
  them.
- The child runs as the daemon's user mapped to root inside its namespace. Files in the project
  that the daemon's user cannot write are read-only to the child.
- macOS runs D5 under a Seatbelt profile (`sandbox-exec`) and Windows in an AppContainer inside a job
  object; neither has namespaces or seccomp, and neither supports terminal runs. See
  [the macOS and Windows broker guide](guides/broker-macos-windows.md) for what each confines.
- The optional `bwrap` backend and a degraded Landlock-only mode are not implemented.
