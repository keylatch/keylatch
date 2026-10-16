# Policy

Keylatch denies by default. A connection can be used only when a policy says
so for the kind of process asking.

## One decision point

`run`, `call` and the gateway all ask the same function, `enforce.Decide`
(`internal/policy/enforce`). None of them re-implements a check, so one request
gets one answer wherever it is made. `keylatch policy check` asks it too, so a
dry run is always the real answer.

A request carries the connection, the capability asked for (`inject` for `run`,
`call` for `call`, the route capability at the gateway), the runtime, and the
caller kind. The answer comes from the first source that applies:

1. **The connection's policy document**, `policy.d/<connection>.json`, decides
   on its own.
2. **The rules file**, `policy.json`, when it has a rule that allows the request.
   A rules file that does not say `default_deny` denies whatever no rule
   allows; only an explicit `"default_deny": false` allows.
3. **The fallback document**, `policy.d/_default.json` (connection `*`).
4. Otherwise the request is denied with
   ``no policy for <connection>: run `keylatch policy init` ``.

A policy file that cannot be read denies. A denial can be overridden only by a
grant that was issued with a human presence proof (`keylatch grant create`);
a grant written without one is ignored.

`policy.json` patterns match exactly unless they end in `*`: `pnpm test` does
not allow `pnpm test -- rm`.

## Caller kinds

`internal/callerkind` is the one classifier. The control socket, the ssh-agent
socket, key operations, the mint policy, `run`, `call` and the gateway all take
the kind from it.

| Kind | Evidence |
|---|---|
| `agent` | an agent harness signal, a valid session ticket, or a harness among the caller's ancestors |
| `service` | the process's cgroup is a non-transient systemd service unit that systemd confirms has a unit file |
| `human` | an interactive terminal and none of the above |
| `host` | everything else: the residual class |

Evidence only ever moves a caller away from `human`. An agent that hides every
signal lands in `host`, never `human` or `service`: variables such as
`INVOCATION_ID` are not evidence. Service classification is advisory in this
release and becomes enforced when the broker daemon enrolls units. A gateway
token records the kind it was issued for, in its signed claims and in the store;
an agent's token is an LLM-session token, so the gateway's agent route
restrictions apply to it. A stored record can only add restrictions to what the
claims say.

## Connection policy documents

One document governs one connection. The schema is
`schemas/connection-policy.schema.json`; unknown keys are rejected so that
nothing a policy author writes is silently ignored.

```json
{
  "schema_version": 2,
  "connection": "openrouter",
  "default": "deny",
  "max_ttl": "15m",
  "capabilities": ["inject", "openrouter.*"],
  "callers": {
    "agent": { "allow": true, "runtimes": ["gateway_typed", "gateway_sdk"], "exe": ["python3"] },
    "service": { "allow": true, "units": ["deploy.service"] },
    "human": { "allow": true },
    "host": "deny"
  }
}
```

- A caller kind with no entry is denied; `default` can only be `deny`.
- `runtimes` limits the runtimes the kind may use. A request with no runtime,
  such as `call`, is not covered by an entry that lists runtimes.
- `exe` limits the executables a `run` may start, matched against the command as
  written: `python3` does not cover `/tmp/x/python3`. It is not checked for
  requests without a command, such as gateway calls.
- `units` limits the systemd units of a `service` caller.
- `capabilities` limits what the connection may be used for, as globs.
- `max_ttl` caps the lifetime of a session token or child process.

Examples are in `examples/policy.d/`: `default.json` (the fallback: humans
only), `agent-gateway-only.json`, `service-only.json` and `human-only.json`.

## Tiers, hosts, egress, filesystem and approval

A document can say more than who may use a connection. Every key below is
optional, and a document without them keeps the meaning above.

```json
{
  "schema_version": 2,
  "connection": "stripe-test",
  "hosts": ["api.stripe.com", "files.stripe.com"],
  "egress": { "allow": ["registry.npmjs.org"], "deny_private_ranges": true },
  "fs": { "write": ["${project}"], "read": ["${project}", "${toolchain_caches}"], "deny": ["~/.ssh", "${keylatch_state}"] },
  "commands": [
    { "match": ["/usr/bin/pnpm", "test", "**"], "tiers": ["D3", "D4"] },
    { "match": ["/usr/bin/make", "build"], "tiers": ["D5"], "exe_sha256": "<64 hex digits>" }
  ],
  "callers": {
    "agent": { "allow": true, "tiers": ["D2", "D3", "D5"], "approval": "auto_if_contained", "ttl": "15m", "max_requests": 500 },
    "human": { "allow": true }
  }
}
```

- `tiers` lists the delivery tiers (D1 action, D2 gateway, D3 placeholder, D4 adapter, D5 contained raw
  value, D6 uncontained raw value) a kind may use. Without it an agent or host gets D1 to D4, a service D1
  to D5 and a human D1 to D6. D6 is for humans only. A request names a tier and is denied when it is not
  listed, with the allowed ones in the reason.
- `approval` is `auto`, `ask`, `auto_if_contained`, `presence_for_D6` or `presence`. The default is
  `auto_if_contained` for agents and hosts, `presence_for_D6` for humans and `auto` for services.
  Containment is the approval for D1 to D4. D5 holds the real value, so it needs an approval unless a
  command rule pins the exact command, and D6 always needs a human present.
- `ttl` and `max_requests` bound a session for the kind; `max_ttl` bounds the document.
- `hosts` narrows the hosts the connection's credential may reach. Only a host both the provider template
  and the list name stays: the list removes hosts and never adds one.
- `egress.allow` lists the non-secret destinations a contained run may reach beyond those hosts, for
  example a package registry. Private, link-local and cloud metadata ranges are never reachable.
- `fs.write`, `fs.read` and `fs.deny` bound a contained run. Paths are absolute, start with `~/` or start
  with `${project}`, `${toolchain_caches}`, `${keylatch_state}`, `${browser_profiles}` or
  `${harness_config}`. A run whose project is outside `fs.write`, or inside `fs.deny` or a path that holds
  credentials, is refused. A write list that expands to nothing allows nothing.
- `commands` pin argv patterns. `match[0]` is an absolute path pattern compared with the executable the
  command resolves to (after `PATH` lookup and symlinks), never with the name as typed. The other entries
  match one argument each: `*` any one argument, a final `**` the rest. A matched rule narrows `tiers` and
  may set `approval`. With `exe_sha256` the executable must hash to the pin and, with every directory above
  it, be owned and writable only by root; then D5 runs without an approval. A pin that no longer matches
  denies the command rather than running it unpinned.

### One file for several connections

`keylatch policy import <file.yaml>` compiles a file with `defaults` (caller entries, egress, fs that every
listed connection starts from), `connections` and `commands` (each naming the connections it applies to) into
one document per connection. A connection lists only what differs from the defaults; its filesystem denies are
added to the default denies and never replace them. Keys that define how a connection reaches its secret
(`secret`, `slots`, `adapter`, `upstream`, `mint`) are refused: they belong to `keylatch connect`.

### Bounding the policy by the agent's own sandbox

`keylatch policy import --from claude-code|codex|gemini [--settings <file>...] [--connection <name>...]` reads
the harness's sandbox settings and records its limits in the stored documents:

| Harness | Read |
|---|---|
| Claude Code | `sandbox.network.allowedDomains`, `sandbox.filesystem.allowWrite/denyRead/denyWrite`, `sandbox.excludedCommands`, `permissions.deny` entries of the form `Read(path)` and `Edit(path)` |
| Codex | `sandbox_mode`, `[sandbox_workspace_write] writable_roots` and `network_access` in `config.toml` |
| Gemini CLI | `excludedCommands` and `network.allowedDomains` under `sandbox` or `tools.sandbox` |

The import only narrows. Egress becomes the intersection of the document's list and the harness's, so a
document with no `egress.allow` stays without destinations; a write must lie inside the harness's writable
paths (the project is always among them); the harness's denies are added to the document's. Tiers,
approvals and hosts are untouched. The import is repeatable and replaces the earlier one. A setting the
importer does not recognize is not read as "no limit"; entries it cannot use are reported and skipped.

It fails, naming the entries, when the harness excludes `keylatch`, a wildcard, or a program that can start
it (a shell, `env`, `xargs`, `sudo`, an interpreter): such an entry lets an agent run Keylatch outside its
sandbox, past the checks the daemon makes.

## Commands

| Command | What it does | Needs a human |
|---|---|---|
| `keylatch policy init [--force]` | writes `policy.json` (no rules), `policy.d/_default.json` and `policy.examples/` | only with `--force` over an existing policy |
| `keylatch policy import <dir>` | validates every `*.json` against the schema, prints the diff, replaces the connection policy atomically | yes; the approval shows the diff |
| `keylatch policy import <file.yaml>` | compiles the one-file form into one document per connection, then as above | yes |
| `keylatch policy import --from claude-code\|codex\|gemini` | records the harness's sandbox limits in the stored documents; `--dry-run` shows the diff | yes |
| `keylatch policy export <dir>` | writes the connection policy documents to a directory | no |
| `keylatch policy check <connection> --as agent\|host\|service\|human [--runtime <r>] [--action <a>] [--json]` | read-only dry run | no |
| `keylatch policy allow`, `deny`, `remove` | change the rules file or a document | yes |
| `keylatch grant create`, `revoke` | issue or revoke a grant | yes |

A human at a terminal means an interactive terminal that no agent harness
owns, plus the platform prompt where one is available. Nothing in the
environment changes that outcome. See `docs/security/threat-model.md` for what
in-user presence does and does not stop.

An import that contains an invalid file changes nothing. The new set is staged
next to the store and swapped in, so a reader sees the old set or the new one.
