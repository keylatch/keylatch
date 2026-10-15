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

`schema_version` 2 is the base the policy v2 schema (tiers, hosts, egress,
filesystem and approval-by-containment) extends: the v2 schema adds keys next to
`callers` and inside caller entries, and the document keeps the same meaning
for the keys above.

Examples are in `examples/policy.d/`: `default.json` (the fallback: humans
only), `agent-gateway-only.json`, `service-only.json` and `human-only.json`.

## Commands

| Command | What it does | Needs a human |
|---|---|---|
| `keylatch policy init [--force]` | writes `policy.json` (no rules), `policy.d/_default.json` and `policy.examples/` | only with `--force` over an existing policy |
| `keylatch policy import <dir>` | validates every `*.json` against the schema, prints the diff, replaces the connection policy atomically | yes; the approval shows the diff |
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
