---
title: Host guards and keylatch explain
description: Let an agent harness hook judge `keylatch run` by Keylatch's own containment verdict using `keylatch explain --json`.
---

# Host guards and `keylatch explain`

A host guard is a hook in an agent harness (a Claude Code `PreToolUse` hook, a Cursor `beforeShellExecution` hook and so on) that decides whether a shell command may run. For `keylatch run <connection> -- <command>` the guard cannot tell from the command text alone where the child will run or whether the secret reaches it. `keylatch explain` answers that without running anything.

```
keylatch explain [--json] run <connection> -- <command> [args...]
keylatch explain [--json] policy [connection]
keylatch explain schema
```

`explain` reads the policy file and the provider templates. It never opens a vault, never prints a secret value, and echoes the command only as an executable name, an argument count and a SHA-256 digest.

| Flag (`run`) | Meaning |
|---|---|
| `--actor <name>` | Evaluate as this actor instead of the inferred one |
| `--cwd <dir>` | Evaluate for this working directory (default: current directory) |
| `--tier <D1..D6>` | Ask about one tier; this can narrow the answer but never relaxes policy |

`explain` exits 0 whenever it produced an answer, including a `deny`. A non-zero exit means it could not evaluate (for example, an unreadable policy file); a guard must treat that as a denial.

## Delivery tiers

| Tier | Name | What the child receives |
|---|---|---|
| D1 | `typed_action` | nothing; Keylatch performs a typed request (`keylatch call`) |
| D2 | `gateway_session` | a scoped, short-lived gateway token and a base URL |
| D3 | `placeholder_substitution` | a placeholder that Keylatch swaps for the real value toward the connection's hosts only |
| D4 | `protocol_adapter` | a credential-free local endpoint (database proxy, SSH agent, credential helper) |
| D5 | `contained_raw` | the real value, inside a sandbox Keylatch builds |
| D6 | `uncontained_raw` | the real value, in an uncontained process; human-only |

`explain` picks the strongest tier that policy, the provider template and this build all allow. D1 never applies to `run` because `run` always starts a child. A tier that this build does not implement is listed under `rejected_tiers` with the reason.

## Output (schema version 1)

`keylatch explain --json run ...` prints one JSON document. The JSON Schema ships with the binary (`keylatch explain schema`) and lives at [`internal/explain/schema_v1.json`](https://github.com/keylatch/keylatch/blob/main/internal/explain/schema_v1.json).

```json
{
  "schema_version": 1,
  "kind": "run",
  "decision": "allow",
  "tier": "D2",
  "tier_name": "gateway_session",
  "runtime": "gateway_typed",
  "child_location": "caller",
  "containment": { "verdict": "no_secret_in_child", "secret_in_child": false },
  "approval": { "required": false, "mode": "none" },
  "request": {
    "caller_kind": "agent",
    "actor": "claude-code",
    "connection": "openai",
    "executable": "pnpm",
    "argc": 2,
    "argv_sha256": "…",
    "cwd": "/work/app"
  },
  "hosts": ["api.openai.com"],
  "scope": { "rule_id": "r1", "capabilities": ["inject"], "connections": ["openai"], "ttl_seconds": null },
  "reasons": ["allowed by policy rule r1", "strongest eligible tier D2 (gateway_session) via runtime gateway_typed"],
  "rejected_tiers": [{ "tier": "D1", "tier_name": "typed_action", "why": "typed actions run without a child process; use keylatch call" }],
  "residual_risk": "The child holds a scoped, short-lived gateway session token, not the provider key. …",
  "policy": { "mode": "enforcing", "default_deny": true }
}
```

| Field | Values and meaning |
|---|---|
| `schema_version` | Integer. Changes only when an existing field is removed or changes meaning. New optional fields can appear within a version, so parse leniently. |
| `decision` | `allow`: runs without a prompt. `approval`: runs only after the approval in `approval`. `deny`: does not run. |
| `tier`, `tier_name` | The chosen tier, or `null` on `deny`. |
| `runtime` | The runtime mode that implements the tier, or `null`. |
| `child_location` | `caller`: the child stays in the caller's process tree, inside the caller's sandbox if it has one. `keylatch_sandbox`: Keylatch spawns it in its own sandbox. `unsandboxed`: no containment. `none`: nothing runs. |
| `containment.verdict` | `no_secret_in_child`, `contained_by_keylatch`, `uncontained`, `not_applicable`. |
| `approval.mode` | `none`, `ask` (a person confirms), `presence` (a person proves presence). |
| `request.caller_kind` | `human`, `agent` or `service`, derived from the actor and from agent-session detection. |
| `hosts` | Hosts the secret is bound to. Sorted. |
| `scope` | The matching rule and its capabilities, connections and TTL (`null` when the rule sets none). |
| `reasons`, `rejected_tiers`, `residual_risk` | Human-readable explanation. Do not parse them; use the enumerated fields. |
| `error` | Present only when the request could not be evaluated: `unknown_connection`, `invalid_request` or `tier_unavailable`. `decision` is then `deny`. |

`keylatch explain --json policy [connection]` prints `{"kind": "policy", ...}` with, per caller (`human-shell`, `llm-session` and every literal actor named in a rule) and connection, a `status` for each tier: `allowed`, `approval`, `denied` or `unavailable`. Rules limited by command or working directory are flagged `restricted`; confirm those with `explain run`.

`explain` does not consider temporary grants. A run that a grant would allow shows as `deny`, which is the safe direction for a guard.

## Residual risk

A `deny`-free answer does not mean the run cannot misuse a capability it legitimately holds. D2 and D3 children can use the connection's allowed actions until the session ends; policy scope, rate and audit bound that, they do not prevent it. D5 and D6 put the real value in a process that can encode it past output masking. The `residual_risk` field states the applicable limit for the chosen tier.

## Guard adapter example (Claude Code)

This `PreToolUse` hook allows `keylatch run` when Keylatch says the secret stays out of the child and the child stays in the caller's sandbox, asks the user when Keylatch requires approval, and denies everything else. Anything it cannot judge with certainty (shell operators, an unparsable command, a failing `explain`) is denied.

```bash
#!/usr/bin/env bash
# PreToolUse hook for Bash commands. Needs bash and jq.
set -uo pipefail

KEYLATCH_BIN=${KEYLATCH_BIN:-keylatch}   # prefer an absolute path owned by root

deny() { echo "keylatch guard: $1" >&2; exit 2; }
ask() {
  jq -n --arg r "$1" '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: $r}}'
  exit 0
}

cmd=$(jq -r '.tool_input.command // empty') || deny "unreadable hook input"

re='^[[:space:]]*([^[:space:]]*/)?keylatch[[:space:]]+run[[:space:]]+([^[:space:]-][^[:space:]]*)[[:space:]]+--[[:space:]]+(.+)$'
[[ $cmd =~ $re ]] || exit 0   # not a keylatch run: leave it to the other guards

[[ $cmd == *[\;\&\|\`\$\(\)\<\>\"\'\\]* ]] && deny "keylatch run with shell syntax cannot be judged; run the command without operators or quoting"

conn=${BASH_REMATCH[2]}
read -r -a argv <<<"${BASH_REMATCH[3]}"

# CLAUDECODE=1 makes explain treat the caller as an agent even if the hook's own environment lacks the marker.
report=$(CLAUDECODE=1 "$KEYLATCH_BIN" explain --json run --actor claude-code --cwd "$PWD" "$conn" -- "${argv[@]}") \
  || deny "keylatch explain failed"

IFS=$'\t' read -r decision tier location reason < <(
  jq -r '[.decision, (.tier // "none"), .child_location, (.reasons | join("; "))] | @tsv' <<<"$report"
) || deny "unreadable keylatch explain output"

case "$decision:$tier:$location" in
  allow:D[1-4]:caller)
    exit 0 ;;   # no secret in the child, child stays in the caller's sandbox
  approval:D[1-5]:*)
    ask "keylatch requires approval ($tier): $reason" ;;
  *)
    deny "keylatch run is $decision ($tier, child $location): $reason" ;;
esac
```

Register it under `hooks.PreToolUse` with the `Bash` matcher in `settings.json`. The guard evaluates the inner command (`pnpm test`) with its own rules as if it were sandboxed only when `child_location` is `caller`; for `keylatch_sandbox` Keylatch's verdict stands, and `unsandboxed` or `none` is denied.

Never list `keylatch` in a harness sandbox's excluded commands: an excluded `keylatch run` starts its child outside the sandbox.

## Versioning

Consumers should check `schema_version` and fail closed on a value they do not know. `keylatch explain schema` prints the schema for the binary in use, so a guard can validate the document it receives.
