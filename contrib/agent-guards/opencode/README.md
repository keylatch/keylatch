# Keylatch Guard — OpenCode

Blocks credential-exfiltration patterns from OpenCode tool calls via the `tool.execute.before` plugin hook.

## Hook Mechanism

OpenCode supports TypeScript plugins with a `tool.execute.before` hook. The plugin is loaded from `~/.config/opencode/plugins/keylatch-guard/index.ts` and registered in `~/.config/opencode/opencode.json`. Throwing an error from the hook blocks the tool call.

## Install

```bash
keylatch install-guard opencode
```

Or manually:

```bash
bash contrib/agent-guards/opencode/install.sh
```

This copies `keylatch-guard.ts` to `~/.config/opencode/plugins/keylatch-guard/index.ts` and patches `~/.config/opencode/opencode.json`.

## What It Blocks

- `keylatch get` / `keylatch secret get`
- `security find-password` / `security find-generic-password`
- `op read`
- `bw get`
- `cat ~/.keylatch/config.yaml`
- Direct access to `~/.keylatch/keylatch.keychain-db`

## Verify

```bash
keylatch doctor
```
