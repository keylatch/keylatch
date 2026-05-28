# Keylatch Integration — OpenCode

Blocks credential-exfiltration patterns in OpenCode sessions via the `tool.execute.before` plugin hook.

## Hook Mechanism

OpenCode TypeScript plugin with a `tool.execute.before` hook. The plugin is installed at `~/.config/opencode/plugins/keylatch-guard/index.ts` and registered in `~/.config/opencode/opencode.json`. Throwing an error from the hook blocks the tool call.

## Install

```bash
keylatch install-guard opencode
```

## What It Blocks

- `keylatch get` / `keylatch secret get`
- `security find-password` / `security find-generic-password`
- `op read`, `bw get`
- `cat ~/.keylatch/config.yaml`
- Direct access to `~/.keylatch/keylatch.keychain-db`

## Verify

```bash
keylatch doctor
```

See also: `contrib/agent-guards/opencode/README.md`
