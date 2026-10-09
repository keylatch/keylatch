# Keylatch Guard — Codex CLI

Blocks credential-exfiltration patterns in Codex CLI sessions through a `PreToolUse` hook.

## Hook Mechanism

Codex reads hooks from `~/.codex/hooks.json`, `<repo>/.codex/hooks.json` or a `[hooks]` table in `config.toml`. The installer merges a `PreToolUse` matcher group for `Bash` into `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "~/.keylatch/hooks/block-keylatch-exfiltration.sh --harness codex", "timeout": 30 }
        ]
      }
    ]
  }
}
```

Non-managed hooks must be reviewed and trusted with `/hooks` in Codex before they run. The hook receives `{"tool_name": "Bash", "tool_input": {"command": "..."}}` on stdin. To block, the guard prints `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}` and exits 2.

## Install

```bash
keylatch install-guard codex
```

Or manually:

```bash
bash contrib/agent-guards/codex/install.sh
```

The guard script is written to `~/.keylatch/hooks/block-keylatch-exfiltration.sh`; one script serves every harness and `--harness <id>` selects the payload and deny contract.

## What It Blocks

- `keylatch get` without `--masked`
- Secret-manager reads: `op read`, `op item get`, `bw get`, `bw list`, macOS `security find-generic-password` / `find-internet-password`
- `cat` of `.env` files and of `~/.keylatch/` state
- Environment dumps: `env`, `printenv`, including behind `bash -c`, `eval`, `sudo`, `xargs` and similar wrappers
- Environment managers: `direnv export`, `direnv dump`, `direnv exec <dir> env`, `mise env`, `mise exec -- env`, a bare `mise set`
- Shell history: `atuin search`, `atuin history ...`, and any access to `~/.*_history` or `~/.local/share/atuin`

## Verify

```bash
keylatch doctor
```
