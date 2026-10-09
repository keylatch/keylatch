# Keylatch Guard — Antigravity

Blocks credential-exfiltration patterns in Antigravity agent sessions through a `PreToolUse` hook.

## Hook Mechanism

Antigravity reads `hooks.json` from `.agents/hooks.json` in the workspace and `~/.gemini/config/hooks.json` globally (the CLI also accepts hooks in `~/.gemini/antigravity-cli/settings.json`). The installer adds a named hook to the global file:

```json
{
  "keylatch-guard": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          { "type": "command", "command": "~/.keylatch/hooks/block-keylatch-exfiltration.sh --harness antigravity", "timeout": 10 }
        ]
      }
    ]
  }
}
```

The hook receives `{"toolCall": {"name": "run_command", "args": {"CommandLine": "..."}}}` on stdin. To block, the guard prints `{"decision":"deny","reason":"..."}` and exits 2, so it denies whether the harness reads the JSON or the exit code.

Reports differ on whether the IDE (as opposed to the CLI) runs `PreToolUse` hooks; check that a denied command is actually blocked in your build.

## Install

```bash
keylatch install-guard antigravity
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
