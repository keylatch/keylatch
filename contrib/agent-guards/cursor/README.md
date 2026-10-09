# Keylatch Guard — Cursor

Blocks credential-exfiltration patterns in Cursor agent sessions through a `beforeShellExecution` hook.

## Hook Mechanism

Cursor reads hooks from `~/.cursor/hooks.json` (user), `<project>/.cursor/hooks.json` and the enterprise and team sources. The installer merges a `beforeShellExecution` entry into `~/.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      { "command": "~/.keylatch/hooks/block-keylatch-exfiltration.sh --harness cursor", "timeout": 10, "failClosed": true }
    ]
  }
}
```

The hook receives `{"command": "...", "cwd": "...", "sandbox": false}` on stdin. To block, the guard prints `{"permission":"deny","user_message":"...","agent_message":"..."}` and exits 2. Any other non-zero exit lets the action proceed, so the guard never exits 1; `failClosed: true` also blocks when the hook crashes or times out.

## Install

```bash
keylatch install-guard cursor
```

Or manually:

```bash
bash contrib/agent-guards/cursor/install.sh
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
