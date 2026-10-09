# Keylatch Integration — GitHub Copilot CLI

Blocks credential-exfiltration patterns in GitHub Copilot CLI sessions through a `PreToolUse` hook.

## Hook Mechanism

Copilot loads hooks from `.github/hooks/*.json` (the cloud coding agent reads only this location), `~/.copilot/hooks/*.json` (or `$COPILOT_HOME/hooks/`) and the admin policy directory. The installer writes `~/.copilot/hooks/keylatch-guard.json`:

```json
{
  "version": 1,
  "hooks": {
    "PreToolUse": [
      { "type": "command", "bash": "~/.keylatch/hooks/block-keylatch-exfiltration.sh --harness copilot", "timeoutSec": 10 }
    ]
  }
}
```

The PascalCase `PreToolUse` event delivers `{"tool_name": "Bash", "tool_input": {...}}`; the guard also understands the camelCase `toolName` / `toolArgs` shape. To block, it prints `{"permissionDecision":"deny","permissionDecisionReason":"..."}` and exits 2, which denies the call even if the JSON were ignored. Other non-zero exits also deny, and a timeout fails open.

Copilot has no local OS sandbox, so this guard is the main host-side control for the CLI.

## Install

```bash
keylatch install-guard copilot
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

Status: the hook schemas and deny contracts above follow the vendors' published documentation and are exercised by fixture tests with real payload shapes. None of it has been run inside the real applications.

See also: `contrib/agent-guards/copilot/README.md`
