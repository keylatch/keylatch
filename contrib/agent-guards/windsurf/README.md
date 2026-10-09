# Keylatch Guard — Windsurf

Blocks credential-exfiltration patterns in Windsurf (Devin Desktop) Cascade sessions through a `pre_run_command` hook.

## Hook Mechanism

Cascade reads hooks from `~/.codeium/windsurf/hooks.json` (user), `.devin/hooks.json` in the workspace (legacy `.windsurf/hooks.json` is read when it is absent) and the system file (`/etc/devin/hooks.json` on Linux). Hooks do not run in Restricted Mode. The installer merges a `pre_run_command` entry into the user file:

```json
{
  "hooks": {
    "pre_run_command": [
      { "command": "~/.keylatch/hooks/block-keylatch-exfiltration.sh --harness windsurf", "show_output": false }
    ]
  }
}
```

The hook receives `{"agent_action_name": "pre_run_command", "tool_info": {"command_line": "...", "cwd": "..."}}` on stdin. Cascade documents blocking by exit code only: exit 2 blocks the action and shows stderr to the agent; any other code lets it proceed. The guard prints the reason on stderr and exits 2; it prints no JSON.

## Install

```bash
keylatch install-guard windsurf
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
