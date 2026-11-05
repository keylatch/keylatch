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
    ],
    "beforeReadFile": [
      { "command": "~/.keylatch/hooks/block-keylatch-exfiltration.sh --harness cursor", "timeout": 10, "failClosed": true }
    ]
  }
}
```

The shell hook receives `{"command": "...", "cwd": "...", "sandbox": false}` on stdin. The read hook receives `{"file_path": "...", "content": "...", "attachments": [{"type": "file", "file_path": "..."}]}`; the guard checks `file_path` and every attachment path, and denies a path that is, is inside, or contains a protected location (the credential locations listed under "What It Blocks"). To block, the guard prints `{"permission":"deny","user_message":"...","agent_message":"..."}` and exits 2. Any other non-zero exit lets the action proceed, so the guard never exits 1; `failClosed: true` also blocks when the hook crashes or times out.

**Cursor does not currently enforce a `beforeReadFile` deny for agent reads** (staff-confirmed in [this forum thread](https://forum.cursor.com/t/hook-beforereadfile-does-not-work-in-the-agent/150520)), so the read hook is defence in depth only. Use Cursor's ignore files as the control that applies today. They are per project, so add the patterns below to each project's `.cursorignore`; Cursor's docs also mention a global ignore list in user settings but name no file path, so `install-guard cursor` writes no ignore file and touches no project:

```
.keylatch
.ssh
.aws
.gnupg
.local/share/atuin
.kube
.config/gcloud
.docker/config.json
.netrc
.config/gh/hosts.yml
.git-credentials
.npmrc
.pypirc
.azure
.terraform.d/credentials.tfrc.json
.env
.env.*
```

Ignore files stop the agent, Tab, inline edit and @-mentions, but terminal and MCP tools are not covered, which is what the shell hook is for. Sources: [hooks](https://cursor.com/docs/hooks), [ignore files](https://cursor.com/docs/context/ignore-files).

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
- Direct reads of credential stores, by the agent's file-read tool or a shell reader (`cat`, `head`, `less`, `cp`, `grep`, ...): `~/.keylatch`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.local/share/atuin`, `~/.kube`, `~/.config/gcloud`, `~/.docker/config.json`, `~/.netrc`, `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.azure`, `~/.terraform.d/credentials.tfrc.json`. A path that is, is inside, or contains one of these is denied. Tools that read their own config as child processes (`kubectl`, `gh`, `docker`, `npm`, ...) are unaffected; only direct reads by the agent are denied.

## Verify

```bash
keylatch doctor
```

Status: the hook schemas and deny contracts above follow the vendors' published documentation and are exercised by fixture tests with real payload shapes. None of it has been run inside the real applications.
