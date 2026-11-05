# Keylatch Guard — Gemini CLI

Blocks credential-exfiltration patterns in Gemini CLI sessions through a `BeforeTool` hook.

## Hook Mechanism

Gemini CLI reads hooks from the `hooks` object of `~/.gemini/settings.json` (or `~/.config/gemini/settings.json`), the project settings and the system settings. The installer merges a `BeforeTool` group:

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "matcher": "run_shell_command|read_file|read_many_files",
        "hooks": [
          { "type": "command", "name": "keylatch-guard", "command": "~/.keylatch/hooks/block-keylatch-exfiltration.sh --harness gemini", "timeout": 10000 }
        ]
      }
    ]
  }
}
```

The hook receives `{"tool_name": "run_shell_command", "tool_input": {"command": "..."}}` on stdin. Stdout must contain only JSON: the guard prints `{"decision":"deny","reason":"..."}` and exits 2 to block, and `{"decision":"allow"}` to permit.

## Install

```bash
keylatch install-guard gemini
```

Or manually:

```bash
bash contrib/agent-guards/gemini/install.sh
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
