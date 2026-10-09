# Keylatch Integration — Windsurf

Blocks credential-exfiltration patterns in Windsurf (Devin Desktop) Cascade sessions through a `pre_run_command` hook.

## Hook Mechanism

Cascade reads hooks from `~/.codeium/windsurf/hooks.json` (user), `.devin/hooks.json` in the workspace (legacy `.windsurf/hooks.json` is read when it is absent) and the system file (`/etc/devin/hooks.json` on Linux). Hooks do not run in Restricted Mode. The installer merges a `pre_run_command` entry into the user file:

```json
{
  "hooks": {
    "pre_run_command": [
      { "command": "~/.keylatch/hooks/block-keylatch-exfiltration.sh --harness windsurf", "show_output": false }
    ],
    "pre_read_code": [
      { "command": "~/.keylatch/hooks/block-keylatch-exfiltration.sh --harness windsurf", "show_output": false }
    ]
  }
}
```

The system and workspace locations were renamed for Devin (`/etc/devin/hooks.json`, `.devin/hooks.json`) with the legacy Windsurf names as a fallback; the user path above is unchanged and is the only one the installer writes. The command hook receives `{"agent_action_name": "pre_run_command", "tool_info": {"command_line": "...", "cwd": "..."}}` on stdin. Cascade documents blocking by exit code only: exit 2 blocks the action and shows stderr to the agent; any other code lets it proceed. The guard prints the reason on stderr and exits 2; it prints no JSON.

`pre_read_code` receives `{"agent_action_name": "pre_read_code", "tool_info": {"file_path": "..."}}`. The path may be a directory when Cascade reads recursively, so the guard denies a path that is, is inside, or contains (is an ancestor of) a protected location: the credential locations listed under "What It Blocks". Reading your whole home directory is therefore denied. Source: [Cascade hooks](https://docs.devin.ai/desktop/cascade/hooks.md).

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
- Direct reads of credential stores, by the agent's file-read tool or a shell reader (`cat`, `head`, `less`, `cp`, `grep`, ...): `~/.keylatch`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.local/share/atuin`, `~/.kube`, `~/.config/gcloud`, `~/.docker/config.json`, `~/.netrc`, `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.azure`, `~/.terraform.d/credentials.tfrc.json`. A path that is, is inside, or contains one of these is denied. Tools that read their own config as child processes (`kubectl`, `gh`, `docker`, `npm`, ...) are unaffected; only direct reads by the agent are denied.
- Direct reads of credential stores, by the agent's file-read tool or a shell reader (`cat`, `head`, `less`, `cp`, `grep`, ...): the credential locations listed under "What It Blocks", `~/.kube`, `~/.config/gcloud`, `~/.docker/config.json`, `~/.netrc`, `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.azure`, `~/.terraform.d/credentials.tfrc.json`. A path that is, is inside, or contains one of these is denied. Tools that read their own config as child processes (`kubectl`, `gh`, `docker`, `npm`, ...) are unaffected; only direct reads by the agent are denied.

## Verify

```bash
keylatch doctor
```

Status: the hook schemas and deny contracts above follow the vendors' published documentation and are exercised by fixture tests with real payload shapes. None of it has been run inside the real applications.

See also: `contrib/agent-guards/windsurf/README.md`
