# Keylatch Integration — Antigravity

Blocks credential-exfiltration patterns in Antigravity agent sessions through a `PreToolUse` hook.

## Hook Mechanism

Antigravity reads `hooks.json` from `.agents/hooks.json` in the workspace and `~/.gemini/config/hooks.json` globally (the CLI also accepts hooks in `~/.gemini/antigravity-cli/settings.json`). The installer adds a named hook to the global file:

```json
{
  "keylatch-guard": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "run_command|view_file",
        "hooks": [
          { "type": "command", "command": "~/.keylatch/hooks/block-keylatch-exfiltration.sh --harness antigravity", "timeout": 10 }
        ]
      }
    ]
  }
}
```

The hook receives `{"toolCall": {"name": "run_command", "args": {"CommandLine": "..."}}}` for shell commands and `{"toolCall": {"name": "view_file", "args": {"AbsolutePath": "..."}}}` for file reads on stdin. Antigravity documents decisions as JSON on stdout only and documents no exit codes, so the guard denies with **exit 0** and `{"decision":"deny","reason":"..."}`, and prints `{"decision":"allow"}` otherwise (an empty response is reportedly treated as a deny). Third-party reports say any crash or non-zero exit also blocks the tool (fail-closed, reason lost); that is not documented. File reads are denied for paths that are, are inside, or contain the credential locations listed under "What It Blocks".

Reports differ on whether the IDE (as opposed to the CLI) runs `PreToolUse` hooks. Source: [Antigravity hooks](https://antigravity.google/docs/hooks/).

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
- Direct reads of credential stores, by the agent's file-read tool or a shell reader (`cat`, `head`, `less`, `cp`, `grep`, ...): `~/.keylatch`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.local/share/atuin`, `~/.kube`, `~/.config/gcloud`, `~/.docker/config.json`, `~/.netrc`, `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.azure`, `~/.terraform.d/credentials.tfrc.json`. A path that is, is inside, or contains one of these is denied. Tools that read their own config as child processes (`kubectl`, `gh`, `docker`, `npm`, ...) are unaffected; only direct reads by the agent are denied.
- Direct reads of credential stores, by the agent's file-read tool or a shell reader (`cat`, `head`, `less`, `cp`, `grep`, ...): the credential locations listed under "What It Blocks", `~/.kube`, `~/.config/gcloud`, `~/.docker/config.json`, `~/.netrc`, `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.azure`, `~/.terraform.d/credentials.tfrc.json`. A path that is, is inside, or contains one of these is denied. Tools that read their own config as child processes (`kubectl`, `gh`, `docker`, `npm`, ...) are unaffected; only direct reads by the agent are denied.

## Verify

```bash
keylatch doctor
```

Status: the hook schemas and deny contracts above follow the vendors' published documentation and are exercised by fixture tests with real payload shapes. None of it has been run inside the real applications.

See also: `contrib/agent-guards/antigravity/README.md`
