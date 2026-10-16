# Claude Code Integration

Keylatch keeps your API keys out of agent memory and out of your shell history.

## Quick start

```bash
keylatch install-guard claude-code
```

Keylatch now blocks credential exfiltration from Claude Code at the agent framework level, on top of the built-in LLM-session guard.

## What the exfiltration guard does

The guard is `keylatch guard hook --harness claude-code`, run before every Claude Code tool call as a `PreToolUse` hook. It reads the tool call from stdin and, when it denies it, exits 2 with the reason on stderr and the `permissionDecision: "deny"` JSON on stdout.

For the `Bash` tool it parses the command into a syntax tree. It judges commands, not substrings: `echo 'keylatch run -- env'` and a heredoc that merely contains `printenv` are allowed, while `bash -c "$(…)"`, `eval`, `$()`, backticks, process substitution, here-strings, `sudo`, `env`, `nice`, `nohup`, `time`, `xargs`, `command`, `exec`, `find -exec`, `mise exec --` and `direnv exec` are unwrapped and the command inside is judged. A command it cannot parse is denied.

| Denied | Examples |
|--------|----------|
| Reads or copies of Keylatch state | anything under the config, vault, audit, policy and session directories, `~/.keylatch`, `~/.config/keylatch` |
| Credential stores | `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gcloud`, `~/.docker/config.json`, `~/.netrc`, `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.azure`, `~/.terraform.d/credentials.tfrc.json` |
| Shell history and secret-tool config | `~/.*_history`, `~/.local/share/atuin`, `~/.config/sops/age`, `~/.config/rclone`, `~/.mc/config.json` |
| `.env` files | `cat .env`, `source .env` (`.env.example`, `.env.sample` and `.env.template` are allowed) |
| Secret-manager CLIs | `op read/inject/run/item get/document get`, `bw get/export/list/serve/unlock`, `bws`, `vault kv get/read`, `aws secretsmanager get-secret-value`, `aws ssm get-parameter --with-decryption`, `gcloud secrets versions access`, `gcloud auth print-access-token`, `az keyvault secret show`, `doppler secrets`, `infisical secrets`, `secret-tool lookup`, `systemd-creds decrypt`, `security find-generic-password`, `gh auth token`, `git credential fill`, `docker-credential-*`, `sops -d`, `age -d`, `keylatch get/export/backup` (`keylatch get --masked` is allowed) |
| Environment and history dumps | bare `env` or `printenv`, `set`, `declare -p/-x`, `export -p`, `compgen -v/-e`, `history`, `fc`, `tmux show-environment`, any read of `/proc/*/environ`, `awk` with `ENVIRON`, `os.environ`, `process.env`, `%ENV` or `ENV[` in `python`, `node`, `deno`, `bun`, `perl`, `ruby`, `jq -n env`, `direnv export/dump`, `mise env/set/hook-env/config get`, `atuin search/history/stats` |
| Changes to the guard | writes to Claude Code settings and hook files, and to the Keylatch binary |

`env -C /abs/dir cmd`, `env NAME=value cmd` and `/usr/bin/env python3 file.py` are allowed after the command they run is judged; `env` with no command, a relative or computed `-C` directory, and any other `env` option are denied.

For the `Read`, `Grep`, `Glob`, `Edit`, `Write`, `MultiEdit`, `NotebookEdit` and `NotebookRead` tools it checks `file_path`, `path`, `notebook_path`, `glob` and the `Glob` pattern against the same locations. Paths are normalised (`~`, `$HOME`, `//`, `/./`, `..`) and symlinks are resolved, so a link into `~/.ssh` is caught.

Commands that only use a credential file without printing it stay allowed when they are the whole command: `ls`, `stat`, `ssh -i`, `ssh-add`, `scp -i`, `git clone`, `kubectl --kubeconfig`, `helm --kubeconfig` and `gh --config`.

This is **Layer 2** defence. Keylatch's own LLM-session guard (**Layer 1**) still applies even without this hook. The guard runs as the agent's user: it stops the common ways an agent reads secrets, not an agent that edits its own settings by other means. The boundary is the broker daemon (see [the threat model](../security/threat-model.md)).

## Installation

```bash
keylatch install-guard claude-code
```

installs the hook into `~/.claude/settings.json` and, when `CLAUDE_CONFIG_DIR` is set, into `$CLAUDE_CONFIG_DIR/settings.json`. The installer merges: every other key and hook in the file is kept, and the previous file is saved as `settings.json.keylatch.bak`. The hook entry is

```json
{
  "matcher": "*",
  "hooks": [
    {
      "type": "command",
      "command": "\"/absolute/path/to/keylatch\" guard hook --harness claude-code",
      "timeout": 10
    }
  ]
}
```

and is recognised by its `guard hook --harness claude-code` ending, so running the installer again changes nothing.

| Flag | Effect |
|------|--------|
| `--config-dir <dir>` | also install into this Claude Code configuration directory; repeatable |
| `--upgrade` | rewrite an installed entry in place: the binary path, the `*` matcher and the timeout |
| `--dry-run` | print a unified diff and write nothing |
| `--project` | install into `.claude/settings.json` in the current directory instead |

An entry written by an earlier version (a script path under `~/.keylatch/hooks`) is replaced where it stood. `keylatch install-guard claude-code --uninstall` removes the guard from every settings file.

### Verify installation

```bash
keylatch doctor
```

`guard.installed`, `guard.current` and `guard.matcher` check every Claude Code configuration directory: the hook is present, it runs an existing `keylatch` binary rather than the old shell script, and its matcher covers every tool.

## How Keylatch protects credentials during agent sessions

When Claude Code runs inside a Keylatch-managed session:

1. **No raw keys in context**: Claude Code never sees the credential value. `keylatch run` injects the key into the subprocess environment directly; it never appears in model context, MCP outputs, or agent logs.

2. **Agent guard blocks exfiltration attempts**: If Claude Code attempts to call `keylatch get`, read the Keychain directly, or dump `.env` files, the `PreToolUse` hook blocks the tool call before it executes.

3. **Every access is logged**: The audit log records every secret access attempt. Run `keylatch audit tail` to watch live.

## Recommended setup for Claude Code users

```bash
# 1. Install Keylatch and initialize
keylatch bootstrap

# 2. Store your API credentials
keylatch connect openrouter api_key YOUR_KEY

# 3. Install the exfiltration guard
keylatch install-guard claude-code

# 4. Use credentials in Claude Code sessions
keylatch run openrouter -- node my-script.js

# 5. Watch the audit log
keylatch audit tail
```

## Related

- `keylatch security` — print the five security invariants
- `keylatch audit tail` — live-follow the audit log
- `keylatch doctor` — verify your full setup
- [`docs/security/threat-model.md`](../security/threat-model.md) — full threat model
