# Keylatch Agent Guard — `block-keylatch-exfiltration.sh`

## What this does

This is a **Layer 2 defence** for Claude Code (and compatible agents that support `preToolUse` hooks). It intercepts `Bash` and `Read` tool calls before they execute and blocks patterns that could exfiltrate credentials or bypass the keylatch CLI's internal guard (Layer 1).

Layer 1 (CLI-internal `GuardLLMSession`) still applies even if this hook is not installed. This hook provides an additional interception point at the tool-call level, before any subprocess is created.

Hook version is tracked via the comment `# keylatch-hook-version: N` at the top of the script, which `keylatch doctor` can verify.

## Block patterns

| Pattern | Tool | Reason |
|---------|------|--------|
| `keylatch get` (without `--masked`) | Bash | Direct value retrieval blocked in LLM sessions |
| `security find-generic-password` | Bash | macOS keychain read blocked |
| `security find-internet-password` | Bash | macOS keychain read blocked |
| `op read` / `op item get` | Bash | 1Password CLI blocked |
| `bw get` / `bw list` | Bash | Bitwarden CLI blocked |
| `~/.keylatch/` path | Read | Direct vault file read blocked |
| `keylatch run ... -- env` | Bash | Environment dump via run blocked |
| `cat ... keylatch` / `cat ... .env` | Bash | Direct file read of env/vault files blocked |
| any command naming `~`, `$HOME`, `${HOME}` or the absolute home followed by a protected path | Bash | `cat`, `tar`, `dd`, `diff`, redirections, `python3 -c 'open(...)'` and every other command except `ls`, `kubectl`, `gh`, `docker` and `stat` |
| a protected path (or a glob or directory that reaches one) | Read, Grep, Glob, `read_many_files`, `search_file_content`, `view` | File and search tools are checked on their `path`, `paths`, `file_path` and path-like `pattern` arguments |
| `mise set` with only flags | Bash | Prints the resolved environment |

Protected paths are `~/.keylatch`, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.local/share/atuin`, `~/.kube`, `~/.config/gcloud`, `~/.docker/config.json`, `~/.netrc`, `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/.azure` and `~/.terraform.d/credentials.tfrc.json`.

Before matching, the command text is normalised: quotes and backslashes are removed, repeated slashes, `/./` and `seg/..` are folded. Tool paths are resolved without GNU `realpath -m` (symlinks and `..` through `cd -P`), and on macOS and Windows the comparison is case-insensitive. Without `jq` the payload is parsed with `sed`, `grep` and `awk`, and the raw JSON is scanned for protected paths, so that mode may over-block but does not miss a protected path. Any unexpected failure inside the guard (an unset `HOME`, a missing tool) is a deny.

## Allowed patterns

- `keylatch get --masked` — returns masked values only
- `keylatch run <conn> -- <safe-cmd>` — runs whitelisted commands
- `keylatch list`, `keylatch describe`, `keylatch validate` — safe metadata commands

## Installation

### Global (all projects)

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "\"/absolute/path/to/block-keylatch-exfiltration.sh\""
          }
        ]
      }
    ]
  }
}
```

Event names are case-sensitive (`PreToolUse`, not `preToolUse`). Omitting `matcher` runs the hook for every tool, which is what this guard wants — the script itself filters on `Bash` and `Read`.

### Per-project

Add to `.claude/settings.json` in your project root (same structure as above).

## Known gaps

The guard reads the tool-call text; it does not run or expand anything. These are accepted:

- Paths computed at run time: variables other than `HOME`, command substitution, string concatenation, and globs that expand to a protected name (`~/.ss?/id_rsa` in a shell command).
- Relative paths, except after a `cd` to the home directory in the same command.
- The safe commands (`ls`, `kubectl`, `gh`, `docker`, `stat`) may name a protected path, so `docker run -v ~/.ssh:/k ...` is allowed.
- Interpreters that build the path from the environment (`python3 -c 'open(os.environ["HOME"] + "/.ssh/id_rsa")'`).
- Environment dumps through `export -p`, `declare -x`, `set` and `/proc/self/environ`.

## Verifying the hook is active

Run `keylatch doctor` — it checks for the hook version comment and validates the hook file is executable.

## Hook version

The comment `# keylatch-hook-version: 6` at the top of the script is read by `keylatch doctor` to verify you have a compatible version. If a new hook version is released with additional block patterns, `keylatch doctor` will warn you to update.

## Note

This hook is **Layer 2**. The CLI itself blocks LLM sessions via `GuardLLMSession` (Layer 1). Both layers work independently — you benefit from Layer 1 even without installing this hook, and from Layer 2 even if the CLI is not installed (e.g., when blocking raw `security` commands).
