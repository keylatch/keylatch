# Claude Code Integration

Keylatch keeps your API keys out of agent memory and out of your shell history.

## Quick start

```bash
keylatch install-guard claude-code
```

That's it. Keylatch will now block credential exfiltration attempts from Claude Code at the agent framework level, on top of the built-in LLM-session guard.

## What the exfiltration guard does

The guard is a shell script (`block-keylatch-exfiltration.sh`) that runs before every Claude Code tool call as a `PreToolUse` hook. It exits non-zero — causing the tool call to be blocked — when it detects any of the following patterns:

| Pattern | What it blocks |
|---------|---------------|
| `keylatch get` (without `--masked`) | Direct credential retrieval in agent sessions |
| `security find-generic-password` | macOS Keychain direct access |
| `security find-internet-password` | macOS Keychain internet credentials |
| `op read` / `op item get` | 1Password CLI raw reads |
| `bw get` / `bw list` | Bitwarden CLI raw reads |
| `keylatch run -- env` | Environment dump via keylatch run |
| `cat .env` / `cat ...keylatch...` | Direct reads of credential files |
| `Read` tool on `~/.keylatch/` | MCP Read tool accessing keylatch config |

This is **Layer 2** defence. Keylatch's own LLM-session guard (**Layer 1**) still applies even without this hook.

## Installation

### One-command (recommended)

```bash
keylatch install-guard claude-code
```

Installs the hook into `~/.claude/settings.json` (global — applies to all Claude Code sessions).

To install per-project instead:

```bash
cd /path/to/your/project
keylatch install-guard claude-code --project
```

Installs into `.claude/settings.json` in the current directory.

### Verify installation

```bash
keylatch doctor
```

Look for `[ok  ] hook.preToolUse: keylatch preToolUse hook detected`.

### Manual installation (fallback)

1. Find the script:

   ```bash
   # The script is embedded in the keylatch binary and written to:
   ~/.keylatch/hooks/block-keylatch-exfiltration.sh

   # Or copy from the source:
   cp contrib/agent-guards/claude-code/block-keylatch-exfiltration.sh \
     ~/.keylatch/hooks/block-keylatch-exfiltration.sh
   chmod +x ~/.keylatch/hooks/block-keylatch-exfiltration.sh
   ```

2. Add the hook to `~/.claude/settings.json`:

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "hooks": [
             {
               "type": "command",
               "command": "$HOME/.keylatch/hooks/block-keylatch-exfiltration.sh"
             }
           ]
         }
       ]
     }
   }
   ```

   `$HOME` expands to your actual home directory path.

## How Keylatch protects credentials during agent sessions

When Claude Code runs inside a Keylatch-managed session:

1. **No raw keys in context**: Claude Code never sees the credential value. `keylatch run` injects the key into the subprocess environment directly; it never appears in model context, MCP outputs, or agent logs.

2. **Agent guard blocks exfiltration attempts**: If Claude Code attempts to call `keylatch get`, read Keychain directly, or dump `.env` files, the `PreToolUse` hook blocks the tool call before it executes.

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
