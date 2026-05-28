# Keylatch Integration — Windsurf

## Setup

Windsurf does not expose a hook API for tool interception. Use the `CREDENTIALS_LLM_SESSION` environment variable to trigger Keylatch's LLM-session guard (Layer 1) whenever Windsurf's integrated terminal is active.

Add the following to your shell startup file — once set, every Windsurf terminal session will block direct credential access via `keylatch get`.

**zsh / bash** — add to `~/.zshrc` or `~/.bashrc`:

```bash
echo 'export CREDENTIALS_LLM_SESSION=windsurf' >> ~/.zshrc
```

**fish** — set as a universal variable (persists across sessions):

```fish
set -Ux CREDENTIALS_LLM_SESSION windsurf
```

**PowerShell** — set as a user-level environment variable:

```powershell
[Environment]::SetEnvironmentVariable('CREDENTIALS_LLM_SESSION','windsurf','User')
```

After setting the variable, **restart your terminal or reload your shell rc** (e.g. `source ~/.zshrc`).

### What this does

When `CREDENTIALS_LLM_SESSION` is set to any non-empty value, Keylatch treats the current terminal session as an active LLM session and applies the session guard:

- `keylatch get` — blocked, exit code 2 (SecurityBlock)
- `keylatch run` — allowed for all v1.0.0 runtime modes
- `keylatch ui` — scope locked to `status-only` (read-only)
- `keylatch gateway token create` — `--max-uses=0` tokens are rejected

Setting it to `windsurf` (rather than `1`) makes the guard reason traceable in audit logs and diagnostics.

See also: [docs/integrations/antigravity.md](antigravity.md) for the equivalent setup for Antigravity.

---

## Install command

```bash
keylatch install-guard windsurf
```

This prints the shell-rc snippets above and exits cleanly. No files are written — configuration is manual.

## Gateway mode (optional, strongest protection)

For the strongest protection, run Keylatch in gateway mode. Credentials never leave the gateway process:

```bash
keylatch proxy start --port 8080
# Point Windsurf's network proxy setting to http://localhost:8080
```

See also: `contrib/agent-guards/windsurf/README.md`
