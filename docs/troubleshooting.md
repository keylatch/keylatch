---
title: Troubleshooting
description: Solutions to the top 10 user issues and a KL-error-code index.
---

# Troubleshooting

Run `keylatch doctor` first — it checks backend availability, daemon health, and
common configuration problems in one command.

```bash
keylatch doctor
keylatch doctor --json   # machine-readable output
```

---

## Top 10 issues

### 1. Daemon not running

**Symptom:** `connection refused` when using the browser UI, or `keylatch run`
hangs without output.

**Fix:**
```bash
keylatch gateway up
```

By default, `keylatch run` starts the daemon automatically. Start it manually if needed.

---

### 2. Backend unavailable (KL-0100–0199)

**Symptom:** Exit code 4 (`BackendUnavailable`). Error message like
`backend: keychain unavailable`.

**Fix:**
```bash
keylatch doctor  # check which backend row fails
```

- **macOS Keychain:** unlock your Mac (Touch ID or password) and retry.
- **1Password:** run `op signin` in the same terminal session.
- **Bitwarden:** run `bw unlock` and export `BW_SESSION`.
- **File backend:** check that `~/.keylatch/` exists and is writable.

---

### 3. LLM session block (KL-0500–0599)

**Symptom:** Exit code 2 (`SecurityBlock`). Error message:
`keylatch get is not permitted in AI agent sessions`.

**Fix:** Use `keylatch run <connection> -- <command>` instead of
`keylatch get`. The `run` command never exposes raw credential values to the
calling process.

If you need to debug outside an agent session, unset the environment variable
that triggers detection:

```bash
unset CLAUDE_CODE  # or CODEX_ENV / CREDENTIALS_LLM_SESSION / CURSOR_SESSION / AIDER_SESSION / GEMINI_SESSION / OPENCODE_SESSION
```

---

### 4. Gateway port conflict

**Symptom:** `bind: address already in use` on port 7890 or 7878.

**Fix:**
```bash
# Find what is using the port
lsof -i :7890

# Override the port
export KEYLATCH_GATEWAY_ADDR=127.0.0.1:7891
keylatch gateway up
```

Or set `gateway.endpoint` in `~/.keylatch/config.json`:

```json
{
  "gateway": { "endpoint": "http://127.0.0.1:7891" }
}
```

---

### 6. Bootstrap fails (KL-0001–0099)

**Symptom:** `bootstrap: ...` error on first run.

**Fix:**
```bash
keylatch bootstrap --dry-run  # diagnose without making changes
keylatch bootstrap             # repair
```

If the issue persists, check that `~/.keylatch/` is writable and that you have
network access for provider template download.

---

### 7. No providers registered (KL-0200–0299)

**Symptom:** `no providers registered` error or empty `keylatch list` output.

**Fix:**
```bash
keylatch bootstrap  # loads embedded provider templates
keylatch registry reload  # reloads from all template sources
```

---

### 8. Audit log missing or unwritable (KL-0600–0699)

**Symptom:** `audit: write failure` error. No file at `~/.keylatch/audit.log`.

**Fix:**
```bash
# Check permissions
ls -la ~/.keylatch/audit.log

# Fix permissions
chmod 0600 ~/.keylatch/audit.log

# Or override the path
export KEYLATCH_AUDIT__PATH=/tmp/keylatch-audit.log
```

---

### 9. Wizard not completing

**Symptom:** `keylatch ui` shows the wizard loop on every open. Readiness check
reports `wizard: not completed`.

**Fix:**
Open `http://127.0.0.1:7890` in a browser and complete each wizard step:
1. Backend selection
2. Connect at least one provider
3. Agent profile setup

The wizard must be completed through the browser UI — there is no config flag to skip it.

---

### 10. Spectral lint failure (OpenAPI spec)

**Symptom:** CI `openapi-lint` job fails.

**Fix:**
```bash
npx --yes @stoplight/spectral-cli lint docs/api/openapi.yaml
```

Read the reported rule violations and fix them in `docs/api/openapi.yaml`. See
`docs/api/README.md` for the full list of rules applied.

---

## KL-error-code index

| Range | Area | Examples |
|-------|------|---------|
| KL-0001–0099 | Core / config | Bootstrap failures, config parse errors |
| KL-0100–0199 | Backend | Backend unavailable, encrypt/decrypt errors |
| KL-0200–0299 | Registry | Provider not found, schema validation failures |
| KL-0300–0399 | Runtime / runner | Mode unavailable, command not in allowlist |
| KL-0400–0499 | Gateway | Gateway not running, token expired, SSRF blocked |
| KL-0500–0599 | Security | LLM session block, access denied |
| KL-0600–0699 | Audit | Audit log write failure, chain verification error |

Error codes are stamped on structured errors returned by internal packages. Use
`--json` to see the `code` field in machine-readable output.

---

## Getting more help

```bash
keylatch help-topic troubleshooting  # inline CLI reference
keylatch doctor --json               # full diagnostic JSON
```

For bugs or feature requests: [github.com/keylatch/keylatch/issues](https://github.com/keylatch/keylatch/issues)
