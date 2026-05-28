---
title: Shell Integration
description: Bash and POSIX sh integration patterns for using Keylatch in scripts.
---

# Shell Integration

This guide shows three patterns for using Keylatch in Bash/sh scripts. All patterns assume Keylatch is installed and bootstrapped (`keylatch setup` has been run).

## Prerequisites

```bash
keylatch setup                    # first-time setup
keylatch connect <provider>       # store the credential you want to use
keylatch gateway up --detach      # required for gateway_typed (default) mode
```

---

## Pattern A — Inline variable capture with `keylatch run`

Run your script inside `keylatch run`. The gateway token is injected as `KEYLATCH_GATEWAY_TOKEN` and the gateway URL as `KEYLATCH_GATEWAY_URL`. Your script reads those — never a raw key.

```bash
#!/usr/bin/env bash
# call_api.sh — wrapped by: keylatch run --clean-env openrouter -- bash call_api.sh
set -euo pipefail

# These vars are injected by keylatch run.
# They are NOT raw credentials — they are short-lived gateway tokens.
: "${KEYLATCH_GATEWAY_URL:?ERROR: not running inside keylatch run}"
: "${KEYLATCH_GATEWAY_TOKEN:?ERROR: not running inside keylatch run}"

# Example: call an OpenRouter-compatible endpoint
response=$(curl -sf \
  -H "Authorization: Bearer ${KEYLATCH_GATEWAY_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"model":"openai/gpt-4o","messages":[{"role":"user","content":"hello"}]}' \
  "${KEYLATCH_GATEWAY_URL}/v1/chat/completions")

echo "${response}" | python3 -c "import sys,json; print(json.load(sys.stdin)['choices'][0]['message']['content'])"
```

**Run it:**

```bash
keylatch run --clean-env --runtime gateway_typed openrouter -- bash call_api.sh
```

**With error handling:**

```bash
keylatch run --clean-env openrouter -- bash call_api.sh || {
  echo "Script failed — check keylatch doctor" >&2
  exit 1
}
```

**Dry-run to preview injection (no network calls):**

```bash
keylatch run --dry-run openrouter -- bash call_api.sh
```

---

## Pattern B — `keylatch run` wrapper (preferred for subprocesses)

Use `keylatch run` as a process wrapper when your main entry-point is a shell script that spawns child processes. All child processes inherit `KEYLATCH_GATEWAY_TOKEN` and `KEYLATCH_GATEWAY_URL`.

```bash
#!/usr/bin/env bash
# pipeline.sh — runs multiple steps that all need the same credentials
set -euo pipefail

TMPDIR_WORK=$(mktemp -d)
trap 'rm -rf "${TMPDIR_WORK}"' EXIT

: "${KEYLATCH_GATEWAY_URL:?must run inside keylatch run}"
: "${KEYLATCH_GATEWAY_TOKEN:?must run inside keylatch run}"

# Step 1 — fetch models list
echo "Fetching available models..."
curl -sf \
  -H "Authorization: Bearer ${KEYLATCH_GATEWAY_TOKEN}" \
  "${KEYLATCH_GATEWAY_URL}/v1/models" \
  > "${TMPDIR_WORK}/models.json"

# Step 2 — process and output
model_count=$(python3 -c "import json,sys; data=json.load(open('${TMPDIR_WORK}/models.json')); print(len(data.get('data', [])))")
echo "Found ${model_count} model(s)."
```

**Run it:**

```bash
keylatch run --clean-env --runtime gateway_typed openrouter -- bash pipeline.sh
```

The `--clean-env` flag gives child processes a minimal environment:
`PATH`, `HOME`, `USER`, `SHELL`, `TERM`, `LANG`, plus the injected `KEYLATCH_*` vars.
Add other needed host vars with `--extra`:

```bash
keylatch run --clean-env --extra PYTHONPATH --extra MY_VAR openrouter -- bash pipeline.sh
```

---

## Pattern C — `.env` file generation for scripts that source env files

Some tools expect a `.env` file. Use this pattern to generate a temporary `.env` from gateway tokens injected by `keylatch run`.

```bash
#!/usr/bin/env bash
# gen_dotenv.sh — generate a short-lived .env and clean it up on exit
set -euo pipefail

: "${KEYLATCH_GATEWAY_URL:?must run inside keylatch run}"
: "${KEYLATCH_GATEWAY_TOKEN:?must run inside keylatch run}"

DOTENV_FILE=$(mktemp /tmp/keylatch-session-XXXXXX.env)
# chmod 600 — only current user can read it
chmod 600 "${DOTENV_FILE}"

# Remove the temp file on any exit (including errors and Ctrl-C).
trap 'rm -f "${DOTENV_FILE}"; echo "Temp .env removed."' EXIT

# Write gateway token to .env — NOT the raw credential.
# The gateway token is short-lived and scoped to this session.
cat > "${DOTENV_FILE}" <<EOF
KEYLATCH_GATEWAY_URL=${KEYLATCH_GATEWAY_URL}
KEYLATCH_GATEWAY_TOKEN=${KEYLATCH_GATEWAY_TOKEN}
EOF

echo "Generated temp .env: ${DOTENV_FILE}"

# Run your tool that reads .env
# Replace 'my-tool' with your actual command:
set -a
# shellcheck source=/dev/null
source "${DOTENV_FILE}"
set +a

echo "Running tool with gateway credentials..."
# my-tool --config my-config.json
# ...
```

**Run it:**

```bash
keylatch run --clean-env openrouter -- bash gen_dotenv.sh
```

**Important security notes:**
- The `.env` file is removed by the `trap` handler even if the script fails.
- The file contains a gateway token, not the raw API key.
- Gateway tokens expire when the session ends.
- Never commit the generated `.env` to version control.

---

## Common patterns

### Checking if running inside `keylatch run`

```bash
if [[ -z "${KEYLATCH_GATEWAY_TOKEN:-}" ]]; then
  echo "ERROR: This script must be run inside keylatch run." >&2
  echo "Usage: keylatch run --clean-env <provider> -- bash $0" >&2
  exit 1
fi
```

### Canonical one-liner: call an action directly

`keylatch call` dispatches a provider action and prints the HTTP response body. Use it for one-off API calls:

```bash
# List available models for the openrouter connection
keylatch call openrouter list-models

# JSON output (status_code + body)
keylatch call openrouter list-models --json

# See what actions are available for a provider
keylatch call openrouter --list
```

Note: `keylatch call` dispatches named actions from the provider's action catalog, not arbitrary endpoints. It is useful for provider-specific operations, not general HTTP calls.

---

## Related

- [docs/integration/README.md](README.md) — integration guide index
- [docs/scripting.md](../scripting.md) — gateway scripting patterns in Python, Bash, Node
- [docs/cli/environment.md](../cli/environment.md) — all injected and blocked env vars
- [docs/cli-reference.md](../cli-reference.md) — full CLI reference
