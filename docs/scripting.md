---
title: Scripting with Keylatch
description: How to call provider APIs from Python, Bash, and Node.js scripts using keylatch run as a secure envelope.
---

# Scripting with Keylatch

`keylatch run` is the recommended envelope for all scripts that need to call provider APIs. It injects a short-lived gateway token into the child process rather than a raw API key, so your credentials never appear in the script source, the shell history, process listings, or agent context.

## Why `keylatch run`

When you run a script inside `keylatch run`:

- The raw API key stays in the encrypted backend. The child process never receives it.
- In `gateway_typed` mode (the default), only `KEYLATCH_GATEWAY_TOKEN` and `KEYLATCH_GATEWAY_URL` are injected into the child environment.
- The gateway token expires with the session. If the token leaks, it cannot be replayed after expiry.
- `--clean-env` strips all host environment variables except `PATH`, `HOME`, `USER`, `SHELL`, `TERM`, `LANG`, and the injected credential vars — preventing accidental env propagation into subprocesses.

For a full list of which variables are injected and which are blocked, see [CLI Environment Variables](./cli/environment.md).

## Prerequisites

```bash
# 1. First-time setup (interactive wizard)
keylatch setup

# 2. Store the provider credential
keylatch connect <provider>

# 3. Start the local gateway
keylatch gateway up --detach

# 4. (Optional) Verify the gateway is running
keylatch gateway status
```

The gateway must be running for `gateway_typed` mode. If you prefer a mode that does not require a running gateway, use `--runtime direct_brokered`. See [Configuration](./configuration.md) for gateway settings.

---

## Python

### Script: `call_provider.py`

```python
import os
import urllib.request
import json

# keylatch run injects these two variables.
# Do NOT hard-code these values — they change every session.
gateway_url   = os.environ["KEYLATCH_GATEWAY_URL"]
gateway_token = os.environ["KEYLATCH_GATEWAY_TOKEN"]

payload = json.dumps({
    "model": "openai/gpt-4o",
    "messages": [{"role": "user", "content": "Hello from Keylatch"}],
}).encode()

req = urllib.request.Request(
    f"{gateway_url}/v1/chat/completions",
    data=payload,
    headers={
        "Authorization": f"Bearer {gateway_token}",
        "Content-Type": "application/json",
    },
    method="POST",
)

with urllib.request.urlopen(req) as resp:
    print(json.load(resp)["choices"][0]["message"]["content"])
```

### Run it

```bash
# 1. First-time setup (interactive wizard)
keylatch setup

# 2. Store the provider credential
keylatch connect openrouter
keylatch run --clean-env --runtime gateway_typed openrouter -- python3 call_provider.py
```

The `--clean-env` flag gives `call_provider.py` a minimal environment. If your script needs additional host variables (for example, `PYTHONPATH`), pass them with `--extra`:

```bash
keylatch run --clean-env --extra PYTHONPATH --runtime gateway_typed openrouter -- python3 call_provider.py
```

---

## Bash

### Script: `call_provider.sh`

```bash
#!/usr/bin/env bash
# KEYLATCH_GATEWAY_URL and KEYLATCH_GATEWAY_TOKEN are injected by keylatch run.
# Do not hard-code these values.

curl -sf \
  -H "Authorization: Bearer ${KEYLATCH_GATEWAY_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @- \
  "${KEYLATCH_GATEWAY_URL}/v1/chat/completions" <<'EOF'
{
  "model": "openai/gpt-4o",
  "messages": [{"role": "user", "content": "Hello from Keylatch"}]
}
EOF
```

### Run it

```bash
chmod +x call_provider.sh
keylatch run --clean-env --runtime gateway_typed openrouter -- bash call_provider.sh
```

Use a heredoc (`<<'EOF' ... EOF`) so the JSON payload is not subject to shell variable expansion.

---

## Node.js

### Script: `call_provider.mjs`

```js
import https from "node:https";
import http from "node:http";

// keylatch run injects these two variables every session.
// Do NOT hard-code them or read them from a .env file.
const gatewayUrl   = process.env.KEYLATCH_GATEWAY_URL;
const gatewayToken = process.env.KEYLATCH_GATEWAY_TOKEN;

if (!gatewayUrl || !gatewayToken) {
  console.error("Not running inside keylatch run — gateway vars not set.");
  process.exit(1);
}

const url   = new URL("/v1/chat/completions", gatewayUrl);
const body  = JSON.stringify({
  model: "openai/gpt-4o",
  messages: [{ role: "user", content: "Hello from Keylatch" }],
});

const transport = url.protocol === "https:" ? https : http;

const req = transport.request(url, {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${gatewayToken}`,
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body),
  },
}, (res) => {
  let data = "";
  res.on("data", (chunk) => { data += chunk; });
  res.on("end", () => {
    const parsed = JSON.parse(data);
    console.log(parsed.choices[0].message.content);
  });
});

req.on("error", (err) => { console.error(err); process.exit(1); });
req.write(body);
req.end();
```

### Run it

```bash
# 1. First-time setup (interactive wizard)
keylatch setup

# 2. Store the provider credential
keylatch connect openrouter
keylatch run --clean-env --runtime gateway_typed openrouter -- node call_provider.mjs
```

For CommonJS projects, require `node:https` and `node:http` instead of importing.

---

## Using `subprocess` (calling a provider from Python automation)

If your automation script needs to spawn a child that calls a provider API, pass the gateway variables through explicitly rather than relying on env inheritance:

```python
import subprocess
import os

gateway_url   = os.environ["KEYLATCH_GATEWAY_URL"]
gateway_token = os.environ["KEYLATCH_GATEWAY_TOKEN"]

result = subprocess.run(
    ["curl", "-sf",
     "-H", f"Authorization: Bearer {gateway_token}",
     "-H", "Content-Type: application/json",
     "-d", '{"model":"openai/gpt-4o","messages":[{"role":"user","content":"hi"}]}',
     f"{gateway_url}/v1/chat/completions"],
    capture_output=True,
    text=True,
    check=True,
)
print(result.stdout)
```

The outer `keylatch run` already injected `KEYLATCH_GATEWAY_TOKEN` and `KEYLATCH_GATEWAY_URL`, so this pattern works without any extra configuration.

---

## Dry-run: preview injection before running

Use `--dry-run` to confirm which variables would be injected without executing the script:

```bash
keylatch run --dry-run openrouter -- python3 call_provider.py
# Shows: would inject KEYLATCH_GATEWAY_TOKEN, KEYLATCH_GATEWAY_URL

keylatch run --dry-run --json openrouter -- python3 call_provider.py
# JSON output: {"injected": ["KEYLATCH_GATEWAY_TOKEN","KEYLATCH_GATEWAY_URL"], ...}
```

---

## CI environments

In CI, use a service account or a one-time token rather than an interactive session. Store the encrypted vault file in a CI secret, then bootstrap:

```bash
# CI step — configure backend and run
export KEYLATCH_BACKEND=file
export KEYLATCH_VAULT_PATH=/path/to/ci-vault.age

keylatch gateway up --detach
keylatch run --clean-env --runtime gateway_typed openrouter -- python3 call_provider.py  # gateway_typed is the default; stated explicitly for clarity
keylatch gateway down
```

---

## Related

- [CLI Environment Variables](./cli/environment.md) — full list of injected and blocked variables
- [Configuration](./configuration.md) — gateway endpoint and backend settings
