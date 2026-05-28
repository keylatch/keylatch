---
title: Python Integration
description: Python integration patterns for using Keylatch in scripts and automation.
---

# Python Integration

This guide shows three patterns for using Keylatch in Python scripts. All patterns assume Keylatch is installed and bootstrapped.

## Prerequisites

```bash
keylatch setup                # first-time setup
keylatch connect <provider>   # store the credential you want to use
keylatch gateway up --detach  # required for gateway_typed (default) mode
```

---

## Pattern A — `subprocess.run` to invoke `keylatch run`

Wrap your Python script with `keylatch run` so the gateway token is injected as environment variables. This is the recommended pattern.

```python
#!/usr/bin/env python3
"""
call_api.py — run with: keylatch run --clean-env openrouter -- python3 call_api.py
"""
import os
import json
import urllib.request
import urllib.error
import sys

# Gateway vars are injected by keylatch run.
# They are NOT raw credentials — they are short-lived gateway tokens.
gateway_url   = os.environ.get("KEYLATCH_GATEWAY_URL")
gateway_token = os.environ.get("KEYLATCH_GATEWAY_TOKEN")

if not gateway_url or not gateway_token:
    print(
        "ERROR: KEYLATCH_GATEWAY_URL and KEYLATCH_GATEWAY_TOKEN are not set.\n"
        "Run this script inside keylatch run:\n"
        "  keylatch run --clean-env openrouter -- python3 call_api.py",
        file=sys.stderr,
    )
    sys.exit(1)

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

try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
        print(data["choices"][0]["message"]["content"])
except urllib.error.HTTPError as exc:
    print(f"HTTP {exc.code}: {exc.read().decode()}", file=sys.stderr)
    sys.exit(1)
except urllib.error.URLError as exc:
    print(f"Network error: {exc.reason}", file=sys.stderr)
    sys.exit(1)
```

**Run it:**

```bash
keylatch run --clean-env --runtime gateway_typed openrouter -- python3 call_api.py
```

**With requests library (if installed):**

```python
import os, sys, requests

gateway_url   = os.environ.get("KEYLATCH_GATEWAY_URL")
gateway_token = os.environ.get("KEYLATCH_GATEWAY_TOKEN")

if not gateway_url or not gateway_token:
    sys.exit("ERROR: not running inside keylatch run")

resp = requests.post(
    f"{gateway_url}/v1/chat/completions",
    headers={"Authorization": f"Bearer {gateway_token}"},
    json={"model": "openai/gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
    timeout=30,
)
resp.raise_for_status()
print(resp.json()["choices"][0]["message"]["content"])
```

---

## Pattern B — Context manager that calls `keylatch run` and sets env temporarily

For library code or test fixtures that need to set up and tear down credentials, use a context manager that wraps a subprocess invocation of `keylatch run`.

```python
#!/usr/bin/env python3
"""
keylatch_context.py — Context manager for temporary Keylatch gateway credentials.
"""
import os
import subprocess
import tempfile
import json
import sys
from contextlib import contextmanager
from typing import Generator


@contextmanager
def keylatch_gateway(
    provider: str,
    *,
    runtime: str = "gateway_typed",
    extra_env: dict[str, str] | None = None,
) -> Generator[dict[str, str], None, None]:
    """
    Context manager that resolves Keylatch gateway credentials for ``provider``
    and temporarily sets them in os.environ.

    Usage::

        with keylatch_gateway("openrouter") as creds:
            # os.environ["KEYLATCH_GATEWAY_TOKEN"] and KEYLATCH_GATEWAY_URL are set
            response = requests.post(
                f"{creds['KEYLATCH_GATEWAY_URL']}/v1/chat/completions",
                headers={"Authorization": f"Bearer {creds['KEYLATCH_GATEWAY_TOKEN']}"},
                json=...,
            )

    The environment variables are restored to their previous values on exit,
    even if an exception is raised.
    """
    # Use a sentinel script that prints injected env vars as JSON.
    sentinel = (
        "import os, json; "
        "print(json.dumps({"
        "'KEYLATCH_GATEWAY_URL': os.environ.get('KEYLATCH_GATEWAY_URL',''),"
        "'KEYLATCH_GATEWAY_TOKEN': os.environ.get('KEYLATCH_GATEWAY_TOKEN','')"
        "}))"
    )

    cmd = [
        "keylatch", "run",
        "--clean-env",
        "--runtime", runtime,
        provider,
        "--",
        sys.executable, "-c", sentinel,
    ]
    if extra_env:
        for k in extra_env:
            cmd.insert(cmd.index("--") - 1, "--extra")
            cmd.insert(cmd.index("--") - 1, k)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"keylatch run failed for provider '{provider}': {exc.stderr.strip()}"
        ) from exc
    except FileNotFoundError:
        raise RuntimeError(
            "keylatch binary not found — install with: brew install keylatch/tap/keylatch"
        )

    creds: dict[str, str] = json.loads(result.stdout.strip())

    # Save old values (may be None if not set).
    old_vals = {k: os.environ.get(k) for k in creds}

    # Set temporarily.
    os.environ.update(creds)
    try:
        yield creds
    finally:
        # Restore — delete if not previously set, else restore old value.
        for k, old_v in old_vals.items():
            if old_v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old_v


# --- Example usage ---
if __name__ == "__main__":
    with keylatch_gateway("openrouter") as creds:
        import urllib.request
        req = urllib.request.Request(
            f"{creds['KEYLATCH_GATEWAY_URL']}/v1/models",
            headers={"Authorization": f"Bearer {creds['KEYLATCH_GATEWAY_TOKEN']}"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        print(f"Models available: {len(data.get('data', []))}")
```

---

## Pattern C — Python SDK (planned for v1.1.0)

A native Python SDK is planned for Keylatch v1.1.0. It will provide:

```python
# Future API — not available yet
from keylatch import Client

client = Client(provider="openrouter")
with client.session() as session:
    response = session.post("/v1/chat/completions", json={...})
```

Until the SDK ships, use Pattern A (run inside `keylatch run`) or Pattern B (context manager) for all Python integration work.

**SDK tracking issue**: [keylatch/keylatch#sdk-python](https://github.com/keylatch/keylatch/issues)

---

## Reference implementation

See [docs/integration/examples/python/fetch_data.py](examples/python/fetch_data.py) for a complete, runnable example.

---

## Related

- [docs/integration/README.md](README.md) — integration guide index
- [docs/scripting.md](../scripting.md) — gateway scripting patterns
- [docs/cli/environment.md](../cli/environment.md) — all injected env vars
