#!/usr/bin/env python3
"""
fetch_data.py — Keylatch Python integration reference example.

Run with:
    keylatch run --clean-env --runtime gateway_typed openrouter -- python3 fetch_data.py

This script demonstrates reading KEYLATCH_GATEWAY_URL and KEYLATCH_GATEWAY_TOKEN
from the environment (injected by keylatch run) and calling an OpenRouter-compatible
API endpoint.

No raw credentials ever appear in this script. The gateway token is short-lived
and scoped to this keylatch session.
"""
import json
import os
import sys
import urllib.error
import urllib.request


def get_gateway_vars() -> tuple[str, str]:
    """Read and validate Keylatch gateway env vars."""
    url   = os.environ.get("KEYLATCH_GATEWAY_URL", "")
    token = os.environ.get("KEYLATCH_GATEWAY_TOKEN", "")

    if not url or not token:
        print(
            "ERROR: KEYLATCH_GATEWAY_URL and KEYLATCH_GATEWAY_TOKEN are not set.\n"
            "\n"
            "This script must be run inside keylatch run:\n"
            "\n"
            "  keylatch run --clean-env openrouter -- python3 fetch_data.py\n"
            "\n"
            "If you have not connected a provider yet:\n"
            "  keylatch setup\n"
            "  keylatch connect openrouter",
            file=sys.stderr,
        )
        sys.exit(1)

    return url, token


def fetch_models(gateway_url: str, gateway_token: str) -> list[dict]:
    """Fetch the model list from the gateway."""
    req = urllib.request.Request(
        f"{gateway_url}/v1/models",
        headers={
            "Authorization": f"Bearer {gateway_token}",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
            return data.get("data", [])
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        print(f"HTTP {exc.code} from gateway: {body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as exc:
        print(
            f"Cannot reach gateway at {gateway_url}: {exc.reason}\n"
            "Is the gateway running? Try: keylatch gateway up --detach",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    gateway_url, gateway_token = get_gateway_vars()

    print(f"Fetching models from {gateway_url} ...")
    models = fetch_models(gateway_url, gateway_token)

    if not models:
        print("No models returned — check your provider configuration.")
        return

    print(f"\nAvailable models ({len(models)} total):\n")
    for m in models[:10]:  # show first 10
        print(f"  {m.get('id', 'unknown')}")
    if len(models) > 10:
        print(f"  ... and {len(models) - 10} more")


if __name__ == "__main__":
    main()
