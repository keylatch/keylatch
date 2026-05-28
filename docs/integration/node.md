---
title: Node.js / TypeScript Integration
description: Node.js and TypeScript integration patterns for using Keylatch in scripts and automation.
---

# Node.js / TypeScript Integration

This guide shows integration patterns for Node.js and TypeScript. All patterns assume Keylatch is installed and bootstrapped.

## Prerequisites

```bash
keylatch setup                # first-time setup
keylatch connect <provider>   # store the credential
keylatch gateway up --detach  # required for gateway_typed (default) mode
```

---

## Pattern A — `execSync` (synchronous, script-friendly)

For CLI scripts or one-off jobs, use `child_process.execSync` to call `keylatch run`. All child processes inherit gateway vars from the calling `keylatch run` process.

The simpler approach is to run your entire Node script inside `keylatch run`:

```javascript
// call_api.js — run with: keylatch run --clean-env openrouter -- node call_api.js
'use strict';
const https = require('node:https');
const http  = require('node:http');

const gatewayUrl   = process.env.KEYLATCH_GATEWAY_URL;
const gatewayToken = process.env.KEYLATCH_GATEWAY_TOKEN;

if (!gatewayUrl || !gatewayToken) {
  console.error(
    'ERROR: KEYLATCH_GATEWAY_URL and KEYLATCH_GATEWAY_TOKEN are not set.\n' +
    'Run this script inside keylatch run:\n' +
    '  keylatch run --clean-env openrouter -- node call_api.js'
  );
  process.exit(1);
}

const body = JSON.stringify({
  model: 'openai/gpt-4o',
  messages: [{ role: 'user', content: 'Hello from Keylatch' }],
});

const url       = new URL('/v1/chat/completions', gatewayUrl);
const transport = url.protocol === 'https:' ? https : http;

const req = transport.request(
  url,
  {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${gatewayToken}`,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
  },
  (res) => {
    let data = '';
    res.on('data', (chunk) => { data += chunk; });
    res.on('end', () => {
      const parsed = JSON.parse(data);
      console.log(parsed.choices[0].message.content);
    });
  }
);

req.on('error', (err) => {
  console.error('Request failed:', err.message);
  process.exit(1);
});

req.write(body);
req.end();
```

**Run it:**

```bash
keylatch run --clean-env --runtime gateway_typed openrouter -- node call_api.js
```

---

## Pattern B — Async `child_process.exec` pattern

For async Node.js code that needs to resolve credentials before making API calls, use `child_process.exec` to spawn a short-lived `keylatch run` process that prints resolved credential vars:

```javascript
// keylatch_gateway.js
'use strict';
const { exec } = require('node:child_process');
const { promisify } = require('node:util');

const execAsync = promisify(exec);

/**
 * Resolves Keylatch gateway credentials for the given provider.
 *
 * @param {string} provider - The Keylatch provider name (e.g. 'openrouter')
 * @param {object} [options]
 * @param {string} [options.runtime='gateway_typed'] - Runtime mode
 * @returns {Promise<{gatewayUrl: string, gatewayToken: string}>}
 */
async function resolveGatewayCredentials(provider, { runtime = 'gateway_typed' } = {}) {
  const sentinel =
    'const e=process.env;' +
    'process.stdout.write(JSON.stringify({' +
    'gatewayUrl:e.KEYLATCH_GATEWAY_URL||"",' +
    'gatewayToken:e.KEYLATCH_GATEWAY_TOKEN||""' +
    '}))';

  const cmd = [
    'keylatch', 'run',
    '--clean-env',
    '--runtime', runtime,
    provider,
    '--',
    process.execPath, '-e', sentinel,
  ].join(' ');

  try {
    const { stdout } = await execAsync(cmd, { timeout: 10_000 });
    return JSON.parse(stdout);
  } catch (err) {
    throw new Error(
      `keylatch run failed for provider '${provider}': ${err.message}`
    );
  }
}

module.exports = { resolveGatewayCredentials };
```

**Usage:**

```javascript
const { resolveGatewayCredentials } = require('./keylatch_gateway');

async function main() {
  const { gatewayUrl, gatewayToken } = await resolveGatewayCredentials('openrouter');

  // Use fetch (Node 18+) or node:https
  const response = await fetch(`${gatewayUrl}/v1/models`, {
    headers: { Authorization: `Bearer ${gatewayToken}` },
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  const data = await response.json();
  console.log(`Models: ${data.data.length}`);
}

main().catch((err) => { console.error(err.message); process.exit(1); });
```

---

## TypeScript types for credential response

```typescript
// keylatch.ts — TypeScript types for Keylatch gateway credentials

/** Environment variables injected by `keylatch run` into child processes. */
export interface KeylatchGatewayEnv {
  /** Base URL of the local Keylatch gateway (e.g. http://127.0.0.1:7878) */
  KEYLATCH_GATEWAY_URL: string;
  /** Short-lived session token for the gateway — Bearer auth header value */
  KEYLATCH_GATEWAY_TOKEN: string;
  /** Runtime mode used for this session (e.g. 'gateway_typed') */
  KEYLATCH_RUNTIME: string;
}

/** Result returned by resolveGatewayCredentials() */
export interface GatewayCredentials {
  gatewayUrl: string;
  gatewayToken: string;
}

/** Check if current process was launched by keylatch run. */
export function isRunningInsideKeylatch(): boolean {
  return Boolean(
    process.env.KEYLATCH_GATEWAY_URL && process.env.KEYLATCH_GATEWAY_TOKEN
  );
}

/** Assert gateway vars are set, throw if missing. */
export function requireGatewayEnv(): KeylatchGatewayEnv {
  const url   = process.env.KEYLATCH_GATEWAY_URL;
  const token = process.env.KEYLATCH_GATEWAY_TOKEN;
  const mode  = process.env.KEYLATCH_RUNTIME ?? '';

  if (!url || !token) {
    throw new Error(
      'KEYLATCH_GATEWAY_URL and KEYLATCH_GATEWAY_TOKEN are not set.\n' +
      'Run your script inside keylatch run:\n' +
      '  keylatch run --clean-env <provider> -- npx tsx your-script.ts'
    );
  }

  return {
    KEYLATCH_GATEWAY_URL:   url,
    KEYLATCH_GATEWAY_TOKEN: token,
    KEYLATCH_RUNTIME:       mode,
  };
}
```

---

## `dotenv` interop note

Many Node.js projects use `dotenv` to load credentials from `.env` files. **Do not put raw API keys in `.env` files.** Instead, use `keylatch run` as the outer wrapper and read `KEYLATCH_GATEWAY_TOKEN` + `KEYLATCH_GATEWAY_URL` from `process.env`.

If you have an existing codebase that uses `dotenv`:

```javascript
// Disable dotenv in production/agent sessions — keylatch handles credential injection.
if (!process.env.KEYLATCH_GATEWAY_TOKEN) {
  // Development-only: allow dotenv for local dev without keylatch
  require('dotenv').config();
}
```

For new projects, skip `dotenv` entirely and use `keylatch run` as the process launcher.

---

## Reference implementation

See [docs/integration/examples/node/fetchData.ts](examples/node/fetchData.ts) for a complete, runnable TypeScript example.

---

## Related

- [docs/integration/README.md](README.md) — integration guide index
- [docs/scripting.md](../scripting.md) — gateway scripting patterns
- [docs/cli/environment.md](../cli/environment.md) — all injected env vars
