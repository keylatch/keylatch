# `keylatch call` — Provider Action Dispatch

`keylatch call` dispatches a single named HTTP action from a provider's action catalog.
It reads a stored credential from the vault, sends the request as a Bearer token, and
returns the response — with credential-shaped bytes automatically redacted.

## When to use `call` vs `run`

| | `keylatch run` | `keylatch call` |
|---|---|---|
| **Purpose** | Inject credentials into a subprocess environment | Dispatch a single HTTP action directly |
| **Usage** | `keylatch run openai -- node script.js` | `keylatch call openai list-models` |
| **Output** | Child process stdout/stderr | JSON body of the HTTP response |
| **Actions** | Any command in the provider's allowlist | Named actions in the provider's `actions:` catalog |
| **LLM sessions** | Allowed (no raw credentials returned) | Allowed (response redacted before output) |

Use `call` when you want to make a single, named API call to a provider without spawning
a subprocess. Use `run` when you need to inject credentials into a long-running process.

## Usage

```
keylatch call <connection> <action> [--param key=value]... [--runtime <mode>] [--list] [--json] [--include-headers]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<connection>` | Provider slug (e.g. `openai`, `anthropic`, `openrouter`) |
| `<action>` | Action name from the provider's catalog (e.g. `list-models`) |

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--param key=value` | | Action parameter. Repeat for multiple params. |
| `--runtime <mode>` | | Override the runtime mode for this call. |
| `--list` | `false` | List available actions for the connection and exit. |
| `--json` | `false` | Output as JSON Lines (`{"status_code":200,"duration_ms":42,"body":{...}}`). |
| `--include-headers` | `false` | Append a trailing headers JSON line (Authorization header stripped). |
| `--namespace` | `default` | Vault namespace to read credentials from. |
| `--account` | | Account name for multi-account providers. |
| `--no-daemon-start` | `false` | Do not auto-start `keylatchd` if not running. |

## Action catalog

The action catalog is defined in each provider's template YAML under the `actions:` key.
The catalog for headline providers is shipped with Keylatch core.

### OpenAI

| Action | Method | Path |
|--------|--------|------|
| `list-models` | GET | `/v1/models` |
| `list-files` | GET | `/v1/files` |

```bash
keylatch call openai list-models
keylatch call openai list-files
keylatch call openai list-files --param purpose=fine-tune
```

### Anthropic

| Action | Method | Path |
|--------|--------|------|
| `list-models` | GET | `/v1/models` |

```bash
keylatch call anthropic list-models
```

### OpenRouter

| Action | Method | Path |
|--------|--------|------|
| `list-models` | GET | `/api/v1/models` |

```bash
keylatch call openrouter list-models
```

## Output format

### Human-readable (default)

The response body is printed to stdout. Credential-shaped strings are replaced with
`[REDACTED:<pattern-name>]` before output.

```
{"object":"list","data":[{"id":"gpt-4","object":"model",...},...]}
```

### JSON Lines (`--json`)

Each response is emitted as a single JSON Lines record:

```json
{"status_code":200,"duration_ms":123,"body":{"object":"list","data":[...]}}
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (2xx response) |
| `1` | Non-2xx response or argument error |
| `3` | Credential not found in vault |
| `5` | Dispatch failed (network error, gateway not running) |

## Adding an action to your own template

Add an `actions:` block to your provider's YAML template. The key is the action name
(kebab-case), and the value specifies the HTTP method, path, and optional params.

**Minimal action (no params):**

```yaml
actions:
  list-items:
    method: GET
    path: /v1/items
```

**Action with path substitution:**

```yaml
actions:
  get-item:
    method: GET
    path: /v1/items/{item_id}
    params:
      item_id:
        type: string
        required: true
        in: path
```

**Action with query params:**

```yaml
actions:
  search-items:
    method: GET
    path: /v1/items
    params:
      query:
        type: string
        required: true
        in: query
      limit:
        type: integer
        required: false
        in: query
```

**Action with a JSON body:**

```yaml
actions:
  create-item:
    method: POST
    path: /v1/items
    params:
      name:
        type: string
        required: true
        in: body
      description:
        type: string
        required: false
        in: body
```

### Param locations

| `in` value | Effect |
|-----------|--------|
| `path` | Substituted into `{param_name}` placeholders in the path |
| `query` | Appended to the URL as `?key=value` |
| `body` | Packed into a JSON request body |

### Validating your template

After adding the `actions:` block, validate the template:

```bash
keylatch registry validate path/to/your-provider.yaml
```

Then verify the action appears:

```bash
keylatch call your-provider --list
```

## Security

- The stored credential is read from the vault, used only as a Bearer token, and zeroed immediately after the HTTP request is dispatched.
- The response body is passed through the response redactor before being printed to stdout. The following patterns are redacted:
  - OpenAI API keys (`sk-<20+ chars>` → `[REDACTED:openai-key]`)
  - Anthropic API keys (`sk-ant-<20+ chars>` → `[REDACTED:anthropic-key]`)
  - Stripe keys (`sk_live_<20+>` / `sk_test_<20+>` → `[REDACTED:stripe-key]`)
  - Bearer tokens (`Bearer <token>` → `[REDACTED:bearer-token]`)
  - JWTs (`ey...` three-part → `[REDACTED:jwt]`)
- No credential bytes appear in audit logs, stderr, or the `action_called` audit event.

## See also

- [`keylatch run`](cli-reference.md#keylatch-run) — inject credentials into a subprocess
- [`keylatch registry list`](cli-reference.md) — list all registered providers
- [Provider templates](provider-templates.md) — how to write a provider template
