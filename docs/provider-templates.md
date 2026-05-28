# Provider Templates

Provider templates define how Keylatch stores, validates, and injects credentials for a specific AI tool or API provider. Templates are YAML files validated against a JSON Schema.

## Template location

Templates ship in `templates/providers/` and are validated against `templates/providers/schema.json` (JSON Schema draft-07).

## Listing providers

```bash
keylatch registry list
```

Prints all registered providers — name, display name, category, and trust level.

## Validating a template

```bash
keylatch registry validate templates/providers/my-provider.yaml
```

Exits `0` on success, `1` on validation failure with a diagnostic message.

## Template format

```yaml
provider: openrouter                    # machine-readable ID (kebab-case)
display_name: OpenRouter                # shown in CLI output
category: llm                           # llm | storage | search | communication | ...
auth_flow: api_key                      # api_key | oauth2 | service_account
trust_level: medium                     # low | medium | high
multi_account: false                    # true if provider supports multiple accounts

secret_fields:
  - name: api_key
    description: OpenRouter API key (sk-or-...)
    env_var: OPENROUTER_API_KEY         # injected into subprocess environment

storage_path_tpl: "default/ai/openrouter/{{ .Account }}/{{ .Field }}"

validate:
  endpoint: https://openrouter.ai/api/v1/auth/key
  method: GET
  auth_header: "Authorization: Bearer {{ .api_key }}"
  expect_status: 200
```

## Template fields

| Field | Required | Description |
|-------|----------|-------------|
| `provider` | yes | Machine-readable provider identifier (kebab-case) |
| `display_name` | yes | Human-readable name shown in CLI output |
| `category` | yes | Provider category (`llm`, `storage`, `search`, `communication`, etc.) |
| `auth_flow` | yes | Authentication flow (`api_key`, `oauth2`, `service_account`) |
| `trust_level` | yes | Trust level (`low`, `medium`, `high`) |
| `multi_account` | no | Whether multiple accounts per provider are supported (default: `false`) |
| `secret_fields` | yes | List of credential fields this provider accepts |
| `storage_path_tpl` | yes | Go template for the backend storage path |
| `validate` | no | Optional live validation endpoint configuration |

### `secret_fields` entries

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Field identifier (used in `keylatch connect <provider> <name>`) |
| `description` | yes | Human-readable description shown in connect wizard |
| `env_var` | yes | Environment variable injected into the subprocess by `keylatch run` |

### `trust_level` values

| Level | Meaning |
|-------|---------|
| `low` | Public API with rate limits only. No payment or data exposure risk. |
| `medium` | API with billing or limited data access (most AI provider keys). |
| `high` | Full account access, PII, financial data, or infrastructure credentials. |

## Adding a new template

1. Copy an existing template from `templates/providers/` as a starting point.
2. Fill in all required fields.
3. Validate locally:
   ```bash
   keylatch registry validate templates/providers/my-provider.yaml
   ```
4. Test by connecting and running:
   ```bash
   keylatch connect my-provider   # interactive prompt
   keylatch test my-provider
   ```
5. Open a pull request. CI validates the template automatically.

## Categories

| Category | Examples |
|----------|---------|
| `llm` | OpenRouter, Anthropic, OpenAI, Google AI, Ollama |
| `storage` | AWS S3, Cloudflare R2, Backblaze B2 |
| `search` | Tavily, Brave Search, Serper |
| `communication` | Slack, Discord, SendGrid, Mailgun |
| `monitoring` | Sentry, Datadog, Honeycomb |
| `infra` | GitHub, Cloudflare, Railway, Fly.io |
| `payment` | Stripe, Paddle |
| `ai-tools` | Cursor, Codeium, Copilot |

## See also

- [CLI Reference](./cli-reference.md#keylatch-registry)
- [CONTRIBUTING.md](../CONTRIBUTING.md)
