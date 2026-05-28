# Provider Template Catalog

All first-party provider templates shipped with Keylatch. Run `keylatch registry list` to see all registered providers.

## AI / LLM

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Anthropic | `anthropic` | api_key | gateway_typed |
| Google AI (Gemini) | `google-ai` | api_key | gateway_typed |
| OpenAI | `openai` | api_key | gateway_typed |
| OpenRouter | `openrouter` | api_key | gateway_typed |

**Example — OpenRouter:**
```bash
# Interactive prompt (no shell history exposure):
keylatch connect openrouter
keylatch run openrouter -- node script.js

# Or via stdin (CI-safe):
printf '%s' "$OPENROUTER_API_KEY" | keylatch connect openrouter -f api_key=@-
```

## Code hosting

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| GitHub | `github` | api_key / oauth | gateway_typed |
| GitLab | `gitlab` | api_key | gateway_typed |

**Example — GitHub:**
```bash
# Interactive prompt (no shell history exposure):
keylatch connect github
keylatch run github -- gh repo list

# Or via stdin (CI-safe):
printf '%s' "$GITHUB_PAT" | keylatch connect github -f api_key=@-
```

> **Note:** The GitHub App installation strategy supports `direct_brokered` runtime for short-lived token exchange (GitHub App installation tokens), not just `gateway_typed`. This allows zero-credential-storage workflows where the broker exchanges an App JWT for a scoped installation token at request time.

## Cloud infrastructure

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Cloudflare | `cloudflare` | api_key | gateway_typed |
| Vercel | `vercel` | api_key | gateway_typed |

## Communication

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Slack | `slack` | oauth | gateway_typed |
| Twilio | `twilio` | api_key | gateway_typed |

## CRM

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| HubSpot | `hubspot` | oauth | gateway_typed |
| Salesforce | `salesforce` | oauth | gateway_typed |

## Data / Databases

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Supabase | `supabase` | api_key | gateway_typed |

## Email

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Mailchimp | `mailchimp` | api_key | gateway_typed |
| Mailgun | `mailgun` | api_key | gateway_typed |
| Postmark | `postmark` | api_key | gateway_typed |
| SendGrid | `sendgrid` | api_key | gateway_typed |

## Identity / Auth

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Auth0 | `auth0` | oauth | gateway_typed |
| Okta | `okta` | oauth | gateway_typed |

## Observability

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Datadog | `datadog` | api_key | gateway_typed |
| Honeycomb | `honeycomb` | api_key | gateway_typed |
| PostHog | `posthog` | api_key | gateway_typed |
| Sentry | `sentry` | api_key | gateway_typed |

## Payments

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Stripe | `stripe` | api_key | gateway_typed |

## Storage

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Dropbox | `dropbox` | oauth | gateway_typed |
| Google Workspace | `google-workspace` | oauth | gateway_typed |

## Support

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Intercom | `intercom` | oauth | gateway_typed |
| Zendesk | `zendesk` | api_key | gateway_typed |

## Automation

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Make | `make` | api_key | gateway_typed |
| n8n | `n8n` | api_key | gateway_typed |
| Zapier | `zapier` | api_key | gateway_typed |

## Work management

| Provider | ID | Auth | Default Runtime |
|----------|----|------|-----------------|
| Airtable | `airtable` | api_key | gateway_typed |
| Atlassian (Jira/Confluence) | `atlassian` | oauth | gateway_typed |
| Linear | `linear` | api_key | gateway_typed |
| Notion | `notion` | oauth | gateway_typed |

---

## Runtime modes per provider

Most providers default to `gateway_typed` — credentials are injected via the local gateway with schema validation. Run `keylatch runtime doctor <provider>` to see all modes available for a specific provider:

```bash
keylatch runtime doctor openrouter
keylatch runtime doctor openrouter --json
```

## Adding a custom provider

Use the scaffold command to generate a starter template:

```bash
keylatch registry scaffold my-provider
```

Then validate against the schema:

```bash
keylatch registry validate templates/providers/my-provider.yaml
```

See [provider-templates.md](./provider-templates.md) for the full template format reference.
