---
title: Provider Index
since: 0.1.0
---

# Provider Index

All 35 providers supported in Keylatch 0.1.0, organized by category.

**Trust levels:** 0 = open API, 1 = team-scoped, 2 = elevated (infra/PII), 3 = privileged (financial/identity).

For the full provider catalog with template details, see [provider-template-catalog.md](../provider-template-catalog.md).

---

## AI

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| OpenRouter | `keylatch connect openrouter api_key YOUR_KEY` | `gateway_sdk` | 0 |
| Anthropic | `keylatch connect anthropic api_key YOUR_KEY` | `gateway_typed` | 0 |
| OpenAI | `keylatch connect openai api_key YOUR_KEY` | `gateway_sdk` | 0 |
| Google AI | `keylatch connect google-ai api_key YOUR_KEY` | `gateway_typed` | 0 |

---

## Automation

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Make | `keylatch connect make api_key YOUR_KEY` | `gateway_typed` | 1 |
| n8n | `keylatch connect n8n api_key YOUR_KEY` | `gateway_typed` | 1 |
| Zapier | `keylatch connect zapier api_key YOUR_KEY` | `gateway_typed` | 1 |

---

## Cloud Infrastructure

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Vercel | `keylatch connect vercel api_token YOUR_KEY` | `gateway_typed` | 2 |

---

## Code Hosting

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| GitHub | `keylatch connect github token YOUR_TOKEN` | `gateway_typed` | 2 |
| GitLab | `keylatch connect gitlab access_token YOUR_TOKEN` | `gateway_typed` | 2 |

---

## Communication

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Slack | `keylatch connect slack bot_token YOUR_TOKEN` | `gateway_typed` | 1 |
| Twilio | `keylatch connect twilio account_sid YOUR_SID` | `gateway_typed` | 2 |

---

## CRM

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| HubSpot | `keylatch connect hubspot access_token YOUR_TOKEN` | `gateway_typed` | 2 |
| Salesforce | `keylatch connect salesforce client_id YOUR_ID` | `gateway_typed` | 3 |

---

## Data

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Supabase | `keylatch connect supabase service_role_key YOUR_KEY` | `gateway_typed` | 2 |

---

## Email

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Mailchimp | `keylatch connect mailchimp api_key YOUR_KEY` | `gateway_typed` | 1 |
| Mailgun | `keylatch connect mailgun api_key YOUR_KEY` | `gateway_typed` | 2 |
| Postmark | `keylatch connect postmark server_token YOUR_TOKEN` | `gateway_typed` | 2 |
| SendGrid | `keylatch connect sendgrid api_key YOUR_KEY` | `gateway_typed` | 2 |

---

## Identity

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Auth0 | `keylatch connect auth0 client_id YOUR_ID` | `gateway_typed` | 3 |
| Okta | `keylatch connect okta api_token YOUR_TOKEN` | `gateway_typed` | 3 |

---

## Observability

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Datadog | `keylatch connect datadog api_key YOUR_KEY` | `gateway_typed` | 2 |
| Honeycomb | `keylatch connect honeycomb api_key YOUR_KEY` | `gateway_typed` | 1 |
| PostHog | `keylatch connect posthog personal_api_key YOUR_KEY` | `gateway_typed` | 1 |
| Sentry | `keylatch connect sentry auth_token YOUR_TOKEN` | `gateway_typed` | 0 |

---

## Payments

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Stripe | `keylatch connect stripe secret_key YOUR_KEY` | `gateway_typed` | 3 |

---

## Support

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Intercom | `keylatch connect intercom access_token YOUR_TOKEN` | `gateway_typed` | 2 |
| Zendesk | `keylatch connect zendesk api_token YOUR_TOKEN` | `gateway_typed` | 2 |

---

## Work Management

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Airtable | `keylatch connect airtable api_key YOUR_KEY` | `gateway_typed` | 1 |
| Atlassian | `keylatch connect atlassian api_token YOUR_TOKEN` | `gateway_typed` | 1 |
| Linear | `keylatch connect linear api_key YOUR_KEY` | `gateway_typed` | 1 |
| Notion | `keylatch connect notion api_key YOUR_KEY` | `gateway_typed` | 1 |

---

## Storage / CDN / Workspace (Core)

| Name | `keylatch connect` example | Preferred runtime mode | Trust level |
|------|---------------------------|------------------------|:-----------:|
| Cloudflare | `keylatch connect cloudflare api_token YOUR_TOKEN` | `gateway_typed` | 0 |
| Dropbox | `keylatch connect dropbox access_token YOUR_TOKEN` | `direct_brokered` | 0 |
| Google Workspace | `keylatch connect google_workspace oauth_credentials YOUR_CREDS` | `direct_brokered` | 0 |

---

## Adding a provider

See [Authoring Provider Templates](../dev/authoring-providers.md) for the YAML schema, trust level guide, and PR workflow.
