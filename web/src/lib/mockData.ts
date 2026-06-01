import type { Receipt } from '../api/receipts'
import type { DoctorResponse } from '../api/doctor'
import type { AgentSnippet, Approval, Connection } from './types'

const now = new Date()

/** Unified connection shape that satisfies both Connection and ProviderConnection interfaces. */
export const mockConnections: (Connection & {
  id: string
  account: string
  namespace: string
  fields: Array<{ name: string; mode: 'direct' | 'reference'; uri?: string }>
  created_at: string
  updated_at: string
})[] = [
  {
    id: 'conn-anthropic-01',
    name: 'Anthropic production',
    provider: 'anthropic',
    account: 'prod',
    namespace: 'default',
    status: 'ok',
    risk: 'medium',
    approval_policy: 'global',
    expiresAt: addDays(28),
    lastTestedAt: addMinutes(-4),
    fields: [{ name: 'api_key', mode: 'reference', uri: 'keychain://anthropic/prod' }],
    created_at: addDays(-30),
    updated_at: addDays(-2),
  },
  {
    id: 'conn-openai-01',
    name: 'OpenAI team workspace',
    provider: 'openai',
    account: 'team',
    namespace: 'default',
    status: 'ok',
    risk: 'medium',
    approval_policy: 'global',
    expiresAt: addDays(19),
    lastTestedAt: addMinutes(-7),
    fields: [{ name: 'api_key', mode: 'reference', uri: 'keychain://openai/team' }],
    created_at: addDays(-20),
    updated_at: addDays(-1),
  },
  {
    id: 'conn-github-01',
    name: 'GitHub engineering',
    provider: 'github',
    account: 'engineering',
    namespace: 'default',
    status: 'ok',
    risk: 'low',
    approval_policy: 'global',
    expiresAt: addDays(45),
    lastTestedAt: addMinutes(-14),
    fields: [{ name: 'pat', mode: 'reference', uri: 'keychain://github/engineering' }],
    created_at: addDays(-60),
    updated_at: addDays(-5),
  },
  {
    id: 'conn-stripe-01',
    name: 'Stripe billing',
    provider: 'stripe',
    account: 'billing',
    namespace: 'default',
    status: 'warning',
    risk: 'high',
    approval_policy: 'global',
    expiresAt: addDays(5),
    lastTestedAt: addHours(-2),
    fields: [{ name: 'restricted_key', mode: 'reference', uri: 'keychain://stripe/billing' }],
    created_at: addDays(-10),
    updated_at: addHours(-2),
  },
]

export const mockApprovals: Approval[] = [
  {
    token: 'appr_demo_01',
    connection: 'Stripe billing',
    commandHmac: 'hmac_92f4c8b1',
    actorHmac: 'actor_51b9a22d',
    createdAt: addMinutes(-11),
    expiresAt: addMinutes(19),
  },
]

export const mockReceipts: Receipt[] = [
  {
    id: 'receipt-01',
    runtime: 'gateway_typed',
    provider: 'anthropic',
    capability: 'messages.create',
    policy_decision: 'allowed',
    credential_shape: 'bearer_token',
    exit_code: 0,
    ttl: 900_000_000_000,
  },
  {
    id: 'receipt-02',
    runtime: 'gateway_typed',
    provider: 'github',
    capability: 'issues.write',
    policy_decision: 'allowed',
    credential_shape: 'fine_grained_pat',
    exit_code: 0,
    ttl: 600_000_000_000,
  },
  {
    id: 'receipt-03',
    runtime: 'gateway_classic',
    provider: 'stripe',
    capability: 'customers.read',
    policy_decision: 'allowed',
    credential_shape: 'restricted_key',
    exit_code: 0,
    ttl: 300_000_000_000,
  },
  {
    id: 'receipt-04',
    runtime: 'gateway_typed',
    provider: 'openai',
    capability: 'responses.create',
    policy_decision: 'denied',
    credential_shape: 'project_key',
    exit_code: 1,
    ttl: 0,
  },
]

export const mockAgentSnippet: AgentSnippet = {
  language: 'bash',
  capabilities: ['anthropic:messages.create', 'github:issues.write'],
  snippet: 'keylatch run claude -- claude "review the issue and open a PR"',
}

const mockDoctorResponse: DoctorResponse = {
  exit: 0,
  healthy: true,
  warnings: false,
  checks: [
    { name: 'kek_loaded', section: 'keyring', ok: true, detail: 'KEK loaded from keychain', tags: ['keyring'] },
    { name: 'keyring_accessible', section: 'keyring', ok: true, detail: 'Keyring is accessible', tags: ['keyring'] },
    { name: 'connections_wired', section: 'connections', ok: true, detail: '4 connections wired', tags: ['connections'] },
    { name: 'gateway_reachable', section: 'network', ok: true, detail: 'Gateway reachable at localhost:7890', tags: ['network'] },
    { name: 'csrf_token', section: 'security', ok: true, detail: 'CSRF token present', tags: ['security'] },
  ],
  sections: [
    { name: 'keyring', ok: true, has_warn: false, check_count: 2 },
    { name: 'connections', ok: true, has_warn: false, check_count: 1 },
    { name: 'network', ok: true, has_warn: false, check_count: 1 },
    { name: 'security', ok: true, has_warn: false, check_count: 1 },
  ],
  version: '0.9.0-demo',
  platform: 'darwin/arm64',
}

const mockSettingsState = {
  approval_ttl_seconds: 60,
  approval_ttl_max_seconds: 3600,
  advanced_mode: false,
  operating_mode: 'standard',
  telemetry_disable: false,
  experimental: false,
  approval_policy: 'prompt',
  active_backend: 'keychain',
}

export function mockPatch(path: string, body: unknown): unknown | undefined {
  if (path.startsWith('/api/settings') && body !== null && typeof body === 'object') {
    Object.assign(mockSettingsState, body)
    return { ...mockSettingsState }
  }
  if (path.startsWith('/api/connections/') && !path.includes('/clear') && body !== null && typeof body === 'object') {
    const id = path.replace('/api/connections/', '')
    const conn = mockConnections.find((c) => c.name === id || c.provider === id)
    if (conn && 'approval_policy' in (body as Record<string, unknown>)) {
      conn.approval_policy = (body as Record<string, unknown>).approval_policy as string
    }
    return { status: 'updated', id }
  }
  return undefined
}

export function mockGet(path: string): unknown | undefined {
  if (path === '/api/status') {
    return { ok: true, kek_loaded: true, scope: 'demo', demo: true }
  }

  if (path.startsWith('/api/settings')) {
    return { ...mockSettingsState }
  }

  if (path.startsWith('/api/doctor')) {
    return mockDoctorResponse
  }

  if (path === '/api/password-managers') {
    return { op: true, aws_sm: false, hashivault: false }
  }

  if (path === '/api/agent/snippet') {
    return mockAgentSnippet
  }

  if (path === '/api/connections') {
    return { connections: mockConnections }
  }

  if (path === '/api/approvals') {
    return { approvals: mockApprovals }
  }

  if (path.startsWith('/v1/receipts')) {
    const url = new URL(path, window.location.origin)
    const limit = Number(url.searchParams.get('limit') ?? '10')
    return { receipts: mockReceipts.slice(0, Number.isFinite(limit) ? limit : 10) }
  }

  if (path === '/v1/backends') {
    return [
      { name: 'keychain', display_name: 'macOS Keychain', available: true },
      { name: 'op',       display_name: '1Password',      available: true },
      { name: 'bw',       display_name: 'Bitwarden',      available: false, install_hint: 'Install the Bitwarden CLI: brew install bitwarden-cli' },
      { name: 'file',     display_name: 'Encrypted file', available: true },
    ]
  }

  if (path === '/v1/providers') {
    return [
      // ai
      { slug: 'anthropic',  display_name: 'Anthropic',   category: 'ai',       docs_url: 'https://docs.anthropic.com',              runtime_modes: ['gateway_typed'] },
      { slug: 'openai',     display_name: 'OpenAI',      category: 'ai',       docs_url: 'https://platform.openai.com/docs',         runtime_modes: ['gateway_typed'] },
      { slug: 'openrouter', display_name: 'OpenRouter',  category: 'ai',       docs_url: 'https://openrouter.ai/docs',               runtime_modes: ['gateway_typed'] },
      { slug: 'elevenlabs', display_name: 'ElevenLabs',  category: 'ai',       docs_url: 'https://elevenlabs.io/docs',               runtime_modes: ['gateway_typed'] },
      { slug: 'replicate',  display_name: 'Replicate',   category: 'ai',       docs_url: 'https://replicate.com/docs',               runtime_modes: ['gateway_typed'] },
      // devtools
      { slug: 'github',     display_name: 'GitHub',      category: 'devtools', docs_url: 'https://docs.github.com',                  runtime_modes: ['gateway_classic'] },
      { slug: 'gitlab',     display_name: 'GitLab',      category: 'devtools', docs_url: 'https://docs.gitlab.com',                  runtime_modes: ['gateway_classic'] },
      { slug: 'linear',     display_name: 'Linear',      category: 'devtools', docs_url: 'https://linear.app/docs/api',              runtime_modes: ['gateway_classic'] },
      { slug: 'sentry',     display_name: 'Sentry',      category: 'devtools', docs_url: 'https://docs.sentry.io',                   runtime_modes: ['gateway_classic'] },
      { slug: 'vercel',     display_name: 'Vercel',      category: 'devtools', docs_url: 'https://vercel.com/docs',                  runtime_modes: ['gateway_classic'] },
      { slug: 'supabase',   display_name: 'Supabase',    category: 'devtools', docs_url: 'https://supabase.com/docs',                runtime_modes: ['gateway_classic'] },
      { slug: 'turso',      display_name: 'Turso',       category: 'devtools', docs_url: 'https://docs.turso.tech',                  runtime_modes: ['gateway_classic'] },
      { slug: 'n8n',        display_name: 'n8n',         category: 'devtools', docs_url: 'https://docs.n8n.io',                      runtime_modes: ['gateway_classic'] },
      { slug: 'make',       display_name: 'Make',        category: 'devtools', docs_url: 'https://www.make.com/en/help',             runtime_modes: ['gateway_classic'] },
      // storage
      { slug: 'dropbox',    display_name: 'Dropbox',     category: 'storage',  docs_url: 'https://developers.dropbox.com',           runtime_modes: ['gateway_classic'] },
      { slug: 'airtable',   display_name: 'Airtable',    category: 'storage',  docs_url: 'https://airtable.com/developers/web/api',  runtime_modes: ['gateway_classic'] },
      { slug: 'notion',     display_name: 'Notion',      category: 'storage',  docs_url: 'https://developers.notion.com',            runtime_modes: ['gateway_classic'] },
      // auth
      { slug: 'auth0',      display_name: 'Auth0',       category: 'auth',     docs_url: 'https://auth0.com/docs',                   runtime_modes: ['gateway_classic'] },
      { slug: 'okta',       display_name: 'Okta',        category: 'auth',     docs_url: 'https://developer.okta.com',               runtime_modes: ['gateway_classic'] },
      { slug: 'google',     display_name: 'Google',      category: 'auth',     docs_url: 'https://developers.google.com',            runtime_modes: ['gateway_classic'] },
      { slug: 'atlassian',  display_name: 'Atlassian',   category: 'auth',     docs_url: 'https://developer.atlassian.com',          runtime_modes: ['gateway_classic'] },
      // cloud
      { slug: 'cloudflare', display_name: 'Cloudflare',  category: 'cloud',    docs_url: 'https://developers.cloudflare.com',        runtime_modes: ['gateway_classic'] },
      { slug: 'datadog',    display_name: 'Datadog',     category: 'cloud',    docs_url: 'https://docs.datadoghq.com',               runtime_modes: ['gateway_classic'] },
      // payments
      { slug: 'stripe',     display_name: 'Stripe',      category: 'payments', docs_url: 'https://stripe.com/docs',                  runtime_modes: ['gateway_classic'] },
      // comms
      { slug: 'slack',      display_name: 'Slack',       category: 'comms',    docs_url: 'https://api.slack.com',                    runtime_modes: ['gateway_classic'] },
      { slug: 'twilio',     display_name: 'Twilio',      category: 'comms',    docs_url: 'https://www.twilio.com/docs',              runtime_modes: ['gateway_classic'] },
      { slug: 'mailchimp',  display_name: 'Mailchimp',   category: 'comms',    docs_url: 'https://mailchimp.com/developer',          runtime_modes: ['gateway_classic'] },
      { slug: 'mailgun',    display_name: 'Mailgun',     category: 'comms',    docs_url: 'https://documentation.mailgun.com',        runtime_modes: ['gateway_classic'] },
      { slug: 'sendgrid',   display_name: 'SendGrid',    category: 'comms',    docs_url: 'https://docs.sendgrid.com',                runtime_modes: ['gateway_classic'] },
      { slug: 'intercom',   display_name: 'Intercom',    category: 'comms',    docs_url: 'https://developers.intercom.com',          runtime_modes: ['gateway_classic'] },
      { slug: 'hubspot',    display_name: 'HubSpot',     category: 'comms',    docs_url: 'https://developers.hubspot.com',           runtime_modes: ['gateway_classic'] },
      { slug: 'zendesk',    display_name: 'Zendesk',     category: 'comms',    docs_url: 'https://developer.zendesk.com',            runtime_modes: ['gateway_classic'] },
      { slug: 'posthog',    display_name: 'PostHog',     category: 'comms',    docs_url: 'https://posthog.com/docs',                 runtime_modes: ['gateway_classic'] },
      { slug: 'zapier',     display_name: 'Zapier',      category: 'comms',    docs_url: 'https://platform.zapier.com/docs',         runtime_modes: ['gateway_classic'] },
      { slug: 'salesforce', display_name: 'Salesforce',  category: 'comms',    docs_url: 'https://developer.salesforce.com',         runtime_modes: ['gateway_classic'] },
    ]
  }

  if (path.startsWith('/v1/providers/')) {
    const slug = path.replace('/v1/providers/', '')
    const fieldMap: Record<string, Array<{ name: string; label: string; required: boolean }>> = {
      anthropic:  [{ name: 'api_key', label: 'API Key', required: true }],
      openai:     [{ name: 'api_key', label: 'API Key', required: true }],
      github:     [{ name: 'token', label: 'Personal Access Token', required: true }],
      stripe:     [{ name: 'secret_key', label: 'Secret Key', required: true }, { name: 'webhook_secret', label: 'Webhook Secret', required: false }],
      slack:      [{ name: 'bot_token', label: 'Bot Token', required: true }],
      openrouter: [{ name: 'api_key', label: 'API Key', required: true }],
    }
    const displayNames: Record<string, string> = {
      anthropic: 'Anthropic', openai: 'OpenAI', github: 'GitHub', stripe: 'Stripe',
      slack: 'Slack', openrouter: 'OpenRouter', elevenlabs: 'ElevenLabs', replicate: 'Replicate',
      gitlab: 'GitLab', linear: 'Linear', sentry: 'Sentry', vercel: 'Vercel',
      supabase: 'Supabase', turso: 'Turso', n8n: 'n8n', make: 'Make',
      dropbox: 'Dropbox', airtable: 'Airtable', notion: 'Notion',
      auth0: 'Auth0', okta: 'Okta', google: 'Google', atlassian: 'Atlassian',
      cloudflare: 'Cloudflare', datadog: 'Datadog', twilio: 'Twilio',
      mailchimp: 'Mailchimp', mailgun: 'Mailgun', sendgrid: 'SendGrid',
      intercom: 'Intercom', hubspot: 'HubSpot', zendesk: 'Zendesk',
      posthog: 'PostHog', zapier: 'Zapier', salesforce: 'Salesforce',
    }
    const categoryMap: Record<string, string> = {
      anthropic: 'ai', openai: 'ai', openrouter: 'ai', elevenlabs: 'ai', replicate: 'ai',
      github: 'devtools', gitlab: 'devtools', linear: 'devtools', sentry: 'devtools',
      vercel: 'devtools', supabase: 'devtools', turso: 'devtools', n8n: 'devtools', make: 'devtools',
      dropbox: 'storage', airtable: 'storage', notion: 'storage',
      auth0: 'auth', okta: 'auth', google: 'auth', atlassian: 'auth',
      cloudflare: 'cloud', datadog: 'cloud',
      stripe: 'payments',
      slack: 'comms', twilio: 'comms', mailchimp: 'comms', mailgun: 'comms',
      sendgrid: 'comms', intercom: 'comms', hubspot: 'comms', zendesk: 'comms',
      posthog: 'comms', zapier: 'comms', salesforce: 'comms',
    }
    return {
      slug,
      display_name: displayNames[slug] ?? slug,
      category: categoryMap[slug] ?? 'other',
      fields: fieldMap[slug] ?? [{ name: 'api_key', label: 'API Key', required: true }],
    }
  }

  return undefined
}

function addMinutes(minutes: number): string {
  return new Date(now.getTime() + minutes * 60_000).toISOString()
}

function addHours(hours: number): string {
  return addMinutes(hours * 60)
}

function addDays(days: number): string {
  return addHours(days * 24)
}
