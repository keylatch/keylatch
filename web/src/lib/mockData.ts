import type { Receipt } from '../api/receipts'
import type { AgentSnippet, Approval, Connection } from './types'

const now = new Date()

export const mockConnections: Connection[] = [
  {
    name: 'Anthropic production',
    provider: 'anthropic',
    status: 'ok',
    risk: 'medium',
    expiresAt: addDays(28),
    lastTestedAt: addMinutes(-4),
  },
  {
    name: 'OpenAI team workspace',
    provider: 'openai',
    status: 'ok',
    risk: 'medium',
    expiresAt: addDays(19),
    lastTestedAt: addMinutes(-7),
  },
  {
    name: 'GitHub engineering',
    provider: 'github',
    status: 'ok',
    risk: 'low',
    expiresAt: addDays(45),
    lastTestedAt: addMinutes(-14),
  },
  {
    name: 'Stripe billing',
    provider: 'stripe',
    status: 'warning',
    risk: 'high',
    expiresAt: addDays(5),
    lastTestedAt: addHours(-2),
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

export function mockGet(path: string): unknown | undefined {
  if (path === '/api/status') {
    return { ok: true, kek_loaded: true, scope: 'demo', demo: true }
  }

  if (path === '/api/settings') {
    return { approval_ttl_seconds: 60, approval_ttl_max_seconds: 3600 }
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
