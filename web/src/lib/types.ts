/**
 * Shared TypeScript interfaces for the keylatch UI.
 *
 * Security invariants enforced at type level:
 *   - No `value` field on any type (value-free principle).
 *   - No `direct_run` in any RuntimeMode union.
 *   - MaskedField props deliberately excludes `value`.
 */

// ── Runtime modes ────────────────────────────────────────────────────────────

/**
 * Valid runtime modes for keylatch.
 * "direct_run" and "unrestricted" are intentionally absent from this union.
 */
export type RuntimeMode =
  | 'gateway_typed'
  | 'gateway_classic'
  | 'direct_classic_sandboxed'
  | 'absent'

// @ts-expect-error -- compile-time guard: 'direct_run' must NOT be assignable to RuntimeMode
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _directRunGuard: RuntimeMode = 'direct_run'

// ── Connection ───────────────────────────────────────────────────────────────

export interface Connection {
  /** Unique connection name. */
  name: string
  /** Provider identifier (e.g. "openrouter", "github"). */
  provider: string
  /** Human-readable status. */
  status: ConnectionStatus
  /** ISO-8601 expiry date, if known. */
  expiresAt?: string
  /** ISO-8601 last-tested timestamp. */
  lastTestedAt?: string
  /** Risk classification for this connection. */
  risk: RiskLevel
  /**
   * NOTE: `value` is intentionally absent. The API never returns credential
   * values; only the vault holds them.
   */
}

export type ConnectionStatus = 'ok' | 'error' | 'untested' | 'expired' | 'warning'

export type RiskLevel = 'low' | 'medium' | 'high'

// ── Approval ─────────────────────────────────────────────────────────────────

export interface Approval {
  /** Opaque approval token. */
  token: string
  /** Connection name the approval is for. */
  connection: string
  /** Command HMAC (not the raw command). */
  commandHmac: string
  /** Actor HMAC. */
  actorHmac: string
  /** ISO-8601 expiry timestamp. */
  expiresAt: string
  /** ISO-8601 creation timestamp. */
  createdAt: string
}

// ── Gateway ──────────────────────────────────────────────────────────────────

export interface GatewayStatus {
  running: boolean
  pid?: number
  bind?: string
  activeTokens: number
}

export interface GatewayToken {
  accessor: string
  actor: string
  capabilities: string[]
  expiresAt: string
  llmSession: boolean
  /**
   * NOTE: the raw JWT is never included here. `accessor` is the only identifier.
   */
}

// ── Status ───────────────────────────────────────────────────────────────────

export interface ServerStatus {
  ok: boolean
  scope: string
  demo: boolean
  demoBanner?: string
}

// ── Audit ────────────────────────────────────────────────────────────────────

export interface AuditSummary {
  totalEvents: number
  lastEventAt?: string
  errorCount: number
  deniedCount: number
}

// ── Agent snippet ─────────────────────────────────────────────────────────────

export interface AgentSnippet {
  language: 'bash' | 'python' | 'node'
  /** Snippet text — must never contain a credential value. */
  snippet: string
  capabilities: string[]
}

// ── Doctor / runtime ─────────────────────────────────────────────────────────

export interface DoctorResult {
  connection: string
  runtimeMode: RuntimeMode
  healthy: boolean
  message: string
}

// ── Dashboard health pill ─────────────────────────────────────────────────────

/**
 * ReadinessPillState drives the "Ready for agents" pill on the Dashboard.
 *
 * - not_ready: no verified provider, daemon not running, or no KEK configured.
 * - ready:     daemon running + KEK loaded + at least one provider verified.
 * - degraded:  ready conditions met but at least one provider is returning errors.
 */
export type ReadinessPillState = 'not_ready' | 'ready' | 'degraded'

export interface ReadinessPill {
  state: ReadinessPillState
  /** Human-readable missing item label (only present when state === 'not_ready'). */
  missingItem?: string
  /** Backend name that is failing (only present when state === 'degraded'). */
  failingBackend?: string
}
