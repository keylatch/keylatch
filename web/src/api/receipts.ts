/**
 * receipts.ts — typed client for GET /v1/receipts.
 *
 * Security invariants (S-RM-9):
 *   - Receipt interface never exposes a credential value field.
 *   - credential_shape is metadata only (shape name, not the secret).
 */

import { api, type RequestOptions } from '../lib/api'

/**
 * Receipt mirrors the Go runner.RuntimeReceipt JSON shape.
 * No credential values — only metadata (S-RM-9).
 */
export interface Receipt {
  /**
   * Client-side stable identifier assigned at insertion time (not from server).
   * Used as a React key to prevent card remounts on SSE prepend.
   */
  id?: string
  /** Runtime mode used for this execution (e.g. "gateway_typed"). */
  runtime: string
  /** Provider identifier (e.g. "anthropic", "openai"). */
  provider: string
  /** Capability requested (e.g. "messages", "embed"). */
  capability: string
  /** Policy decision result (e.g. "allowed", "denied"). */
  policy_decision: string
  /** Shape of the credential used — never the credential value itself. */
  credential_shape: string
  /**
   * Process exit code. 0 = success.
   * The JSON tag is `omitempty` in Go so this may be absent (treated as 0).
   */
  exit_code?: number
  /**
   * TTL in nanoseconds (Go time.Duration JSON encoding).
   * May be absent when not relevant to the execution path.
   */
  ttl?: number
}

/**
 * fetchReceipts returns the last `limit` receipts from /v1/receipts.
 *
 * @param limit - number of receipts to fetch (default 10, backend caps at 100)
 * @param opts - optional request options (e.g. AbortSignal for cleanup)
 */
export async function fetchReceipts(limit = 10, opts?: RequestOptions): Promise<Receipt[]> {
  const data = await api.get<{ receipts: Receipt[] }>(`/v1/receipts?limit=${limit}`, opts)
  return data.receipts ?? []
}
