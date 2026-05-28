/**
 * connections store — React state management for the multi-provider connection list.
 *
 * Security: no credential values are ever stored here (value-free, S10-V).
 */

import { useState, useCallback } from 'react'
import { api } from '../lib/api'

// ── Types ─────────────────────────────────────────────────────────────────────

export type FieldMode = 'direct' | 'reference'

export interface ConnectionField {
  name: string
  mode: FieldMode
  /** Only present when mode === 'reference'. */
  uri?: string
}

/** A single wired provider connection returned by GET /api/connections. */
export interface ProviderConnection {
  id: string
  name: string
  provider: string
  account: string
  namespace: string
  status: string
  fields: ConnectionField[]
  created_at?: string
  updated_at?: string
}

/** Payload for creating a new connection (POST /api/connections). */
export interface CreateConnectionPayload {
  provider: string
  account?: string
  namespace?: string
  runtime?: string
  fields: Array<{
    name: string
    mode: FieldMode
    /** Direct-mode secret value — never logged or stored client-side after POST. */
    value?: string
    /** Reference mode URI. */
    uri?: string
  }>
}

/** Payload for updating an existing connection (PUT /api/connections/:id). */
export type UpdateConnectionPayload = Pick<CreateConnectionPayload, 'fields'>

/** Field-level validation error from the server (HTTP 422). */
export interface FieldError {
  field: string
  error: string
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export interface UseConnectionsReturn {
  connections: ProviderConnection[]
  loading: boolean
  error: string | null
  /** Reload the full connection list from the server. */
  refresh: () => Promise<void>
  /** Create a new connection. Throws ApiError on failure. */
  createConnection: (payload: CreateConnectionPayload) => Promise<void>
  /** Update field modes / values for an existing connection. */
  updateConnection: (id: string, payload: UpdateConnectionPayload) => Promise<void>
  /** Remove a connection by its provider name (used as path segment). */
  deleteConnection: (name: string) => Promise<void>
}

/**
 * useConnections provides the full CRUD interface for provider connections.
 *
 * Usage:
 *   const { connections, loading, error, refresh, createConnection, deleteConnection } = useConnections()
 */
export function useConnections(): UseConnectionsReturn {
  const [connections, setConnections] = useState<ProviderConnection[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await api.get<{ connections: ProviderConnection[] }>('/api/connections')
      setConnections(data.connections ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load connections')
    } finally {
      setLoading(false)
    }
  }, [])

  const createConnection = useCallback(async (payload: CreateConnectionPayload) => {
    await api.post<unknown>('/api/connections', payload)
    await refresh()
  }, [refresh])

  const updateConnection = useCallback(async (id: string, payload: UpdateConnectionPayload) => {
    // id is in the form "namespace/provider/account"; the API path uses just the
    // provider (or provider/account) segment — extract from the id.
    // Assumes account names do not contain '/'. See connections.go parseConnectionName.
    const parts = id.split('/')
    const name = parts.length >= 3 ? parts.slice(1).join('/') : id
    await api.put<unknown>(`/api/connections/${name}`, payload)
    await refresh()
  }, [refresh])

  const deleteConnection = useCallback(async (name: string) => {
    await api.delete<unknown>(`/api/connections/${name}`)
    await refresh()
  }, [refresh])

  return {
    connections,
    loading,
    error,
    refresh,
    createConnection,
    updateConnection,
    deleteConnection,
  }
}
