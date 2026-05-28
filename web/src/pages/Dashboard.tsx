import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ConnectionCard } from '../components/ConnectionCard'
import { ReceiptCard } from '../components/ReceiptCard'
import { ReadinessPillWidget } from '../components/ReadinessPill'
import { ActivityFeedPlaceholder } from '../components/ActivityFeedPlaceholder'
import type { Connection, Approval } from '../lib/types'
import { api } from '../lib/api'
import { fetchReceipts } from '../api/receipts'
import type { Receipt } from '../api/receipts'

/**
 * Dashboard — main screen.
 *
 * - Pending approvals banner (role="alert").
 * - ConnectionCard grid.
 * - Activity timeline: receipt feed wired to /v1/receipts + /v1/receipts/stream SSE.
 * - No secret values rendered (canary-safe, S-RM-9).
 * - 5-second polling fallback when EventSource is unavailable.
 * - Polling pauses when document is hidden (Page Visibility API).
 */
export function Dashboard() {
  const navigate = useNavigate()
  const [connections, setConnections] = useState<Connection[]>([])
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [receipts, setReceipts] = useState<Receipt[]>([])
  const [receiptsLoading, setReceiptsLoading] = useState(true)
  const [receiptsError, setReceiptsError] = useState<string | null>(null)

  // Ref to track if the component is still mounted (avoids state updates on unmounted component).
  const mountedRef = useRef(true)
  // Ref to the active EventSource so the poll callback can check its readyState.
  const esRef = useRef<EventSource | null>(null)
  // Ref to the poll interval ID for stable cleanup reference.
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    Promise.all([
      api.get<{ connections: Connection[] }>('/api/connections', { signal: controller.signal }),
      api.get<{ approvals: Approval[] }>('/api/approvals', { signal: controller.signal }),
    ])
      .then(([connData, approvalData]) => {
        setConnections(connData.connections ?? [])
        setApprovals(approvalData.approvals ?? [])
      })
      .catch((err: Error) => {
        if (controller.signal.aborted) return
        setError(err.message)
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false)
      })
    return () => {
      controller.abort()
    }
  }, [])

  // ── Receipt feed ──────────────────────────────────────────────────────────
  useEffect(() => {
    mountedRef.current = true
    const abortController = new AbortController()

    // Initial fetch.
    fetchReceipts(10, { signal: abortController.signal })
      .then((data) => {
        if (!mountedRef.current) return
        setReceipts(data)
        setReceiptsLoading(false)
      })
      .catch(() => {
        if (!mountedRef.current) return
        setReceiptsError('Could not load activity. Retrying...')
        setReceiptsLoading(false)
      })

    // ── SSE live feed (/v1/receipts/stream) ────────────────────────────────
    const es = new EventSource('/v1/receipts/stream')
    esRef.current = es

    es.addEventListener('open', () => {
      if (!mountedRef.current) return
      setReceiptsError(null)
    })

    es.addEventListener('receipt', (event: MessageEvent) => {
      if (!mountedRef.current) return
      try {
        const parsed = JSON.parse(event.data) as Receipt
        const newReceipt: Receipt = { ...parsed, id: crypto.randomUUID() }
        setReceipts((prev) => [newReceipt, ...prev].slice(0, 10))
        setReceiptsError(null)
      } catch {
        // Ignore malformed SSE data.
      }
    })

    es.addEventListener('error', () => {
      if (!mountedRef.current) return
      setReceipts((prev) => {
        if (prev.length === 0) setReceiptsError('Could not load activity. Retrying...')
        return prev
      })
    })

    // ── Polling fallback (5-second interval) ────────────────────────────────
    const POLL_INTERVAL_MS = 5000

    const poll = async () => {
      if (!mountedRef.current) return
      if (document.visibilityState === 'hidden') return
      if (esRef.current?.readyState === EventSource.OPEN) return

      fetchReceipts(10, { signal: abortController.signal })
        .then((data) => {
          if (!mountedRef.current) return
          setReceipts(data)
          setReceiptsError(null)
        })
        .catch(() => {
          if (!mountedRef.current) return
          setReceiptsError('Could not load activity. Retrying...')
        })
    }

    intervalRef.current = setInterval(poll, POLL_INTERVAL_MS)

    return () => {
      mountedRef.current = false
      abortController.abort()
      es.close()
      esRef.current = null
      if (intervalRef.current !== null) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }
  }, [])

  if (loading) {
    return <div aria-busy="true" aria-label="Loading dashboard">Loading…</div>
  }

  if (error) {
    return <div role="alert">Error: {error}</div>
  }

  // ── Activity section rendering ────────────────────────────────────────────
  let activityContent: React.ReactNode

  if (receiptsLoading) {
    activityContent = (
      <div className="text-sm text-[var(--color-text-secondary)]" aria-busy="true" aria-label="Loading activity">
        Loading recent activity…
      </div>
    )
  } else if (receiptsError && receipts.length === 0) {
    activityContent = (
      <div role="alert" className="text-sm text-[var(--color-danger)]">
        {receiptsError}
      </div>
    )
  } else if (receipts.length === 0) {
    activityContent = (
      <div className="text-sm text-[var(--color-text-secondary)]">
        No recent activity
      </div>
    )
  } else {
    activityContent = (
      <div role="list" className="space-y-2" aria-label="Receipt timeline">
        {receipts.map((r, idx) => (
          // eslint-disable-next-line react/no-array-index-key
          <ReceiptCard key={r.id ?? `${r.provider}-${r.capability}-${idx}`} receipt={r} />
        ))}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Readiness pill — dominant above-fold affordance */}
      <ReadinessPillWidget connections={connections} onNavigate={navigate} />

      {/* Pending approvals banner — kept below pill */}
      {approvals.length > 0 && (
        <div
          role="alert"
          className="rounded-md bg-[var(--color-warning-light)] px-4 py-3 text-sm font-medium text-[var(--color-warning-dark)]"
        >
          {approvals.length} pending approval{approvals.length > 1 ? 's' : ''} require attention
        </div>
      )}

      {/* Connections grid */}
      <section aria-label="Connections" className="space-y-3">
        <h2 className="text-xl font-semibold text-[var(--color-text-primary)]">Connections</h2>
        {connections.length === 0 ? (
          <div className="space-y-3">
            <p className="text-sm text-[var(--color-text-secondary)]">
              No connections yet. Add your first connection to get started.
            </p>
            <ConnectionCard isAddCard />
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {connections.map((c) => (
              <ConnectionCard key={c.name} connection={c} />
            ))}
            <ConnectionCard isAddCard />
          </div>
        )}
      </section>

      {/* Activity timeline (value-free, S-RM-9) */}
      <section aria-label="Recent activity" className="space-y-3">
        <h2 className="text-xl font-semibold text-[var(--color-text-primary)]">Recent Activity</h2>
        {activityContent}
      </section>

      {/* Activity feed placeholder — always visible, no close button (spec §4) */}
      <ActivityFeedPlaceholder />
    </div>
  )
}
