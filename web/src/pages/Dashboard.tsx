import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ConnectionCard } from '../components/ConnectionCard'
import { ReceiptCard } from '../components/ReceiptCard'
import { ReadinessPillWidget } from '../components/ReadinessPill'
import { ProviderWizard } from '../components/ProviderWizard'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import type { Connection, Approval } from '../lib/types'
import { api, DEV_MOCK } from '../lib/api'
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
  const [wizardOpen, setWizardOpen] = useState(false)

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
    // Skip SSE in mock mode — polling is sufficient and EventSource would
    // immediately error because the Go server is not running.
    if (!DEV_MOCK) {
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
    }

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
      esRef.current?.close()
      esRef.current = null
      if (intervalRef.current !== null) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24" aria-busy="true" aria-label="Loading dashboard">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-border border-t-primary" />
      </div>
    )
  }

  if (error) {
    return (
      <div
        role="alert"
        className="rounded-lg border border-destructive/20 bg-destructive/10 p-4 text-destructive"
      >
        {error}
      </div>
    )
  }

  // ── Activity section rendering ────────────────────────────────────────────
  let activityContent: React.ReactNode

  if (receiptsLoading) {
    activityContent = (
      <div className="px-3 py-2.5 text-sm text-muted-foreground" aria-busy="true" aria-label="Loading activity">
        Loading recent activity…
      </div>
    )
  } else if (receiptsError && receipts.length === 0) {
    activityContent = (
      <div role="alert" className="px-3 py-2.5 text-sm text-destructive">
        {receiptsError}
      </div>
    )
  } else if (receipts.length === 0) {
    activityContent = (
      <div className="px-3 py-2.5 text-sm text-muted-foreground">
        No recent activity
      </div>
    )
  } else {
    activityContent = receipts.map((r, idx) => (
      // eslint-disable-next-line react/no-array-index-key
      <ReceiptCard key={r.id ?? `${r.provider}-${r.capability}-${idx}`} receipt={r} />
    ))
  }

  return (
    <div className="space-y-8">
      <h1 className="text-2xl font-bold tracking-tight text-foreground mb-0">Dashboard</h1>

      {/* Readiness status pill — above-fold system health indicator */}
      <ReadinessPillWidget connections={connections} onNavigate={(to) => navigate(to)} />

      {/* Pending approvals banner */}
      {approvals.length > 0 && (
        <div
          role="alert"
          className="mt-8 flex items-center gap-3 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 dark:border-amber-800/50 dark:bg-amber-950/30"
        >
          <span className="text-sm font-medium text-amber-800 dark:text-amber-300">
            {approvals.length} pending approval{approvals.length > 1 ? 's' : ''} require attention
          </span>
          <Button
            variant="outline"
            size="sm"
            className="ml-auto shrink-0 bg-transparent border-amber-300 text-amber-700 hover:bg-amber-100 dark:border-amber-700 dark:text-amber-300 dark:hover:bg-amber-900/40"
            onClick={() => navigate('/approvals')}
          >
            Review
          </Button>
        </div>
      )}

      {/* Connections grid */}
      <section aria-label="Connections" className="space-y-3">
        <p className="text-base font-semibold text-foreground">Connections</p>
        {connections.length === 0 ? (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              No connections yet. Add your first connection to get started.
            </p>
            <ConnectionCard isAddCard onSelect={() => setWizardOpen(true)} />
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {connections.map((c) => (
              <ConnectionCard key={c.name} connection={c} />
            ))}
            <ConnectionCard isAddCard onSelect={() => setWizardOpen(true)} />
          </div>
        )}
      </section>

      {/* Activity timeline (value-free, S-RM-9) */}
      <section aria-label="Recent activity" className="space-y-3">
        <p className="text-base font-semibold text-foreground">Recent Activity</p>
        <Card className="divide-y divide-border overflow-hidden">
          <CardContent className="p-0" role="list" aria-label="Receipt timeline">
            {activityContent}
          </CardContent>
        </Card>
      </section>

      {wizardOpen && (
        <ProviderWizard
          onSuccess={async () => {
            setWizardOpen(false)
            const data = await api.get<{ connections: Connection[] }>('/api/connections')
            setConnections(data.connections ?? [])
          }}
          onClose={() => setWizardOpen(false)}
        />
      )}
    </div>
  )
}
