import { useEffect, useRef, useState } from 'react'
import type { Connection, ReadinessPill, ReadinessPillState } from '../lib/types'
import { api } from '../lib/api'
import { cn } from '@/lib/utils'

/** Polling interval for daemon health when no SSE is available. */
const HEALTH_POLL_MS = 5000

interface DaemonHealthResponse {
  ok: boolean
  kek_loaded?: boolean
}

/**
 * computePillState — pure function that derives ReadinessPill from current data.
 *
 * Logic:
 *   - not_ready: daemon not running, or no KEK, or no verified provider.
 *   - ready:     daemon running + KEK loaded + at least one provider verified.
 *   - degraded:  ready conditions met but at least one provider has status 'error'.
 */
function computePillState(
  daemonOk: boolean,
  kekLoaded: boolean,
  connections: Connection[],
): ReadinessPill {
  if (!daemonOk) {
    return { state: 'not_ready', missingItem: 'daemon not running' }
  }
  if (!kekLoaded) {
    return { state: 'not_ready', missingItem: 'KEK not configured' }
  }

  const verifiedConnections = connections.filter((c) => c.status === 'ok')
  if (verifiedConnections.length === 0) {
    return { state: 'not_ready', missingItem: 'no provider verified' }
  }

  // Check for degraded: any configured provider returning errors.
  const failingConnection = connections.find((c) => c.status === 'error')
  if (failingConnection) {
    return { state: 'degraded', failingBackend: failingConnection.name }
  }

  return { state: 'ready' }
}

// ── Pill display config ───────────────────────────────────────────────────────

const PILL_CLASSES: Record<ReadinessPillState, string> = {
  not_ready: 'bg-[var(--color-danger-light)] text-[var(--color-danger-dark)] hover:bg-[var(--color-danger)] hover:text-[var(--color-text-inverse)]',
  ready:     'bg-[var(--color-success-light)] text-[var(--color-success-dark)]',
  degraded:  'bg-[var(--color-warning-light)] text-[var(--color-warning-dark)] hover:bg-[var(--color-warning)] hover:text-[var(--color-text-inverse)]',
}

// ── ReadinessPillWidget ────────────────────────────────────────────────────────

interface ReadinessPillWidgetProps {
  /** Connections from the Dashboard — passed down to avoid a duplicate fetch. */
  connections: Connection[]
  /** Optional navigate callback — injected by parent to avoid router coupling. */
  onNavigate?: (to: string) => void
}

/**
 * ReadinessPillWidget — dominant above-fold status pill.
 *
 * Three states: not_ready (red), ready (green), degraded (amber).
 * Polls /api/status every 5 s; also re-derives state when `connections` changes.
 * Tapping a missing item or failing backend navigates to the relevant page.
 */
export function ReadinessPillWidget({ connections, onNavigate }: ReadinessPillWidgetProps) {
  const [daemonOk, setDaemonOk] = useState(false)
  const [kekLoaded, setKekLoaded] = useState(false)
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true

    const fetchHealth = () => {
      api.get<DaemonHealthResponse>('/api/status')
        .then((data) => {
          if (!mountedRef.current) return
          setDaemonOk(data.ok)
          setKekLoaded(data.kek_loaded ?? data.ok)
        })
        .catch(() => {
          if (!mountedRef.current) return
          setDaemonOk(false)
          setKekLoaded(false)
        })
    }

    fetchHealth()
    const id = setInterval(fetchHealth, HEALTH_POLL_MS)

    return () => {
      mountedRef.current = false
      clearInterval(id)
    }
  }, [])

  const pill = computePillState(daemonOk, kekLoaded, connections)

  const handlePillClick = () => {
    if (!onNavigate) return
    if (pill.state === 'not_ready' && pill.missingItem === 'no provider verified') {
      onNavigate('/settings')
    } else if (pill.state === 'degraded') {
      onNavigate('/settings')
    }
  }

  const label = pillLabel_for(pill)
  const isInteractive = pill.state !== 'ready'
  const baseClasses = cn(
    'inline-flex items-center gap-2 rounded-full px-5 py-2 text-sm font-semibold tracking-wide transition-colors',
    PILL_CLASSES[pill.state]
  )

  return (
    <div
      className="py-4"
      aria-label="Keylatch readiness status"
    >
      {isInteractive ? (
        <button
          type="button"
          className={cn(baseClasses, 'cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)]')}
          onClick={handlePillClick}
          aria-label={label}
        >
          {label}
        </button>
      ) : (
        <div
          className={cn(baseClasses, 'cursor-default')}
          role="status"
          aria-label={label}
          aria-live="polite"
        >
          {label}
        </div>
      )}
    </div>
  )
}

function pillLabel_for(pill: ReadinessPill): string {
  switch (pill.state) {
    case 'ready':
      return 'Ready for agents'
    case 'not_ready':
      return `Not ready — ${pill.missingItem ?? 'setup required'}`
    case 'degraded':
      return `Degraded — ${pill.failingBackend ?? 'backend'} failing`
  }
}

// Export for testing.
export { computePillState }
