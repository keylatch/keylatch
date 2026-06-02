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

// ── Banner display config ──────────────────────────────────────────────────────

const BANNER_CONFIG: Record<ReadinessPillState, { wrapper: string; dot: string; text: string }> = {
  ready: {
    wrapper: 'bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/50',
    dot:     'bg-emerald-500 animate-pulse',
    text:    'text-emerald-700 dark:text-emerald-300',
  },
  not_ready: {
    wrapper: 'bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800/50',
    dot:     'bg-red-500',
    text:    'text-red-700 dark:text-red-300',
  },
  degraded: {
    wrapper: 'bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/50',
    dot:     'bg-amber-500',
    text:    'text-amber-700 dark:text-amber-300',
  },
}

// ── ReadinessPillWidget ────────────────────────────────────────────────────────

interface ReadinessPillWidgetProps {
  /** Connections from the Dashboard — passed down to avoid a duplicate fetch. */
  connections: Connection[]
  /** Optional navigate callback — injected by parent to avoid router coupling. */
  onNavigate?: (to: string) => void
}

/**
 * ReadinessPillWidget — dominant above-fold status banner.
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
  const config = BANNER_CONFIG[pill.state]
  const label = pillLabel_for(pill)
  const isInteractive = pill.state !== 'ready'

  const handlePillClick = () => {
    if (!onNavigate) return
    if (pill.state === 'not_ready' && pill.missingItem === 'no provider verified') {
      onNavigate('/settings')
    } else if (pill.state === 'degraded') {
      onNavigate('/settings')
    }
  }

  const bannerContent = (
    <>
      <div className={cn('h-2 w-2 rounded-full shrink-0', config.dot)} aria-hidden="true" />
      <span className={cn('text-sm font-medium', config.text)}>{label}</span>
    </>
  )

  return (
    <div aria-label="Keylatch readiness status">
      {isInteractive ? (
        <button
          type="button"
          className={cn(
            'flex items-center gap-2 rounded-lg px-4 py-2.5 transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            config.wrapper
          )}
          onClick={handlePillClick}
          aria-label={label}
        >
          {bannerContent}
        </button>
      ) : (
        <div
          className={cn('flex items-center gap-2 rounded-lg px-4 py-2.5', config.wrapper)}
          role="status"
          aria-label={label}
          aria-live="polite"
        >
          {bannerContent}
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
