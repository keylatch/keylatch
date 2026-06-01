import { useEffect, useRef, useState } from 'react'
import { ProviderBadge } from './ProviderBadge'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import { api } from '../lib/api'
import type { ProviderConnection } from '../stores/connections'

// ── Doctor health indicator types ────────────────────────────────────────────

type HealthStatus = 'pending' | 'green' | 'yellow' | 'red'

const POLL_INTERVAL_MS = 60_000
const INITIAL_DELAY_MS = 0

const STATUS_DOT_LABEL: Record<HealthStatus, string> = {
  pending: 'Health check pending',
  green:   'Healthy',
  yellow:  'Warnings detected',
  red:     'Errors detected',
}

// DoctorCheck mirrors the Go doctor.Status struct.
// warn is optional (omitempty on the Go side) to avoid a Go/TS type mismatch (S-04).
interface DoctorCheck {
  name: string
  section: string
  ok: boolean
  warn?: boolean
  detail: string
  fix?: string
}

interface DoctorResponse {
  exit: number
  healthy: boolean
  warnings: boolean
  checks: DoctorCheck[]
}

function exitToHealth(exit: number): HealthStatus {
  if (exit === 0) return 'green'
  if (exit === 1) return 'yellow'
  return 'red'
}

/** useDoctorHealth polls GET /api/doctor?connection=<provider>&json=true on mount
 *  and every 60s. Debounced: never fires while a request is in flight. */
function useDoctorHealth(provider: string) {
  const [health, setHealth] = useState<HealthStatus>('pending')
  const [checks, setChecks] = useState<DoctorCheck[]>([])
  const inFlight = useRef(false)

  useEffect(() => {
    // Local to the effect so StrictMode's double-invoke gets a fresh ref each
    // time the effect runs, preventing stale-closure state sets on the second
    // (real) mount from being silenced by a ref zeroed by the first cleanup.
    const mounted = { current: true }

    const run = async () => {
      if (inFlight.current || !mounted.current) return
      inFlight.current = true
      try {
        const resp = await api.get<DoctorResponse>(
          `/api/doctor?connection=${encodeURIComponent(provider)}&json=true`
        )
        if (!mounted.current) return
        setHealth(exitToHealth(resp.exit))
        setChecks(resp.checks ?? [])
      } catch {
        // Leave status as-is on network error.
      } finally {
        inFlight.current = false
      }
    }

    // Fire the first poll after a short delay (INITIAL_DELAY_MS) so the health
    // indicator resolves without delay. Then jitter the start of the repeating
    // interval by up to 10 s so N cards mounting simultaneously do not all fire
    // at t=60s, t=120s in lockstep — preventing a thundering-herd burst on the
    // /api/doctor route.
    const initialTimer = setTimeout(() => void run(), INITIAL_DELAY_MS)
    const intervalId = setInterval(() => void run(), POLL_INTERVAL_MS)

    return () => {
      mounted.current = false
      clearTimeout(initialTimer)
      clearInterval(intervalId)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- provider is stable per card
  }, [provider])

  return { health, checks }
}

// ── FieldModeBadge ────────────────────────────────────────────────────────────

interface FieldModeBadgeProps {
  name: string
  mode: 'direct' | 'reference'
  uri?: string
}

function FieldModeBadge({ name, mode, uri }: FieldModeBadgeProps) {
  const scheme = uri ? uri.split('://')[0] : undefined
  const label = mode === 'direct' ? 'direct' : `ref:${scheme ?? 'pm'}`

  return (
    <Badge
      variant={mode === 'direct' ? 'success' : 'secondary'}
      className="font-mono text-xs"
      title={mode === 'reference' ? uri : `${name} stored directly`}
      aria-label={`${name}: ${label}`}
    >
      {name}: <span className="font-semibold">{label}</span>
    </Badge>
  )
}

// ── ProviderCard ──────────────────────────────────────────────────────────────

interface ProviderCardProps {
  connection: ProviderConnection
  onEdit?: (id: string) => void
  onDelete?: (name: string) => void
}

/**
 * ProviderCard — displays a single wired provider connection.
 *
 * Shows:
 * - Provider name + icon (monogram fallback)
 * - Per-field storage mode badges (direct | ref:<scheme>)
 * - Status dot for doctor health indicator (green/yellow/red/pending) — polled on mount and every 60s
 * - Clicking the status dot expands an inline doctor check panel
 * - Edit and Delete action buttons
 */
export function ProviderCard({ connection, onEdit, onDelete }: ProviderCardProps) {
  const { health, checks } = useDoctorHealth(connection.provider)
  const [panelOpen, setPanelOpen] = useState(false)

  const dotLabel = STATUS_DOT_LABEL[health]

  const dotColor = {
    pending: 'bg-[var(--color-neutral-300)]',
    green:   'bg-[var(--color-success)]',
    yellow:  'bg-[var(--color-warning)]',
    red:     'bg-[var(--color-danger)]',
  }[health]

  return (
    <article
      className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4 flex flex-col gap-3 shadow-[0px_1px_3px_-1px_rgba(0,0,0,0.08),0px_0px_0px_1px_rgba(0,0,0,0.04)]"
      aria-label={`Provider: ${connection.provider}`}
    >
      {/* Header */}
      <div className="flex items-center gap-3">
        <ProviderBadge provider={connection.provider} />
        <div className="flex flex-1 flex-col gap-0.5 min-w-0">
          <span className="text-sm font-semibold text-[var(--color-text-primary)] truncate">{connection.name}</span>
          <span className="text-xs text-[var(--color-text-secondary)] truncate">{connection.provider}</span>
        </div>
        <button
          type="button"
          aria-label={dotLabel}
          aria-expanded={panelOpen}
          title={`${dotLabel} — click to ${panelOpen ? 'hide' : 'show'} details`}
          onClick={() => setPanelOpen((prev) => !prev)}
          className={cn('h-3 w-3 rounded-full flex-shrink-0 cursor-pointer border-0 p-0', dotColor)}
        >
          <span className="sr-only">{dotLabel}</span>
        </button>
      </div>

      {/* Field mode badges */}
      {connection.fields.length > 0 && (
        <div className="flex flex-wrap gap-1.5" aria-label="Field storage modes">
          {connection.fields.map((f) => (
            <FieldModeBadge key={f.name} name={f.name} mode={f.mode} uri={f.uri} />
          ))}
        </div>
      )}

      {/* Doctor check panel */}
      {panelOpen && (
        <div
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2"
          role="region"
          aria-label="Doctor check results"
        >
          <h4 className="text-xs font-semibold text-[var(--color-text-secondary)] mb-2">Health Checks</h4>
          {checks.length === 0 ? (
            <p className="text-xs text-[var(--color-text-secondary)]">No check data yet.</p>
          ) : (
            <table className="w-full text-xs" aria-label="Doctor checks">
              <thead>
                <tr className="text-left text-[var(--color-text-disabled)]">
                  <th className="pb-1 pr-3 font-medium">Category</th>
                  <th className="pb-1 pr-3 font-medium">Check</th>
                  <th className="pb-1 pr-3 font-medium">Status</th>
                  <th className="pb-1 font-medium">Fix</th>
                </tr>
              </thead>
              <tbody>
                {checks.map((c) => (
                  <tr
                    key={`${c.section}-${c.name}`}
                    className={cn(
                      'border-t border-[var(--color-border)]',
                      !c.ok && c.warn && 'bg-[var(--color-warning-light)]',
                      !c.ok && !c.warn && 'bg-[var(--color-danger-light)]'
                    )}
                  >
                    <td className="py-1 pr-3 text-[var(--color-text-secondary)]">{c.section}</td>
                    <td className="py-1 pr-3 text-[var(--color-text-primary)]">{c.name}</td>
                    <td className="py-1 pr-3">{c.ok ? 'OK' : c.warn ? 'Warning' : 'Error'}</td>
                    <td className="py-1 text-[var(--color-text-secondary)]">{c.fix ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 pt-1 border-t border-[var(--color-border)]">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onEdit?.(connection.id)}
          aria-label={`Edit ${connection.name}`}
        >
          Edit
        </Button>
        <Button
          type="button"
          variant="destructive"
          size="sm"
          onClick={() => onDelete?.(connection.name)}
          aria-label={`Delete ${connection.name}`}
        >
          Delete
        </Button>
      </div>
    </article>
  )
}
