import { useEffect, useRef, useState } from 'react'
import { ProviderBadge } from './ProviderBadge'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu'
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

const SCHEME_LABELS: Record<string, string> = {
  keychain:   'Keychain',
  op:         '1Password',
  'aws-sm':   'AWS Secrets',
  hashivault: 'HashiCorp Vault',
  bw:         'Bitwarden',
}

// ── ProviderCard ──────────────────────────────────────────────────────────────

interface ProviderCardProps {
  connection: ProviderConnection
  onEdit?: () => void
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
    pending: 'bg-neutral-300',
    green:   'bg-emerald-500',
    yellow:  'bg-amber-400',
    red:     'bg-red-500',
  }[health]

  const fieldsText = connection.fields.map((f) => {
    const scheme = f.uri ? f.uri.split('://')[0] : undefined
    const storage = f.mode === 'direct' ? 'Vault' : (SCHEME_LABELS[scheme ?? ''] ?? 'Password manager')
    return `${f.name} · ${storage}`
  }).join('  ·  ')

  return (
    <article
      className="rounded-lg border border-border bg-card px-4 py-3 flex flex-col gap-0"
      aria-label={`Provider: ${connection.provider}`}
    >
      {/* Single row */}
      <div className="flex items-center gap-4 min-w-0">
        {/* Logo */}
        <ProviderBadge provider={connection.provider} className="h-8 w-8 shrink-0 text-xs" />

        {/* Name + field metadata */}
        <div className="flex flex-col min-w-0 flex-1">
          <span className="text-sm font-semibold text-foreground truncate">{connection.name}</span>
          {fieldsText && <span className="text-xs text-muted-foreground truncate">{fieldsText}</span>}
        </div>

        {/* Status badge */}
        <div className="flex items-center gap-1.5 shrink-0">
          <span className={cn('h-2 w-2 rounded-full shrink-0', dotColor)} aria-hidden="true" />
          <span className="text-xs text-muted-foreground whitespace-nowrap">{dotLabel}</span>
        </div>

        {/* Show details */}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="shrink-0 text-xs h-7 px-2 text-muted-foreground hover:bg-accent hover:text-foreground"
          aria-expanded={panelOpen}
          onClick={() => setPanelOpen((prev) => !prev)}
          aria-label={panelOpen ? 'Hide health details' : 'Show health details'}
        >
          {panelOpen ? 'Hide details' : 'Show details'}
        </Button>

        {/* Kebab */}
        {(onEdit || onDelete) && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                aria-label={`Actions for ${connection.name}`}
                className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <svg
                  width="15"
                  height="15"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <circle cx="12" cy="5" r="1" />
                  <circle cx="12" cy="12" r="1" />
                  <circle cx="12" cy="19" r="1" />
                </svg>
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {onEdit && (
                <DropdownMenuItem onClick={() => onEdit()}>
                  Edit
                </DropdownMenuItem>
              )}
              {onEdit && onDelete && <DropdownMenuSeparator />}
              {onDelete && (
                <DropdownMenuItem destructive onClick={() => onDelete(connection.name)}>
                  Delete
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>

      {/* Doctor check panel — expands below the row */}
      {panelOpen && (
        <div
          className="mt-3 rounded-md border border-border bg-background px-3 py-2"
          role="region"
          aria-label="Doctor check results"
        >
          <h4 className="text-xs font-semibold text-muted-foreground mb-2">Health Checks</h4>
          {checks.length === 0 ? (
            <p className="text-xs text-muted-foreground">No check data yet.</p>
          ) : (
            <table className="w-full text-xs" aria-label="Doctor checks">
              <thead>
                <tr className="text-left text-muted-foreground">
                  <th className="pb-1 pr-3 font-medium">Category</th>
                  <th className="pb-1 pr-3 font-medium">Check</th>
                  <th className="pb-1 pr-3 font-medium">Status</th>
                  <th className="pb-1 font-medium">Detail</th>
                </tr>
              </thead>
              <tbody>
                {checks.map((c) => (
                  <tr key={`${c.section}-${c.name}`} className={cn(
                    'border-t border-border',
                    !c.ok && c.warn && 'bg-amber-50 dark:bg-amber-950/30',
                    !c.ok && !c.warn && 'bg-red-50 dark:bg-red-950/30',
                  )}>
                    <td className="py-1 pr-3 text-muted-foreground">{c.section}</td>
                    <td className="py-1 pr-3 text-foreground">{c.name}</td>
                    <td className="py-1 pr-3">{c.ok ? 'OK' : c.warn ? 'Warning' : 'Error'}</td>
                    <td className="py-1 text-muted-foreground">{c.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </article>
  )
}
