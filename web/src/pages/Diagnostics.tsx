import { useState, useEffect, useCallback, useRef } from 'react'
import { fetchDoctorReport } from '../api/doctor'
import type { DoctorCheck, DoctorResponse } from '../api/doctor'
import { ApiError } from '../lib/api'
import { Button } from '@/components/ui/button'

/** Status icon for a single check row. */
function CheckIcon({ ok, warn }: { ok: boolean; warn?: boolean }) {
  if (!ok) {
    return (
      <span
        className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-[var(--color-danger)] text-white text-xs font-bold"
        aria-label="Failed"
        title="Failed"
      >
        ✕
      </span>
    )
  }
  if (warn) {
    return (
      <span
        className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-[var(--color-warning,#f59e0b)] text-white text-xs font-bold"
        aria-label="Warning"
        title="Warning"
      >
        !
      </span>
    )
  }
  return (
    <span
      className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-[var(--color-success)] text-white text-xs font-bold"
      aria-label="OK"
      title="OK"
    >
      ✓
    </span>
  )
}

/** A single check row in the diagnostics table. */
function CheckRow({ check }: { check: DoctorCheck }) {
  return (
    <tr className="border-b border-[var(--color-border)] last:border-0">
      <td className="py-2 pr-3 align-top">
        <CheckIcon ok={check.ok} warn={check.warn} />
      </td>
      <td className="py-2 pr-4 align-top text-sm font-medium text-[var(--color-text-primary)]">
        {check.name}
      </td>
      <td className="py-2 pr-4 align-top text-sm text-[var(--color-text-secondary)]">
        {check.detail}
      </td>
      <td className="py-2 align-top text-sm text-[var(--color-text-secondary)]">
        {(!check.ok || check.warn) && check.fix ? (
          <span className="italic">{check.fix}</span>
        ) : null}
      </td>
    </tr>
  )
}

/** Grouped table of checks for one section. */
function SectionTable({
  section,
  checks,
  quietMode,
}: {
  section: string
  checks: DoctorCheck[]
  quietMode: boolean
}) {
  const visible = quietMode ? checks.filter((c) => !c.ok || c.warn) : checks
  if (visible.length === 0) return null

  return (
    <div className="space-y-1">
      <h3 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
        {section}
      </h3>
      <table className="w-full border-collapse">
        <thead>
          <tr className="text-left text-xs text-[var(--color-text-secondary)]">
            <th className="pb-1 pr-3 w-7 font-medium">Status</th>
            <th className="pb-1 pr-4 font-medium">Check</th>
            <th className="pb-1 pr-4 font-medium">Detail</th>
            <th className="pb-1 font-medium">Fix hint</th>
          </tr>
        </thead>
        <tbody>
          {visible.map((check) => (
            <CheckRow key={`${check.section}-${check.name}`} check={check} />
          ))}
        </tbody>
      </table>
    </div>
  )
}

/**
 * Diagnostics page.
 *
 * - Calls GET /api/doctor?verbose=true to retrieve all checks.
 * - Groups results by section.
 * - Quiet mode toggle collapses OK rows.
 * - Refresh button re-runs the report.
 */
export function Diagnostics() {
  const [report, setReport] = useState<DoctorResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [quietMode, setQuietMode] = useState(false)
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null)

  // Ref to the active AbortController so concurrent Refresh clicks cancel the
  // in-flight request before starting a new one (prevents stale data races).
  const controllerRef = useRef<AbortController | null>(null)

  const runDiagnostics = useCallback((signal?: AbortSignal) => {
    setLoading(true)
    setError(null)
    fetchDoctorReport(signal)
      .then((data) => {
        setReport(data)
        setLastRefreshed(new Date())
        setLoading(false)
      })
      .catch((err: unknown) => {
        if (err instanceof Error && err.name === 'AbortError') return
        const msg = err instanceof ApiError ? err.message : 'Failed to load diagnostics'
        setError(msg)
        setLoading(false)
      })
  }, [])

  // Load on mount.
  useEffect(() => {
    const controller = new AbortController()
    runDiagnostics(controller.signal)
    return () => controller.abort()
  }, [runDiagnostics])

  // Group checks by section for display.
  const bySection: Record<string, DoctorCheck[]> = {}
  const sectionOrder: string[] = []
  for (const check of report?.checks ?? []) {
    const sec = check.section || 'other'
    if (!bySection[sec]) {
      bySection[sec] = []
      sectionOrder.push(sec)
    }
    bySection[sec].push(check)
  }

  const overallExit = report?.exit ?? -1
  const overallLabel =
    overallExit === 0
      ? 'All checks passed'
      : overallExit === 1
        ? 'Warnings detected'
        : overallExit === 2
          ? 'Errors detected'
          : null

  const overallColor =
    overallExit === 0
      ? 'text-[var(--color-success-dark)]'
      : overallExit === 1
        ? 'text-[var(--color-warning,#b45309)]'
        : 'text-[var(--color-danger)]'

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <h2 className="text-2xl font-semibold text-[var(--color-text-primary)]">Diagnostics</h2>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-sm text-[var(--color-text-secondary)] cursor-pointer select-none">
            <input
              type="checkbox"
              className="h-4 w-4 rounded border-[var(--color-border)]"
              checked={quietMode}
              onChange={(e) => setQuietMode(e.target.checked)}
              aria-label="Quiet mode — hide OK rows"
            />
            Hide OK rows
          </label>
          <Button
            type="button"
            variant="outline"
            disabled={loading}
            onClick={() => {
              controllerRef.current?.abort()
              const controller = new AbortController()
              controllerRef.current = controller
              runDiagnostics(controller.signal)
            }}
            aria-label="Refresh diagnostics"
          >
            {loading ? 'Running…' : 'Refresh'}
          </Button>
        </div>
      </div>

      {report && (
        <div className="flex items-center gap-4 flex-wrap text-sm text-[var(--color-text-secondary)]">
          {overallLabel && (
            <span className={`font-medium ${overallColor}`}>{overallLabel}</span>
          )}
          <span>Version: {report.version}</span>
          <span>Platform: {report.platform}</span>
          {lastRefreshed && (
            <span>Last refreshed: {lastRefreshed.toLocaleTimeString()}</span>
          )}
        </div>
      )}

      {error && (
        <p className="rounded-md bg-[var(--color-danger-light,#fee2e2)] px-4 py-3 text-sm text-[var(--color-danger)]" role="alert">
          {error}
        </p>
      )}

      {loading && !report && (
        <p role="status" aria-live="polite" className="text-sm text-[var(--color-text-secondary)]">
          Running diagnostics…
        </p>
      )}

      {!loading && report && report.checks.length === 0 && (
        <p className="text-sm text-[var(--color-text-secondary)]">No checks returned.</p>
      )}

      <div className="space-y-6">
        {sectionOrder.map((sec) => (
          <SectionTable
            key={sec}
            section={sec}
            checks={bySection[sec]}
            quietMode={quietMode}
          />
        ))}
      </div>
    </div>
  )
}
