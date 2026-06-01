import { useState, useEffect, useCallback, useRef } from 'react'
import { fetchDoctorReport } from '../api/doctor'
import type { DoctorCheck, DoctorResponse } from '../api/doctor'
import { ApiError } from '../lib/api'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card'

/** Status icon for a single check row. */
function CheckIcon({ ok, warn }: { ok: boolean; warn?: boolean }) {
  if (!ok) {
    return (
      <span
        className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-red-500 text-white text-xs font-bold"
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
        className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-amber-500 text-white text-xs font-bold"
        aria-label="Warning"
        title="Warning"
      >
        !
      </span>
    )
  }
  return (
    <span
      className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-emerald-500 text-white text-xs font-bold"
      aria-label="OK"
      title="OK"
    >
      ✓
    </span>
  )
}

/** A single check row. */
function CheckRow({ check }: { check: DoctorCheck }) {
  return (
    <div className="flex items-start gap-4 px-6 py-3 border-b border-border last:border-0 transition-colors hover:bg-muted/40">
      <div className="mt-0.5 shrink-0">
        <CheckIcon ok={check.ok} warn={check.warn} />
      </div>
      <div className="w-44 shrink-0">
        <span className="text-sm font-medium text-foreground">{check.name}</span>
      </div>
      <div className="flex-1 text-sm text-muted-foreground">{check.detail}</div>
      <div className="w-40 shrink-0 text-sm text-muted-foreground text-right">
        {(!check.ok || check.warn) && check.fix
          ? <span className="italic">{check.fix}</span>
          : null}
      </div>
    </div>
  )
}

/** Grouped list of checks for one section. */
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
    <Card>
      <CardHeader className="pb-3 border-b border-border">
        <CardTitle className="text-xs font-semibold text-muted-foreground">
          {section}
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {visible.map((check) => (
          <CheckRow key={`${check.section}-${check.name}`} check={check} />
        ))}
      </CardContent>
    </Card>
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
      ? 'text-emerald-700'
      : overallExit === 1
        ? 'text-amber-700'
        : 'text-destructive'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between gap-4 mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Diagnostics</h1>
        <div className="flex items-center gap-3">
          <Checkbox
            id="quiet-mode"
            checked={quietMode}
            onCheckedChange={(checked) => setQuietMode(checked === true)}
          />
          <Label
            htmlFor="quiet-mode"
            className="text-sm text-muted-foreground cursor-pointer select-none"
          >
            Hide OK rows
          </Label>
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
        <div className={`flex items-center gap-3 rounded-lg border px-4 py-3 text-sm ${
          overallExit === 0
            ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
            : overallExit === 1
              ? 'bg-amber-50 border-amber-200 text-amber-800'
              : 'bg-red-50 border-red-200 text-red-800'
        }`}>
          <div className={`h-2 w-2 rounded-full shrink-0 ${
            overallExit === 0 ? 'bg-emerald-500' : overallExit === 1 ? 'bg-amber-500' : 'bg-red-500'
          }`} />
          {overallLabel && <span className="font-medium">{overallLabel}</span>}
          <span className="text-muted-foreground ml-auto flex gap-4">
            <span>v{report.version}</span>
            <span>{report.platform}</span>
            {lastRefreshed && <span>Refreshed {lastRefreshed.toLocaleTimeString()}</span>}
          </span>
        </div>
      )}

      {error && (
        <p className="rounded-md bg-[#fee2e2] px-4 py-3 text-sm text-destructive" role="alert">
          {error}
        </p>
      )}

      {loading && !report && (
        <p role="status" aria-live="polite" className="text-sm text-muted-foreground">
          Running diagnostics…
        </p>
      )}

      {!loading && report && report.checks.length === 0 && (
        <p className="text-sm text-muted-foreground">No checks returned.</p>
      )}

      <div className="space-y-4">
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
