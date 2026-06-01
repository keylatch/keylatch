import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '../lib/api'
import { ApiError } from '../lib/api'
import { safeInvoke, safeRelaunch } from '../lib/tauri'
import { useSaveStatus } from '@/stores/saveStatus'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'

/** Shape returned by GET /api/settings and PUT /api/settings (EPIC-27). */
interface SettingsResponse {
  approval_ttl_seconds: number
  approval_ttl_max_seconds: number
  advanced_mode: boolean
  operating_mode: 'standard' | 'telemetry' | 'canary' | 'custom'
  telemetry_disable: boolean
  experimental: boolean
  approval_policy: 'trust' | 'first-run' | 'prompt'
  active_backend?: string
}

/** Shape returned by GET /v1/backends. */
interface BackendItem {
  name: string
  display_name: string
  available: boolean
  install_hint?: string
}

const BACKEND_DESCRIPTIONS: Record<string, string> = {
  keychain: 'macOS Keychain — hardware-backed, recommended on macOS.',
  op: '1Password — stores the vault key in your 1Password account.',
  bw: 'Bitwarden — stores the vault key in your Bitwarden vault.',
  file: 'Encrypted file — passphrase-protected file on disk.',
}

type OperatingMode = SettingsResponse['operating_mode']
type ApprovalPolicy = SettingsResponse['approval_policy']

/** Fallback default used while the server response is loading. */
export const DEFAULT_APPROVAL_TTL_S = 60

/**
 * Settings page.
 * - "Clear all connections" requires typing "delete all".
 * - "Approval TTL" — configurable timeout for auto-deny (server-validated, T-13-05).
 */
export function Settings() {
  const { setSaving, setSaved, setError, reset } = useSaveStatus()

  const [clearInput, setClearInput] = useState('')
  const [clearError, setClearError] = useState<string | null>(null)
  const [clearStatus, setClearStatus] = useState<'idle' | 'pending' | 'done'>('idle')
  const canClear = clearInput === 'delete all'

  // Approval TTL: loaded from and saved to /api/settings (T-13-05).
  const [approvalTtl, setApprovalTtl] = useState<number>(DEFAULT_APPROVAL_TTL_S)
  const [approvalTtlMax, setApprovalTtlMax] = useState<number>(3600)
  const [ttlLoading, setTtlLoading] = useState(true)
  const [ttlError, setTtlError] = useState<string | null>(null)

  // Advanced mode toggle.
  const [advancedMode, setAdvancedMode] = useState(false)
  const [advancedLoading, setAdvancedLoading] = useState(false)
  const [advancedError, setAdvancedError] = useState<string | null>(null)

  // EPIC-27: Operating mode.
  const [operatingMode, setOperatingMode] = useState<OperatingMode>('standard')
  const [operatingModeError, setOperatingModeError] = useState<string | null>(null)

  // EPIC-27: Telemetry kill-switch.
  const [telemetryDisable, setTelemetryDisable] = useState(false)
  const [telemetryLoading, setTelemetryLoading] = useState(false)
  const [telemetryError, setTelemetryError] = useState<string | null>(null)

  // EPIC-27: Experimental opt-in.
  const [experimental, setExperimental] = useState(false)
  const [experimentalLoading, setExperimentalLoading] = useState(false)
  const [experimentalError, setExperimentalError] = useState<string | null>(null)

  // EPIC-27: Approval policy default.
  const [approvalPolicy, setApprovalPolicy] = useState<ApprovalPolicy>('prompt')
  const [approvalPolicyError, setApprovalPolicyError] = useState<string | null>(null)

  // Credential backend.
  const [backends, setBackends] = useState<BackendItem[]>([])
  const [backendsLoading, setBackendsLoading] = useState(true)
  const [backendsError, setBackendsError] = useState<string | null>(null)
  const [activeBackend, setActiveBackend] = useState<string>('')
  const [pendingBackend, setPendingBackend] = useState<string | null>(null)
  const [backendSwitching, setBackendSwitching] = useState(false)
  const [_backendDone, setBackendDone] = useState<string | null>(null)
  const [backendError, setBackendError] = useState<string | null>(null)
  const retryControllerRef = useRef<AbortController | null>(null)

  const fetchBackends = useCallback((signal?: AbortSignal) => {
    setBackendsLoading(true)
    setBackendsError(null)
    api.get<BackendItem[]>('/v1/backends', { signal })
      .then((data) => {
        setBackends(data)
        setBackendsLoading(false)
      })
      .catch((e: unknown) => {
        if (e instanceof Error && e.name === 'AbortError') return
        setBackendsError('Could not load backends. Check your connection and try again.')
        setBackendsLoading(false)
      })
  }, [])

  // Password managers availability.
  const [pmAvailable, setPmAvailable] = useState<{ op: boolean; aws_sm: boolean; hashivault: boolean }>({
    op: false,
    aws_sm: false,
    hashivault: false,
  })

  // Fetch password manager availability on mount.
  useEffect(() => {
    api.get<{ op: boolean; aws_sm: boolean; hashivault: boolean }>('/api/password-managers')
      .then(setPmAvailable)
      .catch(() => {})
  }, [])

  // Load current settings from server on mount.
  useEffect(() => {
    let cancelled = false
    api.get<SettingsResponse>('/api/settings')
      .then((data) => {
        if (!cancelled) {
          setApprovalTtl(data.approval_ttl_seconds)
          setApprovalTtlMax(data.approval_ttl_max_seconds)
          setAdvancedMode(data.advanced_mode ?? false)
          setOperatingMode(data.operating_mode ?? 'standard')
          setTelemetryDisable(data.telemetry_disable ?? false)
          setExperimental(data.experimental ?? false)
          setApprovalPolicy(data.approval_policy ?? 'prompt')
          if (data.active_backend) setActiveBackend(data.active_backend)
          setTtlLoading(false)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setTtlLoading(false)
        }
      })
    return () => { cancelled = true }
  }, [])

  // Load backends list on mount.
  useEffect(() => {
    const controller = new AbortController()
    fetchBackends(controller.signal)
    return () => { controller.abort() }
  }, [fetchBackends])

  // Once backends load, set activeBackend to first available if not set or if stale.
  useEffect(() => {
    if (backendsLoading || backends.length === 0) return
    const isValid = backends.some((b) => b.name === activeBackend)
    if (!isValid) {
      const firstAvailable = backends.find((b) => b.available)
      if (firstAvailable) setActiveBackend(firstAvailable.name)
    }
  }, [backendsLoading, backends, activeBackend])

  const confirmSwitchBackend = async () => {
    if (!pendingBackend) return
    const target = pendingBackend
    setPendingBackend(null)
    setBackendError(null)
    setBackendDone(null)
    setBackendSwitching(true)
    setSaving()
    try {
      const result = await safeInvoke<{ ok: boolean; error?: string }>('bootstrap', { backend: target })
      if (!result.ok) {
        setBackendError(result.error ?? 'Migration failed')
        setError()
        return
      }
      setActiveBackend(target)
      setBackendDone(backends.find((b) => b.name === target)?.display_name ?? target)
      setSaved()
      await safeRelaunch()
    } catch (e) {
      setBackendError(e instanceof Error ? e.message : 'Migration failed')
      setError()
    } finally {
      setBackendSwitching(false)
    }
  }

  const handleClearConnections = async () => {
    if (!canClear) return
    setClearError(null)
    setClearStatus('pending')
    try {
      await api.post('/api/connections/clear')
      setClearInput('')
      setClearStatus('done')
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to clear connections'
      setClearError(msg)
      setClearStatus('idle')
    }
  }

  const handleSaveTtl = async () => {
    setTtlError(null)
    setSaving()
    try {
      const data = await api.put<SettingsResponse>('/api/settings', {
        approval_ttl_seconds: approvalTtl,
      })
      setApprovalTtl(data.approval_ttl_seconds)
      setApprovalTtlMax(data.approval_ttl_max_seconds)
      setSaved()
      setTimeout(() => reset(), 2500)
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to save TTL'
      setTtlError(msg)
      setError()
    }
  }

  const handleSaveOperatingMode = async (mode: OperatingMode) => {
    const previous = operatingMode
    setOperatingModeError(null)
    setOperatingMode(mode)
    setSaving()
    try {
      const data = await api.put<SettingsResponse>('/api/settings', { operating_mode: mode })
      setOperatingMode(data.operating_mode)
      setSaved()
      setTimeout(() => reset(), 2500)
    } catch (err) {
      setOperatingMode(previous)
      const msg = err instanceof ApiError ? err.message : 'Failed to save operating mode'
      setOperatingModeError(msg)
      setError()
    }
  }

  const handleToggleTelemetry = async (disabled: boolean) => {
    setTelemetryError(null)
    setTelemetryDisable(disabled)
    setTelemetryLoading(true)
    setSaving()
    try {
      const data = await api.put<SettingsResponse>('/api/settings', { telemetry_disable: disabled })
      setTelemetryDisable(data.telemetry_disable)
      setSaved()
      setTimeout(() => reset(), 2500)
    } catch (err) {
      setTelemetryDisable(!disabled)
      const msg = err instanceof ApiError ? err.message : 'Failed to save telemetry setting'
      setTelemetryError(msg)
      setError()
    } finally {
      setTelemetryLoading(false)
    }
  }

  const handleToggleExperimental = async (enabled: boolean) => {
    setExperimentalError(null)
    setExperimental(enabled)
    setExperimentalLoading(true)
    setSaving()
    try {
      const data = await api.put<SettingsResponse>('/api/settings', { experimental: enabled })
      setExperimental(data.experimental)
      setSaved()
      setTimeout(() => reset(), 2500)
    } catch (err) {
      setExperimental(!enabled)
      const msg = err instanceof ApiError ? err.message : 'Failed to save experimental setting'
      setExperimentalError(msg)
      setError()
    } finally {
      setExperimentalLoading(false)
    }
  }

  const handleSaveApprovalPolicy = async (policy: ApprovalPolicy) => {
    const previous = approvalPolicy
    setApprovalPolicyError(null)
    setApprovalPolicy(policy)
    setSaving()
    try {
      const data = await api.put<SettingsResponse>('/api/settings', { approval_policy: policy })
      setApprovalPolicy(data.approval_policy)
      setSaved()
      setTimeout(() => reset(), 2500)
    } catch (err) {
      setApprovalPolicy(previous)
      const msg = err instanceof ApiError ? err.message : 'Failed to save approval policy'
      setApprovalPolicyError(msg)
      setError()
    }
  }

  const handleToggleAdvanced = async (enabled: boolean) => {
    setAdvancedError(null)
    setAdvancedMode(enabled)
    setAdvancedLoading(true)
    // If disabling advanced mode while an advanced operating mode is active,
    // revert to standard so the radio group always has a visible selection.
    const revertMode = !enabled && (operatingMode === 'canary' || operatingMode === 'custom')
    if (revertMode) setOperatingMode('standard')
    setSaving()
    try {
      const payload: Record<string, unknown> = { advanced_mode: enabled }
      if (revertMode) payload.operating_mode = 'standard'
      const data = await api.put<SettingsResponse>('/api/settings', payload)
      setAdvancedMode(data.advanced_mode)
      if (revertMode) setOperatingMode(data.operating_mode)
      setSaved()
      setTimeout(() => reset(), 2500)
    } catch (err) {
      setAdvancedMode(!enabled)
      if (revertMode) setOperatingMode(operatingMode)
      const msg = err instanceof ApiError ? err.message : 'Failed to save advanced mode'
      setAdvancedError(msg)
      setError()
    } finally {
      setAdvancedLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight text-foreground">Settings</h1>

      {/* ── Non-advanced settings ──────────────────────────────────────────── */}

      {/* Operating mode — standard/telemetry always visible; developer options gated by advancedMode */}
      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-base">Operating mode</CardTitle>
          <CardDescription>
            Controls how Keylatch routes credentials and which features are enabled.
          </CardDescription>
        </CardHeader>
        <CardContent className="pb-4 pt-0 space-y-4">
          <RadioGroup
            value={operatingMode}
            onValueChange={(value) => void handleSaveOperatingMode(value as OperatingMode)}
            className="space-y-3"
          >
            {(
              [
                { value: 'standard',  label: 'Standard',  description: 'Stable production mode.' },
                { value: 'telemetry', label: 'Telemetry', description: 'Standard plus anonymous usage telemetry.' },
              ] as { value: OperatingMode; label: string; description: string }[]
            ).map(({ value, label, description }) => (
              <div key={value} className="flex items-center gap-3 py-1">
                <RadioGroupItem value={value} id={`mode-${value}`} />
                <Label htmlFor={`mode-${value}`} className="cursor-pointer">
                  <span className="block text-sm font-medium text-foreground">{label}</span>
                  <span className="block text-xs text-muted-foreground">{description}</span>
                </Label>
              </div>
            ))}

            {advancedMode && (
              <>
                <div className="flex items-center gap-2 pt-1">
                  <div className="h-px flex-1 bg-border" aria-hidden="true" />
                  <span className="text-xs text-muted-foreground">Developer</span>
                  <div className="h-px flex-1 bg-border" aria-hidden="true" />
                </div>
                {(
                  [
                    { value: 'canary', label: 'Canary', description: 'Pre-release features — may be unstable.' },
                    { value: 'custom', label: 'Custom', description: 'Fully custom configuration.' },
                  ] as { value: OperatingMode; label: string; description: string }[]
                ).map(({ value, label, description }) => (
                  <div key={value} className="flex items-center gap-3 py-1">
                    <RadioGroupItem value={value} id={`mode-${value}`} />
                    <Label htmlFor={`mode-${value}`} className="cursor-pointer">
                      <span className="block text-sm font-medium text-foreground">{label}</span>
                      <span className="block text-xs text-muted-foreground">{description}</span>
                    </Label>
                  </div>
                ))}
              </>
            )}
          </RadioGroup>
          {operatingModeError && (
            <p className="text-sm text-destructive mt-2" role="alert">{operatingModeError}</p>
          )}
        </CardContent>
      </Card>

      {/* Approval policy */}
      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-base">Approval policy</CardTitle>
          <CardDescription>
            Global default for all connections — controls what Keylatch does when any agent requests credential access. Can be overridden per connection.
          </CardDescription>
        </CardHeader>
        <CardContent className="pb-4 pt-0 space-y-4">
          <RadioGroup
            value={approvalPolicy}
            onValueChange={(value) => void handleSaveApprovalPolicy(value as ApprovalPolicy)}
            className="space-y-3"
          >
            {(
              [
                { value: 'prompt',    label: 'Prompt',    description: 'Always ask before approving (default).' },
                { value: 'first-run', label: 'First run', description: 'Auto-approve once per session; deny subsequent requests.' },
                { value: 'trust',     label: 'Trust',     description: 'Auto-approve all requests from all connections.' },
              ] as { value: ApprovalPolicy; label: string; description: string }[]
            ).map(({ value, label, description }) => (
              <div key={value} className="flex items-center gap-3 py-1">
                <RadioGroupItem value={value} id={`policy-${value}`} />
                <Label htmlFor={`policy-${value}`} className="cursor-pointer">
                  <span className="block text-sm font-medium text-foreground">{label}</span>
                  <span className="block text-xs text-muted-foreground">{description}</span>
                </Label>
              </div>
            ))}
          </RadioGroup>
          {approvalPolicyError && (
            <p className="text-sm text-destructive mt-2" role="alert">{approvalPolicyError}</p>
          )}
        </CardContent>
      </Card>

      {/* Approval TTL */}
      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-base">Approval TTL</CardTitle>
          <CardDescription>
            Pending approval requests are auto-denied after this many seconds if not acted on.
          </CardDescription>
        </CardHeader>
        <CardContent className="pb-4 pt-0 space-y-4">
          <div className="flex items-center gap-3">
            <Label htmlFor="approval-ttl" className="whitespace-nowrap">
              Auto-deny after (seconds)
            </Label>
            <Input
              id="approval-ttl"
              type="number"
              min={10}
              max={approvalTtlMax}
              value={approvalTtl}
              disabled={ttlLoading}
              className="w-28"
              onChange={(e) => {
                const n = parseInt(e.target.value, 10)
                if (Number.isFinite(n) && n >= 10) setApprovalTtl(n)
              }}
            />
            <Button
              type="button"
              variant="default"
              disabled={ttlLoading}
              onClick={handleSaveTtl}
            >
              Save
            </Button>
          </div>
          {ttlError && (
            <p className="text-sm text-destructive mt-2" role="alert">{ttlError}</p>
          )}
        </CardContent>
      </Card>

      {/* ── Advanced mode toggle ───────────────────────────────────────────── */}
      <Card>
        <div className="flex items-center justify-between gap-6 px-6 py-5">
          <div className="flex flex-col gap-1">
            <p className="text-base font-semibold text-card-foreground">Advanced mode</p>
            <p className="text-sm text-muted-foreground">Shows additional settings intended for power users and developers.</p>
          </div>
          <Switch
            id="advanced-mode-toggle"
            checked={advancedMode}
            disabled={advancedLoading}
            onCheckedChange={(checked) => void handleToggleAdvanced(checked)}
            aria-label="Toggle advanced mode"
            className="shrink-0"
          />
        </div>
        {advancedError && <p className="px-6 pb-4 text-sm text-destructive" role="alert">{advancedError}</p>}
      </Card>

      {/* ── Advanced-only sections ─────────────────────────────────────────── */}

      {/* Credential backend */}
      {advancedMode && (
        <>
          <Card>
            <CardHeader className="pb-4">
              <CardTitle className="text-base">Credential backend</CardTitle>
              <CardDescription>
                Where Keylatch stores your vault key. Switching migrates your key and automatically restarts.
              </CardDescription>
            </CardHeader>
            <CardContent className="pb-4 pt-0 space-y-2">
              {backendsLoading && (
                <p role="status" aria-live="polite" className="text-sm text-muted-foreground">Loading…</p>
              )}
              {backendsError && !backendsLoading && (
                <div className="space-y-2">
                  <p className="text-sm text-destructive" role="alert">{backendsError}</p>
                  <Button type="button" variant="outline" size="sm" onClick={() => {
                    retryControllerRef.current?.abort()
                    const c = new AbortController()
                    retryControllerRef.current = c
                    fetchBackends(c.signal)
                  }}>Retry</Button>
                </div>
              )}
              {!backendsLoading && !backendsError && backends.map((b) => {
                const isCurrent = b.name === activeBackend
                return (
                  <div
                    key={b.name}
                    className={[
                      'flex items-center justify-between gap-4 rounded-lg border px-4 py-3 transition-colors',
                      isCurrent ? 'border-primary/40 bg-primary/5' : 'border-border bg-card',
                      !b.available ? 'opacity-50' : '',
                    ].join(' ')}
                  >
                    <div className="flex flex-col gap-0.5 min-w-0">
                      <span className="text-sm font-medium text-foreground flex items-center gap-2">
                        {b.display_name}
                        {isCurrent && (
                          <span className="inline-flex items-center rounded-full bg-emerald-100 dark:bg-emerald-950 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-300">
                            Current
                          </span>
                        )}
                        {!b.available && (
                          <span className="text-xs font-normal text-muted-foreground">Not available</span>
                        )}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {BACKEND_DESCRIPTIONS[b.name] ?? b.display_name}
                      </span>
                      {!b.available && b.install_hint && (
                        <span className="text-xs text-muted-foreground italic">{b.install_hint}</span>
                      )}
                    </div>
                    {!isCurrent && b.available && (
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={backendSwitching}
                        onClick={() => setPendingBackend(b.name)}
                        className="shrink-0"
                      >
                        Switch
                      </Button>
                    )}
                  </div>
                )
              })}
              {backendSwitching && (
                <div className="flex items-center gap-2 pt-1 text-sm text-muted-foreground" role="status" aria-live="polite">
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-border border-t-primary shrink-0" />
                  Migrating vault key… Keylatch will restart shortly.
                </div>
              )}

              {backendError && (
                <p className="text-sm text-destructive" role="alert">{backendError}</p>
              )}
            </CardContent>
          </Card>

          {/* Confirmation dialog */}
          {pendingBackend && (() => {
            const target = backends.find((b) => b.name === pendingBackend)
            return (
              <Dialog open onOpenChange={(open) => { if (!open) setPendingBackend(null) }}>
                <DialogContent className="sm:max-w-md">
                  <DialogHeader>
                    <DialogTitle>Switch to {target?.display_name}?</DialogTitle>
                  </DialogHeader>
                  <p className="text-sm text-muted-foreground">
                    Your vault key will be migrated to <strong className="text-foreground">{target?.display_name}</strong>.
                    Keylatch will restart automatically once migration completes.
                  </p>
                  <div className="flex justify-end gap-2 pt-2">
                    <Button variant="outline" onClick={() => setPendingBackend(null)}>Cancel</Button>
                    <Button onClick={() => void confirmSwitchBackend()}>Migrate</Button>
                  </div>
                </DialogContent>
              </Dialog>
            )
          })()}
        </>
      )}

      {/* Credential reference sources — advanced mode only */}
      {advancedMode && (
        <Card>
          <CardHeader className="pb-4">
            <CardTitle className="text-base">Credential reference sources</CardTitle>
            <CardDescription>
              These managers support URI references (<code className="font-mono text-xs">op://</code>, <code className="font-mono text-xs">aws-sm://</code>, <code className="font-mono text-xs">hashivault://</code>) — your credentials stay in the manager and Keylatch resolves them at runtime. Multiple can be active at once.
            </CardDescription>
          </CardHeader>
          <CardContent className="pb-4 pt-0">
            <div className="divide-y divide-border">
              {[
                { key: 'op' as const,        label: '1Password',           hint: 'brew install 1password-cli', scheme: 'op://' },
                { key: 'aws_sm' as const,     label: 'AWS Secrets Manager', hint: 'brew install awscli',        scheme: 'aws-sm://' },
                { key: 'hashivault' as const, label: 'HashiCorp Vault',     hint: 'brew install vault',         scheme: 'hashivault://' },
              ].map(({ key, label, hint, scheme }) => (
                <div key={key} className="flex flex-col gap-1 py-3 first:pt-0 last:pb-0">
                  <div className="flex items-center gap-2">
                    <span className={`h-2 w-2 shrink-0 rounded-full ${pmAvailable[key] ? 'bg-emerald-500' : 'bg-neutral-300'}`} aria-hidden="true" />
                    <span className="text-sm font-medium text-foreground">{label}</span>
                    <code className="text-xs font-mono text-muted-foreground">{scheme}</code>
                  </div>
                  {pmAvailable[key] ? (
                    <p className="pl-4 text-xs text-emerald-700">Detected — available for field references</p>
                  ) : (
                    <p className="pl-4 font-mono text-xs text-muted-foreground">Not installed — {hint}</p>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Telemetry — advanced mode only */}
      {advancedMode && (
        <Card>
          <div className="flex items-center justify-between gap-6 px-6 py-5">
            <div className="flex flex-col gap-1">
              <p className="text-base font-semibold text-card-foreground">Disable telemetry</p>
              <p className="text-sm text-muted-foreground">
                Disable all telemetry collection. Equivalent to setting{' '}
                <code className="text-xs bg-popover px-1 py-0.5 rounded">KEYLATCH_TELEMETRY_DISABLE=1</code>.
              </p>
            </div>
            <Switch
              id="telemetry-disable-toggle"
              checked={telemetryDisable}
              disabled={telemetryLoading}
              onCheckedChange={(checked) => void handleToggleTelemetry(checked)}
              aria-label="Toggle disable telemetry"
              className="shrink-0"
            />
          </div>
          {telemetryError && <p className="px-6 pb-4 text-sm text-destructive" role="alert">{telemetryError}</p>}
        </Card>
      )}

      {/* Experimental — advanced mode only */}
      {advancedMode && (
        <Card>
          <div className="flex items-center justify-between gap-6 px-6 py-5">
            <div className="flex flex-col gap-1">
              <p className="text-base font-semibold text-card-foreground">Experimental features</p>
              <p className="text-sm text-muted-foreground">
                Enable experimental features. Equivalent to setting{' '}
                <code className="text-xs bg-popover px-1 py-0.5 rounded">KEYLATCH_EXPERIMENTAL=1</code>.
              </p>
            </div>
            <Switch
              id="experimental-toggle"
              checked={experimental}
              disabled={experimentalLoading}
              onCheckedChange={(checked) => void handleToggleExperimental(checked)}
              aria-label="Toggle experimental features"
              className="shrink-0"
            />
          </div>
          {experimentalError && <p className="px-6 pb-4 text-sm text-destructive" role="alert">{experimentalError}</p>}
        </Card>
      )}

      {/* Danger zone */}
      <Card className="border-destructive/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-base text-destructive">Danger zone</CardTitle>
          <CardDescription>
            To clear all connections, type <strong>delete all</strong> below:
          </CardDescription>
        </CardHeader>
        <CardContent className="pb-4 pt-0 space-y-3">
          <Input
            type="text"
            value={clearInput}
            onChange={(e) => { setClearInput(e.target.value); setClearStatus('idle') }}
            placeholder='Type "delete all" to confirm'
            aria-label="Confirmation input"
          />
          {clearError && (
            <p className="text-sm text-destructive" role="alert">{clearError}</p>
          )}
          {clearStatus === 'done' && (
            <p className="text-sm text-emerald-700" role="status">
              All connections cleared.
            </p>
          )}
          <Button
            type="button"
            variant="destructive"
            disabled={!canClear || clearStatus === 'pending'}
            onClick={handleClearConnections}
          >
            {clearStatus === 'pending' ? 'Clearing…' : 'Clear all connections'}
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
