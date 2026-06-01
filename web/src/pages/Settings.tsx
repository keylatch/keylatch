import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '../lib/api'
import { ApiError } from '../lib/api'
import { safeInvoke } from '../lib/tauri'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

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
  const [clearInput, setClearInput] = useState('')
  const [clearError, setClearError] = useState<string | null>(null)
  const [clearStatus, setClearStatus] = useState<'idle' | 'pending' | 'done'>('idle')
  const canClear = clearInput === 'delete all'

  // Approval TTL: loaded from and saved to /api/settings (T-13-05).
  const [approvalTtl, setApprovalTtl] = useState<number>(DEFAULT_APPROVAL_TTL_S)
  const [approvalTtlMax, setApprovalTtlMax] = useState<number>(3600)
  const [ttlLoading, setTtlLoading] = useState(true)
  const [ttlSaved, setTtlSaved] = useState(false)
  const [ttlError, setTtlError] = useState<string | null>(null)

  // Advanced mode toggle.
  const [advancedMode, setAdvancedMode] = useState(false)
  const [advancedLoading, setAdvancedLoading] = useState(false)
  const [advancedSaved, setAdvancedSaved] = useState(false)
  const [advancedError, setAdvancedError] = useState<string | null>(null)

  // EPIC-27: Operating mode.
  const [operatingMode, setOperatingMode] = useState<OperatingMode>('standard')
  const [operatingModeSaved, setOperatingModeSaved] = useState(false)
  const [operatingModeError, setOperatingModeError] = useState<string | null>(null)

  // EPIC-27: Telemetry kill-switch.
  const [telemetryDisable, setTelemetryDisable] = useState(false)
  const [telemetryLoading, setTelemetryLoading] = useState(false)
  const [telemetrySaved, setTelemetrySaved] = useState(false)
  const [telemetryError, setTelemetryError] = useState<string | null>(null)

  // EPIC-27: Experimental opt-in.
  const [experimental, setExperimental] = useState(false)
  const [experimentalLoading, setExperimentalLoading] = useState(false)
  const [experimentalSaved, setExperimentalSaved] = useState(false)
  const [experimentalError, setExperimentalError] = useState<string | null>(null)

  // EPIC-27: Approval policy default.
  const [approvalPolicy, setApprovalPolicy] = useState<ApprovalPolicy>('prompt')
  const [approvalPolicySaved, setApprovalPolicySaved] = useState(false)
  const [approvalPolicyError, setApprovalPolicyError] = useState<string | null>(null)

  // Credential backend.
  const [backends, setBackends] = useState<BackendItem[]>([])
  const [backendsLoading, setBackendsLoading] = useState(true)
  const [backendsError, setBackendsError] = useState<string | null>(null)
  const [activeBackend, setActiveBackend] = useState<string>('')
  const [backendSwitching, setBackendSwitching] = useState(false)
  const [backendSaved, setBackendSaved] = useState(false)
  const [backendError, setBackendError] = useState<string | null>(null)
  const retryControllerRef = useRef<AbortController | null>(null)

  const fetchBackends = useCallback((signal?: AbortSignal) => {
    setBackendsLoading(true)
    setBackendsError(null)
    fetch('/v1/backends', { signal })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        return res.json() as Promise<BackendItem[]>
      })
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
          if (data.active_backend) {
            setActiveBackend(data.active_backend)
          }
          setTtlLoading(false)
        }
      })
      .catch(() => {
        if (!cancelled) {
          // Server unreachable or not yet upgraded — fall back to default, allow editing.
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

  // Once backends load, set activeBackend to first available if not already set from settings,
  // or if the value from settings is a name no longer present in the backends list (stale/renamed).
  useEffect(() => {
    if (backendsLoading || backends.length === 0) return
    const isValid = backends.some((b) => b.name === activeBackend)
    if (!isValid) {
      const firstAvailable = backends.find((b) => b.available)
      if (firstAvailable) setActiveBackend(firstAvailable.name)
    }
  }, [backendsLoading, backends, activeBackend])

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
    try {
      const data = await api.put<SettingsResponse>('/api/settings', {
        approval_ttl_seconds: approvalTtl,
      })
      // Use the server-returned (possibly clamped) value.
      setApprovalTtl(data.approval_ttl_seconds)
      setApprovalTtlMax(data.approval_ttl_max_seconds)
      setTtlSaved(true)
      setTimeout(() => setTtlSaved(false), 2000)
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to save TTL'
      setTtlError(msg)
    }
  }

  const handleSaveOperatingMode = async (mode: OperatingMode) => {
    const previous = operatingMode
    setOperatingModeError(null)
    setOperatingMode(mode)  // optimistic update
    try {
      const data = await api.put<SettingsResponse>('/api/settings', { operating_mode: mode })
      setOperatingMode(data.operating_mode)
      setOperatingModeSaved(true)
      setTimeout(() => setOperatingModeSaved(false), 2000)
    } catch (err) {
      setOperatingMode(previous)  // revert on error
      const msg = err instanceof ApiError ? err.message : 'Failed to save operating mode'
      setOperatingModeError(msg)
    }
  }

  const handleToggleTelemetry = async (disabled: boolean) => {
    setTelemetryError(null)
    setTelemetryDisable(disabled)
    setTelemetryLoading(true)
    try {
      const data = await api.put<SettingsResponse>('/api/settings', { telemetry_disable: disabled })
      setTelemetryDisable(data.telemetry_disable)
      setTelemetrySaved(true)
      setTimeout(() => setTelemetrySaved(false), 2000)
    } catch (err) {
      setTelemetryDisable(!disabled)
      const msg = err instanceof ApiError ? err.message : 'Failed to save telemetry setting'
      setTelemetryError(msg)
    } finally {
      setTelemetryLoading(false)
    }
  }

  const handleToggleExperimental = async (enabled: boolean) => {
    setExperimentalError(null)
    setExperimental(enabled)
    setExperimentalLoading(true)
    try {
      const data = await api.put<SettingsResponse>('/api/settings', { experimental: enabled })
      setExperimental(data.experimental)
      setExperimentalSaved(true)
      setTimeout(() => setExperimentalSaved(false), 2000)
    } catch (err) {
      setExperimental(!enabled)
      const msg = err instanceof ApiError ? err.message : 'Failed to save experimental setting'
      setExperimentalError(msg)
    } finally {
      setExperimentalLoading(false)
    }
  }

  const handleSaveApprovalPolicy = async (policy: ApprovalPolicy) => {
    const previous = approvalPolicy
    setApprovalPolicyError(null)
    setApprovalPolicy(policy)  // optimistic update
    try {
      const data = await api.put<SettingsResponse>('/api/settings', { approval_policy: policy })
      setApprovalPolicy(data.approval_policy)
      setApprovalPolicySaved(true)
      setTimeout(() => setApprovalPolicySaved(false), 2000)
    } catch (err) {
      setApprovalPolicy(previous)  // revert on error
      const msg = err instanceof ApiError ? err.message : 'Failed to save approval policy'
      setApprovalPolicyError(msg)
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
    try {
      const payload: Record<string, unknown> = { advanced_mode: enabled }
      if (revertMode) payload.operating_mode = 'standard'
      const data = await api.put<SettingsResponse>('/api/settings', payload)
      setAdvancedMode(data.advanced_mode)
      if (revertMode) setOperatingMode(data.operating_mode)
      setAdvancedSaved(true)
      setTimeout(() => setAdvancedSaved(false), 2000)
    } catch (err) {
      setAdvancedMode(!enabled)
      if (revertMode) setOperatingMode(operatingMode)
      const msg = err instanceof ApiError ? err.message : 'Failed to save advanced mode'
      setAdvancedError(msg)
    } finally {
      setAdvancedLoading(false)
    }
  }

  const handleSwitchBackend = async (newBackend: string) => {
    const previous = activeBackend
    setBackendError(null)
    setActiveBackend(newBackend)  // optimistic update
    setBackendSwitching(true)
    try {
      const result = await safeInvoke<{ ok: boolean; error?: string }>('bootstrap', { backend: newBackend })
      if (!result.ok) {
        setActiveBackend(previous)  // revert on failure
        setBackendError(result.error ?? 'Backend switch failed')
        return
      }
      setBackendSaved(true)
      setTimeout(() => setBackendSaved(false), 2000)
    } catch (e) {
      setActiveBackend(previous)  // revert on failure
      setBackendError(e instanceof Error ? e.message : 'Backend switch failed')
    } finally {
      setBackendSwitching(false)
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-8">
      <h2 className="text-2xl font-semibold text-[var(--color-text-primary)]">Settings</h2>

      <section aria-label="Demo mode" className="space-y-2">
        <h3 className="text-lg font-medium text-[var(--color-text-primary)]">Demo mode</h3>
        <p className="text-sm text-[var(--color-text-secondary)]">
          Demo mode uses stub data and does not access real credentials.
        </p>
      </section>

      <section aria-label="Advanced mode" className="space-y-3">
        <h3 className="text-lg font-medium text-[var(--color-text-primary)]">Advanced mode</h3>
        <p className="text-sm text-[var(--color-text-secondary)]">
          When enabled, each panel shows additional settings intended for power users and developers.
        </p>
        <div className="flex items-center gap-3">
          <button
            id="advanced-mode-toggle"
            type="button"
            role="switch"
            aria-checked={advancedMode}
            aria-label="Advanced mode toggle"
            disabled={advancedLoading}
            onClick={() => void handleToggleAdvanced(!advancedMode)}
            className={[
              'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent',
              'transition-colors duration-200 ease-in-out',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)] focus-visible:ring-offset-2',
              'disabled:opacity-50 disabled:cursor-not-allowed',
              advancedMode ? 'bg-[var(--color-primary-600)]' : 'bg-[var(--color-neutral-300)]',
            ].join(' ')}
          >
            <span
              aria-hidden="true"
              className={[
                'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow ring-0',
                'transition duration-200 ease-in-out',
                advancedMode ? 'translate-x-5' : 'translate-x-0',
              ].join(' ')}
            />
          </button>
          <Label htmlFor="advanced-mode-toggle" className="text-sm">
            {advancedMode ? 'Advanced mode on' : 'Advanced mode off'}
          </Label>
          {advancedSaved && (
            <span className="text-xs text-[var(--color-success-dark)]" role="status">Saved!</span>
          )}
        </div>
        {advancedError && (
          <p className="text-sm text-[var(--color-danger)]" role="alert">{advancedError}</p>
        )}
      </section>

      {/* EPIC-27: Operating mode — all options in one section; developer options gated behind advancedMode. */}
      <section aria-label="Operating mode" className="space-y-3">
        <h3 className="text-lg font-medium text-[var(--color-text-primary)]">Operating mode</h3>
        <p className="text-sm text-[var(--color-text-secondary)]">
          Controls how Keylatch routes credentials and which features are enabled.
        </p>
        <fieldset className="space-y-2">
          <legend className="sr-only">Operating mode</legend>
          {(
            [
              { value: 'standard', label: 'Standard', description: 'Stable production mode.' },
              { value: 'telemetry', label: 'Telemetry', description: 'Standard plus anonymous usage telemetry.' },
            ] as { value: OperatingMode; label: string; description: string }[]
          ).map(({ value, label, description }) => (
            <label
              key={value}
              className="flex items-start gap-3 cursor-pointer"
            >
              <input
                type="radio"
                name="operating-mode"
                value={value}
                checked={operatingMode === value}
                onChange={() => void handleSaveOperatingMode(value)}
                className="mt-0.5 h-4 w-4"
                aria-label={label}
              />
              <span>
                <span className="block text-sm font-medium text-[var(--color-text-primary)]">{label}</span>
                <span className="block text-xs text-[var(--color-text-secondary)]">{description}</span>
              </span>
            </label>
          ))}

          {advancedMode && (
            <>
              <div className="flex items-center gap-2 pt-1">
                <div className="h-px flex-1 bg-[var(--color-border)]" aria-hidden="true" />
                <span className="text-xs text-[var(--color-text-disabled)]">Developer</span>
                <div className="h-px flex-1 bg-[var(--color-border)]" aria-hidden="true" />
              </div>
              {(
                [
                  { value: 'canary', label: 'Canary', description: 'Pre-release features — may be unstable.' },
                  { value: 'custom', label: 'Custom', description: 'Fully custom configuration.' },
                ] as { value: OperatingMode; label: string; description: string }[]
              ).map(({ value, label, description }) => (
                <label
                  key={value}
                  className="flex items-start gap-3 cursor-pointer"
                >
                  <input
                    type="radio"
                    name="operating-mode"
                    value={value}
                    checked={operatingMode === value}
                    onChange={() => void handleSaveOperatingMode(value)}
                    className="mt-0.5 h-4 w-4"
                    aria-label={label}
                  />
                  <span>
                    <span className="block text-sm font-medium text-[var(--color-text-primary)]">{label}</span>
                    <span className="block text-xs text-[var(--color-text-secondary)]">{description}</span>
                  </span>
                </label>
              ))}
            </>
          )}
        </fieldset>
        {operatingModeSaved && (
          <p className="text-xs text-[var(--color-success-dark)]" role="status">Saved!</p>
        )}
        {operatingModeError && (
          <p className="text-sm text-[var(--color-danger)]" role="alert">{operatingModeError}</p>
        )}
      </section>

      {/* EPIC-27: Telemetry kill-switch — visible in advanced mode only. */}
      {advancedMode && (
        <section aria-label="Telemetry" className="space-y-3">
          <h3 className="text-lg font-medium text-[var(--color-text-primary)]">Telemetry</h3>
          <p className="text-sm text-[var(--color-text-secondary)]">
            Disable all telemetry collection. Equivalent to setting{' '}
            <code className="text-xs bg-[var(--color-surface-overlay)] px-1 py-0.5 rounded">
              KEYLATCH_TELEMETRY_DISABLE=1
            </code>.
          </p>
          <div className="flex items-center gap-3">
            <button
              id="telemetry-disable-toggle"
              type="button"
              role="switch"
              aria-checked={telemetryDisable}
              aria-label="Disable telemetry"
              disabled={telemetryLoading}
              onClick={() => void handleToggleTelemetry(!telemetryDisable)}
              className={[
                'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent',
                'transition-colors duration-200 ease-in-out',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)] focus-visible:ring-offset-2',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                telemetryDisable ? 'bg-[var(--color-primary-600)]' : 'bg-[var(--color-neutral-300)]',
              ].join(' ')}
            >
              <span
                aria-hidden="true"
                className={[
                  'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow ring-0',
                  'transition duration-200 ease-in-out',
                  telemetryDisable ? 'translate-x-5' : 'translate-x-0',
                ].join(' ')}
              />
            </button>
            <Label htmlFor="telemetry-disable-toggle" className="text-sm">
              {telemetryDisable ? 'Telemetry disabled' : 'Telemetry enabled'}
            </Label>
            {telemetrySaved && (
              <span className="text-xs text-[var(--color-success-dark)]" role="status">Saved!</span>
            )}
          </div>
          {telemetryError && (
            <p className="text-sm text-[var(--color-danger)]" role="alert">{telemetryError}</p>
          )}
        </section>
      )}

      {/* EPIC-27: Experimental opt-in — visible in advanced mode only. */}
      {advancedMode && (
        <section aria-label="Experimental features" className="space-y-3">
          <h3 className="text-lg font-medium text-[var(--color-text-primary)]">Experimental features</h3>
          <p className="text-sm text-[var(--color-text-secondary)]">
            Enable experimental features. Equivalent to setting{' '}
            <code className="text-xs bg-[var(--color-surface-overlay)] px-1 py-0.5 rounded">
              KEYLATCH_EXPERIMENTAL=1
            </code>.
          </p>
          <div className="flex items-center gap-3">
            <button
              id="experimental-toggle"
              type="button"
              role="switch"
              aria-checked={experimental}
              aria-label="Enable experimental features"
              disabled={experimentalLoading}
              onClick={() => void handleToggleExperimental(!experimental)}
              className={[
                'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent',
                'transition-colors duration-200 ease-in-out',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)] focus-visible:ring-offset-2',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                experimental ? 'bg-[var(--color-primary-600)]' : 'bg-[var(--color-neutral-300)]',
              ].join(' ')}
            >
              <span
                aria-hidden="true"
                className={[
                  'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow ring-0',
                  'transition duration-200 ease-in-out',
                  experimental ? 'translate-x-5' : 'translate-x-0',
                ].join(' ')}
              />
            </button>
            <Label htmlFor="experimental-toggle" className="text-sm">
              {experimental ? 'Experimental features on' : 'Experimental features off'}
            </Label>
            {experimentalSaved && (
              <span className="text-xs text-[var(--color-success-dark)]" role="status">Saved!</span>
            )}
          </div>
          {experimentalError && (
            <p className="text-sm text-[var(--color-danger)]" role="alert">{experimentalError}</p>
          )}
        </section>
      )}

      {/* EPIC-27: Approval policy default. */}
      <section aria-label="Approval policy" className="space-y-3">
        <h3 className="text-lg font-medium text-[var(--color-text-primary)]">Approval policy</h3>
        <p className="text-sm text-[var(--color-text-secondary)]">
          Default action when an agent requests credential access.
        </p>
        <fieldset className="space-y-2">
          <legend className="sr-only">Approval policy</legend>
          {(
            [
              { value: 'prompt', label: 'Prompt', description: 'Always ask before approving (default).' },
              { value: 'first-run', label: 'First-run', description: 'Auto-approve once per session; deny subsequent requests.' },
              { value: 'trust', label: 'Trust', description: 'Auto-approve all requests from this connection.' },
            ] as { value: ApprovalPolicy; label: string; description: string }[]
          ).map(({ value, label, description }) => (
            <label
              key={value}
              className="flex items-start gap-3 cursor-pointer"
            >
              <input
                type="radio"
                name="approval-policy"
                value={value}
                checked={approvalPolicy === value}
                onChange={() => void handleSaveApprovalPolicy(value)}
                className="mt-0.5 h-4 w-4"
                aria-label={label}
              />
              <span>
                <span className="block text-sm font-medium text-[var(--color-text-primary)]">{label}</span>
                <span className="block text-xs text-[var(--color-text-secondary)]">{description}</span>
              </span>
            </label>
          ))}
        </fieldset>
        {approvalPolicySaved && (
          <p className="text-xs text-[var(--color-success-dark)]" role="status">Saved!</p>
        )}
        {approvalPolicyError && (
          <p className="text-sm text-[var(--color-danger)]" role="alert">{approvalPolicyError}</p>
        )}
      </section>

      <section aria-label="Approval TTL" className="space-y-3">
        <h3 className="text-lg font-medium text-[var(--color-text-primary)]">Approval TTL</h3>
        <p className="text-sm text-[var(--color-text-secondary)]">
          Pending approval requests are auto-denied after this many seconds if not acted on.
        </p>
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
            variant={ttlSaved ? 'secondary' : 'default'}
            disabled={ttlLoading}
            onClick={handleSaveTtl}
          >
            {ttlSaved ? 'Saved!' : 'Save'}
          </Button>
        </div>
        {ttlError && (
          <p className="text-sm text-[var(--color-danger)]" role="alert">{ttlError}</p>
        )}
        {ttlSaved && (
          <p className="text-sm text-[var(--color-success-dark)]" role="status">
            Approval TTL updated.
          </p>
        )}
      </section>

      {/* Credential backend — switch vault storage backend from the UI. */}
      <section aria-label="Credential backend" className="space-y-3">
        <h3 className="text-lg font-medium text-[var(--color-text-primary)]">Credential backend</h3>
        <p className="text-sm text-[var(--color-text-secondary)]">
          Choose where Keylatch stores your vault key.
        </p>

        {backendsLoading && (
          <p role="status" aria-live="polite" className="text-sm text-[var(--color-text-secondary)]">
            Loading backends…
          </p>
        )}

        {backendsError && !backendsLoading && (
          <div className="space-y-2">
            <p className="text-sm text-[var(--color-danger)]" role="alert">{backendsError}</p>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                retryControllerRef.current?.abort()
                const c = new AbortController()
                retryControllerRef.current = c
                fetchBackends(c.signal)
              }}
            >
              Retry
            </Button>
          </div>
        )}

        {!backendsLoading && !backendsError && backends.length > 0 && (
          <fieldset className="space-y-2" disabled={backendSwitching}>
            <legend className="sr-only">Credential backend</legend>
            {backends.map((b) => (
              <label
                key={b.name}
                className={[
                  'flex items-start gap-3',
                  b.available ? 'cursor-pointer' : 'cursor-not-allowed opacity-50',
                ].join(' ')}
              >
                <input
                  type="radio"
                  name="credential-backend"
                  value={b.name}
                  checked={activeBackend === b.name}
                  disabled={!b.available || backendSwitching}
                  onChange={() => void handleSwitchBackend(b.name)}
                  className="mt-0.5 h-4 w-4"
                  aria-label={b.display_name}
                />
                <span>
                  <span className="block text-sm font-medium text-[var(--color-text-primary)]">
                    {b.display_name}
                    {!b.available && ' (not available)'}
                  </span>
                  <span className="block text-xs text-[var(--color-text-secondary)]">
                    {BACKEND_DESCRIPTIONS[b.name] ?? b.display_name}
                  </span>
                  {!b.available && b.install_hint && (
                    <span className="block text-xs text-[var(--color-text-secondary)]">
                      {b.install_hint}
                    </span>
                  )}
                </span>
              </label>
            ))}
          </fieldset>
        )}

        <p className="text-xs text-[var(--color-warning,#b45309)]" role="note">
          Switching migrates your vault key and restarts Keylatch.
        </p>

        {backendSwitching && (
          <p role="status" aria-live="polite" className="text-xs text-[var(--color-text-secondary)]">
            Switching backend…
          </p>
        )}
        {backendSaved && !backendSwitching && (
          <p className="text-xs text-[var(--color-success-dark)]" role="status">Backend updated</p>
        )}
        {backendError && (
          <p className="text-sm text-[var(--color-danger)]" role="alert">{backendError}</p>
        )}
      </section>

      <section aria-label="Danger zone" className="space-y-3">
        <h3 className="text-lg font-medium text-[var(--color-danger-dark)]">Danger zone</h3>
        <p className="text-sm text-[var(--color-text-secondary)]">
          To clear all connections, type <strong>delete all</strong> below:
        </p>
        <Input
          type="text"
          value={clearInput}
          onChange={(e) => { setClearInput(e.target.value); setClearStatus('idle') }}
          placeholder='Type "delete all" to confirm'
          aria-label="Confirmation input"
        />
        {clearError && (
          <p className="text-sm text-[var(--color-danger)]" role="alert">{clearError}</p>
        )}
        {clearStatus === 'done' && (
          <p className="text-sm text-[var(--color-success-dark)]" role="status">
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
      </section>
    </div>
  )
}
