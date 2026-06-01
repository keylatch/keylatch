/**
 * ProviderWizard — multi-step sheet for adding a new provider connection.
 *
 * Step 1: pick a provider from the template catalogue
 * Step 2: configure per-field storage modes (direct / reference)
 *   Sub-view: PM browse inline (browseState) — no second Sheet
 *
 * Implemented in T-14-03.
 */

import { useState, useEffect } from 'react'
import { FieldInput } from './FieldInput'
import type { PMScheme } from './FieldInput'
import { PMBrowseBody, PM_LABELS } from './PMBrowseModal'
import { WizardStepper } from './WizardStepper'
import { ProviderBadge } from './ProviderBadge'
import {
  Sheet,
  SheetContent,
  SheetTitle,
  SheetClose,
} from '@/components/ui/sheet'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '../lib/api'
import { useConnections } from '../stores/connections'
import type { CreateConnectionPayload } from '../stores/connections'

interface ProviderTemplate {
  slug: string
  display_name: string
  category: string
  docs_url: string
  runtime_modes: string[]
}

interface SecretField {
  name: string
  label: string
  required: boolean
}

interface ProviderDetail {
  slug: string
  display_name: string
  category: string
  fields: SecretField[]
}

// ── Field state ───────────────────────────────────────────────────────────────

interface FieldState {
  id: string        // stable — never changes after creation
  name: string      // derived from label, used as credential key
  label: string
  required: boolean
  mode: 'direct' | 'reference'
  value: string
  uri: string
  error: string | null
}

// ── Props ────────────────────────────────────────────────────────────────────

interface ProviderWizardProps {
  onSuccess: () => Promise<void>
  onClose: () => void
}

const WIZARD_STEPS = [
  { label: 'Choose provider' },
  { label: 'Configure fields' },
]

/**
 * ProviderWizard — two-step dialog for adding a provider connection.
 * PM browse is rendered as an inline sub-view within the same Sheet.
 */
export function ProviderWizard({ onSuccess, onClose }: ProviderWizardProps) {
  const [step, setStep] = useState(0)
  const [providers, setProviders] = useState<ProviderTemplate[]>([])
  const [search, setSearch] = useState('')
  const [selectedProvider, setSelectedProvider] = useState<ProviderTemplate | null>(null)
  const [showCustomForm, setShowCustomForm] = useState(false)
  const [customName, setCustomName] = useState('')
  const [customSlug, setCustomSlug] = useState('')
  const [customSlugTouched, setCustomSlugTouched] = useState(false)
  const [connectionName, setConnectionName] = useState('')
  const [connectionNameError, setConnectionNameError] = useState<string | null>(null)
  const [fields, setFields] = useState<FieldState[]>([])
  const [fieldsLoading, setFieldsLoading] = useState(false)
  const [fieldsError, setFieldsError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)

  // PM browse sub-view state — when set, the wizard body shows PMBrowseBody.
  const [browseState, setBrowseState] = useState<{ fieldName: string; scheme: PMScheme } | null>(null)

  // Available password managers fetched on mount.
  const [availablePMs, setAvailablePMs] = useState<{ op: boolean; aws_sm: boolean; hashivault: boolean }>({
    op: false,
    aws_sm: false,
    hashivault: false,
  })

  // Advanced mode — fetched from /api/settings on mount.
  const [advancedMode, setAdvancedMode] = useState(false)

  const { createConnection } = useConnections()

  // Fetch provider catalogue on mount.
  useEffect(() => {
    api.get<ProviderTemplate[]>('/v1/providers')
      .then(setProviders)
      .catch(() => {
        // Fallback to empty list — user will see no options.
      })
  }, [])

  // Fetch available password managers on mount.
  useEffect(() => {
    api.get<{ op: boolean; aws_sm: boolean; hashivault: boolean }>('/api/password-managers')
      .then(setAvailablePMs)
      .catch(() => {
        // Default all false — Browse button hidden when we cannot determine availability.
      })
  }, [])

  // Fetch advanced_mode from settings on mount.
  useEffect(() => {
    api.get<{ advanced_mode: boolean }>('/api/settings')
      .then((data) => setAdvancedMode(data.advanced_mode ?? false))
      .catch(() => {
        // Default false — reference mode link hidden when settings are unreachable.
      })
  }, [])

  const slugify = (s: string) =>
    s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63)

  // Initialize a default credential field when the custom form opens.
  useEffect(() => {
    if (showCustomForm) {
      setFields([{ id: 'f0', name: 'credential', label: 'Credential', required: true, mode: 'direct', value: '', uri: '', error: null }])
    }
  }, [showCustomForm])

  const handleCustomSubmit = async () => {
    const slug = customSlug.trim() || slugify(customName)
    if (!customName.trim() || !slug) return

    let hasError = false
    const validated = fields.map((f) => {
      if (f.mode === 'direct' && f.required && !f.value.trim()) {
        hasError = true
        return { ...f, error: `${f.label} is required` }
      }
      if (f.mode === 'reference' && !f.uri.trim()) {
        hasError = true
        return { ...f, error: 'Reference URI is required' }
      }
      return { ...f, error: null }
    })
    setFields(validated)
    if (hasError) return

    const payload: CreateConnectionPayload = {
      provider: slug,
      account: customName.trim(),
      fields: fields.map((f) => ({
        name: f.name,
        mode: f.mode,
        ...(f.mode === 'direct' ? { value: f.value } : { uri: f.uri }),
      })),
    }

    setSubmitting(true)
    setSubmitError(null)
    try {
      await createConnection(payload)
      await onSuccess()
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : 'Failed to create connection')
    } finally {
      setSubmitting(false)
    }
  }

  const handleAddField = () => {
    setFields((prev) => [
      ...prev,
      { id: `f${prev.length}`, name: `field_${prev.length + 1}`, label: `Field ${prev.length + 1}`, required: false, mode: 'direct', value: '', uri: '', error: null },
    ])
  }

  const handleRemoveField = (name: string) => {
    setFields((prev) => prev.filter((f) => f.name !== name))
  }

  const handleSelectProvider = async (tmpl: ProviderTemplate) => {
    setSelectedProvider(tmpl)
    setConnectionName(tmpl.display_name)
    setConnectionNameError(null)
    setFieldsLoading(true)
    setFieldsError(null)
    setStep(1)
    try {
      const detail = await api.get<ProviderDetail>(`/v1/providers/${tmpl.slug}`)
      const schemaFields: SecretField[] = detail.fields.length > 0
        ? detail.fields
        : [{ name: 'api_key', label: 'API Key', required: true }]
      setFields(
        schemaFields.map((f, i) => ({
          id: `f${i}`,
          name: f.name,
          label: f.label || f.name,
          required: f.required,
          mode: 'direct',
          value: '',
          uri: '',
          error: null,
        }))
      )
    } catch {
      setFieldsError('Failed to load field schema. Please try again.')
      setFields([{
        id: 'f0',
        name: 'api_key',
        label: 'API Key',
        required: true,
        mode: 'direct',
        value: '',
        uri: '',
        error: null,
      }])
    } finally {
      setFieldsLoading(false)
    }
  }

  const handleFieldChange = (
    name: string,
    patch: Partial<Pick<FieldState, 'mode' | 'value' | 'uri' | 'error'>>
  ) => {
    setFields((prev) =>
      prev.map((f) => (f.name === name ? { ...f, ...patch } : f))
    )
  }

  const handleSubmit = async () => {
    if (!selectedProvider) return

    // Validate connection name.
    if (!connectionName.trim()) {
      setConnectionNameError('Connection name is required')
      return
    }
    setConnectionNameError(null)

    // Validate fields.
    let hasError = false
    const validated = fields.map((f) => {
      if (f.mode === 'direct' && f.required && !f.value.trim()) {
        hasError = true
        return { ...f, error: `${f.label} is required` }
      }
      if (f.mode === 'reference' && !f.uri.trim()) {
        hasError = true
        return { ...f, error: 'Reference URI is required' }
      }
      return { ...f, error: null }
    })
    setFields(validated)
    if (hasError) return

    const payload: CreateConnectionPayload = {
      provider: selectedProvider.slug,
      account: connectionName.trim() || undefined,
      fields: fields.map((f) => ({
        name: f.name,
        mode: f.mode,
        ...(f.mode === 'direct' ? { value: f.value } : { uri: f.uri }),
      })),
    }

    setSubmitting(true)
    setSubmitError(null)
    try {
      await createConnection(payload)
      await onSuccess()
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : 'Failed to create connection')
    } finally {
      setSubmitting(false)
    }
  }

  // ── Header title + back action ───────────────────────────────────────────

  const headerTitle = (() => {
    if (browseState) return `Browse ${PM_LABELS[browseState.scheme]}`
    if (step === 1) return selectedProvider?.display_name ?? 'Configure'
    if (showCustomForm) return 'Custom provider'
    return 'Add Provider'
  })()

  const handleBackClick = () => {
    if (browseState) { setBrowseState(null); return }
    if (showCustomForm) {
      setShowCustomForm(false)
      setCustomName('')
      setCustomSlug('')
      setCustomSlugTouched(false)
      return
    }
    setStep(0)
  }

  const showBackButton = browseState !== null || step === 1 || showCustomForm

  return (
    <Sheet open onOpenChange={(open) => { if (!open) onClose() }}>
      <SheetContent side="right" hideCloseButton className="flex flex-col gap-0 p-0 w-full sm:max-w-lg bg-background">
        {/* Header */}
        <div className="flex items-center justify-between px-6 h-14 shrink-0 border-b border-border">
          <div className="flex items-center gap-2">
            {showBackButton && (
              <button
                type="button"
                onClick={handleBackClick}
                aria-label="Go back"
                className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
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
                  <path d="m15 18-6-6 6-6" />
                </svg>
              </button>
            )}
            <SheetTitle className="text-base font-semibold">
              {headerTitle}
            </SheetTitle>
          </div>
          <SheetClose asChild>
            <button
              type="button"
              aria-label="Close wizard"
              className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
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
                <path d="M18 6 6 18" />
                <path d="m6 6 12 12" />
              </svg>
            </button>
          </SheetClose>
        </div>

        {/* Step content — scrollable */}
        <div className="flex-1 overflow-y-auto">
          {/* PM Browse sub-view — rendered inline, no second Sheet */}
          {browseState && (
            <PMBrowseBody
              pm={browseState.scheme}
              onSelect={(selectedUri) => {
                handleFieldChange(browseState.fieldName, { uri: selectedUri, error: null })
                setBrowseState(null)
              }}
              onBack={() => setBrowseState(null)}
            />
          )}

          {/* Custom provider form — full-step view */}
          {!browseState && step === 0 && showCustomForm && (
            <div className="flex flex-col gap-5 px-6 py-5">
              <p className="text-sm text-muted-foreground">
                For any service without a built-in template — internal APIs, private services, OAuth tokens, or webhooks.
              </p>

              {/* Name */}
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="custom-name">Name <span className="text-destructive">*</span></Label>
                <Input
                  id="custom-name"
                  value={customName}
                  onChange={(e) => {
                    setCustomName(e.target.value)
                    if (!customSlugTouched) setCustomSlug(slugify(e.target.value))
                  }}
                  placeholder="e.g. Internal billing API"
                  autoFocus
                />
              </div>

              {/* Slug */}
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="custom-slug">
                  Slug <span className="text-xs font-normal text-muted-foreground">(auto-generated)</span>
                </Label>
                <Input
                  id="custom-slug"
                  value={customSlug}
                  onChange={(e) => { setCustomSlug(slugify(e.target.value)); setCustomSlugTouched(true) }}
                  placeholder="internal-billing-api"
                  className="font-mono"
                />
                <p className="text-xs text-muted-foreground">CLI identifier: <code className="font-mono">keylatch run {customSlug || 'your-slug'} -- …</code></p>
              </div>

              {/* Credential fields */}
              <div className="border-t border-border pt-4 flex flex-col gap-4">
                <p className="text-base font-semibold text-foreground">Credentials</p>
                {fields.map((f, idx) => (
                  <div key={f.id} className="flex flex-col gap-2">
                    <div className="flex flex-col gap-1.5">
                      <Label htmlFor={`custom-field-label-${f.name}`}>Field name</Label>
                      <div className="flex items-center gap-2">
                        <Input
                          id={`custom-field-label-${f.name}`}
                          value={f.label}
                          onChange={(e) => {
                            const label = e.target.value
                            const name = label.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || `field_${idx + 1}`
                            setFields((prev) => prev.map((x) => x.name === f.name ? { ...x, label, name } : x))
                          }}
                          placeholder="e.g. API Key, Bearer Token…"
                          className="flex-1"
                        />
                        {fields.length > 1 && (
                          <button
                            type="button"
                            onClick={() => handleRemoveField(f.name)}
                            className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-destructive transition-colors"
                            aria-label={`Remove ${f.label}`}
                          >
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
                          </button>
                        )}
                      </div>
                    </div>
                    <FieldInput
                      fieldName={f.name}
                      label={f.label}
                      required={f.required}
                      mode={f.mode}
                      value={f.value}
                      uri={f.uri}
                      error={f.error}
                      advancedMode={advancedMode}
                      availablePMs={availablePMs}
                      onModeChange={(mode) => handleFieldChange(f.name, { mode, error: null })}
                      onValueChange={(value) => handleFieldChange(f.name, { value, error: null })}
                      onUriChange={(uri) => handleFieldChange(f.name, { uri, error: null })}
                      onBrowseRequest={(scheme) => setBrowseState({ fieldName: f.name, scheme })}
                    />
                  </div>
                ))}
                <button
                  type="button"
                  onClick={handleAddField}
                  className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors w-fit"
                >
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 5v14"/><path d="M5 12h14"/></svg>
                  Add field
                </button>
              </div>

              {submitError && (
                <div role="alert" className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {submitError}
                </div>
              )}
            </div>
          )}

          {/* Step 0: pick provider */}
          {!browseState && step === 0 && !showCustomForm && (
            <div data-testid="wizard-step-pick" className="flex flex-col gap-2 px-6 py-4">
              {providers.length === 0 ? (
                <div className="flex items-center gap-2 py-3 text-sm text-muted-foreground" aria-busy="true">
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-border border-t-primary" />
                  Loading providers…
                </div>
              ) : (
                <>
                  {/* Search */}
                  <div className="relative mb-1">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      width="14"
                      height="14"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground"
                      aria-hidden="true"
                    >
                      <circle cx="11" cy="11" r="8" />
                      <path d="m21 21-4.3-4.3" />
                    </svg>
                    <Input
                      type="search"
                      placeholder="Search providers…"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      className="pl-8"
                      aria-label="Search providers"
                    />
                  </div>

                  {/* Provider list */}
                  {(() => {
                    const q = search.toLowerCase()
                    const filtered = q
                      ? providers.filter(
                          (p) =>
                            p.display_name.toLowerCase().includes(q) ||
                            p.category.toLowerCase().includes(q)
                        )
                      : providers

                    if (filtered.length === 0) {
                      return (
                        <p className="py-4 text-center text-sm text-muted-foreground">
                          No providers found
                        </p>
                      )
                    }

                    return (
                      <>
                        <ul className="flex flex-col gap-1.5" role="listbox" aria-label="Provider catalogue">
                          {filtered.map((p) => (
                            <li key={p.slug} role="option" aria-selected={selectedProvider?.slug === p.slug}>
                              <button
                                type="button"
                                className="w-full flex items-center gap-3 rounded-lg border border-border bg-background px-3 py-3 text-left hover:bg-accent hover:border-primary/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 transition-colors"
                                onClick={() => { setShowCustomForm(false); void handleSelectProvider(p) }}
                                aria-label={`Select ${p.display_name}`}
                              >
                                <ProviderBadge provider={p.slug} className="h-8 w-8 text-xs" />
                                <div className="flex flex-col min-w-0 flex-1">
                                  <span className="text-sm font-medium text-foreground">{p.display_name}</span>
                                  <span className="text-xs text-muted-foreground capitalize">{p.category}</span>
                                </div>
                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-muted-foreground shrink-0" aria-hidden="true">
                                  <path d="m9 18 6-6-6-6" />
                                </svg>
                              </button>
                            </li>
                          ))}
                        </ul>

                        {/* Custom provider trigger */}
                        <div className="mt-2 border-t border-border pt-3">
                          <button
                            type="button"
                            className="w-full flex items-center gap-3 rounded-lg border border-dashed border-border px-3 py-3 text-left hover:bg-accent hover:border-primary/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring transition-colors"
                            onClick={() => setShowCustomForm(true)}
                          >
                            <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted text-muted-foreground text-lg font-light">+</span>
                            <div className="flex flex-col min-w-0 flex-1">
                              <span className="text-sm font-medium text-foreground">Custom provider</span>
                              <span className="text-xs text-muted-foreground">Any service without a built-in template</span>
                            </div>
                          </button>
                        </div>
                      </>
                    )
                  })()}
                </>
              )}
            </div>
          )}

          {/* Step 1: configure fields */}
          {!browseState && step === 1 && selectedProvider && (
            <div data-testid="wizard-step-fields" className="flex flex-col gap-5 px-6 py-4">
              {/* Provider context */}
              <div className="flex items-center gap-3 rounded-lg border border-border bg-card px-3 py-2.5">
                <ProviderBadge provider={selectedProvider.slug} className="h-8 w-8 text-xs" />
                <div>
                  <p className="text-sm font-medium text-foreground">{connectionName.trim() || selectedProvider.display_name}</p>
                  <p className="text-xs text-muted-foreground capitalize">{selectedProvider.category}</p>
                </div>
              </div>

              {/* Connection name */}
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="wizard-connection-name">
                  Connection name
                  <span className="text-destructive ml-0.5" aria-hidden="true"> *</span>
                </Label>
                <Input
                  id="wizard-connection-name"
                  type="text"
                  value={connectionName}
                  onChange={(e) => {
                    setConnectionName(e.target.value)
                    setConnectionNameError(null)
                  }}
                  placeholder={selectedProvider.display_name}
                  aria-required
                  aria-invalid={!!connectionNameError}
                  aria-describedby={connectionNameError ? 'wizard-name-error' : undefined}
                />
                {connectionNameError && (
                  <p id="wizard-name-error" role="alert" className="text-xs text-destructive">
                    {connectionNameError}
                  </p>
                )}
                <p className="text-xs text-muted-foreground">
                  A label to identify this connection in your vault.
                </p>
              </div>

              {/* Divider */}
              <div className="border-t border-border" />

              {/* Field schema loading */}
              {fieldsLoading && (
                <div className="flex items-center gap-2 py-1 text-sm text-muted-foreground" aria-busy="true">
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-border border-t-primary" />
                  Loading field schema…
                </div>
              )}

              {fieldsError && (
                <div role="alert" className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-800">
                  {fieldsError}
                </div>
              )}

              {/* Credential fields */}
              {!fieldsLoading && fields.length > 0 && (
                <div className="flex flex-col gap-4">
                  <p className="text-base font-semibold text-foreground">
                    Credential fields
                  </p>
                  {fields.map((f, idx) => (
                    <div key={f.id} className="flex flex-col gap-2">
                      {selectedProvider?.category === 'custom' && (
                        <div className="flex flex-col gap-1.5">
                          <Label htmlFor={`field-label-${f.name}`}>Field name</Label>
                          <div className="flex items-center gap-2">
                          <Input
                            id={`field-label-${f.name}`}
                            value={f.label}
                            onChange={(e) => {
                              const label = e.target.value
                              const name = label.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || `field_${idx + 1}`
                              setFields((prev) => prev.map((x) => x.name === f.name ? { ...x, label, name } : x))
                            }}
                            placeholder="e.g. API Key, Bearer Token, Client Secret…"
                            className="flex-1"
                          />
                          {fields.length > 1 && (
                            <button
                              type="button"
                              onClick={() => handleRemoveField(f.name)}
                              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-destructive transition-colors"
                              aria-label={`Remove ${f.label}`}
                            >
                              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
                            </button>
                          )}
                          </div>
                        </div>
                      )}
                      <FieldInput
                        fieldName={f.name}
                        label={f.label}
                        required={f.required}
                        mode={f.mode}
                        value={f.value}
                        uri={f.uri}
                        error={f.error}
                        availablePMs={availablePMs}
                        advancedMode={advancedMode}
                        onModeChange={(mode) => handleFieldChange(f.name, { mode, error: null })}
                        onValueChange={(value) => handleFieldChange(f.name, { value, error: null })}
                        onUriChange={(uri) => handleFieldChange(f.name, { uri, error: null })}
                        onBrowseRequest={(scheme) => setBrowseState({ fieldName: f.name, scheme })}
                      />
                    </div>
                  ))}
                  {selectedProvider?.category === 'custom' && (
                    <button
                      type="button"
                      onClick={handleAddField}
                      className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors w-fit"
                    >
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M12 5v14"/><path d="M5 12h14"/></svg>
                      Add field
                    </button>
                  )}
                </div>
              )}

              {submitError && (
                <div role="alert" className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {submitError}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer for custom provider — single-step submit */}
        {!browseState && step === 0 && showCustomForm && (
          <div className="px-6 py-4 border-t border-border shrink-0 bg-background">
            <Button
              type="button"
              onClick={() => void handleCustomSubmit()}
              disabled={!customName.trim() || submitting}
              aria-busy={submitting}
              className="w-full"
            >
              {submitting ? 'Saving…' : 'Add connection'}
            </Button>
          </div>
        )}

        {/* Footer actions — sticky at bottom for step 2 (not shown in browse sub-view) */}
        {!browseState && step === 1 && (
          <div className="px-6 py-4 border-t border-border shrink-0 bg-background">
            <Button
              type="button"
              onClick={() => void handleSubmit()}
              disabled={submitting || fieldsLoading}
              aria-busy={submitting || fieldsLoading}
              className="w-full"
            >
              {submitting ? 'Saving…' : 'Save Connection'}
            </Button>
          </div>
        )}
      </SheetContent>
    </Sheet>
  )
}
