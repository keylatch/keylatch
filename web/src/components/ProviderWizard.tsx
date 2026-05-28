/**
 * ProviderWizard — multi-step sheet for adding a new provider connection.
 *
 * Step 1: pick a provider from the template catalogue
 * Step 2: configure per-field storage modes (direct / reference)
 *
 * Implemented in T-14-03.
 */

import { useState, useEffect } from 'react'
import { FieldInput } from './FieldInput'
import { WizardStepper } from './WizardStepper'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetClose,
} from '@/components/ui/sheet'
import { Button } from '@/components/ui/button'
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
  name: string
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
 */
export function ProviderWizard({ onSuccess, onClose }: ProviderWizardProps) {
  const [step, setStep] = useState(0)
  const [providers, setProviders] = useState<ProviderTemplate[]>([])
  const [selectedProvider, setSelectedProvider] = useState<ProviderTemplate | null>(null)
  const [fields, setFields] = useState<FieldState[]>([])
  const [fieldsLoading, setFieldsLoading] = useState(false)
  const [fieldsError, setFieldsError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const { createConnection } = useConnections()

  // Fetch provider catalogue on mount.
  useEffect(() => {
    api.get<ProviderTemplate[]>('/v1/providers')
      .then(setProviders)
      .catch(() => {
        // Fallback to empty list — user will see no options.
      })
  }, [])

  const handleSelectProvider = async (tmpl: ProviderTemplate) => {
    setSelectedProvider(tmpl)
    setFieldsLoading(true)
    setFieldsError(null)
    setStep(1)
    try {
      const detail = await api.get<ProviderDetail>(`/v1/providers/${tmpl.slug}`)
      const schemaFields: SecretField[] = detail.fields.length > 0
        ? detail.fields
        : [{ name: 'api_key', label: 'API Key', required: true }]
      setFields(
        schemaFields.map((f) => ({
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
      // Fall back to minimal api_key field so the user is not completely blocked.
      setFields([{
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

    // Validate.
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

  return (
    <Sheet open onOpenChange={(open) => { if (!open) onClose() }}>
      <SheetContent side="right" hideCloseButton className="flex flex-col gap-0 p-0 overflow-y-auto w-full sm:max-w-md">
        <SheetHeader className="flex flex-row items-center justify-between px-6 pt-6 pb-4 border-b border-[var(--color-border)]">
          <SheetTitle>Add Provider</SheetTitle>
          <SheetClose asChild>
            <button
              type="button"
              aria-label="Close wizard"
              className="rounded-sm opacity-70 transition-opacity hover:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)] focus-visible:ring-offset-2"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="16"
                height="16"
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
        </SheetHeader>

        <div className="px-6 pt-4">
          <WizardStepper steps={WIZARD_STEPS} currentStep={step} />
        </div>

        <div className="flex-1 px-6 py-4">
          {step === 0 && (
            <div data-testid="wizard-step-pick" className="flex flex-col gap-3">
              <p className="text-sm text-[var(--color-text-secondary)]">Select a provider to connect:</p>
              {providers.length === 0 ? (
                <p className="text-sm text-[var(--color-text-secondary)]" aria-busy="true">Loading providers…</p>
              ) : (
                <ul className="flex flex-col gap-1" role="listbox" aria-label="Provider catalogue">
                  {providers.map((p) => (
                    <li key={p.slug} role="option" aria-selected={selectedProvider?.slug === p.slug}>
                      <button
                        type="button"
                        className="w-full flex items-center justify-between rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-3 text-left hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)] focus-visible:ring-offset-2 transition-colors"
                        onClick={() => void handleSelectProvider(p)}
                        aria-label={`Select ${p.display_name}`}
                      >
                        <strong className="text-sm font-medium text-[var(--color-text-primary)]">{p.display_name}</strong>
                        <span className="text-xs text-[var(--color-text-disabled)]">{p.category}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {step === 1 && selectedProvider && (
            <div data-testid="wizard-step-fields" className="flex flex-col gap-4">
              <p className="text-sm text-[var(--color-text-secondary)]">
                Configure fields for <strong className="text-[var(--color-text-primary)]">{selectedProvider.display_name}</strong>:
              </p>

              {fieldsLoading && (
                <p className="text-sm text-[var(--color-text-secondary)]" aria-busy="true">
                  Loading field schema…
                </p>
              )}

              {fieldsError && (
                <div role="alert" className="rounded-md bg-[var(--color-warning-light)] px-3 py-2 text-sm text-[var(--color-text-primary)]">
                  {fieldsError}
                </div>
              )}

              {!fieldsLoading && fields.map((f) => (
                <FieldInput
                  key={f.name}
                  fieldName={f.name}
                  label={f.label}
                  required={f.required}
                  mode={f.mode}
                  value={f.value}
                  uri={f.uri}
                  error={f.error}
                  onModeChange={(mode) => handleFieldChange(f.name, { mode, error: null })}
                  onValueChange={(value) => handleFieldChange(f.name, { value, error: null })}
                  onUriChange={(uri) => handleFieldChange(f.name, { uri, error: null })}
                />
              ))}

              {submitError && (
                <div role="alert" className="rounded-md bg-[var(--color-danger-light)] px-3 py-2 text-sm text-[var(--color-danger-dark)]">
                  {submitError}
                </div>
              )}

              <div className="flex items-center justify-between pt-2 border-t border-[var(--color-border)]">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setStep(0)}
                  disabled={submitting}
                >
                  Back
                </Button>
                <Button
                  type="button"
                  onClick={handleSubmit}
                  disabled={submitting || fieldsLoading}
                  aria-busy={submitting || fieldsLoading}
                >
                  {submitting ? 'Saving…' : 'Save Connection'}
                </Button>
              </div>
            </div>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}
