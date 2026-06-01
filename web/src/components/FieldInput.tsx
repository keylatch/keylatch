/**
 * FieldInput — a single credential field row in the Add Provider wizard.
 *
 * Supports two storage modes per field:
 *   - direct: password input (value encrypted into keylatch vault)
 *   - reference: URI input + optional Browse button (resolves from external PM)
 *
 * Client-side URI validation uses the same regex as the server-side validator
 * (T-14-06): ^(op|aws-sm|hashivault)://[^/][^/]*\/[^/].*
 */

import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'

// ── URI validation constant (mirrors server-side RefURIPattern) ───────────────

/** PM scheme identifiers. Note: 'aws_sm' maps to URI scheme 'aws-sm://'. */
export type PMScheme = 'op' | 'aws_sm' | 'hashivault'

export const REF_URI_PATTERN = /^(op|aws-sm|hashivault):\/\/[^/][^/]*\/[^/].*/

/**
 * Validates a reference URI string.
 * Returns null when valid, or an error string when invalid.
 */
export function validateRefURI(uri: string): string | null {
  const trimmed = uri.trim()
  if (!trimmed) return 'Reference URI must not be empty'
  if (!REF_URI_PATTERN.test(trimmed)) {
    return 'Invalid reference URI — expected op://vault/item/field, aws-sm://region/secret-id, or hashivault://mount/path#field'
  }
  return null
}

// ── Types ─────────────────────────────────────────────────────────────────────

export type FieldMode = 'direct' | 'reference'

export const PM_OPTIONS: { scheme: PMScheme; label: string; placeholder: string }[] = [
  { scheme: 'op',         label: '1Password',            placeholder: 'op://vault/item/field' },
  { scheme: 'aws_sm',     label: 'AWS Secrets Manager',  placeholder: 'aws-sm://region/secret-id' },
  { scheme: 'hashivault', label: 'HashiCorp Vault',       placeholder: 'hashivault://mount/path#field' },
]

// ── Props ────────────────────────────────────────────────────────────────────

interface FieldInputProps {
  fieldName: string
  label: string
  required?: boolean
  mode: FieldMode
  /** Current plaintext value (only used when mode === 'direct'). */
  value: string
  /** Current reference URI (only used when mode === 'reference'). */
  uri: string
  /** Validation error to display inline. */
  error?: string | null
  /**
   * Available password managers. When provided, only PMs with `true` values are shown.
   * If no PMs are available, a note is shown instead of the PM selector pills.
   */
  availablePMs?: { op: boolean; aws_sm: boolean; hashivault: boolean }
  /**
   * When false (default), the "Use reference from password manager" disclosure link
   * is hidden. Only shown when advanced mode is enabled in Settings.
   */
  advancedMode?: boolean
  onModeChange: (mode: FieldMode) => void
  onValueChange: (value: string) => void
  onUriChange: (uri: string) => void
  /**
   * Called when the user clicks Browse. The parent (ProviderWizard) handles opening
   * the browse sub-view inline rather than a second Sheet.
   */
  onBrowseRequest?: (scheme: PMScheme) => void
}

/**
 * FieldInput — renders a single credential field with mode toggle.
 *
 * Direct mode: password `<input>` for the field value.
 * Reference mode: text input for the PM URI + Browse button that calls onBrowseRequest.
 */
export function FieldInput({
  fieldName,
  label,
  required = false,
  mode,
  value,
  uri,
  error,
  availablePMs,
  advancedMode = false,
  onModeChange,
  onValueChange,
  onUriChange,
  onBrowseRequest,
}: FieldInputProps) {
  const [browseScheme, setBrowseScheme] = useState<PMScheme>('op')

  const directInputId = `field-${fieldName}-direct`
  const refInputId = `field-${fieldName}-ref`
  const errorId = `field-${fieldName}-error`

  // Filter PM options to only installed PMs when availablePMs is provided.
  const visiblePMs = availablePMs
    ? PM_OPTIONS.filter((opt) => availablePMs[opt.scheme])
    : PM_OPTIONS

  const handleBrowseClick = () => {
    // Determine scheme from current URI prefix, default to first visible scheme or 'op'.
    let scheme: PMScheme = visiblePMs[0]?.scheme ?? 'op'
    if (uri.startsWith('aws-sm://')) scheme = 'aws_sm'
    else if (uri.startsWith('hashivault://')) scheme = 'hashivault'
    else if (uri.startsWith('op://')) scheme = 'op'
    setBrowseScheme(scheme)
    onBrowseRequest?.(scheme)
  }

  return (
    <div className="flex flex-col gap-1.5" data-field={fieldName}>
      <Label htmlFor={mode === 'direct' ? directInputId : refInputId}>
        {label}
        {required && <span className="text-destructive ml-0.5" aria-hidden="true"> *</span>}
      </Label>

      {mode === 'direct' ? (
        <>
          <Input
            id={directInputId}
            type="password"
            value={value}
            onChange={(e) => onValueChange(e.target.value)}
            placeholder={`Enter ${label}`}
            aria-required={required}
            aria-describedby={error ? errorId : undefined}
            aria-invalid={!!error}
            autoComplete="off"
          />
          {advancedMode && (!availablePMs || visiblePMs.length > 0) && (
            <button
              type="button"
              className="w-fit text-xs text-muted-foreground hover:text-foreground transition-colors underline underline-offset-2"
              onClick={() => onModeChange('reference')}
            >
              Use reference from password manager
            </button>
          )}
        </>
      ) : (
        <>
          {visiblePMs.length === 0 ? (
            /* No PMs installed — show hint + fallback */
            <p className="text-xs text-muted-foreground">
              No password managers detected. Install op, aws-cli, or vault to enable references.{' '}
              <button
                type="button"
                className="underline underline-offset-2 hover:text-foreground transition-colors"
                onClick={() => { onModeChange('direct'); onUriChange('') }}
              >
                Store directly instead
              </button>
            </p>
          ) : (
            <>
              {/* PM selector pills */}
              <div className="flex gap-1.5 flex-wrap">
                {visiblePMs.map((opt) => (
                  <button
                    key={opt.scheme}
                    type="button"
                    className={cn(
                      'px-2.5 py-1 rounded-md border text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                      browseScheme === opt.scheme
                        ? 'border-primary bg-primary/5 text-primary'
                        : 'border-border text-muted-foreground hover:bg-accent hover:text-foreground'
                    )}
                    onClick={() => setBrowseScheme(opt.scheme)}
                    aria-pressed={browseScheme === opt.scheme}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              <Input
                id={refInputId}
                type="text"
                value={uri}
                onChange={(e) => onUriChange(e.target.value)}
                placeholder={visiblePMs.find(o => o.scheme === browseScheme)?.placeholder ?? PM_OPTIONS.find(o => o.scheme === browseScheme)?.placeholder ?? 'op://vault/item/field'}
                aria-required={required}
                aria-describedby={error ? errorId : undefined}
                aria-invalid={!!error}
                autoComplete="off"
              />
              <button
                type="button"
                className="w-fit text-xs text-muted-foreground hover:text-foreground transition-colors underline underline-offset-2"
                onClick={() => { onModeChange('direct'); onUriChange('') }}
              >
                Store directly instead
              </button>
            </>
          )}
        </>
      )}

      {error && (
        <p id={errorId} role="alert" className="text-xs text-destructive" aria-live="polite">
          {error}
        </p>
      )}
    </div>
  )
}
