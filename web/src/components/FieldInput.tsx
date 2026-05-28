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
import { PMBrowseModal } from './PMBrowseModal'
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
  onModeChange: (mode: FieldMode) => void
  onValueChange: (value: string) => void
  onUriChange: (uri: string) => void
}

/**
 * FieldInput — renders a single credential field with mode toggle.
 *
 * Direct mode: password `<input>` for the field value.
 * Reference mode: text input for the PM URI + Browse button that opens PMBrowseModal.
 */
export function FieldInput({
  fieldName,
  label,
  required = false,
  mode,
  value,
  uri,
  error,
  onModeChange,
  onValueChange,
  onUriChange,
}: FieldInputProps) {
  const [browseOpen, setBrowseOpen] = useState(false)
  const [browseScheme, setBrowseScheme] = useState<PMScheme>('op')

  const directInputId = `field-${fieldName}-direct`
  const refInputId = `field-${fieldName}-ref`
  const errorId = `field-${fieldName}-error`

  const handleBrowseSelect = (selectedUri: string) => {
    onUriChange(selectedUri)
    setBrowseOpen(false)
  }

  const handleBrowseOpen = () => {
    // Determine scheme from current URI prefix, default to op.
    if (uri.startsWith('aws-sm://')) setBrowseScheme('aws_sm')
    else if (uri.startsWith('hashivault://')) setBrowseScheme('hashivault')
    else setBrowseScheme('op')
    setBrowseOpen(true)
  }

  return (
    <div className="flex flex-col gap-2" data-field={fieldName}>
      {/* Header: label + mode toggle */}
      <div className="flex items-center justify-between gap-2">
        <Label htmlFor={mode === 'direct' ? directInputId : refInputId}>
          {label}
          {required && <span className="text-[var(--color-danger)] ml-0.5" aria-hidden="true"> *</span>}
        </Label>

        {/* Mode toggle — two pill buttons */}
        <div
          className="flex rounded-md border border-[var(--color-border)] overflow-hidden"
          role="group"
          aria-label={`Storage mode for ${label}`}
        >
          <button
            type="button"
            className={cn(
              'px-3 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)] focus-visible:ring-inset',
              mode === 'direct'
                ? 'bg-[var(--color-primary-600)] text-[var(--color-text-inverse)]'
                : 'bg-transparent text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]'
            )}
            onClick={() => onModeChange('direct')}
            aria-pressed={mode === 'direct'}
          >
            Store directly
          </button>
          <button
            type="button"
            className={cn(
              'px-3 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)] focus-visible:ring-inset border-l border-[var(--color-border)]',
              mode === 'reference'
                ? 'bg-[var(--color-primary-600)] text-[var(--color-text-inverse)]'
                : 'bg-transparent text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)]'
            )}
            onClick={() => onModeChange('reference')}
            aria-pressed={mode === 'reference'}
          >
            From password manager
          </button>
        </div>
      </div>

      {/* Control */}
      <div>
        {mode === 'direct' ? (
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
        ) : (
          <div className="flex gap-2">
            <Input
              id={refInputId}
              type="text"
              value={uri}
              onChange={(e) => onUriChange(e.target.value)}
              placeholder="op://vault/item/field"
              aria-required={required}
              aria-describedby={error ? errorId : undefined}
              aria-invalid={!!error}
              autoComplete="off"
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleBrowseOpen}
              aria-label={`Browse password manager for ${label}`}
            >
              Browse
            </Button>
          </div>
        )}
      </div>

      {/* Inline error */}
      {error && (
        <div
          id={errorId}
          role="alert"
          className="text-xs text-[var(--color-danger)]"
          aria-live="polite"
        >
          {error}
        </div>
      )}

      {browseOpen && (
        <PMBrowseModal
          pm={browseScheme}
          onSelect={handleBrowseSelect}
          onClose={() => setBrowseOpen(false)}
        />
      )}
    </div>
  )
}
