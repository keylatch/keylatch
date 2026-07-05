import { useRef, useState, useId } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'

/**
 * MaskedField — secure credential input.
 *
 * Security invariants:
 * - NEVER accepts a `value` prop. TypeScript enforces this at compile time.
 * - No "show" or "reveal" toggle exists.
 * - The input is always type="password" with no value attribute.
 * - Inline edit: user can type a new value but the current value is never
 * pre-populated or readable from the component.
 */

// Deliberately excludes `value`, `defaultValue`, and any controlled/uncontrolled
// patterns that would expose the credential.
interface MaskedFieldProps {
  label: string
  name: string
  placeholder?: string
  disabled?: boolean
  required?: boolean
  autoComplete?: string
  onSave?: (newValue: string) => void
  className?: string
}

// Compile-time guard: this type must NOT have `value`.
// @ts-expect-error -- intentional: verify `value` is not in MaskedFieldProps
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _noValueProp: MaskedFieldProps = { label: '', name: '', value: 'oops' }

export function MaskedField({
  label,
  name,
  placeholder = '••••••••',
  disabled = false,
  required = false,
  autoComplete = 'current-password',
  onSave,
  className,
}: MaskedFieldProps) {
  const id = useId()
  const [editing, setEditing] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleEdit = () => {
    setEditing(true)
    setTimeout(() => inputRef.current?.focus(), 0)
  }

  const handleSave = () => {
    if (onSave && inputRef.current) {
      onSave(inputRef.current.value)
    }
    setEditing(false)
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') handleSave()
    if (e.key === 'Escape') setEditing(false)
  }

  return (
    <div className={cn('flex flex-col gap-1.5', className)}>
      <Label htmlFor={id}>
        {label}
        {required && <span aria-hidden="true"> *</span>}
      </Label>
      <div className="flex items-center gap-2">
        {editing ? (
          <>
            <Input
              ref={inputRef}
              id={id}
              type="password"
              name={name}
              placeholder={placeholder}
              disabled={disabled}
              required={required}
              autoComplete={autoComplete}
              onKeyDown={handleKeyDown}
              aria-label={label}
              // NOTE: no `value` or `defaultValue` attribute — this is intentional.
              // The field is write-only.
            />
            <Button
              type="button"
              variant="default"
              size="sm"
              onClick={handleSave}
            >
              Save
            </Button>
          </>
        ) : (
          <>
            <span
              className="flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm text-muted-foreground tracking-widest"
              aria-hidden="true"
            >
              ••••••••
            </span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleEdit}
              disabled={disabled}
              aria-label={`Edit ${label}`}
            >
              Edit
            </Button>
          </>
        )}
      </div>
    </div>
  )
}
