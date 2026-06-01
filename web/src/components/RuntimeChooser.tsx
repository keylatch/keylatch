import { useRef } from 'react'
import type { RuntimeMode } from '../lib/types'
import { cn } from '@/lib/utils'

interface RuntimeOption {
  mode: RuntimeMode
  label: string
  description: string
}

// Only supported modes are rendered. "unrestricted"/"direct_run" are NEVER included.
const RUNTIME_OPTIONS: RuntimeOption[] = [
  {
    mode: 'gateway_typed',
    label: 'Gateway (typed)',
    description: 'Route credentials through the local typed gateway.',
  },
  {
    mode: 'gateway_classic',
    label: 'Gateway (classic)',
    description: 'Route credentials through the classic gateway.',
  },
  {
    mode: 'direct_classic_sandboxed',
    label: 'Direct (sandboxed)',
    description: 'Direct injection with hardware approval required.',
  },
  {
    mode: 'absent',
    label: 'Absent',
    description: 'Credentials are not injected (read-only mode).',
  },
]

interface RuntimeChooserProps {
  value?: RuntimeMode
  onChange?: (mode: RuntimeMode) => void
  supportedModes?: RuntimeMode[]
  disabled?: boolean
  className?: string
}

/**
 * RuntimeChooser — a radio group for selecting runtime mode.
 *
 * - Only supported modes are RENDERED (absent from DOM, not just hidden).
 * - "unrestricted"/"direct_run" are never present.
 * - Arrow key navigation between options.
 */
export function RuntimeChooser({
  value,
  onChange,
  supportedModes,
  disabled = false,
  className,
}: RuntimeChooserProps) {
  const groupRef = useRef<HTMLDivElement>(null)

  const visibleOptions = RUNTIME_OPTIONS.filter(
    (opt) => !supportedModes || supportedModes.includes(opt.mode)
  )

  const handleKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>, idx: number) => {
    const buttons = groupRef.current?.querySelectorAll<HTMLButtonElement>('button[role="radio"]')
    if (!buttons) return

    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') {
      e.preventDefault()
      const next = (idx + 1) % buttons.length
      buttons[next].focus()
      onChange?.(visibleOptions[next].mode)
    } else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
      e.preventDefault()
      const prev = (idx - 1 + buttons.length) % buttons.length
      buttons[prev].focus()
      onChange?.(visibleOptions[prev].mode)
    }
  }

  return (
    <div
      ref={groupRef}
      role="radiogroup"
      aria-label="Runtime mode"
      className={cn('flex flex-col gap-2', className)}
    >
      {visibleOptions.map((opt, idx) => (
        <button
          key={opt.mode}
          role="radio"
          type="button"
          aria-checked={value === opt.mode}
          disabled={disabled}
          onClick={() => onChange?.(opt.mode)}
          onKeyDown={(e) => handleKeyDown(e, idx)}
          className={cn(
            'flex w-full flex-col items-start gap-0.5 rounded-lg border px-4 py-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50',
            value === opt.mode
              ? 'border-primary bg-primary-50 text-primary-900'
              : 'border-border bg-background hover:border-primary-300 hover:bg-card'
          )}
          tabIndex={value === opt.mode ? 0 : -1}
        >
          <span className="text-sm font-medium">{opt.label}</span>
          <span className={cn(
            'text-xs',
            value === opt.mode ? 'text-primary-700' : 'text-muted-foreground'
          )}>
            {opt.description}
          </span>
        </button>
      ))}
    </div>
  )
}
