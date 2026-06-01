import type { ConnectionStatus } from '../lib/types'
import { cn } from '@/lib/utils'

interface StatusChipProps {
  status: ConnectionStatus
  className?: string
}

const LABELS: Record<ConnectionStatus, string> = {
  ok: 'Active',
  error: 'Error',
  untested: 'Untested',
  expired: 'Expired',
  warning: 'Warning',
}

const STATUS_CLASSES: Record<ConnectionStatus, string> = {
  ok:       'bg-emerald-100 text-emerald-700 border-transparent',
  error:    'bg-red-100 text-red-700 border-transparent',
  warning:  'bg-amber-100 text-amber-700 border-transparent',
  untested: 'bg-secondary text-secondary-foreground border-transparent',
  expired:  'bg-secondary text-secondary-foreground border-transparent',
}

/**
 * StatusChip — displays a connection status badge.
 * Uses explicit colour pairs for maximum contrast regardless of theme.
 */
export function StatusChip({ status, className }: StatusChipProps) {
  return (
    <span
      role="status"
      aria-label={`Status: ${LABELS[status]}`}
      className={cn(
        'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold',
        STATUS_CLASSES[status],
        className
      )}
    >
      {LABELS[status]}
    </span>
  )
}
