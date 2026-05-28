import type { ConnectionStatus } from '../lib/types'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface StatusChipProps {
  status: ConnectionStatus
  className?: string
}

const LABELS: Record<ConnectionStatus, string> = {
  ok: 'OK',
  error: 'Error',
  untested: 'Untested',
  expired: 'Expired',
  warning: 'Warning',
}

/**
 * StatusChip — displays a connection status badge.
 * Always shows a text label (not just colour) for accessibility.
 */
export function StatusChip({ status, className }: StatusChipProps) {
  const variant =
    status === 'ok' ? 'success' :
    status === 'error' ? 'destructive' :
    status === 'warning' ? 'warning' :
    'secondary'

  return (
    <Badge
      role="status"
      variant={variant}
      className={cn(className)}
      aria-label={`Status: ${LABELS[status]}`}
    >
      {LABELS[status]}
    </Badge>
  )
}
