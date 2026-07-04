import type { Receipt } from '../api/receipts'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface ReceiptCardProps {
  receipt: Receipt
  className?: string
}

/**
 * ReceiptCard — single row in the activity timeline.
 *
 * Renders as a compact flex row: status dot | provider | capability | runtime badge | TTL | outcome.
 *
 * Security invariants:
 * - Renders only provider, capability, runtime mode, timestamp, and exit code.
 * - Never renders a credential value — Receipt type enforces this at the type level.
 */
export function ReceiptCard({ receipt, className }: ReceiptCardProps) {
  const passed = (receipt.exit_code ?? 0) === 0

  // TTL is a Go time.Duration (nanoseconds). Convert to seconds for display.
  const ttlSeconds = receipt.ttl != null ? Math.round(receipt.ttl / 1e9) : null

  return (
    <div
      role="listitem"
      aria-label={`Receipt: ${receipt.provider} ${receipt.capability}`}
      className={cn(
        'flex items-center gap-3 px-3 py-2.5',
        className
      )}
    >
      {/* Status dot */}
      <div
        className={cn(
          'h-2 w-2 rounded-full shrink-0',
          passed ? 'bg-emerald-500' : 'bg-destructive'
        )}
        aria-hidden="true"
      />

      {/* Provider */}
      <span className="text-sm font-medium text-foreground w-24 shrink-0 truncate">
        {receipt.provider}
      </span>

      {/* Capability */}
      <span className="text-sm text-muted-foreground flex-1 truncate">
        {receipt.capability}
      </span>

      {/* Runtime badge */}
      <Badge variant="secondary" className="text-xs shrink-0">
        {receipt.runtime}
      </Badge>

      {/* TTL */}
      {ttlSeconds != null && (
        <span className="text-xs text-muted-foreground w-14 text-right shrink-0">
          {ttlSeconds}s
        </span>
      )}

      {/* Outcome */}
      <span
        className={cn(
          'text-xs font-semibold shrink-0 w-14 text-right',
          passed ? 'text-emerald-600' : 'text-destructive'
        )}
        aria-label={passed ? 'Allowed' : 'Denied'}
      >
        {receipt.policy_decision}
      </span>
    </div>
  )
}
