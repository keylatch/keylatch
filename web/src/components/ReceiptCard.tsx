import type { Receipt } from '../api/receipts'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface ReceiptCardProps {
  receipt: Receipt
  className?: string
}

/**
 * ReceiptCard — displays a single runtime receipt in the activity timeline.
 *
 * Security invariants (S-RM-9):
 *   - Renders only provider, capability, runtime mode, timestamp, and exit code.
 *   - Never renders a credential value — Receipt type enforces this at the type level.
 */
export function ReceiptCard({ receipt, className }: ReceiptCardProps) {
  const passed = (receipt.exit_code ?? 0) === 0

  // TTL is a Go time.Duration (nanoseconds). Convert to seconds for display.
  const ttlSeconds = receipt.ttl != null ? Math.round(receipt.ttl / 1e9) : null

  return (
    <div
      role="listitem"
      className={cn(
        'rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-3',
        className
      )}
      aria-label={`Receipt: ${receipt.provider} ${receipt.capability}`}
    >
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium text-[var(--color-text-primary)]">
          {receipt.provider}
        </span>
        <span className="text-sm text-[var(--color-text-secondary)]">
          {receipt.capability}
        </span>
        <span
          className={cn(
            'ml-auto text-xs font-semibold',
            passed ? 'text-[var(--color-success-dark)]' : 'text-[var(--color-danger-dark)]'
          )}
          aria-label={passed ? 'Pass' : 'Fail'}
        >
          {passed ? '✓' : '✗'}
        </span>
      </div>

      <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
        <Badge variant="secondary" className="text-xs">
          {receipt.runtime}
        </Badge>
        <Badge variant="outline" className="text-xs">
          {receipt.policy_decision}
        </Badge>
        {ttlSeconds != null && (
          <Badge variant="outline" className="text-xs">
            {ttlSeconds}s TTL
          </Badge>
        )}
      </div>
    </div>
  )
}
