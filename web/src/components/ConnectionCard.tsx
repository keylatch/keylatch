import type { Connection } from '../lib/types'
import { StatusChip } from './StatusChip'
import { RiskLabel } from './RiskLabel'
import { ProviderBadge } from './ProviderBadge'
import { cn } from '@/lib/utils'

type CardVariant = 'grid' | 'list'

interface ConnectionCardProps {
  connection?: Connection
  variant?: CardVariant
  onSelect?: (name: string) => void
  isAddCard?: boolean
  className?: string
}

/**
 * ConnectionCard — displays a connection in grid or list layout.
 *
 * When isAddCard=true, renders a dashed "Add connection" card.
 * Error state: adds a red left border.
 * Hover: translateY(-2px) via CSS.
 */
export function ConnectionCard({
  connection,
  variant = 'grid',
  onSelect,
  isAddCard = false,
  className,
}: ConnectionCardProps) {
  if (isAddCard) {
    return (
      <button
        type="button"
        className={cn(
          'flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-[var(--color-border)] bg-[var(--color-surface)] p-6 text-sm text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-primary-400)] hover:text-[var(--color-primary-600)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)]',
          variant === 'list' && 'flex-row justify-start',
          className
        )}
        onClick={() => onSelect?.('__add__')}
        aria-label="Add connection"
      >
        <span className="text-2xl font-light leading-none" aria-hidden="true">+</span>
        <span>Add connection</span>
      </button>
    )
  }

  if (!connection) return null

  const hasError = connection.status === 'error'

  return (
    <button
      type="button"
      className={cn(
        'flex w-full cursor-pointer flex-col gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] p-4 text-left shadow-[var(--shadow-xs)] transition-[transform,box-shadow] hover:-translate-y-0.5 hover:shadow-[var(--shadow-sm)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)]',
        hasError && 'shadow-[inset_3px_0_0_var(--color-danger)]',
        variant === 'list' && 'flex-row items-center',
        className
      )}
      onClick={() => onSelect?.(connection.name)}
      aria-label={`Connection: ${connection.name}`}
    >
      <div className="flex items-center gap-2">
        <ProviderBadge provider={connection.provider} />
        <span className="text-sm font-medium text-[var(--color-text-primary)]">
          {connection.name}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <StatusChip status={connection.status} />
        <RiskLabel risk={connection.risk} />
      </div>
      {connection.expiresAt && (
        <div className="text-xs text-[var(--color-text-secondary)]">
          Expires: {new Date(connection.expiresAt).toLocaleDateString()}
        </div>
      )}
    </button>
  )
}
