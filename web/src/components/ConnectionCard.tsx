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

const PROVIDER_NAMES: Record<string, string> = {
  anthropic: 'Anthropic',
  openai: 'OpenAI',
  github: 'GitHub',
  stripe: 'Stripe',
  slack: 'Slack',
  openrouter: 'OpenRouter',
  google: 'Google',
  azure: 'Azure',
  aws: 'AWS',
}

/**
 * ConnectionCard — displays a connection in grid or list layout.
 *
 * When isAddCard=true, renders a dashed "Add connection" card.
 * Error state: ring-2 ring-destructive ring-inset for reliable cross-browser rendering.
 * Hover: shadow upgrade via transition-all.
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
          'flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-border p-5 text-sm text-muted-foreground transition-colors hover:border-primary/50 hover:bg-primary/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring min-h-[120px]',
          variant === 'list' && 'flex-row justify-start min-h-0',
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
  const isInteractive = !!onSelect
  const displayProvider = PROVIDER_NAMES[connection.provider] ?? connection.provider

  // Format expiry relative to today
  let expiryLabel: string | null = null
  if (connection.expiresAt) {
    const now = Date.now()
    const exp = new Date(connection.expiresAt).getTime()
    const diffDays = Math.round((exp - now) / (1000 * 60 * 60 * 24))
    if (diffDays < 0) {
      expiryLabel = 'Expired'
    } else if (diffDays === 0) {
      expiryLabel = 'Expires today'
    } else {
      expiryLabel = `Expires in ${diffDays} day${diffDays === 1 ? '' : 's'}`
    }
  }

  const cardContent = (
    <>
      {/* Header: badge + name */}
      <div className="flex items-center gap-3">
        <ProviderBadge provider={connection.provider} />
        <div className="flex flex-col min-w-0">
          <span className="text-sm font-semibold text-foreground truncate">
            {connection.name}
          </span>
          <span className="text-xs text-muted-foreground truncate">
            {displayProvider}
          </span>
        </div>
      </div>

      {/* Status row */}
      <div className="flex items-center gap-2 flex-wrap">
        <StatusChip status={connection.status} />
        <RiskLabel risk={connection.risk} />
      </div>

      {/* Expiry */}
      {expiryLabel && (
        <div className="text-xs text-muted-foreground">
          {expiryLabel}
        </div>
      )}
    </>
  )

  if (isInteractive) {
    return (
      <button
        type="button"
        className={cn(
          'rounded-xl border border-border bg-card p-4 hover:border-primary/30 hover:bg-card/80 transition-all duration-150 cursor-pointer text-left w-full',
          'flex flex-col gap-3',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          hasError && 'ring-2 ring-destructive ring-inset',
          variant === 'list' && 'flex-row items-center',
          className
        )}
        onClick={() => onSelect(connection.name)}
        aria-label={`Connection: ${connection.name}`}
      >
        {cardContent}
      </button>
    )
  }

  return (
    <article
      className={cn(
        'rounded-xl border border-border bg-card p-4',
        'flex flex-col gap-3',
        hasError && 'ring-2 ring-destructive ring-inset',
        variant === 'list' && 'flex-row items-center',
        className
      )}
      aria-label={`Connection: ${connection.name}`}
    >
      {cardContent}
    </article>
  )
}
