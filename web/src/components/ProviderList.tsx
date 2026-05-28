import { ProviderCard } from './ProviderCard'
import { Button } from '@/components/ui/button'
import type { ProviderConnection } from '../stores/connections'

interface ProviderListProps {
  connections: ProviderConnection[]
  onAddProvider?: () => void
  onEditProvider?: (id: string) => void
  onDeleteProvider?: (name: string) => void
}

/**
 * ProviderList — displays all wired provider connections as a vertical card list.
 *
 * - Maps connections[] to ProviderCard components.
 * - "Add Provider" button at the top that triggers onAddProvider.
 * - No connection is "selected" — all wired providers are active simultaneously.
 * - Cards are rendered in the order returned by the API (last-modified descending).
 * - No <select> element — replaces the legacy single-provider selector.
 */
export function ProviderList({
  connections,
  onAddProvider,
  onEditProvider,
  onDeleteProvider,
}: ProviderListProps) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-[var(--color-text-primary)]">Providers</h2>
        <Button
          type="button"
          size="sm"
          onClick={() => onAddProvider?.()}
          aria-label="Add Provider"
        >
          + Add Provider
        </Button>
      </div>

      {connections.length === 0 ? (
        <div
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] px-6 py-8 text-center text-sm text-[var(--color-text-secondary)]"
          role="status"
        >
          <p>No providers connected yet.</p>
          <p>Click <strong>+ Add Provider</strong> to wire your first credential source.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-3" role="list" aria-label="Connected providers">
          {connections.map((conn) => (
            <div key={conn.id} role="listitem">
              <ProviderCard
                connection={conn}
                onEdit={onEditProvider}
                onDelete={onDeleteProvider}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
