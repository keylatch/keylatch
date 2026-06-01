import { ProviderCard } from './ProviderCard'
import type { ProviderConnection } from '../stores/connections'

interface ProviderListProps {
  connections: ProviderConnection[]
  onAddProvider?: () => void
  onEditProvider?: (name: string) => void
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
      {connections.length === 0 ? (
        <div
          className="rounded-lg border border-border bg-card px-6 py-8 text-center text-sm text-muted-foreground"
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
                onEdit={onEditProvider ? () => onEditProvider(conn.name) : undefined}
                onDelete={onDeleteProvider}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
