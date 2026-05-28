import { useEffect, useState } from 'react'
import { ProviderList } from '../components/ProviderList'
import { ProviderWizard } from '../components/ProviderWizard'
import { useConnections } from '../stores/connections'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'

/**
 * Connections page — replaces the legacy single-provider <select> with a
 * multi-provider ProviderList.
 *
 * All wired providers are shown simultaneously (matching `keylatch modes`).
 * No provider is "selected" or "active" — all are concurrently active.
 */
export function Connections() {
  const { connections, loading, error, refresh, deleteConnection } = useConnections()
  const [wizardOpen, setWizardOpen] = useState(false)
  // confirmDelete holds the connection name pending deletion.
  // When set, an inline confirmation prompt is rendered instead of using window.confirm.
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  useEffect(() => {
    void refresh()
  }, [refresh])

  const handleDelete = (name: string) => {
    setConfirmDelete(name)
  }

  const handleConfirmDelete = async () => {
    if (!confirmDelete) return
    await deleteConnection(confirmDelete)
    setConfirmDelete(null)
  }

  const handleCancelDelete = () => {
    setConfirmDelete(null)
  }

  const handleWizardSuccess = async () => {
    setWizardOpen(false)
    await refresh()
  }

  if (loading) {
    return <div aria-busy="true" aria-label="Loading connections">Loading…</div>
  }

  if (error) {
    return <div role="alert">Error loading connections: {error}</div>
  }

  return (
    <div className="connections-page">
      <ProviderList
        connections={connections}
        onAddProvider={() => setWizardOpen(true)}
        onDeleteProvider={handleDelete}
      />

      {/* Delete confirmation dialog — accessible modal, no BEM classes (S-01) */}
      <Dialog open={!!confirmDelete} onOpenChange={(open) => { if (!open) handleCancelDelete() }}>
        <DialogContent aria-modal="true" className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete Provider</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-[var(--color-text-secondary)]">
            Remove provider <strong className="text-[var(--color-text-primary)]">&ldquo;{confirmDelete}&rdquo;</strong>? This cannot be undone.
          </p>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={handleCancelDelete}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void handleConfirmDelete()}>
              Delete
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {wizardOpen && (
        <ProviderWizard
          onSuccess={handleWizardSuccess}
          onClose={() => setWizardOpen(false)}
        />
      )}
    </div>
  )
}
