import { useEffect, useState } from 'react'
import { ProviderList } from '../components/ProviderList'
import { ProviderWizard } from '../components/ProviderWizard'
import { useConnections } from '../stores/connections'
import { api } from '../lib/api'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Sheet,
  SheetContent,
  SheetTitle,
  SheetClose,
} from '@/components/ui/sheet'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'

type ApprovalPolicyOverride = 'global' | 'prompt' | 'first-run' | 'trust'

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
  // editConnection holds the connection name being edited.
  const [editConnection, setEditConnection] = useState<string | null>(null)
  // Per-connection approval policy override.
  const [editApprovalPolicy, setEditApprovalPolicy] = useState<ApprovalPolicyOverride>('global')
  const [editSaving, setEditSaving] = useState(false)
  const [editError, setEditError] = useState<string | null>(null)

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

  const handleEdit = (name: string) => {
    const conn = connections.find((c) => c.name === name)
    const rawPolicy = conn?.approval_policy ?? ''
    setEditConnection(name)
    setEditApprovalPolicy(!rawPolicy ? 'global' : rawPolicy as ApprovalPolicyOverride)
    setEditError(null)
  }

  const handleEditClose = () => {
    setEditConnection(null)
    setEditError(null)
  }

  const handleEditSave = async () => {
    if (!editConnection) return
    setEditSaving(true)
    setEditError(null)
    try {
      await api.put(`/api/connections/${editConnection}`, {
        approval_policy: editApprovalPolicy === 'global' ? '' : editApprovalPolicy,
      })
      await refresh()
      setEditConnection(null)
    } catch (err) {
      setEditError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setEditSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24" aria-busy="true" aria-label="Loading connections">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-border border-t-primary" />
      </div>
    )
  }

  if (error) {
    return (
      <div
        role="alert"
        className="rounded-lg border border-destructive/20 bg-destructive/10 p-4 text-destructive"
      >
        {error}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Connections</h1>
        <Button size="sm" onClick={() => setWizardOpen(true)}>+ Add Provider</Button>
      </div>
      <ProviderList
        connections={connections}
        onAddProvider={() => setWizardOpen(true)}
        onEditProvider={handleEdit}
        onDeleteProvider={handleDelete}
      />

      {/* Delete confirmation dialog — accessible modal, no BEM classes (S-01) */}
      <Dialog open={!!confirmDelete} onOpenChange={(open) => { if (!open) handleCancelDelete() }}>
        <DialogContent aria-modal="true" className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete Provider</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            Remove provider <strong className="text-foreground">&ldquo;{confirmDelete}&rdquo;</strong>? This cannot be undone.
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

      {/* Edit Connection Sheet — approval policy override per connection */}
      <Sheet open={!!editConnection} onOpenChange={(open) => { if (!open) handleEditClose() }}>
        <SheetContent side="right" hideCloseButton className="flex flex-col gap-0 p-0 w-full sm:max-w-md bg-background">
          {/* Header */}
          <div className="flex items-center justify-between px-6 h-14 shrink-0 border-b border-border">
            <div className="flex items-center gap-2">
              <SheetTitle className="text-base font-semibold">Edit Connection</SheetTitle>
            </div>
            <SheetClose asChild>
              <button
                type="button"
                aria-label="Close edit panel"
                className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <path d="M18 6 6 18" /><path d="m6 6 12 12" />
                </svg>
              </button>
            </SheetClose>
          </div>

          {/* Body */}
          <div className="flex-1 overflow-y-auto px-6 py-5 flex flex-col gap-6">
            {/* Connection name (read-only) */}
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium text-muted-foreground">Connection</p>
              <p className="text-sm font-medium text-foreground">{editConnection}</p>
            </div>

            {/* Approval policy override */}
            <div className="flex flex-col gap-3">
              <p className="text-sm font-medium text-muted-foreground">Approval policy override</p>
              <RadioGroup
                value={editApprovalPolicy}
                onValueChange={(v) => setEditApprovalPolicy(v as ApprovalPolicyOverride)}
                className="space-y-3"
              >
                {(
                  [
                    { value: 'global',    label: 'Global default (use setting)', description: 'Inherits the approval policy set in Settings.' },
                    { value: 'prompt',    label: 'Prompt',                        description: 'Always ask before approving.' },
                    { value: 'first-run', label: 'First-run',                     description: 'Auto-approve once per session; deny subsequent requests.' },
                    { value: 'trust',     label: 'Trust',                         description: 'Auto-approve all requests from this connection.' },
                  ] as { value: ApprovalPolicyOverride; label: string; description: string }[]
                ).map(({ value, label, description }) => (
                  <div key={value} className="flex items-center gap-3 py-1">
                    <RadioGroupItem value={value} id={`edit-policy-${value}`} />
                    <Label htmlFor={`edit-policy-${value}`} className="cursor-pointer">
                      <span className="block text-sm font-medium text-foreground">{label}</span>
                      <span className="block text-xs text-muted-foreground">{description}</span>
                    </Label>
                  </div>
                ))}
              </RadioGroup>
            </div>
            {editError && (
              <p role="alert" className="text-xs text-destructive">{editError}</p>
            )}
          </div>

          {/* Footer */}
          <div className="px-6 py-4 border-t border-border shrink-0">
            <Button
              type="button"
              onClick={() => void handleEditSave()}
              className="w-full"
              disabled={editSaving}
            >
              {editSaving ? (
                <span className="flex items-center gap-2">
                  <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" aria-hidden="true" />
                  Saving…
                </span>
              ) : (
                'Save changes'
              )}
            </Button>
          </div>
        </SheetContent>
      </Sheet>

      {wizardOpen && (
        <ProviderWizard
          onSuccess={handleWizardSuccess}
          onClose={() => setWizardOpen(false)}
        />
      )}
    </div>
  )
}
