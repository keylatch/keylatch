/**
 * PMBrowseModal — Browse items from a password manager CLI.
 *
 * When the PM CLI is authenticated, shows a list of items the user can select
 * to build a reference URI automatically.
 *
 * When the PM CLI is not authenticated (exit non-zero), shows a hint string
 * with a copy button — no item list is requested.
 *
 * A manual URI input is always available as a fallback regardless of auth state.
 *
 * For 1Password (op), selecting an item produces a URI with a `<field>` placeholder
 * (e.g. op://Item-Title/<field>) that the user completes in the URI input before
 * submitting. Spaces in item titles are replaced with hyphens so the URI is valid.
 *
 * Implemented in T-14-05.
 */

import { useEffect, useRef, useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '../lib/api'
import { validateRefURI } from './FieldInput'

// ── Types ─────────────────────────────────────────────────────────────────────

type PMScheme = 'op' | 'aws_sm' | 'hashivault'

interface PMItem {
  id: string
  title: string
}

interface PMBrowseResponse {
  authenticated: boolean
  items?: PMItem[]
  hint?: string
}

// ── URI building helpers ──────────────────────────────────────────────────────

/**
 * Slugify a title for use in a URI (replace spaces and special chars with hyphens).
 */
function slugifyTitle(title: string): string {
  return title.replace(/[^a-zA-Z0-9._~-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '')
}

/**
 * Build a reference URI from a PM scheme and item.
 *
 * For 1Password, the URI includes a `<field>` placeholder the user must complete.
 * The item title is slugified to ensure the URI contains no spaces.
 */
function buildURI(pm: PMScheme, item: PMItem): string {
  switch (pm) {
    case 'op': {
      const slug = slugifyTitle(item.title) || item.id
      // op:// URIs require op://vault/item/field — we use a <field> placeholder
      // since we only have the item title at this point, not vault or field info.
      return `op://${slug}/<field>`
    }
    case 'aws_sm':
      return `aws-sm://${item.id}`
    case 'hashivault':
      return `hashivault://${item.id}`
    default:
      return item.id
  }
}

const PM_LABELS: Record<PMScheme, string> = {
  op: '1Password',
  aws_sm: 'AWS Secrets Manager',
  hashivault: 'HashiCorp Vault',
}

// ── Props ─────────────────────────────────────────────────────────────────────

interface PMBrowseModalProps {
  pm: PMScheme
  onSelect: (uri: string) => void
  onClose: () => void
}

/**
 * PMBrowseModal — shows PM items when authenticated, hint when not.
 */
export function PMBrowseModal({ pm, onSelect, onClose }: PMBrowseModalProps) {
  const [response, setResponse] = useState<PMBrowseResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [manualURI, setManualURI] = useState('')
  const [manualError, setManualError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => () => { if (copyTimerRef.current) clearTimeout(copyTimerRef.current) }, [])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    api.get<PMBrowseResponse>(`/api/pm-browse?pm=${pm}`)
      .then((data) => { if (!cancelled) setResponse(data) })
      .catch((err) => { if (!cancelled) setError(err instanceof Error ? err.message : 'Request failed') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [pm])

  const handleCopyHint = async () => {
    if (!response?.hint) return
    try {
      await navigator.clipboard.writeText(response.hint)
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current)
      setCopied(true)
      copyTimerRef.current = setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard API not available — silently skip.
    }
  }

  const handleSelectItem = (item: PMItem) => {
    const uri = buildURI(pm, item)
    // For op:// items, the URI contains a <field> placeholder — place it in the
    // manual input so the user can complete it before submitting.
    if (pm === 'op') {
      setManualURI(uri)
      return
    }
    const validationError = validateRefURI(uri)
    if (validationError) {
      setError(validationError)
      return
    }
    onSelect(uri)
  }

  const handleManualSubmit = () => {
    const uri = manualURI.trim()
    if (!uri) return
    const err = validateRefURI(uri)
    if (err) {
      setManualError(err)
      return
    }
    setManualError(null)
    onSelect(uri)
  }

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Browse {PM_LABELS[pm]}</DialogTitle>
        </DialogHeader>

        <div className="flex flex-col gap-4">
          {loading && (
            <div
              className="text-sm text-[var(--color-text-secondary)]"
              aria-busy="true"
              aria-label="Loading password manager items"
            >
              Loading…
            </div>
          )}

          {error && (
            <div
              role="alert"
              className="rounded-md bg-[var(--color-danger-light)] px-3 py-2 text-sm text-[var(--color-danger-dark)]"
            >
              {error}
            </div>
          )}

          {!loading && !error && response && (
            <>
              {response.authenticated ? (
                <>
                  <p className="text-sm text-[var(--color-text-secondary)]">Select an item to build the URI:</p>
                  {(!response.items || response.items.length === 0) ? (
                    <p role="status" className="text-sm text-[var(--color-text-secondary)]">No items found.</p>
                  ) : (
                    <ul
                      className="flex flex-col gap-1 max-h-52 overflow-y-auto"
                      role="listbox"
                      aria-label="Password manager items"
                    >
                      {response.items.map((item) => (
                        <li key={item.id} role="option">
                          <button
                            type="button"
                            className="w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-left text-sm text-[var(--color-text-primary)] hover:bg-[var(--color-surface-raised)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)] focus-visible:ring-offset-2 transition-colors"
                            onClick={() => handleSelectItem(item)}
                            aria-label={`Select ${item.title}`}
                          >
                            {item.title}
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              ) : (
                <div
                  className="flex flex-col gap-3"
                  role="status"
                  aria-label="Not authenticated"
                >
                  <p className="text-sm text-[var(--color-text-secondary)]">
                    Not authenticated. Run the following command and try again:
                  </p>
                  {response.hint && (
                    <div className="flex items-center gap-2">
                      <code className="flex-1 rounded-md bg-[var(--color-neutral-100)] px-3 py-2 font-mono text-xs text-[var(--color-text-primary)]">
                        {response.hint}
                      </code>
                      <button
                        type="button"
                        onClick={handleCopyHint}
                        aria-label={copied ? 'Copied to clipboard' : 'Copy authentication command'}
                        title={copied ? 'Copied!' : 'Copy'}
                        className="inline-flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-md border border-[var(--color-border)] bg-transparent text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-overlay)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)]"
                      >
                        {copied ? (
                          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12" /></svg>
                        ) : (
                          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2" ry="2" /><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" /></svg>
                        )}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {/* Manual fallback — always available.
              For 1Password, selecting an item populates this input with an op://slug/<field>
              placeholder that the user must complete before submitting. */}
          <div className="flex flex-col gap-2 border-t border-[var(--color-border)] pt-4" aria-label="Manual URI input">
            <Label htmlFor="pm-browse-manual-input">
              {pm === 'op'
                ? 'Complete the URI (replace <field> with the actual field name):'
                : 'Or enter URI manually:'}
            </Label>
            <div className="flex gap-2">
              <Input
                id="pm-browse-manual-input"
                type="text"
                value={manualURI}
                onChange={(e) => { setManualURI(e.target.value); setManualError(null) }}
                placeholder="op://vault/item/field"
                aria-label="Manual reference URI"
                aria-invalid={!!manualError}
                aria-describedby={manualError ? 'pm-browse-manual-error' : undefined}
                autoComplete="off"
              />
              <Button
                type="button"
                variant="outline"
                onClick={handleManualSubmit}
                disabled={!manualURI.trim()}
              >
                Use this URI
              </Button>
            </div>
            {manualError && (
              <div
                id="pm-browse-manual-error"
                role="alert"
                className="text-xs text-[var(--color-danger)]"
                aria-live="polite"
              >
                {manualError}
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}
