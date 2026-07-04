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
 * Implemented in .
 *
 * Exports:
 * PMBrowseBody — the browse body without any Sheet wrapper (used inline in ProviderWizard)
 * PMBrowseModal — standalone Sheet-wrapped version for use outside the wizard
 */

import { useEffect, useRef, useState } from 'react'
import {
  Sheet,
  SheetContent,
  SheetTitle,
  SheetClose,
} from '@/components/ui/sheet'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '../lib/api'
import type { PMScheme } from './FieldInput'
import { validateRefURI } from './FieldInput'

// ── Types ─────────────────────────────────────────────────────────────────────

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

export const PM_LABELS: Record<PMScheme, string> = {
  op: '1Password',
  aws_sm: 'AWS Secrets Manager',
  hashivault: 'HashiCorp Vault',
}

// ── PMBrowseBody ──────────────────────────────────────────────────────────────

interface PMBrowseBodyProps {
  pm: PMScheme
  onSelect: (uri: string) => void
  onBack: () => void
}

/**
 * PMBrowseBody — the PM browse content without any Sheet wrapper.
 * Used inline inside ProviderWizard so the wizard stays a single drawer.
 */
export function PMBrowseBody({ pm, onSelect, onBack }: PMBrowseBodyProps) {
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

  // onBack is provided so callers can wire the header back arrow — not used inside the body itself.
  void onBack

  return (
    <div className="flex flex-col gap-5 px-6 py-5">
      {loading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground" aria-busy="true">
          <div className="h-4 w-4 animate-spin rounded-full border-2 border-border border-t-primary" />
          Loading…
        </div>
      )}

      {error && (
        <div role="alert" className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {!loading && !error && response && (
        response.authenticated ? (
          <div className="flex flex-col gap-2">
            <p className="text-xs text-muted-foreground">Select an item to build the reference URI:</p>
            {(!response.items || response.items.length === 0) ? (
              <p role="status" className="text-sm text-muted-foreground">No items found.</p>
            ) : (
              <ul className="flex flex-col gap-1.5" role="listbox" aria-label="Password manager items">
                {response.items.map((item) => (
                  <li key={item.id} role="option">
                    <button
                      type="button"
                      className="w-full flex items-center justify-between rounded-lg border border-border px-3 py-2.5 text-left text-sm text-foreground hover:bg-accent hover:border-primary/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring transition-colors"
                      onClick={() => handleSelectItem(item)}
                    >
                      {item.title}
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-muted-foreground shrink-0" aria-hidden="true">
                        <path d="m9 18 6-6-6-6" />
                      </svg>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : (
          <div className="flex flex-col gap-3" role="status">
            <p className="text-sm text-muted-foreground">
              Not signed in to {PM_LABELS[pm]}. Run this command in your terminal, then reopen:
            </p>
            {response.hint && (
              <div className="flex items-center gap-2">
                <code className="flex-1 rounded-md bg-muted px-3 py-2 font-mono text-xs text-foreground">
                  {response.hint}
                </code>
                <button
                  type="button"
                  onClick={handleCopyHint}
                  aria-label={copied ? 'Copied to clipboard' : 'Copy authentication command'}
                  title={copied ? 'Copied!' : 'Copy'}
                  className="inline-flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-md border border-border bg-transparent text-muted-foreground transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
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
        )
      )}

      {/* Manual URI — always visible */}
      <div className="flex flex-col gap-2 border-t border-border pt-4">
        <Label htmlFor="pm-browse-manual-input" className="text-sm">
          {pm === 'op' ? 'Complete the URI (replace <field> with the field name):' : 'Enter URI manually:'}
        </Label>
        <div className="flex gap-2">
          <Input
            id="pm-browse-manual-input"
            type="text"
            value={manualURI}
            onChange={(e) => { setManualURI(e.target.value); setManualError(null) }}
            placeholder={pm === 'op' ? 'op://vault/item/field' : pm === 'aws_sm' ? 'aws-sm://region/secret-id' : 'hashivault://mount/path#field'}
            aria-invalid={!!manualError}
            aria-describedby={manualError ? 'pm-browse-manual-error' : undefined}
            autoComplete="off"
          />
          <Button type="button" variant="outline" onClick={handleManualSubmit} disabled={!manualURI.trim()}>
            Use URI
          </Button>
        </div>
        {manualError && (
          <p id="pm-browse-manual-error" role="alert" className="text-xs text-destructive" aria-live="polite">
            {manualError}
          </p>
        )}
      </div>
    </div>
  )
}

// ── PMBrowseModal (Sheet-wrapped standalone version) ──────────────────────────

interface PMBrowseModalProps {
  pm: PMScheme
  onSelect: (uri: string) => void
  onClose: () => void
}

/**
 * PMBrowseModal — shows PM items when authenticated, hint when not.
 * Wraps PMBrowseBody in a Sheet for standalone use outside ProviderWizard.
 */
export function PMBrowseModal({ pm, onSelect, onClose }: PMBrowseModalProps) {
  return (
    <Sheet open onOpenChange={(open) => { if (!open) onClose() }}>
      <SheetContent side="right" hideCloseButton className="flex flex-col gap-0 p-0 w-full sm:max-w-lg bg-background">
        {/* Header — matches ProviderWizard */}
        <div className="flex items-center justify-between px-6 h-14 shrink-0 border-b border-border">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              aria-label="Go back"
              className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="m15 18-6-6 6-6" />
              </svg>
            </button>
            <SheetTitle className="text-base font-semibold">Browse {PM_LABELS[pm]}</SheetTitle>
          </div>
          <SheetClose asChild>
            <button
              type="button"
              aria-label="Close"
              className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M18 6 6 18" /><path d="m6 6 12 12" />
              </svg>
            </button>
          </SheetClose>
        </div>

        {/* Body — scrollable */}
        <div className="flex-1 overflow-y-auto">
          <PMBrowseBody pm={pm} onSelect={onSelect} onBack={onClose} />
        </div>
      </SheetContent>
    </Sheet>
  )
}
