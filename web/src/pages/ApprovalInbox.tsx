import { useEffect, useRef, useState } from 'react'
import { ApprovalCard } from '../components/ApprovalCard'
import type { Approval } from '../lib/types'
import { api, ApiError, DEV_MOCK } from '../lib/api'
import { Button } from '@/components/ui/button'
import { DEFAULT_APPROVAL_TTL_S } from './Settings'

/** Auto-deny banner entry — one per expired request. */
interface AutoDenyBanner {
  id: string
  agentHmac: string
  ttlSeconds: number
}

/**
 * ApprovalInbox — SSE primary, polling fallback.
 *
 * Extensions over the original:
 *   - 3c: Auto-deny TTL — when a request TTL hits 0, call /deny automatically
 *         and show a sticky (non-dismissable-until-acknowledged) banner.
 *   - Banner stacks per expired request, each with its own dismiss button.
 */
export function ApprovalInbox() {
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [connected, setConnected] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [autoDenyBanners, setAutoDenyBanners] = useState<AutoDenyBanner[]>([])
  const [approvalTtlSeconds, setApprovalTtlSeconds] = useState<number>(DEFAULT_APPROVAL_TTL_S)
  const eventSourceRef = useRef<EventSource | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)
  // Track tokens that have already been auto-denied so we don't double-call.
  const autoDeniedRef = useRef<Set<string>>(new Set())

  const fetchApprovals = () => {
    api.get<{ approvals: Approval[] }>('/api/approvals')
      .then((d) => setApprovals(d.approvals ?? []))
      .catch(() => {})
  }

  // Load approval TTL from server on mount (T-13-05: TTL is server-validated).
  useEffect(() => {
    api.get<{ approval_ttl_seconds: number }>('/api/settings')
      .then((d) => setApprovalTtlSeconds(d.approval_ttl_seconds))
      .catch(() => {})
  }, [])

  useEffect(() => {
    // SSE primary — skip in mock mode, poll only.
    if (!DEV_MOCK) {
      try {
        const es = new EventSource('/api/approvals/stream')
        eventSourceRef.current = es
        es.addEventListener('approval', () => { fetchApprovals() })
        es.onopen = () => {
          setConnected(true)
          // Clear any polling fallback when SSE reconnects successfully.
          if (pollRef.current) {
            clearInterval(pollRef.current)
            pollRef.current = null
          }
        }
        es.onerror = () => {
          setConnected(false)
          // Start polling only if not already polling (prevents stacked intervals).
          if (!pollRef.current) {
            pollRef.current = setInterval(fetchApprovals, 5000)
          }
        }
      } catch {
        // SSE not supported; fall back to polling.
        if (!pollRef.current) {
          pollRef.current = setInterval(fetchApprovals, 5000)
        }
      }
    }

    fetchApprovals()

    return () => {
      eventSourceRef.current?.close()
      eventSourceRef.current = null
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    }
  }, [])

  // ── Auto-deny TTL monitor ─────────────────────────────────────────────────
  useEffect(() => {
    if (approvals.length === 0) return

    const id = setInterval(() => {
      const now = Date.now()
      const expired = approvals.filter((a) => {
        const expiresMs = new Date(a.expiresAt).getTime()
        return expiresMs <= now && !autoDeniedRef.current.has(a.token)
      })

      for (const approval of expired) {
        autoDeniedRef.current.add(approval.token)

        const ttlSeconds = approvalTtlSeconds

        api.post(`/api/approvals/${approval.token}/deny`)
          .catch(() => {})

        setApprovals((prev) => prev.filter((a) => a.token !== approval.token))

        setAutoDenyBanners((prev) => [
          ...prev,
          {
            id: approval.token,
            agentHmac: approval.actorHmac.slice(0, 8),
            ttlSeconds,
          },
        ])
      }
    }, 1000)

    return () => clearInterval(id)
  }, [approvals, approvalTtlSeconds])

  const handleApprove = async (token: string) => {
    setActionError(null)
    try {
      await api.post(`/api/approvals/${token}/approve`)
      setApprovals((prev) => prev.filter((a) => a.token !== token))
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to approve request'
      setActionError(msg)
    }
  }

  const handleDeny = async (token: string) => {
    setActionError(null)
    try {
      await api.post(`/api/approvals/${token}/deny`)
      setApprovals((prev) => prev.filter((a) => a.token !== token))
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Failed to deny request'
      setActionError(msg)
    }
  }

  const dismissBanner = (id: string) => {
    setAutoDenyBanners((prev) => prev.filter((b) => b.id !== id))
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold tracking-tight text-foreground">
        Pending Approvals
      </h1>

      {!connected && (
        <p className="sr-only" aria-live="polite">Using polling mode (SSE unavailable)</p>
      )}

      {/* Auto-deny sticky banners — stack above action errors */}
      {autoDenyBanners.map((banner) => (
        <div
          key={banner.id}
          className="flex items-start justify-between gap-4 rounded-md border border-warning bg-[#fef9c3] p-3 text-sm text-amber-700"
          role="alert"
          aria-live="assertive"
        >
          <span>
            Request from <strong>{banner.agentHmac}…</strong> was auto-denied after{' '}
            {banner.ttlSeconds}s.{' '}
            <a
              href="/settings"
              className="font-medium underline underline-offset-2 hover:no-underline"
            >
              Adjust TTL in Settings.
            </a>
          </span>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => dismissBanner(banner.id)}
            aria-label="Dismiss auto-deny notification"
            className="shrink-0 border-amber-500 text-amber-700 hover:bg-warning hover:text-primary-foreground"
          >
            Dismiss
          </Button>
        </div>
      ))}

      {actionError && (
        <p className="text-sm text-destructive" role="alert" aria-live="assertive">
          {actionError}
        </p>
      )}

      {approvals.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No pending approvals. You&apos;re all caught up.
        </p>
      ) : (
        <div className="space-y-3">
          {approvals.map((a) => (
            <ApprovalCard
              key={a.token}
              approval={a}
              onApprove={handleApprove}
              onDeny={handleDeny}
            />
          ))}
        </div>
      )}
    </div>
  )
}
