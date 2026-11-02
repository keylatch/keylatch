import { useCallback, useEffect, useRef, useState } from 'react'
import { ApprovalCard } from '../components/ApprovalCard'
import type { Approval } from '../lib/types'
import { api, ApiError, DEV_MOCK } from '../lib/api'

export function ApprovalInbox() {
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [loaded, setLoaded] = useState(false)
  const [connected, setConnected] = useState(false)
  const [listError, setListError] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const mounted = useRef(false)
  const generation = useRef(0)
  const deciding = useRef(new Map<string, AbortController>())

  const fetchApprovals = useCallback(async () => {
    const current = ++generation.current
    try {
      const entries = await api.get<Approval[]>('/api/approvals')
      if (!mounted.current || current !== generation.current || deciding.current.size > 0) return
      setApprovals(entries.filter((entry) => entry.status === 'pending'))
      setLoaded(true)
      setListError(null)
    } catch (err) {
      if (!mounted.current || current !== generation.current) return
      setListError(err instanceof ApiError ? err.message : 'Cannot load approval requests')
    }
  }, [])

  useEffect(() => {
    mounted.current = true
    let events: EventSource | undefined
    let poll: ReturnType<typeof setInterval> | undefined
    const startPolling = () => {
      if (!poll) poll = setInterval(() => { void fetchApprovals() }, 5000)
    }
    if (!DEV_MOCK) {
      try {
        events = new EventSource('/api/approvals/stream')
        events.addEventListener('approval', () => { void fetchApprovals() })
        events.onopen = () => {
          setConnected(true)
          clearInterval(poll)
          poll = undefined
        }
        events.onerror = () => {
          setConnected(false)
          startPolling()
        }
      } catch {
        startPolling()
      }
    } else {
      startPolling()
    }
    void fetchApprovals()
    return () => {
      mounted.current = false
      generation.current++
      events?.close()
      clearInterval(poll)
      for (const controller of deciding.current.values()) controller.abort()
    }
  }, [fetchApprovals])

  const decide = async (approval: Approval, action: 'approve' | 'deny') => {
    if (deciding.current.has(approval.token)) return
    const controller = new AbortController()
    deciding.current.set(approval.token, controller)
    generation.current++
    setActionError(null)
    try {
      await api.post(`/api/approvals/${approval.token}/${action}`, { digest: approval.digest }, { signal: controller.signal })
      if (mounted.current) setApprovals((prev) => prev.filter((entry) => entry.token !== approval.token))
    } catch (err) {
      if (mounted.current) setActionError(err instanceof ApiError ? err.message : `Failed to ${action} request`)
      throw err
    } finally {
      deciding.current.delete(approval.token)
      generation.current++
      if (mounted.current && deciding.current.size === 0) void fetchApprovals()
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold tracking-tight text-foreground">Pending Approvals</h1>
      {!connected && <p className="sr-only" aria-live="polite">Using polling mode (SSE unavailable)</p>}
      {(listError || actionError) && (
        <p className="text-sm text-destructive" role="alert" aria-live="assertive">{actionError ?? listError}</p>
      )}
      {!loaded && !listError && <p className="text-sm text-muted-foreground">Loading approvals…</p>}
      {loaded && !listError && approvals.length === 0 && (
        <p className="text-sm text-muted-foreground">No pending approvals.</p>
      )}
      <div className="space-y-3">
        {approvals.map((approval) => (
          <ApprovalCard
            key={`${approval.token}:${approval.digest}`}
            approval={approval}
            onApprove={(entry) => decide(entry, 'approve')}
            onDeny={(entry) => decide(entry, 'deny')}
          />
        ))}
      </div>
    </div>
  )
}
