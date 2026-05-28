import { useEffect, useState } from 'react'
import { apiFetch } from '../api'

interface Approval { id: string; actor: string; capability: string; provider: string; created_at: string }

export default function ApprovalInbox() {
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [error, setError] = useState<string | null>(null)

  const load = () =>
    fetch('/v1/approvals')
      .then(r => r.json())
      .then(d => { setApprovals(d.approvals ?? d ?? []); setError(null) })
      .catch(() => setError('Failed to load approvals'))

  useEffect(() => { load() }, [])

  const act = async (id: string, action: 'approve' | 'deny') => {
    try {
      await apiFetch(`/v1/approvals/${id}/${action}`, { method: 'POST' })
      load()
    } catch {
      setError('Action failed')
    }
  }

  if (approvals.length === 0)
    return (
      <div>
        <p style={{ color: '#666', fontSize: 14 }}>No pending approvals.</p>
        {error && <div style={{ color: '#f87171', fontSize: 13, marginTop: 8 }}>{error}</div>}
      </div>
    )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {approvals.map(a => (
        <div key={a.id} style={{ background: '#1a1a1a', border: '1px solid #444', borderRadius: 8, padding: 12 }}>
          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>{a.provider} &middot; {a.capability}</div>
          <div style={{ fontSize: 12, color: '#888', marginBottom: 10 }}>from {a.actor}</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => act(a.id, 'approve')} style={{ background: '#16a34a', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: 6, cursor: 'pointer', fontSize: 13 }}>Approve</button>
            <button onClick={() => act(a.id, 'deny')} style={{ background: '#dc2626', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: 6, cursor: 'pointer', fontSize: 13 }}>Deny</button>
          </div>
        </div>
      ))}
      {error && <div style={{ color: '#f87171', fontSize: 13, marginTop: 8 }}>{error}</div>}
    </div>
  )
}
