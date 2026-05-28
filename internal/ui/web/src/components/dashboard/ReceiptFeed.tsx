import { useEffect, useRef, useState } from 'react'

interface Receipt {
  provider: string
  capability: string
  policy_decision: string
  mode: string
  ttl: number
  _key?: number  // assigned client-side for React reconciliation
}

export default function ReceiptFeed() {
  const [receipts, setReceipts] = useState<Receipt[]>([])
  const keyCounter = useRef(0)

  useEffect(() => {
    // Load last 20 on mount.
    fetch('/v1/receipts')
      .then(r => r.json())
      .then(d => {
        const items: Receipt[] = (d.receipts ?? []).map((r: Receipt) => ({ ...r, _key: ++keyCounter.current }))
        setReceipts(items)
      })

    // SSE stream for live updates.
    const es = new EventSource('/v1/receipts/stream')
    es.addEventListener('receipt', (e: MessageEvent) => {
      const r: Receipt = JSON.parse(e.data)
      r._key = ++keyCounter.current
      setReceipts(prev => [r, ...prev].slice(0, 20))
    })
    return () => es.close()
  }, [])

  if (receipts.length === 0)
    return <p style={{ color: '#666', fontSize: 14 }}>No activity yet.</p>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {receipts.map(r => (
        <div key={r._key} style={{ background: '#1a1a1a', border: '1px solid #333', borderRadius: 8, padding: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontWeight: 600, fontSize: 14 }}>{r.provider}</span>
            <span style={{ fontSize: 12, color: r.policy_decision === 'allowed' ? '#4ade80' : '#f87171' }}>
              {r.policy_decision}
            </span>
          </div>
          <div style={{ fontSize: 12, color: '#888' }}>{r.capability} &middot; {r.mode}</div>
        </div>
      ))}
    </div>
  )
}
