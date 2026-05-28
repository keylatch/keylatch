import React, { useEffect, useState } from 'react'

interface Check { name: string; ok: boolean; message?: string }
interface Readiness { status: 'green' | 'yellow' | 'red'; checks: Check[] }

const statusColor: Record<string, string> = { green: '#4ade80', red: '#f87171' }
const statusLabel: Record<string, string> = { green: 'Ready', red: 'Not ready' }

interface Props { onSetupAgain: () => void }

export default function ReadinessIndicator({ onSetupAgain }: Props) {
  const [data, setData] = useState<Readiness | null>(null)
  const [expanded, setExpanded] = useState(false)

  const load = () =>
    fetch('/v1/health/readiness').then(r => r.json()).then(setData).catch(() => {})

  useEffect(() => {
    load()
    const id = setInterval(load, 30_000)
    return () => clearInterval(id)
  }, [])

  if (!data) return null

  const color = statusColor[data.status] ?? '#888'
  return (
    <div style={{ position: 'relative' }}>
      <button onClick={() => setExpanded(e => !e)} style={{
        display: 'flex', alignItems: 'center', gap: 8, background: 'none',
        border: `1.5px solid ${color}`, borderRadius: 20, padding: '6px 14px', cursor: 'pointer', color,
      }}>
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />
        {statusLabel[data.status] ?? data.status}
      </button>
      {expanded && (
        <div style={{
          position: 'absolute', right: 0, top: '100%', marginTop: 8,
          background: '#1a1a1a', border: '1px solid #333', borderRadius: 8,
          padding: 16, minWidth: 260, zIndex: 100,
        }}>
          {data.checks.map(c => (
            <div key={c.name} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{ color: c.ok ? '#4ade80' : '#f87171' }}>{c.ok ? '✓' : '✗'}</span>
              <span style={{ fontSize: 14 }}>{c.name.replace(/_/g, ' ')}</span>
              {c.message && <span style={{ color: '#888', fontSize: 12 }}>{c.message}</span>}
            </div>
          ))}
          <button onClick={onSetupAgain} style={{
            marginTop: 8, background: 'none', border: '1px solid #555', borderRadius: 6,
            padding: '6px 12px', color: '#aaa', cursor: 'pointer', fontSize: 13, width: '100%',
          }}>Run setup again</button>
        </div>
      )}
    </div>
  )
}
