import React, { useState } from 'react'
import { apiFetch } from '../../api'

const AGENTS = [
  { id: 'claude-code', label: 'Claude Code', hint: 'claude' },
  { id: 'codex',       label: 'OpenAI Codex CLI', hint: 'codex' },
  { id: 'cursor',      label: 'Cursor IDE', hint: 'cursor' },
]

interface Props { onFinish: () => void; onBack: () => void }

export default function AgentPanel({ onFinish, onBack }: Props) {
  const [checked, setChecked] = useState<Set<string>>(new Set(['claude-code']))
  const [status, setStatus] = useState<'idle' | 'loading' | 'done'>('idle')

  const toggle = (id: string) => setChecked(prev => {
    const next = new Set(prev)
    next.has(id) ? next.delete(id) : next.add(id)
    return next
  })

  const handleFinish = async () => {
    setStatus('loading')
    try {
      for (const agent of checked) {
        await apiFetch('/v1/agent/setup', {
          method: 'POST',
          body: JSON.stringify({ agent }),
        })
      }
      setStatus('done')
      onFinish()
    } catch {
      setStatus('idle') // unblock the button
    }
  }

  return (
    <div style={{ maxWidth: 480, margin: '60px auto', padding: '0 24px' }}>
      <h2>Set up AI agents</h2>
      <p style={{ color: '#aaa', marginBottom: 24 }}>Choose which agents to configure for Keylatch.</p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 32 }}>
        {AGENTS.map(a => (
          <label key={a.id} style={{
            display: 'flex', alignItems: 'center', gap: 12, padding: 16,
            border: `2px solid ${checked.has(a.id) ? '#2563eb' : '#333'}`,
            borderRadius: 8, cursor: 'pointer',
          }}>
            <input type="checkbox" checked={checked.has(a.id)} onChange={() => toggle(a.id)} />
            <span style={{ fontWeight: 600 }}>{a.label}</span>
          </label>
        ))}
      </div>
      <div style={{ display: 'flex', gap: 12 }}>
        <button onClick={onBack} style={ghostBtn}>&larr; Back</button>
        <button onClick={handleFinish} disabled={status === 'loading'} style={primaryBtn}>
          {status === 'loading' ? 'Setting up…' : 'Finish →'}
        </button>
      </div>
    </div>
  )
}

const primaryBtn: React.CSSProperties = { background: '#2563eb', color: '#fff', border: 'none', padding: '10px 24px', borderRadius: 8, fontSize: 15, cursor: 'pointer', fontWeight: 600 }
const ghostBtn: React.CSSProperties = { background: 'none', color: '#888', border: '1px solid #444', padding: '10px 20px', borderRadius: 8, fontSize: 15, cursor: 'pointer' }
