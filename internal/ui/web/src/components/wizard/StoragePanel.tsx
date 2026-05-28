import React, { useEffect, useState } from 'react'

interface Backend { name: string; display_name: string; available: boolean; install_hint?: string }
interface Props { onNext: () => void; onBack: () => void; onBackendSelect: (name: string) => void }

export default function StoragePanel({ onNext, onBack, onBackendSelect }: Props) {
  const [backends, setBackends] = useState<Backend[]>([])
  const [selected, setSelected] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [experimental, setExperimental] = useState(false)

  useEffect(() => {
    fetch('/v1/config/experimental')
      .then(r => r.json())
      .then((data: { experimental: boolean }) => setExperimental(data.experimental))
      .catch(() => {}) // safe default: experimental=false
  }, [])

  useEffect(() => {
    fetch('/v1/backends')
      .then(r => r.json())
      .then((data: Backend[]) => {
        setBackends(data)
        const first = data.find(b => b.available)
        if (first) {
          setSelected(first.name)
          onBackendSelect(first.name)
        }
      })
      .finally(() => setLoading(false))
  }, [])

  const visible = backends.filter(b =>
    b.name !== 'nordpass' || experimental
  )

  return (
    <div style={{ maxWidth: 480, margin: '60px auto', padding: '0 24px' }}>
      <h2>Choose where to store your keys</h2>
      {loading ? <p>Loading backends&hellip;</p> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, margin: '24px 0' }}>
          {visible.map(b => (
            <label key={b.name} style={{
              display: 'flex', alignItems: 'flex-start', gap: 12, padding: 16,
              border: `2px solid ${selected === b.name ? '#2563eb' : '#333'}`,
              borderRadius: 8, cursor: b.available ? 'pointer' : 'not-allowed',
              opacity: b.available ? 1 : 0.5,
            }}>
              <input type="radio" name="backend" value={b.name}
                checked={selected === b.name}
                disabled={!b.available}
                onChange={() => {
                  if (b.available) {
                    setSelected(b.name)
                    onBackendSelect(b.name)
                  }
                }} />
              <div>
                <div style={{ fontWeight: 600 }}>{b.display_name}</div>
                {b.name === 'lastpass' && (
                  <div style={{ color: '#f59e0b', fontSize: 12, marginTop: 4 }}>
                    LastPass has experienced significant security breaches. Use only for legacy compatibility.
                  </div>
                )}
                {!b.available && b.install_hint && (
                  <div style={{ color: '#888', fontSize: 12, marginTop: 4 }}>{b.install_hint}</div>
                )}
              </div>
            </label>
          ))}
        </div>
      )}
      <div style={{ display: 'flex', gap: 12 }}>
        <button onClick={onBack} style={ghostBtn}>&larr; Back</button>
        <button onClick={onNext} disabled={!selected} style={primaryBtn}>Continue &rarr;</button>
      </div>
    </div>
  )
}

const primaryBtn: React.CSSProperties = { background: '#2563eb', color: '#fff', border: 'none', padding: '10px 24px', borderRadius: 8, fontSize: 15, cursor: 'pointer', fontWeight: 600 }
const ghostBtn: React.CSSProperties = { background: 'none', color: '#888', border: '1px solid #444', padding: '10px 20px', borderRadius: 8, fontSize: 15, cursor: 'pointer' }
