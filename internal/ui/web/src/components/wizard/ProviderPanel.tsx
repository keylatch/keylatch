import React, { useEffect, useState } from 'react'
import { apiFetch } from '../../api'

interface Provider { slug: string; display_name: string; docs_url: string }
interface Props { onNext: () => void; onBack: () => void; selectedBackend: string }

export default function ProviderPanel({ onNext, onBack, selectedBackend }: Props) {
  const [providers, setProviders] = useState<Provider[]>([])
  const [selected, setSelected] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [status, setStatus] = useState<'idle' | 'loading' | 'ok' | 'error'>('idle')
  const [errMsg, setErrMsg] = useState('')

  useEffect(() => {
    fetch('/v1/providers')
      .then(r => r.json())
      .then((data: Provider[]) => { setProviders(data); if (data[0]) setSelected(data[0].slug) })
  }, [])

  const provider = providers.find(p => p.slug === selected)

  const handleConnect = async () => {
    setStatus('loading')
    try {
      const res = await apiFetch('/v1/connect', {
        method: 'POST',
        body: JSON.stringify({ provider: selected, api_key: apiKey, backend: selectedBackend || 'keychain' }),
      })
      const data = await res.json()
      if (data.ok) { setStatus('ok') } else { setStatus('error'); setErrMsg(data.error ?? 'Connection failed') }
    } catch {
      setStatus('error')
      setErrMsg('Network error — is Keylatch running?')
    }
  }

  return (
    <div style={{ maxWidth: 480, margin: '60px auto', padding: '0 24px' }}>
      <h2>Connect a provider</h2>
      <div style={{ margin: '24px 0', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div>
          <label style={{ display: 'block', marginBottom: 6, color: '#aaa', fontSize: 14 }}>Provider</label>
          <select value={selected} onChange={e => setSelected(e.target.value)}
            style={{ width: '100%', padding: '10px 12px', background: '#1a1a1a', color: '#e8e8e8', border: '1px solid #333', borderRadius: 6, fontSize: 15 }}>
            {providers.map(p => <option key={p.slug} value={p.slug}>{p.display_name}</option>)}
          </select>
        </div>
        <div>
          <label style={{ display: 'block', marginBottom: 6, color: '#aaa', fontSize: 14 }}>API Key</label>
          <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
            placeholder="Paste your API key here"
            style={{ width: '100%', padding: '10px 12px', background: '#1a1a1a', color: '#e8e8e8', border: '1px solid #333', borderRadius: 6, fontSize: 15 }} />
          {provider?.docs_url && (
            <div style={{ marginTop: 6, fontSize: 13, color: '#888' }}>
              Get a key at <a href={provider.docs_url} target="_blank" rel="noopener noreferrer" style={{ color: '#60a5fa' }}>{provider.docs_url}</a>
            </div>
          )}
        </div>
        {status === 'ok' && <div style={{ color: '#4ade80', fontSize: 14 }}>{selected} connected successfully</div>}
        {status === 'error' && <div style={{ color: '#f87171', fontSize: 14 }}>{errMsg}</div>}
      </div>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <button onClick={onBack} style={ghostBtn}>&larr; Back</button>
        <button onClick={handleConnect} disabled={!apiKey || status === 'loading'} style={primaryBtn}>
          {status === 'loading' ? 'Testing…' : 'Test & save →'}
        </button>
        <button onClick={onNext} style={ghostBtn}>Skip</button>
      </div>
    </div>
  )
}

const primaryBtn: React.CSSProperties = { background: '#2563eb', color: '#fff', border: 'none', padding: '10px 24px', borderRadius: 8, fontSize: 15, cursor: 'pointer', fontWeight: 600 }
const ghostBtn: React.CSSProperties = { background: 'none', color: '#888', border: '1px solid #444', padding: '10px 20px', borderRadius: 8, fontSize: 15, cursor: 'pointer' }
