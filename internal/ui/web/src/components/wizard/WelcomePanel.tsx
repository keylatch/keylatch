import React from 'react'

interface Props { onNext: () => void; onSkip: () => void }

export default function WelcomePanel({ onNext, onSkip }: Props) {
  return (
    <div style={{ maxWidth: 480, margin: '80px auto', textAlign: 'center', padding: '0 24px' }}>
      <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 12 }}>
        Keep API keys out of AI tools.
      </h1>
      <p style={{ color: '#aaa', marginBottom: 40, lineHeight: 1.6 }}>
        Keylatch intercepts credential requests from AI agents and injects them
        securely — your keys never leave your machine.
      </p>
      <button onClick={onNext} style={primaryBtn}>Get started &rarr;</button>
      <div style={{ marginTop: 16 }}>
        <button onClick={onSkip} style={ghostBtn}>Skip setup</button>
      </div>
    </div>
  )
}

const primaryBtn: React.CSSProperties = {
  background: '#2563eb', color: '#fff', border: 'none', padding: '12px 32px',
  borderRadius: 8, fontSize: 16, cursor: 'pointer', fontWeight: 600,
}
const ghostBtn: React.CSSProperties = {
  background: 'none', color: '#666', border: 'none', fontSize: 14, cursor: 'pointer',
}
