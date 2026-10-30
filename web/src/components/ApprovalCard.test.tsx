import { render, screen } from '@testing-library/react'
import { ApprovalCard } from './ApprovalCard'
import type { Approval } from '../lib/types'

function makeApproval(expiresInSeconds = 300): Approval {
  return {
    token: 'test-token-abc',
    connection: 'my-openrouter',
    actor: 'agent',
    capability: 'run:D5',
    summary: 'Command: ["deploy"]\nHosts: ["example.test"]',
    request_hash: 'request-hash',
    digest: 'b'.repeat(64),
    status: 'pending',
    expires_at: new Date(Date.now() + expiresInSeconds * 1000).toISOString(),
    created_at: new Date().toISOString(),
  }
}

describe('ApprovalCard', () => {
  it('has role=region', () => {
    render(<ApprovalCard approval={makeApproval()} />)
    expect(screen.getByRole('region')).toBeInTheDocument()
  })

  it('shows connection name', () => {
    render(<ApprovalCard approval={makeApproval()} />)
    expect(screen.getByText('my-openrouter')).toBeInTheDocument()
  })

  it('shows TTL countdown', () => {
    render(<ApprovalCard approval={makeApproval(300)} />)
    expect(screen.getByLabelText(/expires in/i)).toBeInTheDocument()
  })

  it('TTL < 60s gets urgent styling (danger color)', () => {
    render(<ApprovalCard approval={makeApproval(30)} />)
    const ttlEl = screen.getByLabelText(/expires in/i)
    // Urgent TTL uses text-destructive (Tailwind) for the danger color
    expect(ttlEl.className).toContain('text-destructive')
  })

  it('TTL >= 60s does NOT get urgent styling', () => {
    render(<ApprovalCard approval={makeApproval(120)} />)
    const ttlEl = screen.getByLabelText(/expires in/i)
    expect(ttlEl.className).not.toContain('color-danger')
  })

  it('renders Approve and Deny buttons', () => {
    render(<ApprovalCard approval={makeApproval()} />)
    expect(screen.getByRole('button', { name: 'Approve request' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Deny request' })).toBeInTheDocument()
  })
})
