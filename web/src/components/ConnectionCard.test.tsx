import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ConnectionCard } from './ConnectionCard'
import type { Connection } from '../lib/types'

const mockConn: Connection = {
  name: 'my-openrouter',
  provider: 'openrouter',
  status: 'ok',
  risk: 'low',
}

describe('ConnectionCard', () => {
  it('renders connection name', () => {
    render(<ConnectionCard connection={mockConn} />)
    expect(screen.getByText('my-openrouter')).toBeInTheDocument()
  })

  it('renders status chip', () => {
    render(<ConnectionCard connection={mockConn} />)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('renders risk label', () => {
    render(<ConnectionCard connection={mockConn} />)
    // RiskLabel now uses 'Low risk' label (not just 'Low')
    expect(screen.getByLabelText('Risk level: Low risk')).toBeInTheDocument()
  })

  it('renders add card variant', () => {
    render(<ConnectionCard isAddCard onSelect={vi.fn()} />)
    expect(screen.getByRole('button', { name: 'Add connection' })).toBeInTheDocument()
  })

  it('calls onSelect with name when clicked', async () => {
    const user = userEvent.setup()
    const onSelect = vi.fn()
    render(<ConnectionCard connection={mockConn} onSelect={onSelect} />)
    await user.click(screen.getByRole('button'))
    expect(onSelect).toHaveBeenCalledWith('my-openrouter')
  })

  it('renders as button when onSelect is provided', () => {
    render(<ConnectionCard connection={mockConn} onSelect={vi.fn()} />)
    expect(screen.getByRole('button', { name: /Connection: my-openrouter/i })).toBeInTheDocument()
  })

  it('renders as article (non-interactive) when no onSelect provided', () => {
    render(<ConnectionCard connection={mockConn} />)
    expect(screen.queryByRole('button', { name: /Connection: my-openrouter/i })).not.toBeInTheDocument()
    expect(screen.getByRole('article', { name: /Connection: my-openrouter/i })).toBeInTheDocument()
  })

  it('error state adds destructive ring indicator', () => {
    const errorConn: Connection = { ...mockConn, status: 'error' }
    render(<ConnectionCard connection={errorConn} />)
    // Non-interactive card renders as article
    const card = screen.getByRole('article')
    expect(card.className).toContain('ring-destructive')
  })

  it('grid variant default — column layout', () => {
    render(<ConnectionCard connection={mockConn} onSelect={vi.fn()} />)
    const card = screen.getByRole('button', { name: /Connection: my-openrouter/i })
    // grid variant uses flex-col, not flex-row
    expect(card.className).toContain('flex-col')
  })

  it('list variant — row layout', () => {
    render(<ConnectionCard connection={mockConn} variant="list" onSelect={vi.fn()} />)
    const card = screen.getByRole('button', { name: /Connection: my-openrouter/i })
    // list variant adds flex-row
    expect(card.className).toContain('flex-row')
  })
})
