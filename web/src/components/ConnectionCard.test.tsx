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
    expect(screen.getByLabelText('Risk level: Low')).toBeInTheDocument()
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

  it('error state adds visual indicator (inset shadow)', () => {
    const errorConn: Connection = { ...mockConn, status: 'error' }
    render(<ConnectionCard connection={errorConn} />)
    const card = screen.getByRole('button')
    // Error state uses inset box-shadow for left accent to avoid border shorthand conflicts
    expect(card.className).toContain('shadow-[inset_3px_0_0_var(--color-danger)]')
  })

  it('grid variant default — column layout', () => {
    render(<ConnectionCard connection={mockConn} />)
    const card = screen.getByRole('button')
    // grid variant uses flex-col, not flex-row
    expect(card.className).toContain('flex-col')
  })

  it('list variant — row layout', () => {
    render(<ConnectionCard connection={mockConn} variant="list" />)
    const card = screen.getByRole('button')
    // list variant adds flex-row
    expect(card.className).toContain('flex-row')
  })
})
