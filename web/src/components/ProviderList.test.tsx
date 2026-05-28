import { render, screen, fireEvent } from '@testing-library/react'
import { ProviderList } from './ProviderList'
import type { ProviderConnection } from '../stores/connections'

const makeConn = (provider: string): ProviderConnection => ({
  id: `default/${provider}/default`,
  name: provider,
  provider,
  account: 'default',
  namespace: 'default',
  status: 'untested',
  fields: [{ name: 'api_key', mode: 'direct' as const }],
})

const mockConnections: ProviderConnection[] = [
  makeConn('openrouter'),
  makeConn('github'),
  makeConn('sentry'),
]

describe('ProviderList', () => {
  it('renders 3 cards when given 3 connections', () => {
    render(<ProviderList connections={mockConnections} />)
    const items = screen.getAllByRole('listitem')
    expect(items).toHaveLength(3)
  })

  it('renders correct provider names on all cards', () => {
    render(<ProviderList connections={mockConnections} />)
    // Each card renders name+provider — getAllByText to handle duplicates.
    expect(screen.getAllByText('openrouter').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('github').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('sentry').length).toBeGreaterThanOrEqual(1)
  })

  it('does NOT render any <select> element', () => {
    render(<ProviderList connections={mockConnections} />)
    expect(document.querySelector('select')).toBeNull()
  })

  it('renders Add Provider button', () => {
    render(<ProviderList connections={[]} />)
    expect(screen.getByRole('button', { name: 'Add Provider' })).toBeInTheDocument()
  })

  it('calls onAddProvider when Add Provider button is clicked', () => {
    const onAdd = vi.fn()
    render(<ProviderList connections={[]} onAddProvider={onAdd} />)
    fireEvent.click(screen.getByRole('button', { name: 'Add Provider' }))
    expect(onAdd).toHaveBeenCalledTimes(1)
  })

  it('shows empty state when no connections', () => {
    render(<ProviderList connections={[]} />)
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.getByText(/No providers connected yet/)).toBeInTheDocument()
  })
})
