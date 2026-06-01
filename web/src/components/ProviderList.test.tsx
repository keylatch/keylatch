import { render, screen } from '@testing-library/react'
import { ProviderList } from './ProviderList'
import type { ProviderConnection } from '../stores/connections'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
  },
}))

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

  // ProviderList does not render an "Add Provider" button directly.
  // The empty-state shows text with "+ Add Provider" hint.
  // The onAddProvider callback is passed to a parent for wiring via external UI.
  it('shows empty state when no connections', () => {
    render(<ProviderList connections={[]} />)
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.getByText(/No providers connected yet/)).toBeInTheDocument()
  })

  it('mentions Add Provider in the empty state', () => {
    render(<ProviderList connections={[]} />)
    expect(screen.getByText(/\+ Add Provider/i)).toBeInTheDocument()
  })
})
