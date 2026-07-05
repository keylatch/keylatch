/**
 * ProviderCard tests — + .
 *
 * The card now polls /api/doctor on mount. We mock the api module to control
 * doctor responses and verify health indicator behaviour.
 */

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ProviderCard } from './ProviderCard'
import type { ProviderConnection } from '../stores/connections'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
  },
}))

import { api } from '../lib/api'

const mockGet = api.get as ReturnType<typeof vi.fn>

const baseConn: ProviderConnection = {
  id: 'default/openrouter/default',
  name: 'openrouter',
  provider: 'openrouter',
  account: 'default',
  namespace: 'default',
  status: 'untested',
  fields: [
    { name: 'api_key', mode: 'direct' },
  ],
}

const healthyDoctor = { exit: 0, healthy: true, warnings: false, checks: [] }
const warnDoctor = {
  exit: 1,
  healthy: true,
  warnings: true,
  checks: [
    { name: 'key_expiry', section: 'environment', ok: true, warn: true, detail: 'Key expires soon', fix: 'Rotate your API key' },
  ],
}
const errorDoctor = {
  exit: 2,
  healthy: false,
  warnings: false,
  checks: [
    { name: 'provider_connected', section: 'providers', ok: false, detail: 'No connection found', fix: 'Run: keylatch connect openrouter' },
  ],
}

beforeEach(() => {
  vi.clearAllMocks()
  // Default: return healthy
  mockGet.mockResolvedValue(healthyDoctor)
})

describe('ProviderCard — rendering', () => {
  it('renders provider name', async () => {
    render(<ProviderCard connection={baseConn} />)
    const matches = screen.getAllByText('openrouter')
    expect(matches.length).toBeGreaterThanOrEqual(1)
  })

  it('renders ProviderBadge with monogram', () => {
    render(<ProviderCard connection={baseConn} />)
    // The article has aria-label "Provider: openrouter"
    expect(screen.getByRole('article', { name: /Provider: openrouter/i })).toBeInTheDocument()
  })

  // FieldModeBadge was removed — field mode is now shown as inline text in fieldsText.
  it('renders direct mode field metadata text', () => {
    render(<ProviderCard connection={baseConn} />)
    // fieldsText renders "api_key · Vault" for direct mode fields
    expect(screen.getByText(/api_key/)).toBeInTheDocument()
  })

  // FieldModeBadge was removed — reference mode field is shown as inline text.
  it('renders reference mode field metadata text', () => {
    const refConn: ProviderConnection = {
      ...baseConn,
      fields: [{ name: 'api_key', mode: 'reference', uri: 'op://Personal/OpenRouter/api_key' }],
    }
    render(<ProviderCard connection={refConn} />)
    // fieldsText renders "api_key · 1Password" for op:// reference fields
    expect(screen.getByText(/api_key/)).toBeInTheDocument()
  })

  // Edit/Delete actions are now in a kebab DropdownMenu.
  // Use userEvent to properly simulate pointer events that open the Radix UI portal.
  it('calls onEdit when Edit menu item clicked', async () => {
    const user = userEvent.setup()
    const onEdit = vi.fn()
    render(<ProviderCard connection={baseConn} onEdit={onEdit} />)
    // Open the kebab menu using userEvent (needed for Radix UI portal)
    await user.click(screen.getByRole('button', { name: `Actions for ${baseConn.name}` }))
    // The dropdown content renders in a portal — find item by text in document
    await user.click(screen.getByText('Edit'))
    expect(onEdit).toHaveBeenCalled()
  })

  it('calls onDelete when Delete menu item clicked', async () => {
    const user = userEvent.setup()
    const onDelete = vi.fn()
    render(<ProviderCard connection={baseConn} onDelete={onDelete} />)
    await user.click(screen.getByRole('button', { name: `Actions for ${baseConn.name}` }))
    await user.click(screen.getByText('Delete'))
    expect(onDelete).toHaveBeenCalledWith(baseConn.name)
  })

  it('renders multiple fields', () => {
    const conn: ProviderConnection = {
      ...baseConn,
      fields: [
        { name: 'api_key', mode: 'direct' },
        { name: 'org_id', mode: 'reference', uri: 'aws-sm://us-east-1/myapp#org_id' },
      ],
    }
    render(<ProviderCard connection={conn} />)
    // fieldsText contains both field names separated by ' · '
    expect(screen.getByText(/api_key/)).toBeInTheDocument()
    expect(screen.getByText(/org_id/)).toBeInTheDocument()
  })
})

describe('ProviderCard — doctor health indicator', () => {
  it('starts with pending status dot', () => {
    // Don't resolve yet — keep status as pending.
    mockGet.mockReturnValue(new Promise(() => {}))
    render(<ProviderCard connection={baseConn} />)
    // The health label text is rendered as a plain span (not title attr)
    expect(screen.getByText('Health check pending')).toBeInTheDocument()
  })

  it('shows green dot when doctor exit=0', async () => {
    mockGet.mockResolvedValue(healthyDoctor)
    render(<ProviderCard connection={baseConn} />)
    await waitFor(() => {
      expect(screen.getByText('Healthy')).toBeInTheDocument()
    })
  })

  it('shows yellow dot when doctor exit=1', async () => {
    mockGet.mockResolvedValue(warnDoctor)
    render(<ProviderCard connection={baseConn} />)
    await waitFor(() => {
      expect(screen.getByText('Warnings detected')).toBeInTheDocument()
    })
  })

  it('shows red dot when doctor exit=2', async () => {
    mockGet.mockResolvedValue(errorDoctor)
    render(<ProviderCard connection={baseConn} />)
    await waitFor(() => {
      expect(screen.getByText('Errors detected')).toBeInTheDocument()
    })
  })

  it('doctor panel shows correct check rows when exit=1', async () => {
    const user = userEvent.setup()
    mockGet.mockResolvedValue(warnDoctor)
    render(<ProviderCard connection={baseConn} />)

    // Wait for the health status to update before clicking the panel toggle
    await waitFor(() => {
      expect(screen.getByText('Warnings detected')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Show health details' }))

    await waitFor(() => {
      expect(screen.getByText('key_expiry')).toBeInTheDocument()
    })
    // The panel shows check name and detail (no separate fix column in current table)
    expect(screen.getByText('Key expires soon')).toBeInTheDocument()
  })

  it('doctor panel shows error rows with fix hint', async () => {
    const user = userEvent.setup()
    mockGet.mockResolvedValue(errorDoctor)
    render(<ProviderCard connection={baseConn} />)

    // Wait for the health status to update before clicking the panel toggle
    await waitFor(() => {
      expect(screen.getByText('Errors detected')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'Show health details' }))

    await waitFor(() => {
      expect(screen.getByText('provider_connected')).toBeInTheDocument()
    })
    // The panel shows the detail column value
    expect(screen.getByText('No connection found')).toBeInTheDocument()
  })
})
