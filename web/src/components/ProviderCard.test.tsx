/**
 * ProviderCard tests — T-14-01 + T-14-07.
 *
 * The card now polls /api/doctor on mount. We mock the api module to control
 * doctor responses and verify health indicator behaviour.
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
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
    expect(screen.getByText('OP')).toBeInTheDocument()
  })

  it('renders direct mode field badge', () => {
    render(<ProviderCard connection={baseConn} />)
    expect(screen.getByLabelText('api_key: direct')).toBeInTheDocument()
  })

  it('renders reference mode field badge with scheme', () => {
    const refConn: ProviderConnection = {
      ...baseConn,
      fields: [{ name: 'api_key', mode: 'reference', uri: 'op://Personal/OpenRouter/api_key' }],
    }
    render(<ProviderCard connection={refConn} />)
    expect(screen.getByLabelText('api_key: ref:op')).toBeInTheDocument()
  })

  it('calls onEdit when Edit button clicked', async () => {
    const onEdit = vi.fn()
    render(<ProviderCard connection={baseConn} onEdit={onEdit} />)
    fireEvent.click(screen.getByRole('button', { name: 'Edit openrouter' }))
    expect(onEdit).toHaveBeenCalledWith(baseConn.id)
  })

  it('calls onDelete when Delete button clicked', async () => {
    const onDelete = vi.fn()
    render(<ProviderCard connection={baseConn} onDelete={onDelete} />)
    fireEvent.click(screen.getByRole('button', { name: 'Delete openrouter' }))
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
    expect(screen.getByLabelText('api_key: direct')).toBeInTheDocument()
    expect(screen.getByLabelText('org_id: ref:aws-sm')).toBeInTheDocument()
  })
})

describe('ProviderCard — doctor health indicator (T-14-07)', () => {
  it('starts with pending status dot', () => {
    // Don't resolve yet — keep status as pending.
    mockGet.mockReturnValue(new Promise(() => {}))
    render(<ProviderCard connection={baseConn} />)
    expect(screen.getByRole('button', { name: 'Health check pending' })).toBeInTheDocument()
  })

  it('shows green dot when doctor exit=0', async () => {
    mockGet.mockResolvedValue(healthyDoctor)
    render(<ProviderCard connection={baseConn} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Healthy' })).toBeInTheDocument()
    })
  })

  it('shows yellow dot when doctor exit=1', async () => {
    mockGet.mockResolvedValue(warnDoctor)
    render(<ProviderCard connection={baseConn} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Warnings detected' })).toBeInTheDocument()
    })
  })

  it('shows red dot when doctor exit=2', async () => {
    mockGet.mockResolvedValue(errorDoctor)
    render(<ProviderCard connection={baseConn} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Errors detected' })).toBeInTheDocument()
    })
  })

  it('clicking status dot opens doctor check panel', async () => {
    mockGet.mockResolvedValue(warnDoctor)
    render(<ProviderCard connection={baseConn} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Warnings detected' })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Warnings detected' }))
    expect(screen.getByRole('region', { name: 'Doctor check results' })).toBeInTheDocument()
  })

  it('doctor panel shows correct check rows when exit=1', async () => {
    mockGet.mockResolvedValue(warnDoctor)
    render(<ProviderCard connection={baseConn} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Warnings detected' })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Warnings detected' }))

    expect(screen.getByText('key_expiry')).toBeInTheDocument()
    expect(screen.getByText('Rotate your API key')).toBeInTheDocument()
  })

  it('doctor panel shows error rows with fix hint', async () => {
    mockGet.mockResolvedValue(errorDoctor)
    render(<ProviderCard connection={baseConn} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Errors detected' })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: 'Errors detected' }))

    expect(screen.getByText('provider_connected')).toBeInTheDocument()
    expect(screen.getByText('Run: keylatch connect openrouter')).toBeInTheDocument()
  })
})
