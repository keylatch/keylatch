import { render, screen, waitFor, act } from '@testing-library/react'
import { vi, describe, it, expect, afterEach } from 'vitest'
import { ReadinessPillWidget, computePillState } from './ReadinessPill'
import type { Connection } from '../lib/types'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
  },
}))

import { api } from '../lib/api'
const mockApiGet = vi.mocked(api.get)

const makeConnection = (overrides: Partial<Connection> = {}): Connection => ({
  name: 'test-conn',
  provider: 'openrouter',
  status: 'ok',
  risk: 'low',
  ...overrides,
})

// ── computePillState unit tests ───────────────────────────────────────────────

describe('computePillState', () => {
  it('returns not_ready when daemon is down', () => {
    const pill = computePillState(false, false, [])
    expect(pill.state).toBe('not_ready')
    expect(pill.missingItem).toBe('daemon not running')
  })

  it('returns not_ready when KEK not loaded', () => {
    const pill = computePillState(true, false, [makeConnection()])
    expect(pill.state).toBe('not_ready')
    expect(pill.missingItem).toBe('KEK not configured')
  })

  it('returns not_ready when no verified providers', () => {
    const pill = computePillState(true, true, [makeConnection({ status: 'untested' })])
    expect(pill.state).toBe('not_ready')
    expect(pill.missingItem).toBe('no provider verified')
  })

  it('returns ready when daemon up + KEK + verified provider', () => {
    const pill = computePillState(true, true, [makeConnection({ status: 'ok' })])
    expect(pill.state).toBe('ready')
  })

  it('returns degraded when at least one provider has error', () => {
    const connections = [
      makeConnection({ name: 'good', status: 'ok' }),
      makeConnection({ name: 'bad-backend', status: 'error' }),
    ]
    const pill = computePillState(true, true, connections)
    expect(pill.state).toBe('degraded')
    expect(pill.failingBackend).toBe('bad-backend')
  })
})

// ── ReadinessPillWidget integration tests ─────────────────────────────────────

describe('ReadinessPillWidget', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.useRealTimers()
  })

  const renderPill = (connections: Connection[] = []) =>
    render(<ReadinessPillWidget connections={connections} />)

  it('shows Not ready when daemon is down', async () => {
    mockApiGet.mockResolvedValue({ ok: false, kek_loaded: false })

    renderPill([])

    await waitFor(() => {
      expect(screen.getByText(/Not ready/)).toBeInTheDocument()
    })
  })

  it('shows Ready for agents when daemon up + KEK + verified provider', async () => {
    mockApiGet.mockResolvedValue({ ok: true, kek_loaded: true })

    renderPill([makeConnection({ status: 'ok' })])

    await waitFor(() => {
      expect(screen.getByText('Ready for agents')).toBeInTheDocument()
    })
  })

  it('shows Degraded when a provider has error status', async () => {
    mockApiGet.mockResolvedValue({ ok: true, kek_loaded: true })

    const connections = [
      makeConnection({ name: 'ok-conn', status: 'ok' }),
      makeConnection({ name: 'bad-conn', status: 'error' }),
    ]
    renderPill(connections)

    await waitFor(() => {
      expect(screen.getByText(/Degraded/)).toBeInTheDocument()
      expect(screen.getByText(/bad-conn/)).toBeInTheDocument()
    })
  })

  it('polls /api/status a second time after 5 seconds', async () => {
    vi.useFakeTimers()
    mockApiGet.mockResolvedValue({ ok: true, kek_loaded: true })

    renderPill([makeConnection({ status: 'ok' })])

    // Let the initial fetch settle.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(100)
    })

    const callsAfterInit = mockApiGet.mock.calls.length

    // Advance to trigger the 5-second poll.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000)
    })

    expect(mockApiGet.mock.calls.length).toBeGreaterThan(callsAfterInit)
  }, 15000)
})
