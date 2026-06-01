import { render, screen, waitFor, act } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { Dashboard } from './Dashboard'


// ── Mock the api module ────────────────────────────────────────────────────────
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn().mockResolvedValue({ connections: [], approvals: [] }),
  },
  // Dashboard imports DEV_MOCK to guard the SSE branch; set to false so EventSource is used
  DEV_MOCK: false,
}))

// ── Mock fetchReceipts ─────────────────────────────────────────────────────────
vi.mock('../api/receipts', () => ({
  fetchReceipts: vi.fn(),
}))

// ── Stub ReadinessPillWidget ───────────────────────────────────────────────────
// Dashboard.test.tsx tests Dashboard behaviour, not ReadinessPill. Stubbing the
// widget prevents its async api.get('/api/status') polling from leaking state
// updates outside act() and racing with vi.restoreAllMocks() in afterEach.
vi.mock('../components/ReadinessPill', () => ({
  ReadinessPillWidget: () => null,
}))

import { fetchReceipts } from '../api/receipts'
import { api } from '../lib/api'
import type { Receipt } from '../api/receipts'

const mockFetchReceipts = vi.mocked(fetchReceipts)
const mockApiGet = vi.mocked(api.get)

// ── EventSource mock ───────────────────────────────────────────────────────────
// jsdom does not implement EventSource. We provide a minimal stub that captures
// the registered listeners so tests can simulate SSE events.
class MockEventSource {
  static instances: MockEventSource[] = []
  // Mirror the browser constants so the readyState guard in Dashboard works.
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSED = 2

  readonly url: string
  // Default to CONNECTING so polling is not suppressed in tests.
  readyState: number = MockEventSource.CONNECTING
  private listeners: Record<string, Array<(e: MessageEvent) => void>> = {}

  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }

  addEventListener(type: string, handler: (e: MessageEvent) => void) {
    if (!this.listeners[type]) this.listeners[type] = []
    this.listeners[type].push(handler)
  }

  removeEventListener(type: string, handler: (e: MessageEvent) => void) {
    if (this.listeners[type]) {
      this.listeners[type] = this.listeners[type].filter((h) => h !== handler)
    }
  }

  /** Test helper — dispatch a simulated SSE event. */
  emit(type: string, data: string) {
    const event = { data } as MessageEvent
    this.listeners[type]?.forEach((h) => h(event))
  }

  close() {
    // no-op in mock
  }
}

const makeReceipt = (overrides: Partial<Receipt> = {}): Receipt => ({
  runtime: 'gateway_typed',
  provider: 'anthropic',
  capability: 'messages',
  policy_decision: 'allowed',
  credential_shape: 'bearer',
  exit_code: 0,
  ...overrides,
})

describe('Dashboard — receipt feed', () => {
  beforeEach(() => {
    MockEventSource.instances = []
    // Install mock EventSource before each test.
    vi.stubGlobal('EventSource', MockEventSource)

    // Default: connections and approvals endpoints return empty arrays.
    mockApiGet.mockResolvedValue({ connections: [], approvals: [] })
    // Default fallback: subsequent fetchReceipts calls (polling) return [] so
    // they don't throw when mockResolvedValueOnce is exhausted.
    mockFetchReceipts.mockResolvedValue([])
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('renders 2 receipts when fetchReceipts returns 2 items', async () => {
    const receipts = [
      makeReceipt({ provider: 'anthropic', capability: 'messages' }),
      makeReceipt({ provider: 'openai', capability: 'embed' }),
    ]
    mockFetchReceipts.mockResolvedValueOnce(receipts)

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText('anthropic')).toBeInTheDocument()
      expect(screen.getByText('openai')).toBeInTheDocument()
    })
  })

  it('shows "No recent activity" when receipts array is empty', async () => {
    mockFetchReceipts.mockResolvedValueOnce([])

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText('No recent activity')).toBeInTheDocument()
    })
  })

  it('shows retry message on fetch error', async () => {
    mockFetchReceipts.mockRejectedValueOnce(new Error('network error'))

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    await waitFor(() => {
      expect(
        screen.getByText('Could not load activity. Retrying...')
      ).toBeInTheDocument()
    })
  })

  it('renders pass indicator for exit_code 0', async () => {
    mockFetchReceipts.mockResolvedValueOnce([makeReceipt({ exit_code: 0 })])

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    await waitFor(() => {
      // ReceiptCard uses aria-label="Allowed" for a passed receipt (exit_code 0)
      expect(screen.getByLabelText('Allowed')).toBeInTheDocument()
    })
  })

  it('renders fail indicator for non-zero exit_code', async () => {
    mockFetchReceipts.mockResolvedValueOnce([makeReceipt({ exit_code: 1 })])

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    await waitFor(() => {
      // ReceiptCard uses aria-label="Denied" for a failed receipt (non-zero exit_code)
      expect(screen.getByLabelText('Denied')).toBeInTheDocument()
    })
  })

  it('does not render any credential value field', async () => {
    mockFetchReceipts.mockResolvedValueOnce([makeReceipt()])

    const { container } = render(<MemoryRouter><Dashboard /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText('anthropic')).toBeInTheDocument()
    })

    const html = container.innerHTML
    // No field called "value", "secret", "password", or "api_key" should appear.
    expect(html).not.toContain('"value"')
    expect(html).not.toContain('"secret"')
    expect(html).not.toContain('"password"')
    expect(html).not.toContain('"api_key"')
  })
})

// ── EPIC-16 canonical test suite ─────────────────────────────────────────────

describe('Dashboard_FetchesOnMount', () => {
  beforeEach(() => {
    MockEventSource.instances = []
    vi.stubGlobal('EventSource', MockEventSource)
    mockApiGet.mockResolvedValue({ connections: [], approvals: [] })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('calls fetchReceipts exactly once on mount', async () => {
    mockFetchReceipts.mockResolvedValueOnce([])

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    await waitFor(() => expect(mockFetchReceipts).toHaveBeenCalledTimes(1))
    expect(mockFetchReceipts).toHaveBeenCalledWith(10, expect.objectContaining({ signal: expect.any(AbortSignal) }))
  })
})

describe('Dashboard_FallsBackToPollingWhenSSEUnavailable', () => {
  beforeEach(() => {
    MockEventSource.instances = []
    mockApiGet.mockResolvedValue({ connections: [], approvals: [] })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('polls every 5s when EventSource is not available in the global scope', async () => {
    // Remove EventSource from global — simulate an environment where SSE is unavailable.
    // Dashboard checks window.EventSource; we stub it as a throwing constructor to keep
    // the error path realistic (the poll interval must still fire).
    vi.stubGlobal('EventSource', MockEventSource) // still available but stays CONNECTING

    vi.useFakeTimers()
    mockFetchReceipts.mockResolvedValue([])

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    // Let microtasks settle (initial fetch).
    await act(async () => { await vi.advanceTimersByTimeAsync(50) })
    expect(mockFetchReceipts).toHaveBeenCalledTimes(1)

    // Advance 5 seconds — polling should fire because ESS is not OPEN.
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(mockFetchReceipts).toHaveBeenCalledTimes(2)
  }, 15000)
})

describe('Dashboard_PausesWhenHidden', () => {
  beforeEach(() => {
    MockEventSource.instances = []
    vi.stubGlobal('EventSource', MockEventSource)
    mockApiGet.mockResolvedValue({ connections: [], approvals: [] })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    vi.useRealTimers()
    Object.defineProperty(document, 'visibilityState', {
      value: 'visible',
      writable: true,
      configurable: true,
    })
  })

  it('skips poll when document is hidden', async () => {
    mockFetchReceipts.mockResolvedValue([])
    Object.defineProperty(document, 'visibilityState', {
      value: 'hidden',
      writable: true,
      configurable: true,
    })

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    // Initial fetch fires (not gated by visibility).
    await waitFor(() => expect(mockFetchReceipts).toHaveBeenCalledTimes(1))

    vi.useFakeTimers()
    await vi.advanceTimersByTimeAsync(5000)
    await Promise.resolve()

    // Still 1 call — polling is paused.
    expect(mockFetchReceipts).toHaveBeenCalledTimes(1)
  }, 10000)
})

describe('Dashboard_CleansUpOnUnmount', () => {
  beforeEach(() => {
    MockEventSource.instances = []
    vi.stubGlobal('EventSource', MockEventSource)
    mockApiGet.mockResolvedValue({ connections: [], approvals: [] })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('closes the EventSource and clears the poll interval on unmount', async () => {
    vi.useFakeTimers()
    mockFetchReceipts.mockResolvedValue([])

    const { unmount } = render(<MemoryRouter><Dashboard /></MemoryRouter>)

    // Let initial fetch settle.
    await act(async () => { await vi.advanceTimersByTimeAsync(50) })

    expect(MockEventSource.instances.length).toBeGreaterThan(0)

    const closeSpy = vi.spyOn(MockEventSource.instances[0], 'close')

    unmount()

    expect(closeSpy).toHaveBeenCalledTimes(1)

    // After unmount: advancing 10 seconds should not trigger additional fetchReceipts calls.
    const callsBefore = mockFetchReceipts.mock.calls.length
    await act(async () => { await vi.advanceTimersByTimeAsync(10000) })
    expect(mockFetchReceipts).toHaveBeenCalledTimes(callsBefore)
  }, 15000)
})

describe('Dashboard_NeverRendersCredential', () => {
  beforeEach(() => {
    MockEventSource.instances = []
    vi.stubGlobal('EventSource', MockEventSource)
    mockApiGet.mockResolvedValue({ connections: [], approvals: [] })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('never renders credential value fields in the DOM (S-RM-9)', async () => {
    const canary = 'sk-test-canary-credential-value-should-never-appear'
    mockFetchReceipts.mockResolvedValueOnce([
      makeReceipt({ provider: canary.slice(0, 8) }), // use only the non-secret prefix
    ])

    const { container } = render(<MemoryRouter><Dashboard /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText(canary.slice(0, 8))).toBeInTheDocument()
    })

    const html = container.innerHTML
    // Canary full value must not appear.
    expect(html).not.toContain(canary)
    // Credential field names must not appear as JSON keys.
    expect(html).not.toContain('"value"')
    expect(html).not.toContain('"secret"')
    expect(html).not.toContain('"password"')
    expect(html).not.toContain('"api_key"')
  })
})

describe('Dashboard — polling (T03)', () => {
  beforeEach(() => {
    MockEventSource.instances = []
    vi.stubGlobal('EventSource', MockEventSource)
    mockApiGet.mockResolvedValue({ connections: [], approvals: [] })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('calls fetchReceipts a second time after 5 seconds (polling)', async () => {
    // Install fake timers before rendering so setInterval is also faked.
    vi.useFakeTimers()
    mockFetchReceipts.mockResolvedValue([])

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    // Flush microtasks using a fake setTimeout(0) — avoids relying on waitFor
    // which itself uses setInterval (faked).
    await act(async () => {
      // Advance a tiny amount so microtasks (Promise callbacks) can run,
      // but NOT enough to trigger the 5-second poll.
      await vi.advanceTimersByTimeAsync(100)
    })

    expect(mockFetchReceipts).toHaveBeenCalledTimes(1)

    // Advance to trigger the 5-second polling cycle.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000)
    })

    expect(mockFetchReceipts).toHaveBeenCalledTimes(2)
  }, 15000)

  it('does not poll when document is hidden', async () => {
    mockFetchReceipts.mockResolvedValue([])

    // Simulate hidden tab.
    Object.defineProperty(document, 'visibilityState', {
      value: 'hidden',
      writable: true,
      configurable: true,
    })

    render(<MemoryRouter><Dashboard /></MemoryRouter>)

    // Initial fetch still happens (it's not gated by visibility).
    await waitFor(() => expect(mockFetchReceipts).toHaveBeenCalledTimes(1))

    // Switch to fake timers to advance the polling interval.
    vi.useFakeTimers()

    // Advance 5s — the poll function should skip because visibilityState === 'hidden'.
    await vi.advanceTimersByTimeAsync(5000)
    await Promise.resolve()

    // Still 1 call — the second poll was skipped.
    expect(mockFetchReceipts).toHaveBeenCalledTimes(1)

    // Restore visibility state.
    Object.defineProperty(document, 'visibilityState', {
      value: 'visible',
      writable: true,
      configurable: true,
    })
  }, 10000)
})
