/**
 * useConnections store tests.
 *
 * Uses fetch mocking to verify that creating two connections via the mock API
 * results in both being available in the connections array.
 */

import { renderHook, act, waitFor } from '@testing-library/react'
import { useConnections } from './connections'

// Mock the api module so we can control server responses.
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

import { api } from '../lib/api'

const mockApi = api as unknown as {
  get: ReturnType<typeof vi.fn>
  post: ReturnType<typeof vi.fn>
  put: ReturnType<typeof vi.fn>
  delete: ReturnType<typeof vi.fn>
}

const connA = {
  id: 'default/openrouter/default',
  name: 'openrouter',
  provider: 'openrouter',
  account: 'default',
  namespace: 'default',
  status: 'untested',
  fields: [{ name: 'api_key', mode: 'direct' as const }],
}

const connB = {
  id: 'default/github/default',
  name: 'github',
  provider: 'github',
  account: 'default',
  namespace: 'default',
  status: 'untested',
  fields: [{ name: 'token', mode: 'reference' as const, uri: 'op://Personal/GitHub/token' }],
}

describe('useConnections', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('starts with empty connections and not loading', () => {
    const { result } = renderHook(() => useConnections())
    expect(result.current.connections).toEqual([])
    expect(result.current.loading).toBe(false)
    expect(result.current.error).toBeNull()
  })

  it('refresh loads connections from the API', async () => {
    mockApi.get.mockResolvedValueOnce({ connections: [connA] })

    const { result } = renderHook(() => useConnections())

    await act(async () => {
      await result.current.refresh()
    })

    expect(result.current.connections).toHaveLength(1)
    expect(result.current.connections[0].provider).toBe('openrouter')
    expect(result.current.loading).toBe(false)
    expect(result.current.error).toBeNull()
  })

  it('creating two connections yields two cards', async () => {
    // First call: initial refresh after create A.
    mockApi.get.mockResolvedValueOnce({ connections: [connA] })
    // Second call: refresh after create B.
    mockApi.get.mockResolvedValueOnce({ connections: [connA, connB] })
    mockApi.post.mockResolvedValue({})

    const { result } = renderHook(() => useConnections())

    await act(async () => {
      await result.current.createConnection({
        provider: 'openrouter',
        fields: [{ name: 'api_key', mode: 'direct', value: 'sk-test' }],
      })
    })
    expect(result.current.connections).toHaveLength(1)

    await act(async () => {
      await result.current.createConnection({
        provider: 'github',
        fields: [{ name: 'token', mode: 'reference', uri: 'op://Personal/GitHub/token' }],
      })
    })
    expect(result.current.connections).toHaveLength(2)
  })

  it('sets error state when refresh fails', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('network error'))

    const { result } = renderHook(() => useConnections())

    await act(async () => {
      await result.current.refresh()
    })

    await waitFor(() => {
      expect(result.current.error).toBeTruthy()
    })
    expect(result.current.connections).toHaveLength(0)
  })

  it('deleteConnection calls DELETE and then refresh', async () => {
    mockApi.delete.mockResolvedValueOnce(undefined)
    mockApi.get.mockResolvedValueOnce({ connections: [] })

    const { result } = renderHook(() => useConnections())

    await act(async () => {
      await result.current.deleteConnection('openrouter')
    })

    expect(mockApi.delete).toHaveBeenCalledWith('/api/connections/openrouter')
    expect(result.current.connections).toHaveLength(0)
  })
})
