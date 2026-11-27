import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import { ApprovalInbox } from './ApprovalInbox'
import { api } from '../lib/api'
import type { Approval } from '../lib/types'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn() },
  ApiError: class extends Error {},
  DEV_MOCK: true,
}))

const approval: Approval = {
  token: 'apv_' + 'a'.repeat(32), connection: 'production', actor: 'agent',
  capability: 'run:D5', summary: 'Command: ["deploy", "--production"]\nHosts: ["api.example.test"]\nTTL: 5m',
  request_hash: 'request-hash', digest: 'b'.repeat(64), status: 'pending',
  created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 300_000).toISOString(),
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(api.get).mockResolvedValue([approval])
})

it('shows the full plan and sends exactly the displayed digest', async () => {
  vi.mocked(api.post).mockImplementation(async () => {
    vi.mocked(api.get).mockResolvedValue([])
    return { ok: true }
  })
  render(<ApprovalInbox />)
  expect(await screen.findByLabelText('Requested operation')).toHaveTextContent('--production')
  expect(screen.getByLabelText('Requested operation')).toHaveTextContent('api.example.test')
  fireEvent.click(screen.getByRole('button', { name: 'Approve request' }))
  await waitFor(() => expect(api.post).toHaveBeenCalledWith(`/api/approvals/${approval.token}/approve`, { digest: approval.digest }, { signal: expect.any(AbortSignal) }))
  expect(await screen.findByText('No pending approvals.')).toBeInTheDocument()
})

it('retains the card and allows retry after a refused decision', async () => {
  vi.mocked(api.post).mockRejectedValue(new Error('presence denied'))
  render(<ApprovalInbox />)
  fireEvent.click(await screen.findByRole('button', { name: 'Deny request' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Failed to deny request')
  expect(screen.getByRole('button', { name: 'Deny request' })).toBeEnabled()
  expect(screen.getByLabelText('Requested operation')).toBeInTheDocument()
})

it('shows broker outages rather than claiming the inbox is empty', async () => {
  vi.mocked(api.get).mockRejectedValue(new Error('offline'))
  render(<ApprovalInbox />)
  expect(await screen.findByRole('alert')).toHaveTextContent('Cannot load approval requests')
  expect(screen.queryByText('No pending approvals.')).not.toBeInTheDocument()
})

it('disables expired decisions without submitting a denial', async () => {
  vi.mocked(api.get).mockResolvedValue([{ ...approval, expires_at: new Date(Date.now() - 1000).toISOString() }])
  render(<ApprovalInbox />)
  expect(await screen.findByText('Expired')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Approve request' })).toBeDisabled()
  expect(screen.getByRole('button', { name: 'Deny request' })).toBeDisabled()
  expect(api.post).not.toHaveBeenCalled()
})

it('cancels the pending HTTP decision when leaving the inbox', async () => {
  let signal: AbortSignal | undefined
  vi.mocked(api.post).mockImplementation((_path, _body, opts) => {
    signal = opts?.signal
    return new Promise((_resolve, reject) => {
      signal?.addEventListener('abort', () => reject(new Error('aborted')))
    })
  })
  const view = render(<ApprovalInbox />)
  fireEvent.click(await screen.findByRole('button', { name: 'Approve request' }))
  await waitFor(() => expect(signal).toBeDefined())
  await act(async () => { view.unmount() })
  expect(signal?.aborted).toBe(true)
})

it('keeps the reviewed plan visible while its decision is pending', async () => {
  vi.useFakeTimers()
  try {
    let rejectDecision!: (err: Error) => void
    vi.mocked(api.post).mockImplementation(() => new Promise((_resolve, reject) => { rejectDecision = reject }))
    const changed = { ...approval, digest: 'c'.repeat(64), summary: 'A changed operation' }
    let view!: ReturnType<typeof render>
    await act(async () => { view = render(<ApprovalInbox />) })
    fireEvent.click(screen.getByRole('button', { name: 'Approve request' }))
    vi.mocked(api.get).mockResolvedValue([changed])
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(screen.getByLabelText('Requested operation')).toHaveTextContent('--production')
    expect(api.post).toHaveBeenCalledWith(`/api/approvals/${approval.token}/approve`, { digest: approval.digest }, { signal: expect.any(AbortSignal) })
    await act(async () => { rejectDecision(new Error('request changed')) })
    expect(screen.getByRole('button', { name: 'Approve request' })).toBeEnabled()
    expect(screen.getByLabelText('Requested operation')).toHaveTextContent('A changed operation')
    view.unmount()
  } finally {
    vi.useRealTimers()
  }
})
