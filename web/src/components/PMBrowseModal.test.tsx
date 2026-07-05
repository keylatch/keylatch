/**
 * PMBrowseModal tests — .
 *
 * Tests:
 * - Unauthenticated: shows hint text and copy button, no item list
 * - Authenticated: shows item list; clicking an item builds + passes URI to onSelect
 * - Manual fallback: always rendered regardless of auth state
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { PMBrowseModal } from './PMBrowseModal'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
  },
}))

import { api } from '../lib/api'

const mockGet = api.get as ReturnType<typeof vi.fn>

beforeEach(() => {
  vi.clearAllMocks()
})

describe('PMBrowseModal — unauthenticated', () => {
  beforeEach(() => {
    mockGet.mockResolvedValue({
      authenticated: false,
      hint: 'Run: op signin',
    })
  })

  it('shows unauthenticated status when authenticated is false', async () => {
    render(<PMBrowseModal pm="op" onSelect={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      // The unauthenticated block renders with role="status" (no aria-label name)
      expect(screen.getByRole('status')).toBeInTheDocument()
    })
  })

  it('shows the hint text', async () => {
    render(<PMBrowseModal pm="op" onSelect={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByText('Run: op signin')).toBeInTheDocument()
    })
  })

  it('shows Copy button for the hint', async () => {
    render(<PMBrowseModal pm="op" onSelect={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      // The copy button has aria-label 'Copy authentication command' (icon-only button)
      expect(screen.getByRole('button', { name: 'Copy authentication command' })).toBeInTheDocument()
    })
  })

  it('does NOT render an item list when unauthenticated', async () => {
    render(<PMBrowseModal pm="op" onSelect={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.queryByRole('listbox')).toBeNull()
    })
  })

  it('manual URI input is always present', async () => {
    render(<PMBrowseModal pm="op" onSelect={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      // For 'op' PM the label is 'Complete the URI (replace <field> with the field name):'
      // The input has id="pm-browse-manual-input" linked to that label
      expect(screen.getByLabelText(/Complete the URI/i)).toBeInTheDocument()
    })
  })
})

describe('PMBrowseModal — authenticated', () => {
  beforeEach(() => {
    mockGet.mockResolvedValue({
      authenticated: true,
      items: [
        // Use a realistic multi-segment ID so buildURI produces a valid URI
        // that passes the updated REF_URI_PATTERN (requires at least one '/').
        { id: 'us-east-1/openrouter-api-key', title: 'OpenRouter API Key' },
        { id: 'us-east-1/github-pat', title: 'GitHub PAT' },
      ],
    })
  })

  it('shows the item list when authenticated', async () => {
    render(<PMBrowseModal pm="op" onSelect={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByRole('listbox')).toBeInTheDocument()
    })
    // Item buttons have just the title as accessible name (no "Select" prefix)
    expect(screen.getByRole('button', { name: 'OpenRouter API Key' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'GitHub PAT' })).toBeInTheDocument()
  })

  it('populates the manual URI input with a placeholder when an op item is clicked (C-01)', async () => {
    // For 1Password items, clicking an item populates the manual URI input with an
    // op://<slug>/<field> placeholder rather than immediately calling onSelect.
    // The user must replace <field> with the actual field name before submitting.
    const onSelect = vi.fn()
    render(<PMBrowseModal pm="op" onSelect={onSelect} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'OpenRouter API Key' })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: 'OpenRouter API Key' }))
    // onSelect is NOT called directly — the URI is placed in the manual input.
    expect(onSelect).not.toHaveBeenCalled()
    const input = screen.getByLabelText(/Complete the URI/i) as HTMLInputElement
    expect(input.value).toMatch(/^op:\/\//)
    expect(input.value).toContain('<field>')
  })

  it('calls onSelect with aws-sm:// URI for aws_sm PM', async () => {
    const onSelect = vi.fn()
    render(<PMBrowseModal pm="aws_sm" onSelect={onSelect} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'OpenRouter API Key' })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: 'OpenRouter API Key' }))
    expect(onSelect).toHaveBeenCalledWith(expect.stringContaining('aws-sm://'))
  })

  it('manual fallback still present when authenticated', async () => {
    render(<PMBrowseModal pm="op" onSelect={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByLabelText(/Complete the URI/i)).toBeInTheDocument()
    })
  })

  it('calls onSelect with manual URI when "Use URI" is clicked', async () => {
    const onSelect = vi.fn()
    render(<PMBrowseModal pm="op" onSelect={onSelect} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByLabelText(/Complete the URI/i)).toBeInTheDocument()
    })
    fireEvent.change(screen.getByLabelText(/Complete the URI/i), {
      target: { value: 'op://vault/item/field' },
    })
    // Button text is 'Use URI' (not 'Use this URI')
    fireEvent.click(screen.getByRole('button', { name: 'Use URI' }))
    expect(onSelect).toHaveBeenCalledWith('op://vault/item/field')
  })
})
