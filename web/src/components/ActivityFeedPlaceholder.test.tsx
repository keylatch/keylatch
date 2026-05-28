import { render, screen, act, fireEvent } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach } from 'vitest'
import { ActivityFeedPlaceholder } from './ActivityFeedPlaceholder'

const mockWriteText = vi.fn()

// Stub clipboard at module level — same pattern as SafeCopyButton.test.tsx.
vi.stubGlobal('navigator', {
  ...navigator,
  clipboard: { writeText: mockWriteText },
})

describe('ActivityFeedPlaceholder', () => {
  beforeEach(() => {
    mockWriteText.mockResolvedValue(undefined)
    vi.clearAllMocks()
  })

  it('renders the coming-soon title', () => {
    render(<ActivityFeedPlaceholder />)
    expect(screen.getByText(/Activity feed — coming in 0\.1\.1/)).toBeInTheDocument()
  })

  it('renders the CLI command', () => {
    render(<ActivityFeedPlaceholder />)
    expect(screen.getByText('keylatch receipts list')).toBeInTheDocument()
  })

  it('has a Copy command button', () => {
    render(<ActivityFeedPlaceholder />)
    expect(screen.getByRole('button', { name: /copy command/i })).toBeInTheDocument()
  })

  it('Copy command button copies the receipts command to clipboard', async () => {
    render(<ActivityFeedPlaceholder />)
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /copy command/i }))
    })
    expect(mockWriteText).toHaveBeenCalledWith('keylatch receipts list')
  })

  it('has no close or dismiss button', () => {
    render(<ActivityFeedPlaceholder />)
    // All buttons must not be labeled "close", "dismiss", or "don't show again".
    const allButtons = screen.getAllByRole('button')
    for (const btn of allButtons) {
      const label = (btn.textContent ?? '').toLowerCase()
      const ariaLabel = (btn.getAttribute('aria-label') ?? '').toLowerCase()
      expect(label).not.toMatch(/\bclose\b|\bdismiss\b/)
      expect(ariaLabel).not.toMatch(/\bclose\b|\bdismiss\b/)
    }
  })

  it('has role=complementary landmark', () => {
    const { container } = render(<ActivityFeedPlaceholder />)
    const el = container.querySelector('[role="complementary"]')
    expect(el).not.toBeNull()
  })
})
