import { render, screen } from '@testing-library/react'
import { StatusChip } from './StatusChip'
import type { ConnectionStatus } from '../lib/types'

describe('StatusChip', () => {
  const statuses: ConnectionStatus[] = ['ok', 'error', 'untested', 'expired', 'warning']

  it.each(statuses)('renders text label for status=%s', (status) => {
    render(<StatusChip status={status} />)
    // Must always show a text label
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.getByRole('status').textContent).toBeTruthy()
  })

  it('has role=status', () => {
    render(<StatusChip status="ok" />)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })

  it('includes aria-label describing the status', () => {
    render(<StatusChip status="error" />)
    expect(screen.getByRole('status')).toHaveAttribute('aria-label', 'Status: Error')
  })

  it('renders all 5 variants without throwing', () => {
    statuses.forEach((s) => {
      const { unmount } = render(<StatusChip status={s} />)
      unmount()
    })
  })
})
