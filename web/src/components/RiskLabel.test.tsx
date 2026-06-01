import { render, screen } from '@testing-library/react'
import { RiskLabel } from './RiskLabel'
import type { RiskLevel } from '../lib/types'

describe('RiskLabel', () => {
  const levels: RiskLevel[] = ['low', 'medium', 'high']

  // Labels are now 'Low risk', 'Medium risk', 'High risk' (LABELS map in RiskLabel.tsx)
  const LABELS: Record<RiskLevel, string> = {
    low: 'Low risk',
    medium: 'Medium risk',
    high: 'High risk',
  }

  it.each(levels)('renders text label for risk=%s', (risk) => {
    render(<RiskLabel risk={risk} />)
    const el = screen.getByText(LABELS[risk])
    expect(el).toBeInTheDocument()
  })

  it.each(levels)('has aria-label="Risk level: ..." for risk=%s', (risk) => {
    render(<RiskLabel risk={risk} />)
    // aria-label uses the full label including "risk" suffix: e.g. "Risk level: Low risk"
    const label = `Risk level: ${LABELS[risk]}`
    expect(screen.getByLabelText(label)).toBeInTheDocument()
  })

  it('renders all 3 variants without throwing', () => {
    levels.forEach((r) => {
      const { unmount } = render(<RiskLabel risk={r} />)
      unmount()
    })
  })
})
