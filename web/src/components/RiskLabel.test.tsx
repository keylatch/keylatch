import { render, screen } from '@testing-library/react'
import { RiskLabel } from './RiskLabel'
import type { RiskLevel } from '../lib/types'

describe('RiskLabel', () => {
  const levels: RiskLevel[] = ['low', 'medium', 'high']

  it.each(levels)('renders text label for risk=%s', (risk) => {
    render(<RiskLabel risk={risk} />)
    const el = screen.getByText(risk.charAt(0).toUpperCase() + risk.slice(1))
    expect(el).toBeInTheDocument()
  })

  it.each(levels)('has aria-label="Risk level: ..." for risk=%s', (risk) => {
    render(<RiskLabel risk={risk} />)
    const label = `Risk level: ${risk.charAt(0).toUpperCase() + risk.slice(1)}`
    expect(screen.getByLabelText(label)).toBeInTheDocument()
  })

  it('renders all 3 variants without throwing', () => {
    levels.forEach((r) => {
      const { unmount } = render(<RiskLabel risk={r} />)
      unmount()
    })
  })
})
