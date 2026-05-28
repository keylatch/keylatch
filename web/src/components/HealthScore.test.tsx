import { render, screen } from '@testing-library/react'
import { HealthScore } from './HealthScore'

describe('HealthScore', () => {
  it('has role=meter', () => {
    render(<HealthScore score={75} />)
    expect(screen.getByRole('meter')).toBeInTheDocument()
  })

  it('sets aria-valuenow correctly', () => {
    render(<HealthScore score={80} />)
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '80')
  })

  it('sets aria-valuemin=0 and aria-valuemax=100', () => {
    render(<HealthScore score={50} />)
    const meter = screen.getByRole('meter')
    expect(meter).toHaveAttribute('aria-valuemin', '0')
    expect(meter).toHaveAttribute('aria-valuemax', '100')
  })

  it('clamps score above 100', () => {
    render(<HealthScore score={150} />)
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '100')
  })

  it('clamps score below 0', () => {
    render(<HealthScore score={-10} />)
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '0')
  })

  it('renders tooltip when provided', () => {
    render(<HealthScore score={60} tooltip="Connection health" />)
    const container = document.querySelector('[title="Connection health"]')
    expect(container).toBeInTheDocument()
  })
})
