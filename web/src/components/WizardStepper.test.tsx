import { render, screen } from '@testing-library/react'
import { WizardStepper } from './WizardStepper'

const steps = [
  { label: 'Backend' },
  { label: 'Connection' },
  { label: 'Verify' },
  { label: 'Policy' },
  { label: 'Agent' },
  { label: 'Done' },
]

describe('WizardStepper', () => {
  it('has role=progressbar', () => {
    render(<WizardStepper steps={steps} currentStep={0} />)
    expect(screen.getByRole('progressbar')).toBeInTheDocument()
  })

  it('sets aria-valuenow to currentStep+1', () => {
    render(<WizardStepper steps={steps} currentStep={2} />)
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuenow', '3')
  })

  it('sets aria-valuemax to total steps', () => {
    render(<WizardStepper steps={steps} currentStep={0} />)
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuemax', String(steps.length))
  })

  it('completed steps show checkmarks', () => {
    render(<WizardStepper steps={steps} currentStep={2} />)
    const indicators = screen.getAllByTestId('wizard-step-indicator')
    // Steps 0 and 1 should be completed (before currentStep=2)
    expect(indicators[0].textContent).toBe('✓')
    expect(indicators[1].textContent).toBe('✓')
  })

  it('active step shows current number', () => {
    render(<WizardStepper steps={steps} currentStep={2} />)
    const indicators = screen.getAllByTestId('wizard-step-indicator')
    expect(indicators[2].textContent).toBe('3')
  })

  it('active step label is shown for mobile', () => {
    render(<WizardStepper steps={steps} currentStep={1} />)
    const mobileLabels = screen.getAllByTestId('wizard-step-label-mobile')
    expect(mobileLabels).toHaveLength(1)
    expect(mobileLabels[0].textContent).toBe('Connection')
  })
})
