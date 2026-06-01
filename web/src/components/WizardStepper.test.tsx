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

  // WizardStepper was refactored to a minimal <p> tag with no per-step indicators.
  // It shows "Step N of M" text and the current step label — no checkmarks or
  // per-step data-testid attributes. Tests below verify the new minimal output.

  it('shows current step number in text', () => {
    render(<WizardStepper steps={steps} currentStep={2} />)
    expect(screen.getByText(/Step 3 of 6/)).toBeInTheDocument()
  })

  it('shows active step label', () => {
    render(<WizardStepper steps={steps} currentStep={2} />)
    // The active step label is rendered as a <span> with font-medium class
    expect(screen.getByText('Verify')).toBeInTheDocument()
  })

  it('renders for any valid currentStep without throwing', () => {
    steps.forEach((_, idx) => {
      const { unmount } = render(<WizardStepper steps={steps} currentStep={idx} />)
      unmount()
    })
  })
})
