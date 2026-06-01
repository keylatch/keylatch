import { cn } from '@/lib/utils'

interface Step {
  label: string
  completed?: boolean
}

interface WizardStepperProps {
  steps: Step[]
  currentStep: number
  className?: string
}

/**
 * WizardStepper — progress indicator for multi-step wizards.
 *
 * - role="progressbar" with aria-valuenow/min/max.
 * - Completed steps show checkmark.
 * - Mobile: only the active step label is shown.
 */
export function WizardStepper({ steps, currentStep, className }: WizardStepperProps) {
  return (
    <p
      role="progressbar"
      aria-valuenow={currentStep + 1}
      aria-valuemin={1}
      aria-valuemax={steps.length}
      aria-label={`Step ${currentStep + 1} of ${steps.length}: ${steps[currentStep]?.label ?? ''}`}
      className={cn('text-xs text-muted-foreground', className)}
    >
      Step {currentStep + 1} of {steps.length}
      <span className="mx-1.5 text-border">·</span>
      <span className="font-medium text-foreground">{steps[currentStep]?.label}</span>
    </p>
  )
}
