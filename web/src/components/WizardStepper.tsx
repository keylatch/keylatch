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
  const pct = steps.length <= 1 ? 100 : (currentStep / (steps.length - 1)) * 100

  return (
    <div
      role="progressbar"
      aria-valuenow={currentStep + 1}
      aria-valuemin={1}
      aria-valuemax={steps.length}
      aria-label={`Step ${currentStep + 1} of ${steps.length}: ${steps[currentStep]?.label ?? ''}`}
      className={cn('space-y-3', className)}
    >
      {/* Progress track */}
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-neutral-200)]">
        <div
          className="h-full rounded-full bg-[var(--color-primary-600)] transition-[width] duration-[var(--duration-slow)]"
          style={{ width: `${pct}%` }}
        />
      </div>

      {/* Steps list */}
      <ol className="flex items-start gap-2" aria-hidden="true">
        {steps.map((step, idx) => {
          const isCompleted = step.completed || idx < currentStep
          const isActive = idx === currentStep

          return (
            <li
              key={step.label}
              className="flex flex-1 flex-col items-center gap-1.5"
            >
              {/* Step indicator circle */}
              <span
                data-testid="wizard-step-indicator"
                className={cn(
                  'flex h-6 w-6 items-center justify-center rounded-full text-xs font-semibold transition-colors',
                  isCompleted && 'bg-[var(--color-primary-600)] text-[var(--color-text-inverse)]',
                  isActive && !isCompleted && 'border-2 border-[var(--color-primary-600)] text-[var(--color-primary-600)]',
                  !isActive && !isCompleted && 'border-2 border-[var(--color-neutral-300)] text-[var(--color-text-disabled)]'
                )}
              >
                {isCompleted ? '✓' : idx + 1}
              </span>

              {/* Step label — always on desktop */}
              <span
                className={cn(
                  'hidden text-xs text-center leading-tight sm:block',
                  isActive ? 'font-medium text-[var(--color-text-primary)]' : 'text-[var(--color-text-secondary)]'
                )}
              >
                {step.label}
              </span>

              {/* Mobile: only active step label */}
              {isActive && (
                <span
                  data-testid="wizard-step-label-mobile"
                  className="text-xs font-medium text-[var(--color-text-primary)] text-center sm:hidden"
                >
                  {step.label}
                </span>
              )}
            </li>
          )
        })}
      </ol>
    </div>
  )
}
