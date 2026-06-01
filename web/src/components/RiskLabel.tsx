import type { RiskLevel } from '../lib/types'
import { cn } from '@/lib/utils'

interface RiskLabelProps {
  risk: RiskLevel
  className?: string
}

const LABELS: Record<RiskLevel, string> = {
  low: 'Low risk',
  medium: 'Medium risk',
  high: 'High risk',
}

const RISK_CLASSES: Record<RiskLevel, string> = {
  low:    'bg-emerald-100 text-emerald-700',
  medium: 'bg-amber-100 text-amber-700',
  high:   'bg-red-100 text-red-700',
}

/**
 * RiskLabel — displays a risk classification badge.
 *
 * Always includes an aria-label with the full description so
 * screen readers announce "Risk level: High" not just "High".
 */
export function RiskLabel({ risk, className }: RiskLabelProps) {
  return (
    <span
      aria-label={`Risk level: ${LABELS[risk]}`}
      className={cn(
        'inline-flex items-center rounded-full border border-transparent px-2.5 py-0.5 text-xs font-semibold',
        RISK_CLASSES[risk],
        className
      )}
    >
      {LABELS[risk]}
    </span>
  )
}
