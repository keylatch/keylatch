import type { RiskLevel } from '../lib/types'
import { Badge } from '@/components/ui/badge'
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

/**
 * RiskLabel — displays a risk classification badge.
 *
 * Always includes an aria-label with the full description so
 * screen readers announce "Risk level: High" not just "High".
 */
export function RiskLabel({ risk, className }: RiskLabelProps) {
  const variant =
    risk === 'high' ? 'destructive' :
    risk === 'medium' ? 'warning' :
    'success'

  return (
    <Badge
      variant={variant}
      className={cn(className)}
      aria-label={`Risk level: ${LABELS[risk]}`}
    >
      {LABELS[risk]}
    </Badge>
  )
}
