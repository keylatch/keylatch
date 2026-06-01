import { useState, useEffect, useRef } from 'react'
import { cn } from '@/lib/utils'

interface HealthScoreProps {
  score: number        // 0–100
  label?: string
  tooltip?: string
  className?: string
}

/**
 * HealthScore — animated meter (0–100).
 *
 * Accessibility: role="meter" with aria-valuenow/min/max.
 * prefers-reduced-motion: animation collapses to 0ms via CSS token.
 */
export function HealthScore({
  score,
  label = 'Health',
  tooltip,
  className,
}: HealthScoreProps) {
  const clampedScore = Math.max(0, Math.min(100, score))
  const [displayed, setDisplayed] = useState(0)
  const rafRef = useRef<number | null>(null)
  const startRef = useRef<number | null>(null)

  useEffect(() => {
    startRef.current = null

    // Respect prefers-reduced-motion at runtime.
    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (prefersReduced) {
      setDisplayed(clampedScore)
      return
    }

    const duration = 600 // ms
    const startValue = 0

    const animate = (timestamp: number) => {
      if (!startRef.current) startRef.current = timestamp
      const elapsed = timestamp - startRef.current
      const progress = Math.min(elapsed / duration, 1)
      setDisplayed(Math.round(startValue + (clampedScore - startValue) * progress))
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(animate)
      }
    }

    rafRef.current = requestAnimationFrame(animate)
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clampedScore])

  // Color the fill based on score — use CSS variable values directly in style
  const fillColor =
    clampedScore >= 80 ? '#22c55e' :
    clampedScore >= 50 ? '#eab308' :
    '#ef4444'

  return (
    <div className={cn('flex items-center gap-3', className)} title={tooltip}>
      <div
        role="meter"
        aria-valuenow={clampedScore}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`${label}: ${clampedScore} out of 100`}
        className="h-2 flex-1 overflow-hidden rounded-full bg-neutral-200"
      >
        <div
          className="h-full rounded-full transition-[width] duration-500"
          style={{ width: `${displayed}%`, backgroundColor: fillColor }}
        />
      </div>
      <span className="w-8 text-right text-xs font-medium tabular-nums text-muted-foreground" aria-hidden="true">
        {displayed}
      </span>
    </div>
  )
}
