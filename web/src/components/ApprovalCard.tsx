import { useEffect, useState, useCallback } from 'react'
import type { Approval } from '../lib/types'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { cn } from '@/lib/utils'

interface ApprovalCardProps {
  approval: Approval
  onApprove?: (token: string) => Promise<void>
  onDeny?: (token: string) => Promise<void>
  className?: string
}

/**
 * ApprovalCard — displays a pending approval with TTL countdown.
 *
 * - TTL < 60s: text turns red (warning).
 * - Approve: green flash → fade out animation.
 * - Deny: immediate removal.
 * - role="region" for landmark navigation.
 */
export function ApprovalCard({ approval, onApprove, onDeny, className }: ApprovalCardProps) {
  const [ttlSeconds, setTtlSeconds] = useState(() => {
    const expires = new Date(approval.expiresAt).getTime()
    return Math.max(0, Math.floor((expires - Date.now()) / 1000))
  })
  const [state, setState] = useState<'idle' | 'approving' | 'approved' | 'denying' | 'denied'>('idle')

  useEffect(() => {
    const interval = setInterval(() => {
      const expires = new Date(approval.expiresAt).getTime()
      setTtlSeconds(Math.max(0, Math.floor((expires - Date.now()) / 1000)))
    }, 1000)
    return () => clearInterval(interval)
  }, [approval.expiresAt])

  const handleApprove = useCallback(async () => {
    setState('approving')
    try {
      await onApprove?.(approval.token)
      setState('approved')
    } catch {
      setState('idle')
    }
  }, [approval.token, onApprove])

  const handleDeny = useCallback(async () => {
    setState('denying')
    try {
      await onDeny?.(approval.token)
      setState('denied')
    } catch {
      setState('idle')
    }
  }, [approval.token, onDeny])

  const isExpiringSoon = ttlSeconds < 60

  return (
    <Card
      role="region"
      aria-label={`Approval request for ${approval.connection}`}
      className={cn(
        'p-4 transition-opacity',
        state === 'approved' && 'border-success bg-[#dcfce7]',
        state === 'denied' && 'opacity-50',
        className
      )}
    >
      <div className="flex items-center justify-between gap-4">
        <span className="font-medium text-foreground">
          {approval.connection}
        </span>
        <span
          className={cn(
            'text-sm font-semibold tabular-nums',
            isExpiringSoon ? 'text-destructive' : 'text-muted-foreground'
          )}
          aria-label={`Expires in ${ttlSeconds} seconds`}
        >
          {ttlSeconds}s
        </span>
      </div>

      <div className="mt-1.5 text-sm text-muted-foreground">
        Actor: {approval.actorHmac.slice(0, 8)}…
      </div>

      <div className="mt-3 flex gap-2">
        <Button
          type="button"
          variant="default"
          size="sm"
          onClick={handleApprove}
          disabled={state !== 'idle' || ttlSeconds === 0}
          aria-label="Approve request"
        >
          {state === 'approving' ? 'Approving…' : 'Approve'}
        </Button>
        <Button
          type="button"
          variant="destructive"
          size="sm"
          onClick={handleDeny}
          disabled={state !== 'idle' || ttlSeconds === 0}
          aria-label="Deny request"
        >
          {state === 'denying' ? 'Denying…' : 'Deny'}
        </Button>
      </div>
    </Card>
  )
}
