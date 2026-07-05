import { Card, CardContent } from '@/components/ui/card'
import { SafeCopyButton } from './SafeCopyButton'

const RECEIPTS_COMMAND = 'keylatch receipts list'

/**
 * ActivityFeedPlaceholder — non-removable placeholder card.
 *
 * Spec:
 * - Always visible (no close button, no "don't show again").
 * - "Copy command" copies `keylatch receipts list` to clipboard.
 * - Muted/secondary styling — does not compete with the readiness pill.
 * - Positioned below the fold (after readiness pill and approval queue summary).
 */
export function ActivityFeedPlaceholder() {
  return (
    <Card
      role="complementary"
      aria-label="Activity feed — coming in 0.1.1"
      className="border-dashed"
    >
      <CardContent className="p-5 flex items-start gap-4">
        <div className="shrink-0 mt-0.5">
          <div className="h-8 w-8 rounded-md bg-muted flex items-center justify-center" aria-hidden="true">
            <svg className="h-4 w-4 text-muted-foreground" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 6.75h7.5M8.25 12h7.5m-7.5 5.25h3.75" />
            </svg>
          </div>
        </div>
        <div className="flex min-w-0 flex-col gap-1">
          <p className="text-sm font-medium text-foreground">
            Activity feed — coming in 0.1.1
          </p>
          <p className="text-sm text-muted-foreground">
            View receipts now via CLI:
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <code className="rounded-md bg-muted px-2 py-1 font-mono text-sm text-foreground">
              {RECEIPTS_COMMAND}
            </code>
            <SafeCopyButton content={RECEIPTS_COMMAND} label="Copy command" />
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
