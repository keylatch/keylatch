import { SafeCopyButton } from './SafeCopyButton'

const RECEIPTS_COMMAND = 'keylatch receipts list'

/**
 * ActivityFeedPlaceholder — non-removable placeholder card.
 *
 * Spec:
 *   - Always visible (no close button, no "don't show again").
 *   - "Copy command" copies `keylatch receipts list` to clipboard.
 *   - Muted/secondary styling — does not compete with the readiness pill.
 *   - Positioned below the fold (after readiness pill and approval queue summary).
 */
export function ActivityFeedPlaceholder() {
  return (
    <div
      className="mt-6 flex items-start gap-4 rounded-lg border border-dashed border-[var(--color-border)] bg-[var(--color-surface-raised)] p-5"
      role="complementary"
      aria-label="Activity feed — coming in 0.1.1"
    >
      <div className="shrink-0 text-xl leading-none" aria-hidden="true">
        📋
      </div>
      <div className="flex min-w-0 flex-col gap-1">
        <p className="font-medium text-[var(--color-text-primary)]">
          Activity feed — coming in 0.1.1
        </p>
        <p className="text-sm text-[var(--color-text-secondary)]">
          View receipts now via CLI:
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <code className="rounded-sm bg-[var(--color-surface-overlay)] px-2 py-1 font-mono text-sm text-[var(--color-text-primary)]">
            {RECEIPTS_COMMAND}
          </code>
          <SafeCopyButton content={RECEIPTS_COMMAND} label="Copy command" />
        </div>
      </div>
    </div>
  )
}
