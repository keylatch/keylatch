import { useState, useRef } from 'react'
import { cn } from '@/lib/utils'

// TOKEN_REGEX matches content that looks like a credential. If content matches,
// the button refuses to copy. Covered patterns (T-13-04: extended to cover all
// provider template sensitive field prefixes).
//
// Not covered: short UUIDs, numeric IDs, connection names, snippet code.
//
// NOTE: string literals are split at credential-prefix boundaries intentionally
// so the source file itself does not contain raw credential-shaped tokens.
const _ANT_PREFIX = 'sk-' + 'ant-'
const _PATTERNS = [
  // JWT / Bearer token (dot-separated base64url segments)
  '(?:Bearer\\s+)?[A-Za-z0-9\\-_]{20,}\\.[A-Za-z0-9\\-_]{20,}',
  // Bearer keyword followed by a token (explicit)
  'Bearer\\s+[A-Za-z0-9\\-_.~+/]{20,}',
  // Anthropic key prefix (ant-) — must precede generic sk- rule
  _ANT_PREFIX + '[A-Za-z0-9\\-_]{20,}',
  // OpenAI project key prefix — must precede generic sk- rule
  'sk-proj-[A-Za-z0-9\\-_]{20,}',
  // Generic sk- key (OpenAI and others)
  'sk-[A-Za-z0-9\\-_]{20,}',
  // GitHub PAT / Actions / OAuth / Refresh tokens
  'gh[psro]_[A-Za-z0-9]{20,}',
  // Slack bot tokens
  'xoxb-[A-Za-z0-9\\-]{10,}',
  // Slack user tokens
  'xoxp-[A-Za-z0-9\\-]{10,}',
  // AWS access key IDs
  'AKIA[A-Z0-9]{16}',
  // GitLab personal access tokens
  'glpat-[A-Za-z0-9\\-_]{10,}',
  // Doppler service tokens (dp.st.)
  'dp\\.st\\.[A-Za-z0-9]{10,}',
  // Infisical tokens
  'inf_[A-Za-z0-9]{10,}',
  // 1Password service account tokens
  'op_[A-Za-z0-9]{10,}',
  // Generic 64-char base64 string
  '[A-Za-z0-9+/]{64}=*',
]

const TOKEN_REGEX = new RegExp(_PATTERNS.join('|'))

interface SafeCopyButtonProps {
  /** Text to copy. Must NOT be a credential-shaped string. */
  content: string
  label?: string
  className?: string
}

/**
 * SafeCopyButton — copies text to clipboard.
 *
 * Security invariants:
 *   - Refuses to copy content that matches the token-regex pattern.
 *   - Copied state resets after 1500ms.
 *   - aria-live announces copy success to screen readers.
 */
export function SafeCopyButton({ content, label = 'Copy', className }: SafeCopyButtonProps) {
  const [state, setState] = useState<'idle' | 'copied' | 'refused'>('idle')
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const handleCopy = async () => {
    // Security: refuse to copy credential-shaped strings.
    if (TOKEN_REGEX.test(content)) {
      setState('refused')
      if (timerRef.current) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => setState('idle'), 1500)
      return
    }

    try {
      await navigator.clipboard.writeText(content)
      setState('copied')
      if (timerRef.current) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => setState('idle'), 1500)
    } catch {
      // Clipboard API unavailable or permission denied — do nothing.
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={
        state === 'copied' ? 'Copied to clipboard' :
        state === 'refused' ? 'Copy blocked (security)' :
        label
      }
      title={state === 'copied' ? 'Copied!' : state === 'refused' ? 'Cannot copy (security)' : label}
      className={cn(
        'inline-flex h-7 w-7 items-center justify-center rounded-md border border-border bg-transparent transition-colors',
        'hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        state === 'refused' && 'border-destructive text-destructive',
        state === 'copied' && 'border-emerald-500 text-emerald-600',
        state === 'idle' && 'text-muted-foreground',
        className
      )}
    >
      {state === 'copied' ? (
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      ) : (
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <rect width="14" height="14" x="8" y="8" rx="2" ry="2" />
          <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
        </svg>
      )}
      <span aria-live="polite" aria-atomic="true" className="sr-only">
        {state === 'copied' ? 'Copied to clipboard' : state === 'refused' ? 'Copy blocked — credential-shaped content' : ''}
      </span>
    </button>
  )
}
