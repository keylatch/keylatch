import { useState } from 'react'
import { cn } from '@/lib/utils'

interface ProviderBadgeProps {
  provider: string
  logoSrc?: string
  className?: string
  /**
   * When true, applies `dark:brightness-0 dark:invert` to the logo image so it
   * renders as white in dark mode. Intended for monochrome logos on a transparent
   * background only — do NOT use for logos with color regions or opaque backgrounds
   * (e.g. AWS, Bitwarden) as the result will be a flat white blob.
   */
  invertOnDark?: boolean
}

/**
 * ProviderBadge — displays a provider logo with monogram fallback on 404.
 */
export function ProviderBadge({ provider, logoSrc, className, invertOnDark = false }: ProviderBadgeProps) {
  const [imgError, setImgError] = useState(false)

  const monogram = provider.slice(0, 2).toUpperCase()

  if (!logoSrc || imgError) {
    return (
      <span
        className={cn(
          'inline-flex h-8 w-8 items-center justify-center rounded-md bg-[var(--color-primary-100)] text-xs font-semibold text-[var(--color-primary-700)]',
          className
        )}
        aria-label={`Provider: ${provider}`}
        title={provider}
      >
        {monogram}
      </span>
    )
  }

  return (
    <img
      src={logoSrc}
      alt={`${provider} logo`}
      className={cn('h-8 w-8 rounded-md object-contain', invertOnDark && 'dark:brightness-0 dark:invert', className)}
      onError={() => setImgError(true)}
    />
  )
}
