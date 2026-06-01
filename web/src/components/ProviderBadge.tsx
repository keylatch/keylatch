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
   * as the result will be a flat white blob.
   */
  invertOnDark?: boolean
}

/** Map each slug to its static logo path. */
const PROVIDER_LOGOS: Record<string, string> = {
  airtable:   '/logos/airtable.svg',
  anthropic:  '/logos/anthropic.svg',
  atlassian:  '/logos/atlassian.svg',
  auth0:      '/logos/auth0.svg',
  cloudflare: '/logos/cloudflare.svg',
  datadog:    '/logos/datadog.svg',
  dropbox:    '/logos/dropbox.svg',
  elevenlabs: '/logos/elevenlabs.svg',
  github:     '/logos/github.svg',
  gitlab:     '/logos/gitlab.svg',
  google:     '/logos/google.svg',
  hubspot:    '/logos/hubspot.svg',
  intercom:   '/logos/intercom.svg',
  linear:     '/logos/linear.svg',
  mailchimp:  '/logos/mailchimp.svg',
  mailgun:    '/logos/mailgun.svg',
  make:       '/logos/make.svg',
  n8n:        '/logos/n8n.svg',
  notion:     '/logos/notion.svg',
  okta:       '/logos/okta.svg',
  openai:     '/logos/openai.svg',
  openrouter: '/logos/openrouter.svg',
  posthog:    '/logos/posthog.svg',
  replicate:  '/logos/replicate.svg',
  salesforce: '/logos/salesforce.svg',
  sendgrid:   '/logos/sendgrid.svg',
  sentry:     '/logos/sentry.svg',
  slack:      '/logos/slack.svg',
  stripe:     '/logos/stripe.svg',
  supabase:   '/logos/supabase.svg',
  turso:      '/logos/turso.svg',
  twilio:     '/logos/twilio.svg',
  vercel:     '/logos/vercel.svg',
  zapier:     '/logos/zapier.svg',
  zendesk:    '/logos/zendesk.svg',
}

const PROVIDER_COLORS: Record<string, { bg: string; text: string }> = {
  // ai
  anthropic:  { bg: 'bg-orange-100',   text: 'text-orange-700' },
  openai:     { bg: 'bg-emerald-100',  text: 'text-emerald-700' },
  openrouter: { bg: 'bg-sky-100',      text: 'text-sky-700' },
  elevenlabs: { bg: 'bg-indigo-100',   text: 'text-indigo-700' },
  replicate:  { bg: 'bg-blue-100',     text: 'text-blue-700' },
  // devtools
  github:     { bg: 'bg-slate-100',    text: 'text-slate-700' },
  gitlab:     { bg: 'bg-red-100',      text: 'text-red-700' },
  linear:     { bg: 'bg-purple-100',   text: 'text-purple-700' },
  sentry:     { bg: 'bg-rose-100',     text: 'text-rose-700' },
  vercel:     { bg: 'bg-zinc-100',     text: 'text-zinc-700' },
  supabase:   { bg: 'bg-teal-100',     text: 'text-teal-700' },
  turso:      { bg: 'bg-lime-100',     text: 'text-lime-700' },
  n8n:        { bg: 'bg-fuchsia-100',  text: 'text-fuchsia-700' },
  make:       { bg: 'bg-violet-100',   text: 'text-violet-700' },
  // storage
  dropbox:    { bg: 'bg-blue-100',     text: 'text-blue-700' },
  airtable:   { bg: 'bg-yellow-100',   text: 'text-yellow-700' },
  notion:     { bg: 'bg-stone-100',    text: 'text-stone-700' },
  // auth
  auth0:      { bg: 'bg-amber-100',    text: 'text-amber-700' },
  okta:       { bg: 'bg-cyan-100',     text: 'text-cyan-700' },
  google:     { bg: 'bg-blue-100',     text: 'text-blue-700' },
  atlassian:  { bg: 'bg-blue-100',     text: 'text-blue-700' },
  // cloud
  cloudflare: { bg: 'bg-orange-100',   text: 'text-orange-700' },
  datadog:    { bg: 'bg-violet-100',   text: 'text-violet-700' },
  // payments
  stripe:     { bg: 'bg-purple-100',   text: 'text-purple-700' },
  // comms
  slack:      { bg: 'bg-rose-100',     text: 'text-rose-700' },
  twilio:     { bg: 'bg-red-100',      text: 'text-red-700' },
  mailchimp:  { bg: 'bg-yellow-100',   text: 'text-yellow-700' },
  mailgun:    { bg: 'bg-red-100',      text: 'text-red-700' },
  sendgrid:   { bg: 'bg-sky-100',      text: 'text-sky-700' },
  intercom:   { bg: 'bg-blue-100',     text: 'text-blue-700' },
  hubspot:    { bg: 'bg-orange-100',   text: 'text-orange-700' },
  zendesk:    { bg: 'bg-green-100',    text: 'text-green-700' },
  posthog:    { bg: 'bg-rose-100',     text: 'text-rose-700' },
  zapier:     { bg: 'bg-orange-100',   text: 'text-orange-700' },
  salesforce: { bg: 'bg-sky-100',      text: 'text-sky-700' },
}
const DEFAULT_COLOR = { bg: 'bg-primary/10', text: 'text-primary' }

const PROVIDER_MONOGRAMS: Record<string, string> = {
  anthropic:  'AN',
  openai:     'AI',
  openrouter: 'OR',
  elevenlabs: 'EL',
  replicate:  'RE',
  github:     'GH',
  gitlab:     'GL',
  linear:     'LN',
  sentry:     'SN',
  vercel:     'VC',
  supabase:   'SB',
  turso:      'TS',
  n8n:        'N8',
  make:       'MK',
  dropbox:    'DB',
  airtable:   'AT',
  notion:     'NT',
  auth0:      'A0',
  okta:       'OK',
  google:     'GO',
  atlassian:  'AS',
  cloudflare: 'CF',
  datadog:    'DD',
  stripe:     'ST',
  slack:      'SL',
  twilio:     'TW',
  mailchimp:  'MC',
  mailgun:    'MG',
  sendgrid:   'SG',
  intercom:   'IC',
  hubspot:    'HS',
  zendesk:    'ZD',
  posthog:    'PH',
  zapier:     'ZP',
  salesforce: 'SF',
}

/**
 * ProviderBadge — displays a provider logo with monogram fallback on 404.
 * If no logoSrc prop is passed, resolves from the PROVIDER_LOGOS map.
 * Each provider gets a distinct colour so cards have visual weight.
 */
export function ProviderBadge({ provider, logoSrc, className, invertOnDark = false }: ProviderBadgeProps) {
  const [imgError, setImgError] = useState(false)

  const key = provider.toLowerCase()
  const resolvedSrc = logoSrc ?? PROVIDER_LOGOS[key]
  const monogram = PROVIDER_MONOGRAMS[key] ?? provider.slice(0, 2).toUpperCase()
  const colors = PROVIDER_COLORS[key] ?? DEFAULT_COLOR

  if (!resolvedSrc || imgError) {
    return (
      <span
        className={cn(
          'inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-xs font-bold',
          colors.bg,
          colors.text,
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
      src={resolvedSrc}
      alt={`${provider} logo`}
      className={cn('h-10 w-10 rounded-lg object-contain', invertOnDark && 'dark:brightness-0 dark:invert', className)}
      onError={() => setImgError(true)}
    />
  )
}
