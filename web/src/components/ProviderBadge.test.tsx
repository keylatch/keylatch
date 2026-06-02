import { render, screen, fireEvent } from '@testing-library/react'
import { ProviderBadge } from './ProviderBadge'

describe('ProviderBadge', () => {
  it('renders monogram when no logoSrc provided', () => {
    // openrouter has a logo in PROVIDER_LOGOS so it renders an img, not a monogram.
    // Use a provider that is NOT in PROVIDER_LOGOS to get monogram fallback.
    render(<ProviderBadge provider="myservice" />)
    // myservice is not in PROVIDER_LOGOS or PROVIDER_MONOGRAMS — falls back to slice(0,2).toUpperCase()
    expect(screen.getByText('MY')).toBeInTheDocument()
  })

  it('renders img when logoSrc provided', () => {
    render(<ProviderBadge provider="github" logoSrc="/logos/github.svg" />)
    expect(screen.getByAltText('github logo')).toBeInTheDocument()
  })

  it('falls back to monogram on img error', () => {
    render(<ProviderBadge provider="github" logoSrc="/logos/github.svg" />)
    const img = screen.getByAltText('github logo')
    fireEvent.error(img)
    // github is in PROVIDER_MONOGRAMS with code 'GH'
    expect(screen.getByText('GH')).toBeInTheDocument()
  })

  it('monogram is uppercase 2-char prefix', () => {
    // anthropic is in PROVIDER_LOGOS so it renders an img by default.
    // Trigger an img error to fall back to the monogram from PROVIDER_MONOGRAMS ('AN').
    render(<ProviderBadge provider="anthropic" />)
    const img = screen.getByAltText('anthropic logo')
    fireEvent.error(img)
    // PROVIDER_MONOGRAMS maps 'anthropic' → 'AN'
    expect(screen.getByText('AN')).toBeInTheDocument()
  })
})
