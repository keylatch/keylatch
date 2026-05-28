import { render, screen, fireEvent } from '@testing-library/react'
import { ProviderBadge } from './ProviderBadge'

describe('ProviderBadge', () => {
  it('renders monogram when no logoSrc provided', () => {
    render(<ProviderBadge provider="openrouter" />)
    expect(screen.getByText('OP')).toBeInTheDocument()
  })

  it('renders img when logoSrc provided', () => {
    render(<ProviderBadge provider="github" logoSrc="/logos/github.svg" />)
    expect(screen.getByAltText('github logo')).toBeInTheDocument()
  })

  it('falls back to monogram on img error', () => {
    render(<ProviderBadge provider="github" logoSrc="/logos/github.svg" />)
    const img = screen.getByAltText('github logo')
    fireEvent.error(img)
    expect(screen.getByText('GI')).toBeInTheDocument()
  })

  it('monogram is uppercase 2-char prefix', () => {
    render(<ProviderBadge provider="anthropic" />)
    expect(screen.getByText('AN')).toBeInTheDocument()
  })
})
