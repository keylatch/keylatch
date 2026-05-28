import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AgentSnippet } from './AgentSnippet'

describe('AgentSnippet', () => {
  it('renders tabs', () => {
    render(<AgentSnippet snippet="echo hello" />)
    expect(screen.getByRole('tablist')).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(3)
  })

  it('"No secrets" badge is always visible', () => {
    render(<AgentSnippet snippet="some code" />)
    expect(screen.getByLabelText('No secrets in this snippet')).toBeInTheDocument()
  })

  it('has SafeCopyButton', () => {
    render(<AgentSnippet snippet="keylatch gateway up" />)
    expect(screen.getByRole('button', { name: /copy snippet/i })).toBeInTheDocument()
  })

  it('renders snippet content in tabpanel', () => {
    render(<AgentSnippet snippet="keylatch gateway up" />)
    expect(screen.getByRole('tabpanel')).toBeInTheDocument()
  })

  it('switches tabs on click', async () => {
    const user = userEvent.setup()
    render(<AgentSnippet snippet="code" />)
    await user.click(screen.getByRole('tab', { name: 'python' }))
    expect(screen.getByRole('tab', { name: 'python' })).toHaveAttribute('aria-selected', 'true')
  })
})
