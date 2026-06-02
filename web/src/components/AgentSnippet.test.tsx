import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AgentSnippet } from './AgentSnippet'

describe('AgentSnippet', () => {
  // Tabs are only rendered when NO snippet prop is provided (snippet='').
  // When a snippet prop is given, showTabs=false and the tablist is hidden.
  it('renders tabs when no snippet is provided', () => {
    render(<AgentSnippet snippet="" />)
    expect(screen.getByRole('tablist')).toBeInTheDocument()
    expect(screen.getAllByRole('tab')).toHaveLength(3)
  })

  // The "No secrets" badge was removed in the component refactor.
  // Replaced with: copy button uses icon-only SafeCopyButton (aria-label="Copy snippet").
  it('has SafeCopyButton with aria-label "Copy snippet"', () => {
    render(<AgentSnippet snippet="keylatch gateway up" />)
    expect(screen.getByRole('button', { name: /copy snippet/i })).toBeInTheDocument()
  })

  it('renders snippet content in a code block', () => {
    render(<AgentSnippet snippet="keylatch gateway up" />)
    expect(screen.getByText('keylatch gateway up')).toBeInTheDocument()
  })

  it('switches tabs on click', async () => {
    const user = userEvent.setup()
    render(<AgentSnippet snippet="" />)
    await user.click(screen.getByRole('tab', { name: 'python' }))
    expect(screen.getByRole('tab', { name: 'python' })).toHaveAttribute('aria-selected', 'true')
  })
})
