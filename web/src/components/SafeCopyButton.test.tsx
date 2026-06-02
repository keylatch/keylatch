import { render, screen, act, fireEvent } from '@testing-library/react'
import { SafeCopyButton } from './SafeCopyButton'

const mockWriteText = vi.fn()

// Stub clipboard at module level to avoid userEvent redefine conflicts.
vi.stubGlobal('navigator', {
  ...navigator,
  clipboard: { writeText: mockWriteText },
})

describe('SafeCopyButton', () => {
  beforeEach(() => {
    mockWriteText.mockResolvedValue(undefined)
    vi.clearAllMocks()
  })

  it('renders with default label', () => {
    render(<SafeCopyButton content="some text" />)
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument()
  })

  it('calls clipboard.writeText on click', async () => {
    render(<SafeCopyButton content="hello world" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).toHaveBeenCalledWith('hello world')
  })

  it('shows Copied! state after successful copy', async () => {
    render(<SafeCopyButton content="snippet code" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    // The button is now icon-only; after copy the aria-label changes to 'Copied to clipboard'
    expect(screen.getByRole('button', { name: 'Copied to clipboard' })).toBeInTheDocument()
  })

  it('has aria-live region for screen reader announcement', () => {
    render(<SafeCopyButton content="text" />)
    const liveRegion = document.querySelector('[aria-live="polite"]')
    expect(liveRegion).toBeInTheDocument()
  })

  it('refuses to copy credential-shaped JWT', async () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'
    render(<SafeCopyButton content={jwt} />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses to copy sk- prefixed API key', async () => {
    render(<SafeCopyButton content="sk-abcdefghijklmnopqrstuvwxyz123456" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('allows copying non-credential content', async () => {
    render(<SafeCopyButton content="keylatch gateway up --port 7878" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).toHaveBeenCalledWith('keylatch gateway up --port 7878')
  })

  it('resets state after 1500ms', async () => {
    vi.useFakeTimers()
    render(<SafeCopyButton content="text" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    await act(async () => { vi.advanceTimersByTime(1600) })
    // After reset, aria-label returns to the label prop ('Copy')
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument()
    vi.useRealTimers()
  })

  // T-13-04: extended regex coverage — all provider template sensitive field prefixes.

  it('refuses GitHub personal access token (ghp_)', async () => {
    render(<SafeCopyButton content="ghp_abcdefghijklmnopqrstu1234567890" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses GitHub Actions token (ghs_)', async () => {
    render(<SafeCopyButton content="ghs_abcdefghijklmnopqrstu1234567890" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses GitHub OAuth token (gho_)', async () => {
    render(<SafeCopyButton content="gho_abcdefghijklmnopqrstu1234567890" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses GitHub refresh token (ghr_)', async () => {
    render(<SafeCopyButton content="ghr_abcdefghijklmnopqrstu1234567890" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses Slack bot token (xoxb-)', async () => {
    render(<SafeCopyButton content="xoxb-test-token-placeholder" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses Slack user token (xoxp-)', async () => {
    render(<SafeCopyButton content="xoxp-test-token-placeholder" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses AWS access key ID (AKIA)', async () => {
    render(<SafeCopyButton content="AKIAIOSFODNN7EXAMPLE" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses GitLab personal access token (glpat-)', async () => {
    render(<SafeCopyButton content="glpat-abcdefghij1234567890" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses Doppler service token (dp.st.)', async () => {
    render(<SafeCopyButton content="dp.st.abcdefghij1234567890" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses Infisical token (inf_)', async () => {
    render(<SafeCopyButton content="inf_abcdefghijklmnopqrst" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses 1Password service account token (op_)', async () => {
    render(<SafeCopyButton content="op_abcdefghijklmnopqrst" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses OpenAI project key (sk-proj-)', async () => {
    render(<SafeCopyButton content="sk-proj-abcdefghijklmnopqrstuvwxyz123" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses Anthropic key (sk-ant-)', async () => {
    render(<SafeCopyButton content="sk-ant-abcdefghijklmnopqrstuvwxyz123456" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('refuses 64-char base64 string', async () => {
    render(<SafeCopyButton content="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).not.toHaveBeenCalled()
  })

  it('allows short non-credential identifiers', async () => {
    render(<SafeCopyButton content="project-123" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).toHaveBeenCalledWith('project-123')
  })

  it('allows UUID-shaped strings', async () => {
    render(<SafeCopyButton content="550e8400-e29b-41d4-a716-446655440000" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    expect(mockWriteText).toHaveBeenCalledWith('550e8400-e29b-41d4-a716-446655440000')
  })

  it('shows Refused state when credential-shaped content is clicked', async () => {
    render(<SafeCopyButton content="sk-abcdefghijklmnopqrstuvwxyz123456" />)
    await act(async () => { fireEvent.click(screen.getByRole('button')) })
    // After refusal the aria-label changes to 'Copy blocked (security)'
    expect(screen.getByRole('button', { name: 'Copy blocked (security)' })).toBeInTheDocument()
  })
})
