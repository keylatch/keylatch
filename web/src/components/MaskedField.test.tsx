import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MaskedField } from './MaskedField'

describe('MaskedField', () => {
  it('renders without exposing a value', () => {
    render(<MaskedField label="API Key" name="api_key" />)
    // Should not have an input in the DOM initially (shows placeholder)
    const inputs = document.querySelectorAll('input[type="password"]')
    expect(inputs).toHaveLength(0)
  })

  it('does not show a "show" or "reveal" button', () => {
    render(<MaskedField label="API Key" name="api_key" />)
    expect(screen.queryByRole('button', { name: /show/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /reveal/i })).toBeNull()
  })

  it('shows Edit button in idle state', () => {
    render(<MaskedField label="API Key" name="api_key" />)
    expect(screen.getByRole('button', { name: /edit api key/i })).toBeInTheDocument()
  })

  it('switches to edit mode on click', async () => {
    const user = userEvent.setup()
    render(<MaskedField label="API Key" name="api_key" />)
    await user.click(screen.getByRole('button', { name: /edit api key/i }))
    // password inputs don't have role=textbox; query by type instead
    expect(document.querySelector('input[type="password"]')).toBeTruthy()
  })

  it('input type is always password when editing', async () => {
    const user = userEvent.setup()
    render(<MaskedField label="Secret" name="secret" />)
    await user.click(screen.getByRole('button', { name: /edit secret/i }))
    const input = document.querySelector('input')
    expect(input?.type).toBe('password')
  })

  it('input has no value attribute when rendered', async () => {
    const user = userEvent.setup()
    render(<MaskedField label="Token" name="token" />)
    await user.click(screen.getByRole('button', { name: /edit token/i }))
    const input = document.querySelector('input[type="password"]')
    // value attribute should not be set (not pre-populated)
    expect(input?.getAttribute('value')).toBeNull()
  })

  it('calls onSave with new value', async () => {
    const user = userEvent.setup()
    const onSave = vi.fn()
    render(<MaskedField label="Key" name="key" onSave={onSave} />)
    await user.click(screen.getByRole('button', { name: /edit key/i }))
    const input = document.querySelector('input[type="password"]')!
    await user.type(input, 'newvalue')
    await user.click(screen.getByRole('button', { name: /save/i }))
    expect(onSave).toHaveBeenCalledWith('newvalue')
  })
})
