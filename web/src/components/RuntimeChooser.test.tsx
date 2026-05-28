import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RuntimeChooser } from './RuntimeChooser'
import type { RuntimeMode } from '../lib/types'

describe('RuntimeChooser', () => {
  it('has role=radiogroup', () => {
    render(<RuntimeChooser />)
    expect(screen.getByRole('radiogroup')).toBeInTheDocument()
  })

  it('never renders "unrestricted" or "direct_run"', () => {
    render(<RuntimeChooser />)
    const buttons = screen.getAllByRole('radio')
    for (const btn of buttons) {
      expect(btn.textContent?.toLowerCase()).not.toContain('unrestricted')
      expect(btn.textContent?.toLowerCase()).not.toContain('direct_run')
    }
    // Also check DOM text
    expect(document.body.textContent?.toLowerCase()).not.toContain('direct_run')
    expect(document.body.textContent?.toLowerCase()).not.toContain('unrestricted')
  })

  it('renders only supported modes when provided', () => {
    const modes: RuntimeMode[] = ['gateway_typed']
    render(<RuntimeChooser supportedModes={modes} />)
    const buttons = screen.getAllByRole('radio')
    expect(buttons).toHaveLength(1)
    expect(buttons[0].textContent).toContain('typed')
  })

  it('absent modes are not rendered (not just hidden)', () => {
    const modes: RuntimeMode[] = ['gateway_typed']
    render(<RuntimeChooser supportedModes={modes} />)
    // "absent" mode should not be in DOM
    const allText = document.body.innerHTML
    expect(allText).not.toContain('Absent')
  })

  it('calls onChange when option clicked', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<RuntimeChooser onChange={onChange} />)
    const firstOption = screen.getAllByRole('radio')[0]
    await user.click(firstOption)
    expect(onChange).toHaveBeenCalled()
  })

  it('marks selected option as checked', () => {
    render(<RuntimeChooser value="gateway_typed" />)
    const selected = screen.getByRole('radio', { name: /gateway.*typed/i })
    expect(selected).toHaveAttribute('aria-checked', 'true')
  })

  it('other options are not checked', () => {
    render(<RuntimeChooser value="gateway_typed" />)
    const radios = screen.getAllByRole('radio')
    for (const radio of radios) {
      if (radio.textContent?.includes('typed')) {
        expect(radio).toHaveAttribute('aria-checked', 'true')
      } else {
        expect(radio).toHaveAttribute('aria-checked', 'false')
      }
    }
  })
})
