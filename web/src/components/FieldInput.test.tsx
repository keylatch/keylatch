/**
 * FieldInput tests — validates URI validation logic and mode toggle behaviour.
 * T-14-06: client-side validation matches server-side RefURIPattern.
 */

import { render, screen, fireEvent } from '@testing-library/react'
import { FieldInput, validateRefURI, REF_URI_PATTERN } from './FieldInput'

// ── validateRefURI unit tests ─────────────────────────────────────────────────

describe('validateRefURI', () => {
  it('accepts valid op:// URI', () => {
    expect(validateRefURI('op://Personal/OpenRouter/api_key')).toBeNull()
  })

  it('accepts valid aws-sm:// URI', () => {
    expect(validateRefURI('aws-sm://us-east-1/my-secret')).toBeNull()
  })

  it('accepts valid hashivault:// URI', () => {
    expect(validateRefURI('hashivault://secret/myapp/config#api_key')).toBeNull()
  })

  it('rejects empty string', () => {
    expect(validateRefURI('')).toBeTruthy()
  })

  it('rejects aws-sm:// with no path', () => {
    const err = validateRefURI('aws-sm://')
    expect(err).toBeTruthy()
    expect(err).toContain('Invalid reference URI')
  })

  it('rejects hashivault:// with no path', () => {
    const err = validateRefURI('hashivault://')
    expect(err).toBeTruthy()
  })

  it('rejects op:// with no path', () => {
    const err = validateRefURI('op://')
    expect(err).toBeTruthy()
  })

  it('rejects unknown scheme', () => {
    const err = validateRefURI('doppler://some/path')
    expect(err).toBeTruthy()
  })

  it('rejects plain text without scheme', () => {
    const err = validateRefURI('not-a-uri')
    expect(err).toBeTruthy()
  })

  it('REF_URI_PATTERN regex matches valid URIs', () => {
    expect(REF_URI_PATTERN.test('op://vault/item/field')).toBe(true)
    expect(REF_URI_PATTERN.test('aws-sm://region/secret-id')).toBe(true)
    expect(REF_URI_PATTERN.test('hashivault://mount/path#field')).toBe(true)
  })

  it('REF_URI_PATTERN regex rejects malformed URIs', () => {
    expect(REF_URI_PATTERN.test('aws-sm://')).toBe(false)
    expect(REF_URI_PATTERN.test('op://')).toBe(false)
    expect(REF_URI_PATTERN.test('hashivault://')).toBe(false)
    expect(REF_URI_PATTERN.test('')).toBe(false)
    // Single-segment paths (no slash separator) must fail
    expect(REF_URI_PATTERN.test('op://ab')).toBe(false)
  })
})

// ── FieldInput component tests ────────────────────────────────────────────────

const noop = () => {}

describe('FieldInput', () => {
  it('renders in direct mode with password input', () => {
    render(
      <FieldInput
        fieldName="api_key"
        label="API Key"
        mode="direct"
        value=""
        uri=""
        onModeChange={noop}
        onValueChange={noop}
        onUriChange={noop}
      />
    )
    expect(screen.getByLabelText('API Key')).toHaveAttribute('type', 'password')
  })

  it('renders in reference mode with URI text input', () => {
    render(
      <FieldInput
        fieldName="api_key"
        label="API Key"
        mode="reference"
        value=""
        uri=""
        onModeChange={noop}
        onValueChange={noop}
        onUriChange={noop}
      />
    )
    const input = screen.getByLabelText('API Key')
    expect(input).toHaveAttribute('type', 'text')
  })

  it('shows PM selector pills in reference mode', () => {
    render(
      <FieldInput
        fieldName="api_key"
        label="API Key"
        mode="reference"
        value=""
        uri=""
        onModeChange={noop}
        onValueChange={noop}
        onUriChange={noop}
      />
    )
    // In reference mode, PM pills are shown (1Password, AWS Secrets Manager, HashiCorp Vault)
    expect(screen.getByRole('button', { name: '1Password' })).toBeInTheDocument()
  })

  it('displays inline error when error prop is set', () => {
    render(
      <FieldInput
        fieldName="api_key"
        label="API Key"
        mode="reference"
        value=""
        uri="aws-sm://"
        error="Invalid reference URI — expected op://vault/item/field, aws-sm://region/secret-id, or hashivault://mount/path#field"
        onModeChange={noop}
        onValueChange={noop}
        onUriChange={noop}
      />
    )
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByRole('alert').textContent).toContain('Invalid reference URI')
  })

  it('calls onModeChange when mode toggle link is clicked', () => {
    const onModeChange = vi.fn()
    render(
      <FieldInput
        fieldName="api_key"
        label="API Key"
        mode="direct"
        value=""
        uri=""
        // advancedMode=true required to render the "Use reference from password manager" toggle
        advancedMode={true}
        onModeChange={onModeChange}
        onValueChange={noop}
        onUriChange={noop}
      />
    )
    // The toggle link is only shown when advancedMode=true
    fireEvent.click(screen.getByRole('button', { name: 'Use reference from password manager' }))
    expect(onModeChange).toHaveBeenCalledWith('reference')
  })

  it('calls onValueChange when direct input changes', () => {
    const onValueChange = vi.fn()
    render(
      <FieldInput
        fieldName="api_key"
        label="API Key"
        mode="direct"
        value=""
        uri=""
        onModeChange={noop}
        onValueChange={onValueChange}
        onUriChange={noop}
      />
    )
    fireEvent.change(screen.getByLabelText('API Key'), { target: { value: 'sk-test' } })
    expect(onValueChange).toHaveBeenCalledWith('sk-test')
  })

  it('calls onUriChange when URI input changes', () => {
    const onUriChange = vi.fn()
    render(
      <FieldInput
        fieldName="api_key"
        label="API Key"
        mode="reference"
        value=""
        uri=""
        onModeChange={noop}
        onValueChange={noop}
        onUriChange={onUriChange}
      />
    )
    fireEvent.change(screen.getByLabelText('API Key'), { target: { value: 'op://vault/item/field' } })
    expect(onUriChange).toHaveBeenCalledWith('op://vault/item/field')
  })
})
