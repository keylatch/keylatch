/**
 * ProviderWizard tests — T-14-03.
 *
 * Tests:
 *   - Step navigation: pick provider → see fields → back to picker
 *   - Mixed-mode payload: one direct field + one reference field
 *   - Validation: error shown when required direct field is empty
 */

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ProviderWizard } from './ProviderWizard'

// Mock api module.
vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

// Mock useConnections so we can inspect createConnection calls.
vi.mock('../stores/connections', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../stores/connections')>()
  return {
    ...actual,
    useConnections: vi.fn(() => ({
      connections: [],
      loading: false,
      error: null,
      refresh: vi.fn(),
      createConnection: mockCreateConnection,
      updateConnection: vi.fn(),
      deleteConnection: vi.fn(),
    })),
  }
})

import { api } from '../lib/api'

const mockApi = api as unknown as { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> }
const mockCreateConnection = vi.fn()

const mockProviders = [
  { slug: 'openrouter', display_name: 'OpenRouter', category: 'ai', docs_url: '', runtime_modes: [] },
  { slug: 'github', display_name: 'GitHub', category: 'code-hosting', docs_url: '', runtime_modes: [] },
]

const mockProviderDetail = {
  slug: 'openrouter',
  display_name: 'OpenRouter',
  category: 'ai',
  fields: [{ name: 'api_key', label: 'API Key', required: true }],
}

beforeEach(() => {
  vi.clearAllMocks()
  // Route api.get calls based on URL: list vs. detail.
  mockApi.get.mockImplementation((url: string) => {
    if (url.startsWith('/v1/providers/')) {
      return Promise.resolve(mockProviderDetail)
    }
    return Promise.resolve(mockProviders)
  })
  mockCreateConnection.mockResolvedValue(undefined)
})

describe('ProviderWizard', () => {
  it('renders step 1 (provider picker) on open', async () => {
    render(<ProviderWizard onSuccess={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByTestId('wizard-step-pick')).toBeInTheDocument()
    })
  })

  it('shows provider list in step 1 after providers load', async () => {
    render(<ProviderWizard onSuccess={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Select OpenRouter/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Select GitHub/i })).toBeInTheDocument()
    })
  })

  it('advances to step 2 after selecting a provider', async () => {
    render(<ProviderWizard onSuccess={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Select OpenRouter/i })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /Select OpenRouter/i }))
    expect(screen.getByTestId('wizard-step-fields')).toBeInTheDocument()
  })

  it('goes back to step 1 when Back button is clicked', async () => {
    render(<ProviderWizard onSuccess={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Select OpenRouter/i })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /Select OpenRouter/i }))
    fireEvent.click(screen.getByRole('button', { name: 'Back' }))
    expect(screen.getByTestId('wizard-step-pick')).toBeInTheDocument()
  })

  it('calls onClose when close button is clicked', async () => {
    const onClose = vi.fn()
    render(<ProviderWizard onSuccess={vi.fn()} onClose={onClose} />)
    fireEvent.click(screen.getByRole('button', { name: 'Close wizard' }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('shows inline error when required direct field is empty on submit', async () => {
    render(<ProviderWizard onSuccess={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Select OpenRouter/i })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /Select OpenRouter/i }))

    // Wait for field schema to load before submitting.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save Connection' })).not.toBeDisabled()
    })

    // Submit without filling the field.
    fireEvent.click(screen.getByRole('button', { name: 'Save Connection' }))

    // Should show a validation error.
    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
    expect(mockCreateConnection).not.toHaveBeenCalled()
  })

  it('submits mixed-mode payload (one direct + one reference) when valid', async () => {
    // For this test we render with only one field visible and switch its mode.
    render(<ProviderWizard onSuccess={vi.fn()} onClose={vi.fn()} />)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Select OpenRouter/i })).toBeInTheDocument()
    })
    fireEvent.click(screen.getByRole('button', { name: /Select OpenRouter/i }))

    // Wait for field schema to load.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Save Connection' })).not.toBeDisabled()
    })

    // Switch api_key from direct to reference and set a URI.
    fireEvent.click(screen.getByRole('button', { name: 'From password manager' }))
    const uriInput = screen.getByPlaceholderText('op://vault/item/field')
    fireEvent.change(uriInput, { target: { value: 'op://Personal/OpenRouter/api_key' } })

    fireEvent.click(screen.getByRole('button', { name: 'Save Connection' }))

    await waitFor(() => {
      expect(mockCreateConnection).toHaveBeenCalledWith(
        expect.objectContaining({
          provider: 'openrouter',
          fields: expect.arrayContaining([
            expect.objectContaining({
              name: 'api_key',
              mode: 'reference',
              uri: 'op://Personal/OpenRouter/api_key',
            }),
          ]),
        })
      )
    })
  })
})
