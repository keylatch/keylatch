import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { Diagnostics } from './Diagnostics'
import type { DoctorResponse } from '../api/doctor'

// Mock the doctor API module.
vi.mock('../api/doctor', () => ({
  fetchDoctorReport: vi.fn(),
}))

import { fetchDoctorReport } from '../api/doctor'
const mockFetchDoctorReport = vi.mocked(fetchDoctorReport)

const makeDoctorResponse = (overrides: Partial<DoctorResponse> = {}): DoctorResponse => ({
  exit: 0,
  healthy: true,
  warnings: false,
  version: '1.2.3',
  platform: 'linux/amd64',
  sections: [
    { name: 'environment', ok: true, has_warn: false, check_count: 2 },
  ],
  checks: [
    {
      name: 'Config file',
      section: 'environment',
      ok: true,
      detail: '/home/user/.keylatch.yaml exists',
      fix: '',
    },
    {
      name: 'Keyring access',
      section: 'environment',
      ok: true,
      detail: 'keyring accessible',
      fix: '',
    },
  ],
  ...overrides,
})

describe('Diagnostics_RendersChecks', () => {
  beforeEach(() => {
    mockFetchDoctorReport.mockResolvedValue(makeDoctorResponse())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders check names when the report loads', async () => {
    render(<MemoryRouter><Diagnostics /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText('Config file')).toBeInTheDocument()
      expect(screen.getByText('Keyring access')).toBeInTheDocument()
    })
  })

  it('renders the section header', async () => {
    render(<MemoryRouter><Diagnostics /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText('environment')).toBeInTheDocument()
    })
  })

  it('shows version and platform metadata', async () => {
    render(<MemoryRouter><Diagnostics /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText(/1\.2\.3/)).toBeInTheDocument()
      expect(screen.getByText(/linux\/amd64/)).toBeInTheDocument()
    })
  })

  it('shows "All checks passed" for exit code 0', async () => {
    render(<MemoryRouter><Diagnostics /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText('All checks passed')).toBeInTheDocument()
    })
  })
})

describe('Diagnostics_RendersFailedAndWarnChecks', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('renders failed checks with ✕ icon', async () => {
    mockFetchDoctorReport.mockResolvedValue(
      makeDoctorResponse({
        exit: 2,
        healthy: false,
        checks: [
          {
            name: 'Backend connection',
            section: 'backends',
            ok: false,
            detail: 'cannot connect to keychain',
            fix: 'Run: security unlock-keychain',
          },
        ],
        sections: [{ name: 'backends', ok: false, has_warn: false, check_count: 1 }],
      })
    )

    render(<MemoryRouter><Diagnostics /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText('Backend connection')).toBeInTheDocument()
      expect(screen.getByLabelText('Failed')).toBeInTheDocument()
      expect(screen.getByText(/Run: security unlock-keychain/)).toBeInTheDocument()
    })
  })

  it('renders warning checks with ! icon', async () => {
    mockFetchDoctorReport.mockResolvedValue(
      makeDoctorResponse({
        exit: 1,
        warnings: true,
        checks: [
          {
            name: 'CLI version',
            section: 'environment',
            ok: true,
            warn: true,
            detail: 'update available',
            fix: 'Run: keylatch upgrade',
          },
        ],
      })
    )

    render(<MemoryRouter><Diagnostics /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText('CLI version')).toBeInTheDocument()
      expect(screen.getByLabelText('Warning')).toBeInTheDocument()
    })
  })
})

describe('Diagnostics_QuietMode', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('hides OK rows when quiet mode is enabled', async () => {
    mockFetchDoctorReport.mockResolvedValue(
      makeDoctorResponse({
        checks: [
          { name: 'Config file', section: 'environment', ok: true, detail: 'ok' },
          {
            name: 'Backend connection',
            section: 'environment',
            ok: false,
            detail: 'failed',
            fix: 'fix it',
          },
        ],
      })
    )

    render(<MemoryRouter><Diagnostics /></MemoryRouter>)

    // Wait for checks to load.
    await waitFor(() => {
      expect(screen.getByText('Config file')).toBeInTheDocument()
    })

    // Enable quiet mode.
    const toggle = screen.getByLabelText('Quiet mode — hide OK rows')
    await userEvent.click(toggle)

    // OK row should be hidden; failed row should remain.
    expect(screen.queryByText('Config file')).not.toBeInTheDocument()
    expect(screen.getByText('Backend connection')).toBeInTheDocument()
  })
})

describe('Diagnostics_ErrorState', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('shows error message when the API call fails', async () => {
    mockFetchDoctorReport.mockRejectedValue(new Error('network error'))

    render(<MemoryRouter><Diagnostics /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
  })
})

describe('Diagnostics_Refresh', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('re-fetches the report when Refresh is clicked', async () => {
    mockFetchDoctorReport.mockResolvedValue(makeDoctorResponse())

    render(<MemoryRouter><Diagnostics /></MemoryRouter>)

    await waitFor(() => {
      expect(screen.getByText('Config file')).toBeInTheDocument()
    })

    const refreshBtn = screen.getByRole('button', { name: /refresh/i })
    await userEvent.click(refreshBtn)

    await waitFor(() => {
      expect(mockFetchDoctorReport).toHaveBeenCalledTimes(2)
    })
  })
})
