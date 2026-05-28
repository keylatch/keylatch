import { api } from '../lib/api'

/** A single diagnostic check result from GET /api/doctor. */
export interface DoctorCheck {
  name: string
  section: string
  ok: boolean
  warn?: boolean
  detail: string
  fix?: string
  tags?: string[]
}

/** A section summary aggregating results for one labeled section. */
export interface DoctorSectionSummary {
  name: string
  ok: boolean
  has_warn: boolean
  check_count: number
}

/** Full response from GET /api/doctor. */
export interface DoctorResponse {
  exit: number
  healthy: boolean
  warnings: boolean
  checks: DoctorCheck[]
  sections: DoctorSectionSummary[]
  version: string
  platform: string
}

/**
 * Fetch the full doctor report.
 *
 * Passes verbose=true so all checks (including passing ones) are returned.
 * The Diagnostics panel controls quiet-mode client-side by collapsing OK rows.
 */
export async function fetchDoctorReport(signal?: AbortSignal): Promise<DoctorResponse> {
  return api.get<DoctorResponse>('/api/doctor?verbose=true', { signal })
}
