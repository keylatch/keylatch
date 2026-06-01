/**
 * Typed fetch wrapper for the keylatch API.
 *
 * Security: all write methods include the X-CSRF-Token header read from
 * the kl_csrf cookie (double-submit pattern).
 *
 * Mock mode: when VITE_DEV_MOCK=true the real server is never contacted.
 * mockGet() returns stub data for known paths; write methods succeed silently.
 */

import { mockGet, mockPatch } from './mockData'

function getCsrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)kl_csrf=([^;]+)/)
  return match ? decodeURIComponent(match[1]) : ''
}

type Method = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH'

const WRITE_METHODS: Method[] = ['POST', 'PUT', 'DELETE', 'PATCH']

export interface RequestOptions {
  signal?: AbortSignal
}

/** True when the dev server is running with VITE_DEV_MOCK=true. */
export const DEV_MOCK = import.meta.env.VITE_DEV_MOCK === 'true'

async function request<T>(method: Method, path: string, body?: unknown, opts?: RequestOptions): Promise<T> {
  // Mock mode: return stub data, skip CSRF / network entirely.
  if (DEV_MOCK) {
    if (WRITE_METHODS.includes(method)) {
      const patched = mockPatch(path, body)
      if (patched !== undefined) return patched as T
      return undefined as T
    }
    const stub = mockGet(path)
    if (stub !== undefined) return stub as T
    // Unknown GET: fall through to real fetch so Vite HMR still works.
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }

  if (WRITE_METHODS.includes(method)) {
    const csrf = getCsrfToken()
    if (!csrf) {
      throw new ApiError(0, 'CSRF token not available — try refreshing the page')
    }
    headers['X-CSRF-Token'] = csrf
  }

  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal: opts?.signal,
  })

  if (!res.ok) {
    const text = await res.text().catch(() => 'unknown error')
    throw new ApiError(res.status, text)
  }

  // 204 No Content
  if (res.status === 204) {
    return undefined as T
  }

  return res.json() as Promise<T>
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(`API ${status}: ${message}`)
    this.name = 'ApiError'
  }
}

export const api = {
  get: <T>(path: string, opts?: RequestOptions) => request<T>('GET', path, undefined, opts),
  post: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('POST', path, body, opts),
  put: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('PUT', path, body, opts),
  delete: <T>(path: string, opts?: RequestOptions) => request<T>('DELETE', path, undefined, opts),
  patch: <T>(path: string, body?: unknown, opts?: RequestOptions) => request<T>('PATCH', path, body, opts),
}
