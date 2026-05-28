/**
 * Reads the kl_csrf cookie value.
 * The server sets this on every authenticated response; the client must echo
 * it as X-CSRF-Token on all state-mutating requests.
 */
function getCsrfToken(): string {
  return document.cookie
    .split('; ')
    .find(row => row.startsWith('kl_csrf='))
    ?.split('=')[1] ?? ''
}

/**
 * Thin wrapper around fetch that injects Content-Type and X-CSRF-Token headers
 * on every call. Use this instead of raw fetch for all /v1/ POST requests.
 */
export async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': getCsrfToken(),
      ...(init.headers ?? {}),
    },
  })
}
