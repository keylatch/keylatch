import { invoke } from '@tauri-apps/api/core'
import { relaunch } from '@tauri-apps/plugin-process'

const env = (import.meta as unknown as { env?: Record<string, string | undefined> }).env
const USE_MOCKS = env?.VITE_KEYLATCH_MOCKS === '1'

type MockPayload = Record<string, unknown> | undefined

export async function safeInvoke<T>(command: string, payload?: MockPayload): Promise<T> {
  if (USE_MOCKS || !('__TAURI_INTERNALS__' in window)) {
    return mockInvoke<T>(command, payload)
  }

  return invoke<T>(command, payload)
}

/** Restarts the Tauri app. In mock/browser mode, reloads the page instead. */
export async function safeRelaunch(): Promise<void> {
  if (USE_MOCKS || !('__TAURI_INTERNALS__' in window)) {
    setTimeout(() => window.location.reload(), 800)
    return
  }
  await relaunch()
}

function mockInvoke<T>(command: string, payload?: MockPayload): T {
  switch (command) {
    case 'bootstrap':
      return { ok: true } as T
    case 'connect_provider':
      return { verified: Boolean(payload?.key) } as T
    case 'run_agent':
      return {
        exit_code: 0,
        stdout: 'keylatch: scoped credential injected\nagent command completed',
        receipt_id: 'receipt-demo-run',
      } as T
    case 'install_cli':
      return { ok: true } as T
    default:
      throw new Error(`Unsupported mock Tauri command: ${command}`)
  }
}
