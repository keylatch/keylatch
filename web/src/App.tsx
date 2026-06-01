import { useEffect, useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { Dashboard } from './pages/Dashboard'
import { FirstRun } from './pages/wizard/FirstRun'
import { ApprovalInbox } from './pages/ApprovalInbox'
import { AgentSetup } from './pages/AgentSetup'
import { Settings } from './pages/Settings'
import { Connections } from './pages/Connections'
import { Diagnostics } from './pages/Diagnostics'
import { api, DEV_MOCK } from './lib/api'

/**
 * FirstRunGuard — on mount checks whether this looks like a fresh install.
 *
 * Conditions for redirect to /first-run:
 *   - Not in mock/dev mode (DEV_MOCK skips the check — mock always has stub connections)
 *   - GET /api/connections returns an empty list
 *   - GET /api/status returns { demo: false }
 *
 * Renders children immediately — the guard fires async so it never blocks render.
 */
function FirstRunGuard({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => {
    // Skip in mock mode — stub data always includes connections.
    if (DEV_MOCK) return
    // Skip if already on the first-run route to avoid redirect loops.
    if (location.pathname.startsWith('/first-run')) return

    const controller = new AbortController()

    Promise.all([
      api.get<{ connections: unknown[] }>('/api/connections', { signal: controller.signal }),
      api.get<{ demo: boolean }>('/api/status', { signal: controller.signal }),
    ])
      .then(([connData, statusData]) => {
        const hasNoConnections = (connData.connections ?? []).length === 0
        const isNotDemo = !statusData.demo
        if (hasNoConnections && isNotDemo) {
          navigate('/first-run', { replace: true })
        }
      })
      .catch(() => {
        // Network error — don't redirect; let the user see whatever page they're on.
      })

    return () => { controller.abort() }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- intentional: run only on mount
  }, [])

  return <>{children}</>
}

/**
 * App — root router.
 *
 * Route guard: if the server reports a fresh state (no connections),
 * users are redirected to /first-run.
 */
export default function App() {
  return (
    <BrowserRouter>
      <FirstRunGuard>
        <Routes>
          <Route path="/first-run/*" element={<FirstRun />} />
          <Route
            path="/*"
            element={
              <AppShell>
                <Routes>
                  <Route index element={<Dashboard />} />
                  <Route path="connections" element={<Connections />} />
                  <Route path="approvals" element={<ApprovalInbox />} />
                  <Route path="agent" element={<AgentSetup />} />
                  <Route path="settings" element={<Settings />} />
                  <Route path="diagnostics" element={<Diagnostics />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </AppShell>
            }
          />
        </Routes>
      </FirstRunGuard>
    </BrowserRouter>
  )
}
