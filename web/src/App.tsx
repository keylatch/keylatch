import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { Dashboard } from './pages/Dashboard'
import { FirstRun } from './pages/wizard/FirstRun'
import { ApprovalInbox } from './pages/ApprovalInbox'
import { AgentSetup } from './pages/AgentSetup'
import { Settings } from './pages/Settings'
import { Connections } from './pages/Connections'
import { Diagnostics } from './pages/Diagnostics'

/**
 * App — root router.
 *
 * Route guard: if the server reports a fresh state (no connections),
 * users are redirected to /first-run.
 */
export default function App() {
  return (
    <BrowserRouter>
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
    </BrowserRouter>
  )
}
