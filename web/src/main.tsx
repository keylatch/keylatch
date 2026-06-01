import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles/index.css'
import App from './App'
import { applyTheme, getStoredTheme } from './stores/theme'

// Apply persisted theme before first render to avoid flash of wrong theme.
applyTheme(getStoredTheme())

const root = document.getElementById('root')
if (!root) {
  throw new Error('keylatch: #root element not found')
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>
)
