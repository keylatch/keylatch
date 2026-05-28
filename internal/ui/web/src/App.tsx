import { useState } from 'react'
import Wizard from './components/wizard/Wizard'
import Dashboard from './components/dashboard/Dashboard'

type View = 'wizard' | 'dashboard'

export default function App() {
  const [view, setView] = useState<View>('wizard')
  return view === 'wizard'
    ? <Wizard onComplete={() => setView('dashboard')} />
    : <Dashboard onSetupAgain={() => setView('wizard')} />
}
