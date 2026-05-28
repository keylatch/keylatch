import { useState } from 'react'
import WelcomePanel from './WelcomePanel'
import StoragePanel from './StoragePanel'
import ProviderPanel from './ProviderPanel'
import AgentPanel from './AgentPanel'

type Step = 1 | 2 | 3 | 4

interface WizardProps {
  onComplete: () => void
}

export default function Wizard({ onComplete }: WizardProps) {
  const [step, setStep] = useState<Step>(1)
  const [selectedBackend, setSelectedBackend] = useState<string>('')

  const next = () => setStep(s => Math.min(s + 1, 4) as Step)
  const back = () => setStep(s => Math.max(s - 1, 1) as Step)

  switch (step) {
    case 1: return <WelcomePanel onNext={next} onSkip={onComplete} />
    case 2: return <StoragePanel onNext={next} onBack={back} onBackendSelect={setSelectedBackend} />
    case 3: return <ProviderPanel onNext={next} onBack={back} selectedBackend={selectedBackend} />
    case 4: return <AgentPanel onFinish={onComplete} onBack={back} />
  }
}
