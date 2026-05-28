import { useEffect, useState, useCallback } from 'react'
import { AgentSnippet } from '../components/AgentSnippet'
import type { AgentSnippet as AgentSnippetType } from '../lib/types'
import { api } from '../lib/api'

/**
 * AgentSetup — agent configuration with auto-refetch on focus.
 * "No secrets" badge always visible (enforced in AgentSnippet).
 */
export function AgentSetup() {
  const [snippet, setSnippet] = useState<AgentSnippetType | null>(null)

  const fetchSnippet = useCallback(() => {
    api.get<AgentSnippetType>('/api/agent/snippet')
      .then(setSnippet)
      .catch(() => {})
  }, [])

  useEffect(() => {
    fetchSnippet()
    const onFocus = () => fetchSnippet()
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [fetchSnippet])

  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <h2 className="text-2xl font-semibold text-[var(--color-text-primary)]">Agent Setup</h2>
      <p className="text-sm text-[var(--color-text-secondary)]">
        Configure your AI agent to use keylatch credentials securely.
      </p>
      {snippet && (
        <AgentSnippet snippet={snippet.snippet} language={snippet.language} />
      )}
    </div>
  )
}
