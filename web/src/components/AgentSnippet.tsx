import { useState } from 'react'
import { SafeCopyButton } from './SafeCopyButton'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface AgentSnippetProps {
  snippet: string
  language?: string
  className?: string
}

const TABS = ['bash', 'python', 'node'] as const
type Tab = typeof TABS[number]

const SNIPPETS: Record<Tab, string> = {
  bash: '# Set up keylatch gateway\nkeylatch gateway up --port 7878\nexport KEYLATCH_GATEWAY_URL=http://127.0.0.1:7878',
  python: '# Python usage\nimport subprocess\nresult = subprocess.run([\'keylatch\', \'gateway\', \'status\'])',
  node: '// Node.js usage\nconst { execSync } = require(\'child_process\')\nexecSync(\'keylatch gateway status\')',
}

/**
 * AgentSnippet — tabbed snippet display.
 *
 * Security invariants:
 *   - SafeCopyButton never contains a credential — only setup commands.
 *   - "No secrets" badge is always visible.
 */
export function AgentSnippet({ snippet, language = 'bash', className }: AgentSnippetProps) {
  const [activeTab, setActiveTab] = useState<Tab>(
    TABS.includes(language as Tab) ? (language as Tab) : 'bash'
  )
  const snippetToShow = snippet || SNIPPETS[activeTab]

  return (
    <div className={cn('rounded-lg border border-[var(--color-border)] bg-[var(--color-surface-raised)] overflow-hidden', className)}>
      {/* Header: no-secrets badge + tab bar */}
      <div className="flex items-center gap-2 border-b border-[var(--color-border)] bg-[var(--color-surface-overlay)] px-3 py-2">
        <Badge variant="success" aria-label="No secrets in this snippet">
          No secrets
        </Badge>
        <div role="tablist" aria-label="Snippet language" className="ml-auto flex gap-1">
          {TABS.map((tab) => (
            <button
              key={tab}
              role="tab"
              type="button"
              aria-selected={activeTab === tab}
              aria-controls={`snippet-panel-${tab}`}
              onClick={() => setActiveTab(tab)}
              className={cn(
                'rounded px-2.5 py-1 text-xs font-medium transition-colors',
                activeTab === tab
                  ? 'bg-[var(--color-primary-600)] text-[var(--color-text-inverse)]'
                  : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-raised)] hover:text-[var(--color-text-primary)]'
              )}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* Snippet panel */}
      <div
        role="tabpanel"
        id={`snippet-panel-${activeTab}`}
        className="relative"
      >
        <pre className="overflow-x-auto p-4 text-sm font-mono text-[var(--color-text-primary)]">
          <code>{snippetToShow}</code>
        </pre>
        <div className="absolute right-3 top-3">
          <SafeCopyButton content={snippetToShow} label="Copy snippet" />
        </div>
      </div>
    </div>
  )
}
