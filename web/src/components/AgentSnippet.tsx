import { useState } from 'react'
import { SafeCopyButton } from './SafeCopyButton'
import { cn } from '@/lib/utils'

interface AgentSnippetProps {
  snippet: string
  language?: string
  className?: string
}

const TABS = ['bash', 'python', 'node'] as const
type Tab = typeof TABS[number]

const SNIPPETS: Record<Tab, string> = {
  bash: 'keylatch run <provider> -- <your-agent-command>',
  python: 'subprocess.run(["keylatch", "run", "<provider>", "--", "<your-agent-command>"])',
  node: 'execSync("keylatch run <provider> -- <your-agent-command>")',
}

export function AgentSnippet({ snippet, language = 'bash', className }: AgentSnippetProps) {
  const [activeTab, setActiveTab] = useState<Tab>(
    TABS.includes(language as Tab) ? (language as Tab) : 'bash'
  )

  // API snippet overrides tab-based fallbacks.
  const snippetToShow = snippet || SNIPPETS[activeTab]
  const showTabs = !snippet

  return (
    <div className={cn('overflow-hidden', className)}>
      {showTabs && (
        <div className="flex border-b border-border px-4 pt-1 gap-1" role="tablist" aria-label="Snippet language">
          {TABS.map((tab) => (
            <button
              key={tab}
              role="tab"
              type="button"
              aria-selected={activeTab === tab}
              onClick={() => setActiveTab(tab)}
              className={cn(
                'px-3 py-1.5 text-xs font-medium rounded-t transition-colors border-b-2',
                activeTab === tab
                  ? 'text-primary border-primary'
                  : 'text-muted-foreground border-transparent hover:text-foreground'
              )}
            >
              {tab}
            </button>
          ))}
        </div>
      )}

      <div className="relative bg-muted rounded-b-lg">
        <pre className="overflow-x-auto px-4 py-4 text-sm font-mono text-foreground">
          <code>{snippetToShow}</code>
        </pre>
        <div className="absolute right-3 top-3">
          <SafeCopyButton content={snippetToShow} label="Copy snippet" />
        </div>
      </div>
    </div>
  )
}
