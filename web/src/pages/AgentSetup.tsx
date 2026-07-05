import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { ProviderBadge } from '../components/ProviderBadge'
import { Button } from '@/components/ui/button'
import type { Connection } from '../lib/types'
import { api } from '../lib/api'

function CopyIconButton({ content, label }: { content: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content)
      setCopied(true)
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(() => setCopied(false), 1500)
    } catch { /* silent */ }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={copied ? 'Copied!' : label}
      className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      {copied ? (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-emerald-500" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>
      ) : (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
      )}
    </button>
  )
}

const PROVIDER_EXAMPLE_CMD: Record<string, string> = {
  anthropic: 'claude "review the issue and open a PR"',
  openai: 'openai api chat.completions.create ...',
  github: 'gh issue create --title "Fix bug"',
  stripe: 'stripe charges list',
  slack: 'slack chat postMessage ...',
  openrouter: 'curl https://openrouter.ai/api/v1/chat/completions ...',
}

function defaultCmd(provider: string): string {
  return PROVIDER_EXAMPLE_CMD[provider.toLowerCase()] ?? 'your-agent-command'
}

function connectionSnippet(connection: Connection): string {
  return `keylatch run ${connection.name} -- ${defaultCmd(connection.provider)}`
}

export function AgentSetup() {
  const navigate = useNavigate()
  const [connections, setConnections] = useState<Connection[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get<{ connections: Connection[] }>('/api/connections')
      .then((d) => setConnections(d.connections ?? []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">Agent Setup</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Prefix any agent command with <code className="font-mono text-foreground">keylatch run &lt;connection&gt; --</code> and Keylatch injects the credential at runtime. The agent never sees the raw key.
        </p>
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <div className="h-4 w-4 animate-spin rounded-full border-2 border-border border-t-primary" />
          Loading connections…
        </div>
      )}

      {!loading && connections.length === 0 && (
        <div className="rounded-lg border border-dashed border-border px-6 py-10 text-center space-y-3">
          <p className="text-sm text-muted-foreground">No connections yet — add one first.</p>
          <Button variant="outline" size="sm" onClick={() => navigate('/connections')}>
            Go to Connections
          </Button>
        </div>
      )}

      {!loading && connections.length > 0 && (
        <div className="flex flex-col gap-3">
          {connections.map((conn) => {
            const snippet = connectionSnippet(conn)
            return (
              <div key={conn.name} className="rounded-lg border border-border overflow-hidden">
                {/* Connection header */}
                <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
                  <ProviderBadge provider={conn.provider} className="h-7 w-7 text-xs" />
                  <div className="flex flex-col min-w-0">
                    <span className="text-sm font-medium text-foreground truncate">{conn.name}</span>
                    <span className="text-xs text-muted-foreground">{conn.provider}</span>
                  </div>
                </div>
                {/* Snippet */}
                <div className="flex items-center gap-2 bg-muted px-4 py-3">
                  <pre className="flex-1 text-sm font-mono text-foreground overflow-x-auto">
                    <code>{snippet}</code>
                  </pre>
                  <CopyIconButton content={snippet} label={`Copy snippet for ${conn.name}`} />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
