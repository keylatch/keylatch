import { useState, useEffect, useRef, type ReactNode } from 'react'
import { getStoredTheme, applyTheme } from '@/stores/theme'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Plug,
  InboxIcon,
  Bot,
  Settings,
  Activity,
  Menu,
  X,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { DEV_MOCK } from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { KeylatchLogo } from './KeylatchLogo'
import { useSaveStatus } from '@/stores/saveStatus'

interface NavItemDef {
  to: string
  label: string
  icon: React.ElementType
  end?: boolean
}

const NAV_GROUPS: { label: string; items: NavItemDef[] }[] = [
  {
    label: 'Overview',
    items: [
      { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
      { to: '/connections', label: 'Connections', icon: Plug },
      { to: '/approvals', label: 'Approvals', icon: InboxIcon },
    ],
  },
  {
    label: 'Configure',
    items: [
      { to: '/agent', label: 'Agent Setup', icon: Bot },
      { to: '/settings', label: 'Settings', icon: Settings },
      { to: '/diagnostics', label: 'Diagnostics', icon: Activity },
    ],
  },
]

function NavItem({ to, label, icon: Icon, end }: NavItemDef) {
  return (
    <li>
      <NavLink
        to={to}
        end={end}
        className={({ isActive }) =>
          cn(
            'flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors',
            isActive
              ? 'bg-primary/15 text-primary font-semibold'
              : 'text-muted-foreground font-medium hover:bg-accent hover:text-accent-foreground',
          )
        }
      >
        <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
        {label}
      </NavLink>
    </li>
  )
}

function SidebarNav() {
  return (
    <nav className="flex-1 overflow-y-auto py-4" aria-label="Main navigation">
      <div className="space-y-6 px-3">
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            <p className="mb-1 px-3 text-xs font-semibold uppercase tracking-widest text-muted-foreground">
              {group.label}
            </p>
            <ul className="space-y-1">
              {group.items.map((item) => (
                <NavItem key={item.to} {...item} />
              ))}
            </ul>
          </div>
        ))}
      </div>
    </nav>
  )
}

function SaveIndicator() {
  const phase = useSaveStatus((s) => s.phase)
  const isVisible = phase !== 'idle'

  return (
    <div
      className={cn(
        'ml-auto transition-opacity duration-300',
        isVisible ? 'opacity-100' : 'opacity-0 pointer-events-none',
      )}
      aria-live="polite"
      aria-atomic="true"
    >
      {phase === 'saving' && (
        <span className="text-muted-foreground text-xs flex items-center gap-1.5">
          <div className="animate-spin rounded-full border-2 border-current border-t-transparent h-3.5 w-3.5" aria-hidden="true" />
          Saving…
        </span>
      )}
      {phase === 'saved' && (
        <span className="text-emerald-600 text-xs flex items-center gap-1.5">
          <svg
            aria-hidden="true"
            width="16"
            height="16"
            viewBox="0 0 16 16"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M3 8l3.5 3.5L13 4.5" />
          </svg>
          Saved
        </span>
      )}
      {phase === 'error' && (
        <span className="text-destructive text-xs flex items-center gap-1.5">
          <svg
            aria-hidden="true"
            width="16"
            height="16"
            viewBox="0 0 16 16"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M4 4l8 8M12 4l-8 8" />
          </svg>
          Failed to save
        </span>
      )}
    </div>
  )
}

interface AppShellProps {
  children: ReactNode
  isDemo?: boolean
}

export function AppShell({ children, isDemo = false }: AppShellProps) {
  const [drawerOpen, setDrawerOpen] = useState(false)
  const drawerRef = useRef<HTMLDivElement>(null)
  const [theme, setTheme] = useState<'light' | 'dark'>(getStoredTheme)

  useEffect(() => {
    if (!drawerOpen) return
    const drawer = drawerRef.current
    if (!drawer) return
    const focusable = drawer.querySelectorAll<HTMLElement>(
      'a, button, input, [tabindex]:not([tabindex="-1"])',
    )
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    first?.focus()
    const trap = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setDrawerOpen(false); return }
      if (e.key !== 'Tab') return
      if (e.shiftKey) {
        if (document.activeElement === first) { e.preventDefault(); last?.focus() }
      } else {
        if (document.activeElement === last) { e.preventDefault(); first?.focus() }
      }
    }
    document.addEventListener('keydown', trap)
    return () => document.removeEventListener('keydown', trap)
  }, [drawerOpen])

  return (
    <>
      <a href="#main-content" className="skip-link">Skip to main content</a>

      {isDemo && (
        <div role="alert" aria-live="polite" className="demo-banner">
          Demo mode — no real credentials are stored
        </div>
      )}

      {/* Outer shell: column layout */}
      <div className="h-screen overflow-hidden flex flex-col">
        {/* Full-width topbar */}
        <header
          className="h-14 shrink-0 z-10 border-b border-border bg-background flex items-center px-6 gap-4"
          role="banner"
        >
          {/* Hamburger — mobile only */}
          <button
            type="button"
            className="inline-flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 md:hidden"
            aria-label="Open navigation menu"
            aria-expanded={drawerOpen}
            onClick={() => setDrawerOpen(true)}
          >
            <Menu className="h-5 w-5" aria-hidden="true" />
          </button>
          <KeylatchLogo className="h-7 w-auto" />
          {DEV_MOCK && (
            <Badge variant="secondary" className="text-xs">demo</Badge>
          )}
          <SaveIndicator />
          <button
            type="button"
            onClick={() => {
              const next = theme === 'light' ? 'dark' : 'light'
              applyTheme(next)
              setTheme(next)
            }}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            className="inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            {theme === 'dark' ? (
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="4" />
                <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
              </svg>
            ) : (
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
              </svg>
            )}
          </button>
        </header>

        {/* Sidebar + content row */}
        <div className="flex flex-1 overflow-hidden">
          {/* Sidebar — desktop only */}
          <aside className="hidden md:flex w-60 shrink-0 flex-col border-r border-border bg-background overflow-y-auto">
            <SidebarNav />
          </aside>

          {/* Main content */}
          <main
            id="main-content"
            className="flex-1 overflow-y-auto bg-background p-8"
          >
            {children}
          </main>
        </div>
      </div>

      {/* Mobile drawer backdrop */}
      {drawerOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          aria-hidden="true"
          onClick={() => setDrawerOpen(false)}
        />
      )}

      {/* Mobile drawer */}
      <div
        ref={drawerRef}
        className={cn(
          'fixed inset-y-0 left-0 z-50 w-60 transition-transform duration-200 md:hidden',
          drawerOpen ? 'translate-x-0' : '-translate-x-full',
        )}
        role="dialog"
        aria-modal="true"
        aria-label="Navigation menu"
      >
        <div className="relative flex h-full flex-col bg-background border-r border-border">
          {/* Drawer header */}
          <div className="flex h-14 items-center px-4 gap-3 border-b border-border">
            <KeylatchLogo className="h-7 w-auto" />
            <button
              type="button"
              className="ml-auto inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2"
              aria-label="Close navigation menu"
              onClick={() => setDrawerOpen(false)}
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
          <SidebarNav />
        </div>
      </div>
    </>
  )
}
