import { useEffect, useRef, useState, type ReactNode } from 'react'
import { NavLink } from 'react-router-dom'

interface AppShellProps {
  children: ReactNode
  isDemo?: boolean
}

/**
 * AppShell — main layout wrapper.
 *
 * - 56px sticky topbar.
 * - 220px sidebar (desktop) / drawer with focus-trap (mobile).
 * - Skip link is the first DOM element.
 * - Demo banner shown when isDemo=true.
 */
export function AppShell({ children, isDemo = false }: AppShellProps) {
  const [drawerOpen, setDrawerOpen] = useState(false)
  const drawerRef = useRef<HTMLElement>(null)

  // Focus trap for mobile drawer
  useEffect(() => {
    if (!drawerOpen) return
    const drawer = drawerRef.current
    if (!drawer) return
    const focusable = drawer.querySelectorAll<HTMLElement>(
      'a, button, input, [tabindex]:not([tabindex="-1"])'
    )
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    first?.focus()

    const trap = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setDrawerOpen(false)
        return
      }
      if (e.key !== 'Tab') return
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault()
          last?.focus()
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault()
          first?.focus()
        }
      }
    }
    document.addEventListener('keydown', trap)
    return () => document.removeEventListener('keydown', trap)
  }, [drawerOpen])

  return (
    <>
      {/* Skip link — must be first DOM element */}
      <a
        href="#main-content"
        className="skip-link"
      >
        Skip to main content
      </a>

      {isDemo && (
        <div
          role="alert"
          aria-live="polite"
          className="demo-banner"
        >
          Demo mode — no real credentials are stored
        </div>
      )}

      <div className="flex min-h-[100dvh] flex-col">
        {/* Topbar */}
        <header
          className="sticky top-0 z-[var(--z-sticky)] flex h-[var(--topbar-height)] items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface-raised)] px-4"
          role="banner"
          aria-label="keylatch navigation"
        >
          <button
            type="button"
            className="inline-flex h-9 w-9 items-center justify-center rounded-md hover:bg-[var(--color-surface-overlay)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)] md:hidden"
            aria-label="Open navigation menu"
            aria-expanded={drawerOpen}
            aria-controls="main-nav"
            onClick={() => setDrawerOpen(true)}
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="20"
              height="20"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <line x1="4" x2="20" y1="6" y2="6" />
              <line x1="4" x2="20" y1="12" y2="12" />
              <line x1="4" x2="20" y1="18" y2="18" />
            </svg>
          </button>
          <span className="text-sm font-semibold tracking-tight text-[var(--color-text-primary)]">
            keylatch
          </span>
        </header>

        <div className="flex flex-1">
          {/* Sidebar — desktop: always visible; mobile: drawer */}
          <nav
            id="main-nav"
            ref={drawerRef}
            className={[
              'fixed left-0 top-[var(--topbar-height)] bottom-0 z-[var(--z-drawer)] flex w-[var(--sidebar-width)] flex-col gap-1 border-r border-[var(--color-border)] bg-[var(--color-surface-raised)] px-3 pt-4 pb-4',
              'transition-transform duration-[var(--duration-slow)] ease-[var(--ease-out)]',
              // Desktop: always in view; mobile: slide in/out
              'md:translate-x-0',
              drawerOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
            ].join(' ')}
            aria-label="Main navigation"
          >
            {drawerOpen && (
              <button
                type="button"
                className="absolute right-3 top-3 inline-flex h-8 w-8 items-center justify-center rounded-md hover:bg-[var(--color-surface-overlay)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-focus-ring)] md:hidden"
                aria-label="Close navigation menu"
                onClick={() => setDrawerOpen(false)}
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M18 6 6 18" />
                  <path d="m6 6 12 12" />
                </svg>
              </button>
            )}
            <NavLink
              to="/"
              end
              className={({ isActive }) =>
                [
                  'rounded-md px-3 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-[var(--color-primary-50)] text-[var(--color-primary-700)]'
                    : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-overlay)] hover:text-[var(--color-text-primary)]',
                ].join(' ')
              }
            >
              Dashboard
            </NavLink>
            <NavLink
              to="/approvals"
              className={({ isActive }) =>
                [
                  'rounded-md px-3 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-[var(--color-primary-50)] text-[var(--color-primary-700)]'
                    : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-overlay)] hover:text-[var(--color-text-primary)]',
                ].join(' ')
              }
            >
              Approvals
            </NavLink>
            <NavLink
              to="/agent"
              className={({ isActive }) =>
                [
                  'rounded-md px-3 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-[var(--color-primary-50)] text-[var(--color-primary-700)]'
                    : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-overlay)] hover:text-[var(--color-text-primary)]',
                ].join(' ')
              }
            >
              Agent Setup
            </NavLink>
            <NavLink
              to="/settings"
              className={({ isActive }) =>
                [
                  'rounded-md px-3 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-[var(--color-primary-50)] text-[var(--color-primary-700)]'
                    : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-overlay)] hover:text-[var(--color-text-primary)]',
                ].join(' ')
              }
            >
              Settings
            </NavLink>
            <NavLink
              to="/diagnostics"
              className={({ isActive }) =>
                [
                  'rounded-md px-3 py-2 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-[var(--color-primary-50)] text-[var(--color-primary-700)]'
                    : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-overlay)] hover:text-[var(--color-text-primary)]',
                ].join(' ')
              }
            >
              Diagnostics
            </NavLink>
          </nav>

          {/* Drawer overlay — mobile only */}
          {drawerOpen && (
            <div
              className="fixed inset-0 z-[var(--z-drawer-underlay)] bg-black/50 md:hidden"
              aria-hidden="true"
              onClick={() => setDrawerOpen(false)}
            />
          )}

          {/* Main content — offset by sidebar on desktop */}
          <main
            id="main-content"
            className="flex-1 overflow-auto p-6 md:ml-[var(--sidebar-width)]"
          >
            {children}
          </main>
        </div>
      </div>
    </>
  )
}
