export function getStoredTheme(): 'light' | 'dark' {
  const stored = localStorage.getItem('kl-theme') as 'light' | 'dark' | null
  if (stored) return stored
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function applyTheme(theme: 'light' | 'dark') {
  document.documentElement.classList.toggle('dark', theme === 'dark')
  localStorage.setItem('kl-theme', theme)
}
