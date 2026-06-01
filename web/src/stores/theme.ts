export function getStoredTheme(): 'light' | 'dark' {
  return (localStorage.getItem('kl-theme') as 'light' | 'dark') ?? 'light'
}

export function applyTheme(theme: 'light' | 'dark') {
  document.documentElement.classList.toggle('dark', theme === 'dark')
  localStorage.setItem('kl-theme', theme)
}
