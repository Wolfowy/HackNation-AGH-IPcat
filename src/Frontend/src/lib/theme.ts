import { useSyncExternalStore } from 'react'

export type Theme = 'light' | 'dark'
const KEY = 'webscan-theme'
const listeners = new Set<() => void>()

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(KEY)
    return v === 'dark' || v === 'light' ? v : null
  } catch {
    return null
  }
}

const current = (): Theme => (document.documentElement.classList.contains('dark') ? 'dark' : 'light')

/** Runs before the first render (main.tsx): the saved choice, else the OS preference. No inline script: the CSP forbids it. */
export function applyInitialTheme() {
  const prefersDark = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: dark)').matches
  document.documentElement.classList.toggle('dark', (stored() ?? (prefersDark ? 'dark' : 'light')) === 'dark')
}

export function setTheme(theme: Theme) {
  document.documentElement.classList.toggle('dark', theme === 'dark')
  try {
    localStorage.setItem(KEY, theme)
  } catch {
    /* private mode */
  }
  listeners.forEach((l) => l())
}

/** Dark theme = `.dark` on <html> (ipcat-web convention). */
export function useTheme() {
  const theme = useSyncExternalStore(
    (l) => {
      listeners.add(l)
      return () => listeners.delete(l)
    },
    current,
    () => 'light' as Theme,
  )
  return { theme, toggle: () => setTheme(theme === 'dark' ? 'light' : 'dark') }
}
