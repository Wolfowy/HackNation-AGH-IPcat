import type { User } from './types'

export interface Session {
  accessToken: string
  expiresAt: string
  user: User
}

const STORAGE_KEY = 'webscan.session'
const listeners = new Set<() => void>()

function load(): Session | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Session
    return Date.parse(parsed.expiresAt) > Date.now() ? parsed : null
  } catch {
    return null
  }
}

let current: Session | null = load()

function emit() {
  listeners.forEach((l) => l())
}

/** Access token lives in memory and in sessionStorage (survives reloads, not new tabs/browser restarts). */
export const sessionStore = {
  get: (): Session | null => current,
  token: (): string | null => current?.accessToken ?? null,
  set(session: Session) {
    current = session
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session))
    emit()
  },
  updateUser(user: User) {
    if (current) sessionStore.set({ ...current, user })
  },
  clear() {
    if (!current && !sessionStorage.getItem(STORAGE_KEY)) return
    current = null
    sessionStorage.removeItem(STORAGE_KEY)
    emit()
  },
  subscribe(listener: () => void) {
    listeners.add(listener)
    return () => listeners.delete(listener)
  },
}
