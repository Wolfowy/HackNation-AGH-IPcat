import { createContext, useCallback, useContext, useEffect, useMemo, useSyncExternalStore, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Navigate, useLocation } from 'react-router'
import { api } from '@/api/client'
import { sessionStore } from '@/api/session'
import type { LoginResponse, User } from '@/api/types'
import { t } from '@/i18n/strings'
import { hasPermission, type Permission } from './roles'

interface AuthContextValue {
  user: User | null
  login: (userName: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const session = useSyncExternalStore(sessionStore.subscribe, sessionStore.get)
  const user = session?.user ?? null
  const hasSession = session !== null

  // Refresh the user (roles may have changed) whenever a stored session is restored or created.
  useEffect(() => {
    if (!hasSession) return
    const controller = new AbortController()
    api<User>('/api/auth/me', { signal: controller.signal })
      .then((me) => sessionStore.updateUser(me))
      .catch(() => {}) // 401 already clears the session in the client
    return () => controller.abort()
  }, [hasSession])

  // Drop cached data of the previous user after logout / token expiry.
  useEffect(() => {
    if (!hasSession) qc.clear()
  }, [hasSession, qc])

  const login = useCallback(async (userName: string, password: string) => {
    const res = await api<LoginResponse>('/api/auth/login', { method: 'POST', body: { userName, password } })
    sessionStore.set({ accessToken: res.accessToken, expiresAt: res.expiresAt, user: res.user })
  }, [])

  const logout = useCallback(() => sessionStore.clear(), [])

  const value = useMemo(() => ({ user, login, logout }), [user, login, logout])
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}

export function useCan(permission: Permission): boolean {
  return hasPermission(useAuth().user?.roles, permission)
}

/** Renders children only when the current user has the permission. */
export function Can({ permission, children }: { permission: Permission; children: ReactNode }) {
  return useCan(permission) ? <>{children}</> : null
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const location = useLocation()
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />
  return <>{children}</>
}

/** Route guard: pages a role may not use are not rendered at all. */
export function RequirePermission({ permission, children }: { permission: Permission; children: ReactNode }) {
  if (!useCan(permission)) {
    return (
      <div className="py-16 text-center" data-testid="forbidden">
        <h1 className="text-xl font-semibold">{t.common.forbiddenTitle}</h1>
        <p className="text-muted-foreground mt-2">{t.common.forbiddenText}</p>
      </div>
    )
  }
  return <>{children}</>
}
