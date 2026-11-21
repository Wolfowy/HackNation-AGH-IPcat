import { render } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { Toaster } from 'sonner'
import { sessionStore } from '@/api/session'
import type { Role } from '@/api/types'
import { AuthProvider } from '@/auth/AuthProvider'
import { getDb } from '@/mocks/handlers'
import { routes } from '@/routes'

/** Signs in as the seeded mock user holding `role` (no HTTP round trip). */
export function loginAs(role: Role) {
  const user = getDb().users.find((u) => u.roles.includes(role))!
  const { password: _password, ...publicUser } = user
  sessionStore.set({ accessToken: `mock-token.${user.id}`, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), user: publicUser })
  return publicUser
}

/** Renders the full app (real routes, guards, layout) at `path` against the MSW mock API. */
export function renderApp(path: string, { role }: { role?: Role } = {}) {
  if (role) loginAs(role)
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 }, mutations: { retry: false } } })
  const router = createMemoryRouter(routes, { initialEntries: [path] })
  const user = userEvent.setup()
  const utils = render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RouterProvider router={router} />
        <Toaster />
      </AuthProvider>
    </QueryClientProvider>,
  )
  return { ...utils, user, router, queryClient }
}
