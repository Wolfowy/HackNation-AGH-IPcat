import { useState } from 'react'
import { QueryClientProvider } from '@tanstack/react-query'
import { createBrowserRouter, RouterProvider } from 'react-router'
import { Toaster } from 'sonner'
import { createQueryClient } from '@/api/query'
import { AuthProvider } from '@/auth/AuthProvider'
import { useTheme } from '@/lib/theme'
import { routes } from './routes'

const router = createBrowserRouter(routes)

export function App() {
  const [queryClient] = useState(createQueryClient)
  const { theme } = useTheme()
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RouterProvider router={router} />
        <Toaster richColors closeButton position="bottom-right" theme={theme} toastOptions={{ className: '!rounded-md !text-[13px]' }} />
      </AuthProvider>
    </QueryClientProvider>
  )
}
