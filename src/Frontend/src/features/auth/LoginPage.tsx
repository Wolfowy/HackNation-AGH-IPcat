import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router'
import { Radar } from 'lucide-react'
import { ApiError, errorMessage } from '@/api/client'
import { useAuth } from '@/auth/AuthProvider'
import { FormField } from '@/components/form'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { t } from '@/i18n/strings'

export function LoginPage() {
  const { user, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: string } | null)?.from ?? '/'
  const [userName, setUserName] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  if (user) return <Navigate to={from} replace />

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await login(userName.trim(), password)
      navigate(from, { replace: true })
    } catch (err) {
      setError(err instanceof ApiError && (err.status === 401 || err.status === 400) ? t.login.failed : errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="bg-muted/40 flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-xl">
            <Radar className="text-primary size-6" /> {t.login.title}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form className="grid gap-4" onSubmit={submit}>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <FormField label={t.login.userName}>
              <Input autoComplete="username" required value={userName} onChange={(e) => setUserName(e.target.value)} autoFocus />
            </FormField>
            <FormField label={t.login.password}>
              <Input type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
            </FormField>
            <Button type="submit" disabled={busy}>
              {t.login.submit}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
