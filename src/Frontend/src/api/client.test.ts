import { http, HttpResponse } from 'msw'
import { server } from '@/mocks/node'
import { api, ApiError, asList, normalizeFieldKey } from './client'
import { sessionStore } from './session'

const user = { id: 'u1', userName: 'alice', displayName: 'Alice', roles: ['Viewer' as const] }
const signIn = () => sessionStore.set({ accessToken: 'token-123', expiresAt: new Date(Date.now() + 60_000).toISOString(), user })

describe('api client', () => {
  it('sends the bearer token and parses JSON', async () => {
    let auth: string | null = null
    server.use(
      http.get('*/api/ping', ({ request }) => {
        auth = request.headers.get('Authorization')
        return HttpResponse.json({ ok: true })
      }),
    )
    signIn()
    await expect(api('/api/ping')).resolves.toEqual({ ok: true })
    expect(auth).toBe('Bearer token-123')
  })

  it('omits the Authorization header when signed out and resolves undefined for 204', async () => {
    let auth: string | null = 'unset'
    server.use(
      http.delete('*/api/thing', ({ request }) => {
        auth = request.headers.get('Authorization')
        return new HttpResponse(null, { status: 204 })
      }),
    )
    await expect(api('/api/thing', { method: 'DELETE' })).resolves.toBeUndefined()
    expect(auth).toBeNull()
  })

  it('maps RFC 7807 ProblemDetails to ApiError with normalized field errors', async () => {
    server.use(
      http.post('*/api/networks', () =>
        HttpResponse.json(
          {
            title: 'One or more validation errors occurred.',
            status: 400,
            errors: { Name: ['Name is required.'], 'Ranges[0]': ['Bad CIDR.'], 'Ranges[2]': ['Outside scope.'] },
          },
          { status: 400, headers: { 'Content-Type': 'application/problem+json' } },
        ),
      ),
    )
    signIn()
    const error = await api('/api/networks', { body: {} }).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(ApiError)
    const apiError = error as ApiError
    expect(apiError.status).toBe(400)
    expect(apiError.message).toBe('One or more validation errors occurred.')
    expect(apiError.fieldErrors).toEqual({ name: 'Name is required.', ranges: 'Bad CIDR. Outside scope.' })
  })

  it('logs out on 401 when a token was sent', async () => {
    server.use(http.get('*/api/agents', () => HttpResponse.json({ title: 'Unauthorized', status: 401 }, { status: 401 })))
    signIn()
    await expect(api('/api/agents')).rejects.toMatchObject({ status: 401 })
    expect(sessionStore.get()).toBeNull()
  })

  it('keeps the session on 403', async () => {
    server.use(http.get('*/api/users', () => HttpResponse.json({ title: 'Forbidden', status: 403 }, { status: 403 })))
    signIn()
    await expect(api('/api/users')).rejects.toMatchObject({ status: 403 })
    expect(sessionStore.get()).not.toBeNull()
  })

  it('wraps non-JSON error bodies', async () => {
    server.use(http.get('*/api/boom', () => new HttpResponse('upstream exploded', { status: 502 })))
    const error = (await api('/api/boom').catch((e: unknown) => e)) as ApiError
    expect(error.status).toBe(502)
    expect(error.message).toBe('upstream exploded')
  })

  it('normalizes field keys and list envelopes', () => {
    expect(normalizeFieldKey('$.ranges[0]')).toBe('ranges')
    expect(normalizeFieldKey('Defaults.TimeoutSeconds')).toBe('defaults')
    expect(asList([1, 2])).toEqual([1, 2])
    expect(asList({ items: [3], total: 1, page: 1, pageSize: 50 })).toEqual([3])
  })
})
