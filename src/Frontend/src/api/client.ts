import { sessionStore } from './session'
import type { Paged, ProblemDetails, ValidationMessage } from './types'

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? ''

export type QueryParams = Record<string, string | number | boolean | null | undefined>

/** Error raised for every non-2xx response; carries the RFC 7807 problem and normalized field errors. */
export class ApiError extends Error {
  readonly status: number
  readonly problem: ProblemDetails

  constructor(status: number, problem: ProblemDetails) {
    super(problem.detail || problem.title || `Request failed (HTTP ${status})`)
    this.name = 'ApiError'
    this.status = status
    this.problem = problem
  }

  /** Validation errors keyed by camelCase top-level field name (`Ranges[0]` → `ranges`). */
  get fieldErrors(): Record<string, string> {
    const result: Record<string, string> = {}
    for (const [key, messages] of Object.entries(this.problem.errors ?? {})) {
      const field = normalizeFieldKey(key)
      result[field] = [result[field], ...messages].filter(Boolean).join(' ')
    }
    return result
  }
}

export function normalizeFieldKey(key: string): string {
  const first = key.replace(/^\$\.?/, '').split(/[.[]/)[0] ?? ''
  return first.charAt(0).toLowerCase() + first.slice(1)
}

export function buildUrl(path: string, query?: QueryParams): string {
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null && v !== '') params.set(k, String(v))
  }
  const qs = params.toString()
  // Absolute URL so requests also work outside a browser page (tests); same origin unless VITE_API_BASE_URL is set.
  return `${API_BASE_URL || window.location.origin}${path}${qs ? `?${qs}` : ''}`
}

export interface RequestOptions {
  method?: string
  query?: QueryParams
  /** JSON-serialized request body. */
  body?: unknown
  /** Raw request body (file uploads); sent as-is with `contentType`. */
  rawBody?: BodyInit
  contentType?: string
  signal?: AbortSignal
}

async function toProblem(res: Response): Promise<ProblemDetails> {
  const text = await res.text().catch(() => '')
  if (text) {
    try {
      const parsed = JSON.parse(text) as unknown
      if (parsed && typeof parsed === 'object') return { status: res.status, ...(parsed as ProblemDetails) }
    } catch {
      return { status: res.status, title: res.statusText || undefined, detail: text.slice(0, 500) }
    }
  }
  return { status: res.status, title: res.statusText || `HTTP ${res.status}` }
}

/** Low-level request: adds the bearer token, maps errors to ApiError and logs out on 401. */
export async function apiRequest(path: string, options: RequestOptions = {}): Promise<Response> {
  const token = sessionStore.token()
  const headers: Record<string, string> = { Accept: 'application/json, application/problem+json' }
  if (token) headers.Authorization = `Bearer ${token}`
  let body: BodyInit | undefined
  if (options.rawBody !== undefined) {
    body = options.rawBody
    if (options.contentType) headers['Content-Type'] = options.contentType
  } else if (options.body !== undefined) {
    body = JSON.stringify(options.body)
    headers['Content-Type'] = 'application/json'
  }

  let res: Response
  try {
    res = await fetch(buildUrl(path, options.query), {
      method: options.method ?? (body ? 'POST' : 'GET'),
      headers,
      body,
      signal: options.signal,
    })
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err
    throw new ApiError(0, { title: 'Network error', detail: 'The server could not be reached.' })
  }

  if (res.status === 401 && token) sessionStore.clear()
  if (!res.ok) throw new ApiError(res.status, await toProblem(res))
  return res
}

/** JSON request; resolves `undefined` for empty (204) responses. */
export async function api<T>(path: string, options?: RequestOptions): Promise<T> {
  const res = await apiRequest(path, options)
  const text = await res.text()
  return (text ? JSON.parse(text) : undefined) as T
}

/** Downloads an authenticated file (export endpoints) through a temporary object URL. */
export async function downloadFile(path: string, query: QueryParams, fallbackName: string): Promise<void> {
  const res = await apiRequest(path, { query })
  const blob = await res.blob()
  const disposition = res.headers.get('Content-Disposition') ?? ''
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition)
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = match ? decodeURIComponent(match[1]) : fallbackName
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** Accepts both plain arrays and paged envelopes (for endpoints whose shape §11 leaves open). */
export function asList<T>(data: T[] | Paged<T> | undefined): T[] {
  if (!data) return []
  return Array.isArray(data) ? data : data.items
}

export function formatValidationMessage(m: ValidationMessage): string {
  if (typeof m === 'string') return m
  const where = m.path ?? m.field ?? (m.line !== undefined ? `line ${m.line}` : undefined)
  return where ? `${where}: ${m.message}` : m.message
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    const fields = Object.entries(err.fieldErrors)
    return fields.length ? `${err.message} ${fields.map(([k, v]) => `${k}: ${v}`).join('; ')}` : err.message
  }
  return err instanceof Error ? err.message : String(err)
}
