const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'short', timeStyle: 'medium' })

export function formatDateTime(value?: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : dateTime.format(d)
}

/** Display name of a zone; '' is the default zone. */
export const zoneLabel = (zone?: string | null) => zone || 'default'

export function formatRelative(value?: string | null, now = Date.now()): string {
  if (!value) return '—'
  const seconds = Math.round((now - Date.parse(value)) / 1000)
  if (Number.isNaN(seconds)) return value
  const abs = Math.abs(seconds)
  const suffix = seconds >= 0 ? 'ago' : 'from now'
  if (abs < 60) return `${abs}s ${suffix}`
  if (abs < 3600) return `${Math.round(abs / 60)}m ${suffix}`
  if (abs < 86400) return `${Math.round(abs / 3600)}h ${suffix}`
  return `${Math.round(abs / 86400)}d ${suffix}`
}

export function formatDuration(ms?: number | null): string {
  if (ms === undefined || ms === null) return '—'
  if (ms < 1000) return `${Math.round(ms)} ms`
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  return m < 60 ? `${m}m ${s % 60}s` : `${Math.floor(m / 60)}h ${m % 60}m`
}

export function formatNumber(n?: number | null): string {
  return n === undefined || n === null ? '—' : n.toLocaleString()
}

/** Multi-line textarea ⇄ string[] (blank lines and surrounding whitespace dropped). */
export const splitLines = (text: string): string[] =>
  text
    .split(/[\r\n]+/)
    .map((s) => s.trim())
    .filter(Boolean)

export const splitList = (text: string): string[] =>
  text
    .split(/[,\r\n]+/)
    .map((s) => s.trim())
    .filter(Boolean)

export const optionalNumber = (v: unknown): number | undefined =>
  v === '' || v === null || v === undefined || Number.isNaN(Number(v)) ? undefined : Number(v)
