// Client-side format hints for network ranges/exclusions. The server (IpRangeSet + scope policy) is authoritative.

const ipv4Part = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
const ipv4 = new RegExp(`^${ipv4Part}(\\.${ipv4Part}){3}$`)
const hostname = /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/

function isIpv6(value: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(value) || !value.includes(':')) return false
  try {
    new URL(`http://[${value}]/`)
    return true
  } catch {
    return false
  }
}

const ipv4ToNumber = (ip: string) => ip.split('.').reduce((acc, octet) => acc * 256 + Number(octet), 0)

/** Returns an error message for an invalid target, or null when the format is acceptable. */
export function validateTarget(raw: string): string | null {
  const value = raw.trim()
  if (!value) return null
  if (value.includes('/')) {
    const [addr, prefix, extra] = value.split('/')
    if (extra !== undefined || !/^\d{1,3}$/.test(prefix)) return `"${value}": invalid CIDR prefix`
    const bits = Number(prefix)
    if (ipv4.test(addr)) return bits <= 32 ? null : `"${value}": IPv4 prefix must be 0–32`
    if (isIpv6(addr)) return bits <= 128 ? null : `"${value}": IPv6 prefix must be 0–128`
    return `"${value}": invalid CIDR address`
  }
  if (value.includes('-') && ipv4.test(value.split('-')[0])) {
    const [from, to] = value.split('-')
    if (!ipv4.test(to)) return `"${value}": invalid range end`
    return ipv4ToNumber(from) <= ipv4ToNumber(to) ? null : `"${value}": range start is after its end`
  }
  if (value.includes('-') && value.split('-').length === 2 && value.split('-').every(isIpv6)) return null
  if (ipv4.test(value) || isIpv6(value)) return null
  if (/^[\d.]+$/.test(value)) return `"${value}": invalid IPv4 address`
  // Domains may be wildcards in the scope policy (*.example.com).
  return hostname.test(value.replace(/^\*\./, '')) ? null : `"${value}": not an IP, CIDR, range or hostname`
}

/** Validates every line; returns a combined message or true (react-hook-form `validate` contract). */
export function validateTargetLines(lines: string[], required: boolean): true | string {
  if (required && lines.length === 0) return 'At least one entry is required.'
  return combine(lines.map(validateTarget))
}

/** Scope policy port entry: "80" or "8000-8100" (1–65535). */
export function validatePort(raw: string): string | null {
  const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(raw.trim())
  if (!match) return `"${raw.trim()}": not a port or port range (e.g. 443, 8000-8100)`
  const from = Number(match[1])
  const to = Number(match[2] ?? match[1])
  if (from < 1 || to > 65535) return `"${raw.trim()}": ports are 1–65535`
  return from <= to ? null : `"${raw.trim()}": range start is after its end`
}

export const validatePortLines = (lines: string[]): true | string => combine(lines.map(validatePort))

function combine(results: (string | null)[]): true | string {
  const errors = results.filter((e): e is string => e !== null)
  return errors.length ? errors.slice(0, 3).join('; ') + (errors.length > 3 ? ` (+${errors.length - 3} more)` : '') : true
}
