import { ExternalLink, Server } from 'lucide-react'
import { Link } from 'react-router'
import { cn } from '@/lib/utils'

export interface Endpoint {
  address: string
  port: number
  /** Server-derived service URL (preferred when present). */
  url?: string
  serviceName?: string
  /** Endpoint known to speak TLS (e.g. a certificate was seen). */
  tls?: boolean
}

const TLS_PORTS = new Set([443, 8443, 9443, 4443, 10443])

/** IPv6 addresses go in brackets in URLs and `addr:port` labels. */
export const hostPart = (address: string) => (address.includes(':') && !address.startsWith('[') ? `[${address}]` : address)

export const endpointLabel = ({ address, port }: Endpoint) => `${hostPart(address)}:${port}`

/** Server URL when known; otherwise https for TLS-like services/ports, else http. */
export function endpointHref({ address, port, url, serviceName, tls }: Endpoint): string {
  if (url) return url
  const name = serviceName?.toLowerCase() ?? ''
  const secure = tls || name.startsWith('https') || name.includes('ssl') || name.includes('tls') || TLS_PORTS.has(port)
  return `${secure ? 'https' : 'http'}://${hostPart(address)}:${port}/`
}

/** `address:port` opening the endpoint in a new tab. */
export function EndpointLink({ className, ...endpoint }: Endpoint & { className?: string }) {
  const href = endpointHref(endpoint)
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      title={`Open ${href} in a new tab`}
      className={cn('inline-flex items-center gap-1 font-mono hover:underline', className)}
      data-testid="endpoint-link"
    >
      {endpointLabel(endpoint)}
      <ExternalLink className="size-3 shrink-0 opacity-60" aria-hidden />
    </a>
  )
}

/** A finding/change target: the endpoint link when a port is known (plus a host-detail icon), else the address linking to the host. */
export function TargetLink({ hostId, address, port, ...rest }: Omit<Endpoint, 'port'> & { hostId?: string; port?: number }) {
  if (port === undefined || port === null)
    return hostId ? (
      <Link to={`/assets/hosts/${hostId}`} className="font-mono hover:underline">
        {address}
      </Link>
    ) : (
      <span className="font-mono">{address}</span>
    )
  return (
    <span className="inline-flex items-center gap-1.5">
      <EndpointLink address={address} port={port} {...rest} />
      {hostId && (
        <Link to={`/assets/hosts/${hostId}`} aria-label={`Host ${address}`} title="Host details" className="text-muted-foreground hover:text-foreground">
          <Server className="size-3" />
        </Link>
      )}
    </span>
  )
}
