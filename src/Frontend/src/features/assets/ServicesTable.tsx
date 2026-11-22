import { Link } from 'react-router'
import type { Service } from '@/api/types'
import { EndpointLink } from '@/components/EndpointLink'
import { EmptyState } from '@/components/feedback'
import { Chips } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatRelative, zoneLabel } from '@/lib/format'
import { InterestBadge, TimeOfDayBadge } from './insight'

export function ServicesTable({ services, showHost = true }: { services: Service[]; showHost?: boolean }) {
  if (services.length === 0) return <EmptyState>No services.</EmptyState>
  return (
    <Table>
      <TableHeader>
        <TableRow>
          {showHost && <TableHead>Zone</TableHead>}
          {showHost && <TableHead>Host</TableHead>}
          <TableHead>Endpoint</TableHead>
          <TableHead title="Analytical priority 0–100; hover for the reasons">Interest</TableHead>
          <TableHead>State</TableHead>
          <TableHead>Service</TableHead>
          <TableHead>HTTP</TableHead>
          <TableHead>TLS</TableHead>
          <TableHead>Technologies</TableHead>
          <TableHead>Last seen</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {services.map((s) => (
          <TableRow key={s.id} data-testid="service-row">
            {showHost && <TableCell>{zoneLabel(s.zone)}</TableCell>}
            {showHost && (
              <TableCell>
                <Link to={`/assets/hosts/${s.hostId}`} className="font-mono hover:underline">
                  {s.address}
                </Link>
              </TableCell>
            )}
            <TableCell className="font-mono whitespace-nowrap">
              <EndpointLink address={s.address} port={s.port} url={s.url} serviceName={s.serviceName} tls={!!s.tls} />
              <span className="text-muted-foreground">/{s.transport.toLowerCase()}</span>
            </TableCell>
            <TableCell>
              <InterestBadge score={s.interestScore} reasons={s.interestReasons} />
            </TableCell>
            <TableCell>
              <Badge variant={s.state === 'Open' ? 'success' : 'outline'}>{s.state}</Badge>
            </TableCell>
            <TableCell>
              <div className="flex items-center gap-1 font-medium">
                {s.serviceName ?? 'unknown'} {s.timeOfDayVariance && <TimeOfDayBadge />}
              </div>
              <div className="text-muted-foreground text-xs">
                {[s.product, s.version].filter(Boolean).join(' ')}
                {s.confidence !== undefined && ` · ${Math.round(s.confidence * 100)}%`}
              </div>
            </TableCell>
            <TableCell className="max-w-56 text-xs">
              {s.http ? (
                <>
                  <span className="font-mono">{s.http.statusCode}</span> {s.http.title}
                  <div className="text-muted-foreground truncate">{s.http.webServer}</div>
                </>
              ) : (
                '—'
              )}
            </TableCell>
            <TableCell className="text-xs">
              {s.tls ? (
                <>
                  {s.tls.subjectCommonName}
                  <div className="text-muted-foreground">until {s.tls.notAfter?.slice(0, 10)}</div>
                </>
              ) : (
                '—'
              )}
            </TableCell>
            <TableCell>
              <Chips values={s.technologies} />
            </TableCell>
            <TableCell className="text-muted-foreground">{formatRelative(s.lastSeenAt)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
