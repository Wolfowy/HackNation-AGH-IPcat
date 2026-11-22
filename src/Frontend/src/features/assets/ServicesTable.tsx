import { useState } from 'react'
import { Link } from 'react-router'
import { Pencil } from 'lucide-react'
import type { Service } from '@/api/types'
import { useCan } from '@/auth/AuthProvider'
import { EndpointLink } from '@/components/EndpointLink'
import { EmptyState } from '@/components/feedback'
import { Chips, StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatRelative, zoneLabel } from '@/lib/format'
import { ServiceAnnotationDialog } from './ServiceAnnotationDialog'

export function ServicesTable({ services, showHost = true }: { services: Service[]; showHost?: boolean }) {
  const canEdit = useCan('edit')
  const [editing, setEditing] = useState<Service | null>(null)
  if (services.length === 0) return <EmptyState>No services.</EmptyState>
  return (
    <>
      {editing && <ServiceAnnotationDialog key={editing.id} service={editing} onClose={() => setEditing(null)} />}
      <Table>
        <TableHeader>
          <TableRow>
            {showHost && <TableHead>Zone</TableHead>}
            {showHost && <TableHead>Host</TableHead>}
            <TableHead>Endpoint</TableHead>
            <TableHead>State</TableHead>
            <TableHead>Service</TableHead>
            <TableHead>HTTP</TableHead>
            <TableHead>TLS</TableHead>
            <TableHead>Technologies</TableHead>
            <TableHead>Annotation</TableHead>
            <TableHead>Last seen</TableHead>
            {canEdit && <TableHead className="w-10" />}
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
                <Badge variant={s.state === 'Open' ? 'success' : 'outline'}>{s.state}</Badge>
              </TableCell>
              <TableCell>
                <div className="font-medium">{s.serviceName ?? 'unknown'}</div>
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
              <TableCell className="max-w-56 text-xs" data-testid="service-annotation">
                {s.annotation ? (
                  <div className="space-y-1">
                    {s.annotation.criticality && <StatusBadge status={s.annotation.criticality} />}
                    {s.annotation.owner && <div>{s.annotation.owner}</div>}
                    {s.annotation.tags.length > 0 && <Chips values={s.annotation.tags} />}
                    {s.annotation.notes && (
                      <div className="text-muted-foreground truncate" title={s.annotation.notes}>
                        {s.annotation.notes}
                      </div>
                    )}
                  </div>
                ) : (
                  <span className="text-muted-foreground">—</span>
                )}
              </TableCell>
              <TableCell className="text-muted-foreground">{formatRelative(s.lastSeenAt)}</TableCell>
              {canEdit && (
                <TableCell>
                  <Button variant="ghost" size="icon" aria-label={`Annotate ${s.address}:${s.port}`} onClick={() => setEditing(s)}>
                    <Pencil />
                  </Button>
                </TableCell>
              )}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </>
  )
}
