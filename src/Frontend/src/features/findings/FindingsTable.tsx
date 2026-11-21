import { Link } from 'react-router'
import type { Finding } from '@/api/types'
import { TargetLink } from '@/components/EndpointLink'
import { EmptyState } from '@/components/feedback'
import { StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatRelative } from '@/lib/format'

interface Selection {
  selected: Set<string>
  onToggle: (id: string, on: boolean) => void
  onToggleAll: (on: boolean) => void
}

export function FindingsTable({
  findings,
  selection,
  urlFor,
}: {
  findings: Finding[]
  selection?: Selection
  /** Service URL of a port of the host (host detail knows its services). */
  urlFor?: (port: number) => string | undefined
}) {
  if (findings.length === 0) return <EmptyState>No findings.</EmptyState>
  const allSelected = selection ? findings.every((f) => selection.selected.has(f.id)) : false
  return (
    <Table>
      <TableHeader>
        <TableRow>
          {selection && (
            <TableHead className="w-8">
              <input
                type="checkbox"
                className="accent-primary size-4"
                aria-label="Select all findings"
                checked={allSelected}
                onChange={(e) => selection.onToggleAll(e.target.checked)}
              />
            </TableHead>
          )}
          <TableHead>Severity</TableHead>
          <TableHead>Finding</TableHead>
          <TableHead>Target</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Evidence</TableHead>
          <TableHead>Last seen</TableHead>
          <TableHead>External</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {findings.map((f) => (
          <TableRow key={f.id} data-state={selection?.selected.has(f.id) ? 'selected' : undefined}>
            {selection && (
              <TableCell>
                <input
                  type="checkbox"
                  className="accent-primary size-4"
                  aria-label={`Select ${f.name} on ${f.address}`}
                  checked={selection.selected.has(f.id)}
                  onChange={(e) => selection.onToggle(f.id, e.target.checked)}
                />
              </TableCell>
            )}
            <TableCell>
              <StatusBadge status={f.severity} />
            </TableCell>
            <TableCell>
              <div className="font-medium">{f.name}</div>
              <Link to={`/signatures/${encodeURIComponent(f.signatureId)}`} className="text-muted-foreground font-mono text-xs hover:underline">
                {f.signatureId}
                {f.signatureVersion !== undefined && ` v${f.signatureVersion}`}
              </Link>
            </TableCell>
            <TableCell className="font-mono text-xs">
              <TargetLink hostId={f.hostId} address={f.address} port={f.port} url={f.port === undefined ? undefined : urlFor?.(f.port)} />
              {f.matchedUrl && <div className="text-muted-foreground max-w-56 truncate">{f.matchedUrl}</div>}
            </TableCell>
            <TableCell>
              <StatusBadge status={f.status} />
            </TableCell>
            <TableCell className="max-w-64 truncate font-mono text-xs" title={f.evidence}>
              {f.evidence ?? '—'}
            </TableCell>
            <TableCell className="text-muted-foreground">{formatRelative(f.lastSeenAt)}</TableCell>
            <TableCell>
              {f.externalRefs.map((r) => (
                <Badge key={`${r.system}:${r.externalId}`} variant="outline">
                  {r.system} #{r.externalId}
                </Badge>
              ))}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
