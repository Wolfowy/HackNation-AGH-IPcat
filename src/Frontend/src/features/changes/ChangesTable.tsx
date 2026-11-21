import { Link } from 'react-router'
import type { Change } from '@/api/types'
import { EmptyState } from '@/components/feedback'
import { StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDateTime } from '@/lib/format'

const show = (v: unknown) => (v === undefined || v === null ? '' : typeof v === 'string' ? v : JSON.stringify(v))

export function ChangesTable({ changes }: { changes: Change[] }) {
  if (changes.length === 0) return <EmptyState>No changes.</EmptyState>
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Detected</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Severity</TableHead>
          <TableHead>Target</TableHead>
          <TableHead>Summary</TableHead>
          <TableHead>Before → after</TableHead>
          <TableHead>Scan</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {changes.map((c) => (
          <TableRow key={c.id} data-testid="change-row">
            <TableCell className="text-muted-foreground whitespace-nowrap">{formatDateTime(c.detectedAt)}</TableCell>
            <TableCell>
              <Badge variant="outline">{c.type}</Badge>
            </TableCell>
            <TableCell>
              <StatusBadge status={c.severity} />
            </TableCell>
            <TableCell className="font-mono text-xs whitespace-nowrap">
              {c.hostId ? (
                <Link to={`/assets/hosts/${c.hostId}`} className="hover:underline">
                  {c.address}
                </Link>
              ) : (
                c.address
              )}
              {c.port !== undefined && `:${c.port}`}
            </TableCell>
            <TableCell>{c.summary}</TableCell>
            <TableCell className="max-w-72 truncate font-mono text-xs" title={`${show(c.before)} → ${show(c.after)}`}>
              {c.before !== undefined || c.after !== undefined ? `${show(c.before) || '∅'} → ${show(c.after) || '∅'}` : ''}
            </TableCell>
            <TableCell>
              <Link to={`/scans/${c.scanRunId}`} className="font-mono text-xs hover:underline">
                {c.scanRunId.slice(0, 8)}
              </Link>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
