import { Link } from 'react-router'
import { Clock } from 'lucide-react'
import type { Change, ChangeType } from '@/api/types'
import { TargetLink } from '@/components/EndpointLink'
import { EmptyState } from '@/components/feedback'
import { pillDot, StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDateTime } from '@/lib/format'
import { cn } from '@/lib/utils'

const show = (v: unknown) => (v === undefined || v === null ? '' : typeof v === 'string' ? v : JSON.stringify(v))

const CHANGE_COLORS: Partial<Record<ChangeType, string>> = {
  NewHost: 'bg-chg-new-bg text-chg-new-fg',
  NewPort: 'bg-chg-new-bg text-chg-new-fg',
  NewService: 'bg-chg-new-bg text-chg-new-fg',
  HostReappeared: 'bg-chg-new-bg text-chg-new-fg',
  HostGone: 'bg-chg-gone-bg text-chg-gone-fg',
  PortGone: 'bg-chg-gone-bg text-chg-gone-fg',
}

/** Change type as an ipcat-web change pill (new = blue, changed = yellow, gone = gray); time-of-day variance stands out. */
export function ChangeTypeBadge({ type }: { type: ChangeType }) {
  return type === 'TimeOfDayVariance' ? (
    <Badge variant="warning" className="rounded-full" title="Responses differ consistently by hour of day; repeated HTTP changes are suppressed">
      <Clock /> Time of day
    </Badge>
  ) : (
    <span
      className={cn(
        'inline-flex items-center gap-[5px] rounded-full px-2 py-0.5 text-[12px] whitespace-nowrap',
        pillDot,
        CHANGE_COLORS[type] ?? 'bg-chg-changed-bg text-chg-changed-fg',
      )}
    >
      {type}
    </span>
  )
}

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
              <ChangeTypeBadge type={c.type} />
            </TableCell>
            <TableCell>
              <StatusBadge status={c.severity} />
            </TableCell>
            <TableCell className="font-mono text-xs whitespace-nowrap">
              <TargetLink hostId={c.hostId} address={c.address} port={c.port} />
            </TableCell>
            <TableCell>{c.summary}</TableCell>
            <TableCell
              className={cn('max-w-72 font-mono text-xs', c.type === 'TimeOfDayVariance' ? 'whitespace-normal' : 'truncate')}
              title={`${show(c.before)} → ${show(c.after)}`}
            >
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
