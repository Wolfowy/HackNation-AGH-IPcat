import { useState } from 'react'
import { Link } from 'react-router'
import { Pencil } from 'lucide-react'
import type { Finding } from '@/api/types'
import { useCan } from '@/auth/AuthProvider'
import { TargetLink } from '@/components/EndpointLink'
import { EmptyState } from '@/components/feedback'
import { StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatRelative } from '@/lib/format'
import { cn } from '@/lib/utils'
import { FindingEditDialog, triageLabels } from './FindingEditDialog'

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
  const canEdit = useCan('edit')
  const [editing, setEditing] = useState<Finding | null>(null)
  if (findings.length === 0) return <EmptyState>No findings.</EmptyState>
  const allSelected = selection ? findings.every((f) => selection.selected.has(f.id)) : false
  return (
    <>
      {editing && <FindingEditDialog key={editing.id} finding={editing} onClose={() => setEditing(null)} />}
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
            {canEdit && <TableHead className="w-10" />}
          </TableRow>
        </TableHeader>
        <TableBody>
          {findings.map((f) => (
            <TableRow
              key={f.id}
              data-state={selection?.selected.has(f.id) ? 'selected' : undefined}
              data-triage={f.triage}
              className={cn(f.triage === 'FalsePositive' && 'text-muted-foreground opacity-60')}
            >
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
                <StatusBadge status={f.effectiveSeverity} />
                {f.severityOverride && f.severityOverride !== f.severity && (
                  <div className="text-muted-foreground mt-0.5 text-xs" title="Detected severity (overridden by a user)">
                    was <span className="line-through">{f.severity}</span>
                  </div>
                )}
              </TableCell>
              <TableCell>
                <div className="font-medium">{f.name}</div>
                <Link to={`/signatures/${encodeURIComponent(f.signatureId)}`} className="text-muted-foreground font-mono text-xs hover:underline">
                  {f.signatureId}
                  {f.signatureVersion !== undefined && ` v${f.signatureVersion}`}
                </Link>
                {f.userTags.length > 0 && (
                  <div className="mt-1 flex flex-wrap gap-1">
                    {f.userTags.map((tag) => (
                      <Badge key={tag} variant="secondary">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                )}
                {f.notes && (
                  <div className="text-muted-foreground mt-1 max-w-72 truncate text-xs" title={f.notes}>
                    {f.notes}
                  </div>
                )}
              </TableCell>
              <TableCell className="font-mono text-xs">
                <TargetLink hostId={f.hostId} address={f.address} port={f.port} url={f.port === undefined ? undefined : urlFor?.(f.port)} />
                {f.matchedUrl && <div className="text-muted-foreground max-w-56 truncate">{f.matchedUrl}</div>}
              </TableCell>
              <TableCell className="space-y-1">
                <StatusBadge status={f.status} />
                {f.triage !== 'None' && (
                  <Badge variant={f.triage === 'Confirmed' ? 'destructive' : 'outline'} title={f.triagedBy && `Triaged by ${f.triagedBy}`}>
                    {triageLabels[f.triage]}
                  </Badge>
                )}
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
              {canEdit && (
                <TableCell>
                  <Button variant="ghost" size="icon" aria-label={`Edit ${f.name} on ${f.address}`} onClick={() => setEditing(f)}>
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
