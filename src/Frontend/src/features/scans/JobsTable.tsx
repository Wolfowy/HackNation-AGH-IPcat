import { Link } from 'react-router'
import { useCancelJob, useRetryJob } from '@/api/scans'
import { ACTIVE_RUN_STATUSES, type ScanJob, type ScanRunStatus } from '@/api/types'
import { useCan } from '@/auth/AuthProvider'
import { EmptyState } from '@/components/feedback'
import { StatusBadge } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDuration, formatRelative } from '@/lib/format'

/** `runStatus`: status of the run all jobs belong to; jobs of a finished run cannot be retried (the server answers 409). */
export function JobsTable({ jobs, showRun = false, runStatus }: { jobs: ScanJob[]; showRun?: boolean; runStatus?: ScanRunStatus }) {
  const canEdit = useCan('edit')
  const canRetry = !runStatus || ACTIVE_RUN_STATUSES.includes(runStatus)
  const cancel = useCancelJob()
  const retry = useRetryJob()
  if (jobs.length === 0) return <EmptyState>No jobs.</EmptyState>
  return (
    <Table>
      <TableHeader>
        <TableRow>
          {showRun && <TableHead>Scan</TableHead>}
          <TableHead>Step</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Agent / interface</TableHead>
          <TableHead>Tool</TableHead>
          <TableHead>Targets</TableHead>
          <TableHead>Attempt</TableHead>
          <TableHead>Duration</TableHead>
          <TableHead>Error</TableHead>
          {canEdit && <TableHead />}
        </TableRow>
      </TableHeader>
      <TableBody>
        {jobs.map((job) => (
          <TableRow key={job.id} data-testid="job-row">
            {showRun && (
              <TableCell>
                <Link to={`/scans/${job.scanRunId}`} className="font-mono text-xs hover:underline">
                  {job.scanRunId.slice(0, 8)}
                </Link>
              </TableCell>
            )}
            <TableCell>
              <div className="font-medium">{job.stepId}</div>
              <div className="text-muted-foreground text-xs">{job.operation}</div>
            </TableCell>
            <TableCell>
              <StatusBadge status={job.status} />
              {job.status === 'Leased' && job.progressPercent !== undefined && (
                <span className="text-muted-foreground ml-1 text-xs">{Math.round(job.progressPercent)}%</span>
              )}
            </TableCell>
            <TableCell className="text-sm">
              {job.agentId ? (
                <Link to={`/agents/${encodeURIComponent(job.agentId)}`} className="hover:underline">
                  {job.agentId}
                </Link>
              ) : (
                '—'
              )}
              {job.interfaceName && <span className="text-muted-foreground font-mono text-xs"> / {job.interfaceName}</span>}
            </TableCell>
            <TableCell className="font-mono text-xs">{job.toolId ?? '—'}</TableCell>
            <TableCell className="text-xs">
              <div className="font-mono">{job.targetSummary}</div>
              <div className="text-muted-foreground">{job.targetCount} targets</div>
            </TableCell>
            <TableCell>
              {job.attempt}/{job.maxAttempts}
            </TableCell>
            <TableCell className="whitespace-nowrap" title={job.startedAt ? `started ${formatRelative(job.startedAt)}` : undefined}>
              {formatDuration(job.durationMs)}
            </TableCell>
            <TableCell className="text-destructive max-w-64 truncate text-xs" title={job.error}>
              {job.error ?? ''}
            </TableCell>
            {canEdit && (
              <TableCell className="text-right whitespace-nowrap">
                {(job.status === 'Queued' || job.status === 'Leased') && (
                  <Button size="sm" variant="outline" onClick={() => cancel.mutate(job.id)}>
                    Cancel
                  </Button>
                )}
                {canRetry && (job.status === 'Failed' || job.status === 'Cancelled') && (
                  <Button size="sm" variant="outline" onClick={() => retry.mutate(job.id)}>
                    Retry
                  </Button>
                )}
              </TableCell>
            )}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
