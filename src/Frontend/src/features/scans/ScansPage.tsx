import { useState } from 'react'
import { Link } from 'react-router'
import { Play } from 'lucide-react'
import { useJoinActiveRuns } from '@/api/scanHub'
import { useScans } from '@/api/scans'
import { SCAN_RUN_STATUSES, type ScanRunStatus } from '@/api/types'
import { Can } from '@/auth/AuthProvider'
import { EmptyState, Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Filters, PageHeader, Pagination, ProgressCell, StatusBadge } from '@/components/page'
import { Button } from '@/components/ui/button'
import { NativeSelect } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDateTime, formatDuration, formatRelative } from '@/lib/format'

export function ScansPage() {
  const [status, setStatus] = useState<ScanRunStatus | ''>('')
  const [page, setPage] = useState(1)
  const pageSize = 25
  const scans = useScans({ status, page, pageSize })
  useJoinActiveRuns(scans.data?.items)

  return (
    <>
      <PageHeader
        title={t.scans.title}
        actions={
          <Can permission="edit">
            <Button asChild>
              <Link to="/scans/new">
                <Play /> {t.scans.start}
              </Link>
            </Button>
          </Can>
        }
      />
      <Filters>
        <FormField label="Status">
          <NativeSelect
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as ScanRunStatus | '')
              setPage(1)
            }}
          >
            <option value="">{t.common.all}</option>
            {SCAN_RUN_STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </NativeSelect>
        </FormField>
      </Filters>
      <Loadable query={scans}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>No scans found.</EmptyState>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Progress</TableHead>
                    <TableHead>Jobs</TableHead>
                    <TableHead>Workflow</TableHead>
                    <TableHead>Triggered by</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Finished</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((run) => (
                    <TableRow key={run.id}>
                      <TableCell>
                        <Link to={`/scans/${run.id}`} className="font-medium hover:underline">
                          {run.name}
                        </Link>
                        {!run.coverageComplete && run.finishedAt && (
                          <div className="text-xs text-amber-600">Coverage incomplete</div>
                        )}
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={run.status} />
                      </TableCell>
                      <TableCell>
                        <ProgressCell percent={run.progress.percent} label={`${run.name} progress`} />
                        {run.remainingSeconds !== undefined && run.remainingSeconds !== null && (
                          <div className="text-muted-foreground text-xs" title={formatDateTime(run.estimatedFinishAt)}>
                            ETA {formatDuration(run.remainingSeconds * 1000)}
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="text-sm whitespace-nowrap">
                        {run.progress.jobsCompleted}/{run.progress.jobsTotal}
                        {run.progress.jobsFailed > 0 && <span className="text-destructive"> · {run.progress.jobsFailed} failed</span>}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {run.workflowKey} v{run.workflowVersion}
                      </TableCell>
                      <TableCell className="text-sm">{run.triggeredBy}</TableCell>
                      <TableCell className="text-muted-foreground" title={formatDateTime(run.createdAt)}>
                        {formatRelative(run.createdAt)}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{formatDateTime(run.finishedAt)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <Pagination page={page} pageSize={pageSize} total={data.total} onPageChange={setPage} />
            </>
          )
        }
      </Loadable>
    </>
  )
}
