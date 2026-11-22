import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { Plus } from 'lucide-react'
import { toast } from 'sonner'
import { useNetworks } from '@/api/networks'
import { useDeleteSchedule, useSchedules, useSetSchedulePaused, useTriggerSchedule } from '@/api/schedules'
import type { Schedule } from '@/api/types'
import { Can, useCan } from '@/auth/AuthProvider'
import { ConfirmButton } from '@/components/actions'
import { EmptyState, Loadable } from '@/components/feedback'
import { Chips, PageHeader, StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDateTime, formatRelative } from '@/lib/format'
import { ScheduleFormDialog } from './ScheduleFormDialog'

export function SchedulesPage() {
  const schedules = useSchedules()
  const networks = useNetworks()
  const trigger = useTriggerSchedule()
  const setPaused = useSetSchedulePaused()
  const remove = useDeleteSchedule()
  const canEdit = useCan('edit')
  const canManage = useCan('manage')
  const navigate = useNavigate()
  const [editing, setEditing] = useState<Schedule | null | undefined>(undefined)
  const networkName = (id: string) => networks.data?.find((n) => n.id === id)?.name ?? id

  const runNow = (s: Schedule) =>
    trigger.mutate(s.id, {
      onSuccess: ({ scanRunId, reason }) => {
        if (!scanRunId) return void toast.info(`Queued: ${reason ?? 'waits for the previous run'}`)
        toast.success(`Scan started from "${s.name}"`)
        navigate(`/scans/${scanRunId}`)
      },
    })

  return (
    <>
      <PageHeader
        title={t.schedules.title}
        actions={
          <Can permission="manage">
            <Button onClick={() => setEditing(null)}>
              <Plus /> {t.schedules.create}
            </Button>
          </Can>
        }
      />
      <Loadable query={schedules}>
        {(list) =>
          list.length === 0 ? (
            <EmptyState>No schedules.</EmptyState>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Cron</TableHead>
                  <TableHead>Next fire</TableHead>
                  <TableHead>Workflow</TableHead>
                  <TableHead>Networks</TableHead>
                  <TableHead>Overlap</TableHead>
                  <TableHead>Last run</TableHead>
                  <TableHead>State</TableHead>
                  {canEdit && <TableHead className="text-right">{t.common.actions}</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="font-medium">{s.name}</TableCell>
                    <TableCell>
                      <code className="text-xs">{s.cronExpression}</code>
                      <div className="text-muted-foreground text-xs">{s.timeZone}</div>
                    </TableCell>
                    <TableCell title={formatDateTime(s.nextFireAt)}>
                      {s.enabled ? formatRelative(s.nextFireAt) : '—'}
                      {s.enabled && s.resumeAt && (
                        <div className="text-xs text-amber-600" title="The last run hit its window end and restarts when the next window opens">
                          Resume pending at {formatDateTime(s.resumeAt)}
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {s.workflowKey}
                      {s.workflowVersion ? ` v${s.workflowVersion}` : ' (latest)'}
                    </TableCell>
                    <TableCell>
                      <Chips values={s.networkIds.map(networkName)} />
                    </TableCell>
                    <TableCell>{s.overlapPolicy}</TableCell>
                    <TableCell>
                      {s.lastRunId ? (
                        <Link to={`/scans/${s.lastRunId}`}>
                          <StatusBadge status={s.lastRunStatus ?? 'Unknown'} />
                        </Link>
                      ) : (
                        '—'
                      )}
                    </TableCell>
                    <TableCell>{s.enabled ? <Badge variant="success">Active</Badge> : <Badge variant="outline">Paused</Badge>}</TableCell>
                    {canEdit && (
                      <TableCell className="space-x-2 text-right whitespace-nowrap">
                        <Button size="sm" onClick={() => runNow(s)} disabled={trigger.isPending}>
                          {t.schedules.trigger}
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setPaused.mutate({ id: s.id, paused: s.enabled })}>
                          {s.enabled ? t.schedules.pause : t.schedules.resume}
                        </Button>
                        <Button size="sm" variant="outline" onClick={() => setEditing(s)}>
                          {t.common.edit}
                        </Button>
                        {canManage && (
                          <ConfirmButton
                            size="sm"
                            variant="outline"
                            title={t.common.confirmDelete(`schedule "${s.name}"`)}
                            confirmLabel={t.common.delete}
                            onConfirm={() => remove.mutateAsync(s.id)}
                          >
                            {t.common.delete}
                          </ConfirmButton>
                        )}
                      </TableCell>
                    )}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )
        }
      </Loadable>
      {editing !== undefined && <ScheduleFormDialog key={editing?.id ?? 'new'} schedule={editing ?? undefined} onClose={() => setEditing(undefined)} />}
    </>
  )
}
