import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router'
import { CheckCircle2, Circle, CircleDashed, CircleSlash, Loader2, XCircle } from 'lucide-react'
import { useNetworks } from '@/api/networks'
import { useScanEventListener } from '@/api/scanHub'
import { useCancelScan, useScan, useScanEvents, useScanJobs } from '@/api/scans'
import { ACTIVE_RUN_STATUSES, type ScanExecutionEvent, type ScanStep, type StepStatus } from '@/api/types'
import { Can } from '@/auth/AuthProvider'
import { ConfirmButton } from '@/components/actions'
import { EmptyState, Loadable } from '@/components/feedback'
import { Chips, KeyValues, PageHeader, Pagination, StatusBadge } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { t } from '@/i18n/strings'
import { formatDateTime, formatDuration } from '@/lib/format'
import { JobsTable } from './JobsTable'

const stepIcons: Record<StepStatus, React.ReactNode> = {
  Pending: <Circle className="text-muted-foreground size-4" />,
  Running: <Loader2 className="text-primary size-4 animate-spin" />,
  Completed: <CheckCircle2 className="text-success size-4" />,
  Skipped: <CircleDashed className="text-muted-foreground size-4" />,
  Failed: <XCircle className="text-destructive size-4" />,
  Cancelled: <CircleSlash className="text-muted-foreground size-4" />,
}

function StepsTimeline({ steps }: { steps: ScanStep[] }) {
  if (steps.length === 0) return <EmptyState />
  return (
    <ol className="relative space-y-3 border-l pl-5" data-testid="steps-timeline">
      {steps.map((s) => (
        <li key={s.stepId} className="relative">
          <span className="bg-background absolute top-0.5 -left-[1.6rem]">{stepIcons[s.status]}</span>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-medium">{s.stepId}</span>
            <span className="text-muted-foreground text-xs">{s.operation}</span>
            <StatusBadge status={s.status} />
            {s.jobsTotal > 0 && (
              <span className="text-muted-foreground text-xs">
                {s.jobsCompleted}/{s.jobsTotal} jobs
              </span>
            )}
          </div>
          <div className="text-muted-foreground text-xs">
            {s.startedAt && `started ${formatDateTime(s.startedAt)}`}
            {s.finishedAt && s.startedAt && ` · took ${formatDuration(Date.parse(s.finishedAt) - Date.parse(s.startedAt))}`}
          </div>
          {s.message && <div className="text-xs">{s.message}</div>}
        </li>
      ))}
    </ol>
  )
}

function EventsLog({ events }: { events: ScanExecutionEvent[] }) {
  if (events.length === 0) return <EmptyState>No events yet.</EmptyState>
  return (
    <div className="max-h-[28rem] overflow-y-auto rounded-md border font-mono text-xs" data-testid="events-log">
      {events.map((e) => (
        <div key={e.eventId} className="flex gap-3 border-b px-3 py-1.5 last:border-0">
          <span className="text-muted-foreground shrink-0">{formatDateTime(e.occurredAt)}</span>
          <span className="w-36 shrink-0 font-semibold">{e.type}</span>
          <span className="min-w-0 break-words">
            {[e.stepId, e.agentId, e.message, e.progress !== undefined ? `${Math.round(e.progress)}%` : null].filter(Boolean).join(' · ')}
          </span>
        </div>
      ))}
    </div>
  )
}

export function ScanDetailPage() {
  const { id = '' } = useParams()
  const scan = useScan(id)
  const [jobsPage, setJobsPage] = useState(1)
  const jobsPageSize = 100
  const jobs = useScanJobs(id, jobsPage, jobsPageSize)
  const history = useScanEvents(id)
  const networks = useNetworks()
  const cancel = useCancelScan()
  const [live, setLive] = useState<ScanExecutionEvent[]>([])

  useScanEventListener((event) => setLive((prev) => [event, ...prev].slice(0, 500)), id)

  const events = useMemo(() => {
    const byId = new Map<string, ScanExecutionEvent>()
    for (const e of [...(history.data ?? []), ...live]) byId.set(e.eventId, e)
    return [...byId.values()].sort((a, b) => b.occurredAt.localeCompare(a.occurredAt)).slice(0, 500)
  }, [history.data, live])

  return (
    <Loadable query={scan}>
      {(run) => {
        const active = ACTIVE_RUN_STATUSES.includes(run.status)
        const p = run.progress
        return (
          <>
            <PageHeader
              title={
                <span className="flex items-center gap-3">
                  {run.name} <StatusBadge status={run.status} />
                </span>
              }
              description={
                <>
                  <Link to="/scans" className="hover:underline">
                    {t.scans.title}
                  </Link>{' '}
                  / {run.id}
                </>
              }
              actions={
                <>
                  <Button variant="outline" asChild>
                    <Link to={`/changes/diff?run=${run.id}`}>{t.scans.diff}</Link>
                  </Button>
                  {active && (
                    <Can permission="edit">
                      <ConfirmButton
                        variant="destructive"
                        title={`${t.scans.cancel}?`}
                        description="Active jobs are cancelled; observations collected so far are kept."
                        confirmLabel={t.scans.cancel}
                        onConfirm={() => cancel.mutateAsync(run.id)}
                      >
                        {t.scans.cancel}
                      </ConfirmButton>
                    </Can>
                  )}
                </>
              }
            />
            <div className="grid gap-6 lg:grid-cols-3">
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>Progress</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center gap-3">
                    <Progress value={p.percent} aria-label="Scan progress" className="h-3" />
                    <span className="w-12 text-right font-semibold tabular-nums" data-testid="scan-percent">
                      {Math.round(p.percent)}%
                    </span>
                  </div>
                  <div className="text-muted-foreground flex flex-wrap gap-4 text-sm" data-testid="scan-job-counts">
                    <span>{p.jobsTotal} total</span>
                    <span>{p.jobsQueued} queued</span>
                    <span>{p.jobsRunning} running</span>
                    <span>{p.jobsCompleted} completed</span>
                    <span className={p.jobsFailed ? 'text-destructive' : undefined}>{p.jobsFailed} failed</span>
                  </div>
                  {active && run.startedAt && (
                    <p className="text-muted-foreground text-sm" data-testid="scan-eta">
                      Elapsed {formatDuration(Date.now() - Date.parse(run.startedAt))}
                      {run.remainingSeconds !== undefined && run.remainingSeconds !== null
                        ? ` · about ${formatDuration(run.remainingSeconds * 1000)} left (finishes ${formatDateTime(run.estimatedFinishAt)})`
                        : ' · ETA after the first jobs finish'}
                      {run.notAfter && run.estimatedFinishAt && Date.parse(run.estimatedFinishAt) > Date.parse(run.notAfter) && (
                        <span className="text-amber-600"> · window ends first</span>
                      )}
                    </p>
                  )}
                  {!run.coverageComplete && !active && (
                    <p className="text-sm text-amber-600">Coverage incomplete — missing targets are not counted as gone.</p>
                  )}
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Details</CardTitle>
                </CardHeader>
                <CardContent>
                  <KeyValues
                    items={[
                      ['Workflow', <Link to={`/workflows/${run.workflowKey}`} className="hover:underline">{`${run.workflowKey} v${run.workflowVersion}`}</Link>],
                      ['Networks', <Chips values={run.networkIds.map((nid) => networks.data?.find((n) => n.id === nid)?.name ?? nid)} />],
                      ['Triggered by', run.triggeredBy],
                      ['Priority', run.priority],
                      ['Created', formatDateTime(run.createdAt)],
                      ['Started', formatDateTime(run.startedAt)],
                      ['Finished', formatDateTime(run.finishedAt)],
                      ['Window ends', formatDateTime(run.notAfter)],
                      ['Estimated finish', active ? formatDateTime(run.estimatedFinishAt) : '—'],
                    ]}
                  />
                </CardContent>
              </Card>
            </div>
            <Tabs defaultValue="steps" className="mt-6">
              <TabsList>
                <TabsTrigger value="steps">{t.scans.steps}</TabsTrigger>
                <TabsTrigger value="jobs">{t.scans.jobsTitle}</TabsTrigger>
                <TabsTrigger value="events">{t.scans.events}</TabsTrigger>
              </TabsList>
              <TabsContent value="steps">
                <StepsTimeline steps={run.steps} />
              </TabsContent>
              <TabsContent value="jobs">
                <Loadable query={jobs}>
                  {(data) => (
                    <>
                      <JobsTable jobs={data.items} runStatus={run.status} />
                      <Pagination page={jobsPage} pageSize={jobsPageSize} total={data.total} onPageChange={setJobsPage} />
                    </>
                  )}
                </Loadable>
              </TabsContent>
              <TabsContent value="events">
                <EventsLog events={events} />
              </TabsContent>
            </Tabs>
          </>
        )
      }}
    </Loadable>
  )
}
