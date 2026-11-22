import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router'
import { useForm } from 'react-hook-form'
import { CheckCircle2, Circle, CircleDashed, CircleSlash, Loader2, Pencil, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { useNetworks } from '@/api/networks'
import { useScanEventListener } from '@/api/scanHub'
import { useCancelScan, useScan, useScanEvents, useScanJobs, useUpdateScan } from '@/api/scans'
import { ACTIVE_RUN_STATUSES, type ScanExecutionEvent, type ScanRun, type ScanStep, type StepStatus } from '@/api/types'
import { Can } from '@/auth/AuthProvider'
import { ConfirmButton } from '@/components/actions'
import { EmptyState, Loadable } from '@/components/feedback'
import { FormField, submitHandler } from '@/components/form'
import { Chips, KeyValues, PageHeader, Pagination, StatusBadge } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Input, Textarea } from '@/components/ui/input'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { t } from '@/i18n/strings'
import { formatDateTime, formatDuration, splitList } from '@/lib/format'
import { cn } from '@/lib/utils'
import { JobsTable } from './JobsTable'

const stepIcons: Record<StepStatus, React.ReactNode> = {
  Pending: <Circle className="text-muted-foreground size-4" />,
  Running: <Loader2 className="text-primary size-4 animate-spin" />,
  Completed: <CheckCircle2 className="text-success size-4" />,
  Skipped: <CircleDashed className="text-muted-foreground size-4" />,
  Failed: <XCircle className="text-destructive size-4" />,
  Cancelled: <CircleSlash className="text-muted-foreground size-4" />,
}

const barColors: Record<StepStatus, string> = {
  Pending: 'bg-muted-foreground/30',
  Running: 'bg-primary/70',
  Completed: 'bg-primary',
  Skipped: 'bg-muted-foreground/30',
  Failed: 'bg-destructive',
  Cancelled: 'bg-muted-foreground/40',
}

/** ipcat-web run timeline: one row per step, a bar placed by its start/finish against the whole run. */
function StepsTimeline({ steps, run }: { steps: ScanStep[]; run: ScanRun }) {
  if (steps.length === 0) return <EmptyState />
  const now = Date.now()
  const times = steps.flatMap((s) => [s.startedAt, s.finishedAt]).filter(Boolean).map((v) => Date.parse(v!))
  const start = run.startedAt ? Date.parse(run.startedAt) : Math.min(now, ...times)
  const end = Math.max(run.finishedAt ? Date.parse(run.finishedAt) : now, ...times, start + 1000)
  const total = end - start
  const pct = (ms: number) => `${Math.max(0, Math.min(100, (ms / total) * 100))}%`
  return (
    <div className="min-w-0" data-testid="steps-timeline">
      <div className="grid grid-cols-[minmax(170px,240px)_minmax(0,1fr)] gap-x-4" aria-hidden>
        <span />
        <div className="text-muted-foreground relative flex h-6 justify-between border-b text-[11.5px] tabular-nums">
          <span>0</span>
          <span>{formatDuration(total / 2)}</span>
          <span>{formatDuration(total)}</span>
        </div>
      </div>
      <ol className="m-0 list-none p-0">
        {steps.map((s) => {
          const from = s.startedAt ? Date.parse(s.startedAt) - start : undefined
          const to = s.startedAt ? (s.finishedAt ? Date.parse(s.finishedAt) : now) - start : undefined
          return (
            <li key={s.stepId} className="grid grid-cols-[minmax(170px,240px)_minmax(0,1fr)] gap-x-4 border-b py-3 last:border-b-0">
              <div className="flex min-w-0 items-start gap-2 px-1.5">
                <span className="mt-0.5">{stepIcons[s.status]}</span>
                <span className="min-w-0">
                  <span className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[13.5px] leading-snug font-medium">{s.stepId}</span>
                    <StatusBadge status={s.status} />
                  </span>
                  <span className="text-muted-foreground block font-mono text-[11.5px]">{s.operation}</span>
                </span>
              </div>
              <div className="relative min-w-0">
                <div className="pointer-events-none absolute inset-0" aria-hidden>
                  {[0, 25, 50, 75, 100].map((x) => (
                    <span key={x} className="bg-border/70 absolute inset-y-0 w-px" style={{ left: `${x}%` }} />
                  ))}
                </div>
                <div className="relative h-7">
                  {from !== undefined && to !== undefined ? (
                    <span
                      className={cn('absolute inset-y-0 rounded-md', barColors[s.status], s.status === 'Running' && 'animate-pulse')}
                      style={{ left: pct(from), width: `max(6px, ${pct(to - from)})` }}
                    />
                  ) : (
                    <span className="text-muted-foreground absolute inset-y-0 flex items-center gap-2 text-[12.5px]">
                      <span className="border-muted-foreground h-5 w-2 rounded-sm border-2 border-dashed" aria-hidden />
                      not started
                    </span>
                  )}
                </div>
                <div className="text-muted-foreground relative mt-1.5 flex flex-wrap gap-x-3 text-[12px]">
                  {s.jobsTotal > 0 && (
                    <span className="tabular-nums">
                      {s.jobsCompleted}/{s.jobsTotal} jobs
                    </span>
                  )}
                  {s.startedAt && <span>started {formatDateTime(s.startedAt)}</span>}
                  {s.finishedAt && s.startedAt && <span>took {formatDuration(Date.parse(s.finishedAt) - Date.parse(s.startedAt))}</span>}
                  {s.message && <span className="text-foreground">{s.message}</span>}
                </div>
              </div>
            </li>
          )
        })}
      </ol>
    </div>
  )
}

function EventsLog({ events }: { events: ScanExecutionEvent[] }) {
  if (events.length === 0) return <EmptyState>No events yet.</EmptyState>
  return (
    <div className="max-h-[28rem] overflow-y-auto rounded-lg border font-mono text-[12px]" data-testid="events-log">
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

interface ScanEditValues {
  name: string
  notes: string
  tags: string
}

/** Name, notes and tags of a run: user metadata, editable whatever the run state. */
function ScanEditDialog({ run }: { run: ScanRun }) {
  const [open, setOpen] = useState(false)
  const update = useUpdateScan()
  const form = useForm<ScanEditValues>()
  const { register, formState, reset } = form
  const errors = formState.errors
  const submit = submitHandler(form, async (v) => {
    await update.mutateAsync({ id: run.id, name: v.name.trim(), notes: v.notes.trim() || undefined, tags: splitList(v.tags) })
    toast.success(t.common.saved)
    setOpen(false)
  })
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) reset({ name: run.name, notes: run.notes ?? '', tags: run.tags.join(', ') })
        setOpen(next)
      }}
    >
      <DialogTrigger asChild>
        <Button variant="outline">
          <Pencil /> {t.scans.edit}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t.scans.edit}</DialogTitle>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={submit} noValidate>
          <FormField label="Name" error={errors.name?.message}>
            <Input
              {...register('name', {
                validate: (v) => !!v.trim() || 'Name is required.',
                maxLength: { value: 200, message: 'Max 200 characters.' },
              })}
            />
          </FormField>
          <FormField label="Notes" error={errors.notes?.message}>
            <Textarea rows={4} {...register('notes', { maxLength: { value: 4000, message: 'Max 4000 characters.' } })} />
          </FormField>
          <FormField label="Tags" hint="Comma separated, up to 20" error={errors.tags?.message}>
            <Input {...register('tags', { validate: (v) => splitList(v).length <= 20 || 'Max 20 tags.' })} />
          </FormField>
          <DialogFooter>
            <Button type="submit" disabled={formState.isSubmitting}>
              {formState.isSubmitting ? t.common.saving : t.common.save}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
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
                  <Can permission="edit">
                    <ScanEditDialog run={run} />
                  </Can>
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
            <div className="grid items-start gap-[18px] xl:grid-cols-[minmax(0,1fr)_380px]">
              <div className="grid min-w-0 content-start gap-[18px]">
                <Card>
                  <CardHeader className="flex-row items-center gap-2.5">
                    <CardTitle className="flex-1">Progress</CardTitle>
                    {active && run.startedAt && (
                      <span className="text-muted-foreground text-[12.5px]" data-testid="scan-eta">
                        Elapsed {formatDuration(Date.now() - Date.parse(run.startedAt))}
                        {run.remainingSeconds !== undefined && run.remainingSeconds !== null
                          ? ` · about ${formatDuration(run.remainingSeconds * 1000)} left (finishes ${formatDateTime(run.estimatedFinishAt)})`
                          : ' · ETA after the first jobs finish'}
                        {run.notAfter && run.estimatedFinishAt && Date.parse(run.estimatedFinishAt) > Date.parse(run.notAfter) && (
                          <span className="text-sev-medium-fg"> · window ends first</span>
                        )}
                      </span>
                    )}
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center gap-3">
                      <Progress value={p.percent} aria-label="Scan progress" className="h-2.5" />
                      <span className="w-14 text-right text-[22px] leading-none font-semibold tabular-nums" data-testid="scan-percent">
                        {Math.round(p.percent)}%
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-5" data-testid="scan-job-counts">
                      {(
                        [
                          ['total', p.jobsTotal, ''],
                          ['queued', p.jobsQueued, ''],
                          ['running', p.jobsRunning, 'text-chg-new-fg'],
                          ['completed', p.jobsCompleted, 'text-chg-same-fg'],
                          ['failed', p.jobsFailed, p.jobsFailed ? 'text-destructive' : ''],
                        ] as const
                      ).map(([label, value, color]) => (
                        <div key={label} className="bg-muted/60 rounded-md px-3 py-2">
                          <span className={cn('block text-[18px] leading-tight font-semibold tabular-nums', color)}>{value}</span>{' '}
                          <span className="text-muted-foreground text-[12px]">{label}</span>
                        </div>
                      ))}
                    </div>
                    {!run.coverageComplete && !active && (
                      <p className="text-sev-medium-fg bg-sev-medium-bg m-0 rounded-md px-3 py-2 text-[13px]">
                        Coverage incomplete — missing targets are not counted as gone.
                      </p>
                    )}
                  </CardContent>
                </Card>
                <Card className="p-4">
                  <Tabs defaultValue="steps">
                    <TabsList className="mb-1">
                      <TabsTrigger value="steps">{t.scans.steps}</TabsTrigger>
                      <TabsTrigger value="jobs">{t.scans.jobsTitle}</TabsTrigger>
                      <TabsTrigger value="events">{t.scans.events}</TabsTrigger>
                    </TabsList>
                    <TabsContent value="steps">
                      <StepsTimeline steps={run.steps} run={run} />
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
                </Card>
              </div>
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
                      ['Tags', <Chips values={run.tags} />],
                      ['Notes', <span className="whitespace-pre-wrap">{run.notes ?? '—'}</span>],
                      ['Estimated finish', active ? formatDateTime(run.estimatedFinishAt) : '—'],
                    ]}
                  />
                </CardContent>
              </Card>
            </div>
          </>
        )
      }}
    </Loadable>
  )
}
