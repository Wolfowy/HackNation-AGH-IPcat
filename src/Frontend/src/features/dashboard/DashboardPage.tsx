import { Link } from 'react-router'
import type { ReactNode } from 'react'
import { Activity, ArrowRight, Bot, GitCompare, Play, Server, ShieldAlert, ShieldCheck, ShieldHalf, type LucideIcon } from 'lucide-react'
import { useAgents } from '@/api/agents'
import { useChanges, useDashboardInsights, useDashboardSummary } from '@/api/assets'
import { useJoinActiveRuns } from '@/api/scanHub'
import { useScans } from '@/api/scans'
import type { Severity } from '@/api/types'
import { useCan } from '@/auth/AuthProvider'
import { EndpointLink, TargetLink } from '@/components/EndpointLink'
import { EmptyState, Loadable } from '@/components/feedback'
import { PageHeader, ProgressCell, severityDots, StatusBadge } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDuration, formatNumber, formatRelative, zoneLabel } from '@/lib/format'
import { cn } from '@/lib/utils'
import { InterestBadge } from '../assets/insight'
import { ChangeTypeBadge } from '../changes/ChangesTable'
import { useOpenSeverityCounts } from '../findings/SeverityTiles'
import { ChangesChart } from './ChangesChart'

/** ipcat-web KPI tile: icon + label, large number, one muted line; the whole tile links to its list. */
function Kpi({ icon: Icon, label, value, sub, to }: { icon: LucideIcon; label: string; value: ReactNode; sub?: ReactNode; to: string }) {
  return (
    <Link
      to={to}
      className="bg-card hover:bg-muted focus-visible:outline-ring flex flex-col rounded-lg border px-4 py-3.5 outline-none focus-visible:outline-2"
    >
      <div className="text-muted-foreground flex items-center gap-2 text-[13px]">
        <Icon className="size-4" aria-hidden />
        {label}
      </div>
      <div className="mt-1.5 text-[30px] leading-none font-semibold tracking-tight tabular-nums" data-testid={`stat-${label}`}>
        {value}
      </div>
      <div className="text-muted-foreground mt-2.5 min-h-[18px] truncate text-[12px]">{sub}</div>
    </Link>
  )
}

/** Card with an ipcat-web header row: title (optionally a link) + muted note or actions on the right. */
function Panel({ title, to, aside, children, className }: { title: string; to?: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <Card className={className}>
      <CardHeader className="flex-row flex-wrap items-center gap-2.5">
        <h2 className="m-0 flex-1 text-[15px] font-semibold">
          {to ? (
            <Link to={to} className="hover:underline">
              {title}
            </Link>
          ) : (
            title
          )}
        </h2>
        {aside}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}

const RISKY: Severity[] = ['critical', 'high', 'medium']

/** Status banner: "Requires attention" (open critical/high/medium findings) or "No significant risks", plus scan facts. */
function RiskBanner({ counts, facts }: { counts: Record<Severity, number>; facts: [string, ReactNode][] }) {
  const risky = RISKY.some((s) => counts[s] > 0)
  return (
    <div
      role="status"
      data-testid="risk-banner"
      className={cn(
        'mb-[18px] flex flex-wrap items-center gap-x-6 gap-y-3 rounded-lg border px-4 py-3.5',
        risky ? 'border-sev-high/40 bg-sev-high-bg' : 'border-sev-low/30 bg-sev-low-bg',
      )}
    >
      <div className="flex min-w-[260px] flex-1 items-start gap-3">
        <span className={cn('bg-card grid size-9 shrink-0 place-items-center rounded-full', risky ? 'text-sev-high-fg' : 'text-sev-low-fg')}>
          {risky ? <ShieldAlert className="size-5" aria-hidden /> : <ShieldCheck className="size-5" aria-hidden />}
        </span>
        <div>
          <div className={cn('text-[15px] font-semibold', risky ? 'text-sev-high-fg' : 'text-sev-low-fg')}>
            {risky ? 'Requires attention' : 'No significant risks'}
          </div>
          {risky ? (
            <div className="mt-1 flex flex-wrap items-center gap-2 text-[13px]">
              {RISKY.filter((s) => counts[s] > 0).map((s) => (
                <span key={s} className="inline-flex items-center gap-1">
                  <StatusBadge status={s} />
                  <span className="font-medium">{counts[s]}</span>
                </span>
              ))}
              <Link to="/findings" className="text-foreground ml-1 text-[13px] font-medium underline underline-offset-2">
                Show findings
              </Link>
            </div>
          ) : (
            <div className="text-foreground/80 mt-0.5 text-[13px]">
              No open critical, high or medium findings ({counts.low} low, {counts.info} info).
            </div>
          )}
        </div>
      </div>
      <dl className="m-0 flex flex-wrap items-center gap-x-6 gap-y-2 text-[13px]">
        {facts.map(([k, v]) => (
          <div key={k}>
            <dt className="text-foreground/70 text-[12px]">{k}</dt>
            <dd className="m-0 font-medium">{v}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

/** Open findings by severity: one stacked bar + badges (ipcat-web "Findings by severity"). */
function SeverityBreakdown({ counts }: { counts: Record<Severity, number> }) {
  const nonZero = SEVERITIES.filter((s) => counts[s] > 0)
  if (nonZero.length === 0) return <p className="text-muted-foreground m-0 text-[13px]">{t.dashboard.noFindings}</p>
  return (
    <div className="text-[13px]">
      <div className="flex h-2.5 gap-0.5 overflow-hidden rounded-full" aria-hidden>
        {nonZero.map((s) => (
          <div key={s} className={cn('h-full min-w-2', severityDots[s])} style={{ flexGrow: counts[s] }} />
        ))}
      </div>
      <div className="mt-3 flex flex-wrap gap-x-3 gap-y-2">
        {nonZero.map((s) => (
          <span key={s} className="inline-flex items-center gap-1.5">
            <StatusBadge status={s} />
            <span className="font-medium tabular-nums">{counts[s]}</span>
          </span>
        ))}
      </div>
    </div>
  )
}

export function DashboardPage() {
  const canEdit = useCan('edit')
  const summary = useDashboardSummary()
  const agents = useAgents()
  const running = useScans({ status: 'Running', page: 1, pageSize: 10 })
  useJoinActiveRuns(running.data?.items)
  const changes = useChanges({ page: 1, pageSize: 8 })
  const insights = useDashboardInsights(14)
  const counts = useOpenSeverityCounts()
  const s = summary.data
  const i = insights.data
  const online = agents.data?.filter((a) => a.isOnline).length

  return (
    <>
      <PageHeader
        title={t.dashboard.title}
        description={s?.lastScanAt && `${t.dashboard.lastScan}: ${formatRelative(s.lastScanAt)}`}
        actions={
          canEdit && (
            <Button asChild>
              <Link to="/scans/new">
                <Play /> Start scan
              </Link>
            </Button>
          )
        }
      />

      {counts && (
        <RiskBanner
          counts={counts}
          facts={[
            [t.dashboard.lastScan, s?.lastScanAt ? formatRelative(s.lastScanAt) : '—'],
            [t.dashboard.runningScans, running.data ? String(running.data.total) : '—'],
            [t.dashboard.agentsOnline, agents.data ? `${online}/${agents.data.length}` : '—'],
          ]}
        />
      )}

      <div className="mb-[18px] grid grid-cols-2 gap-3.5 lg:grid-cols-5">
        <Kpi
          icon={Server}
          label={t.dashboard.hosts}
          value={formatNumber(s?.hostsTotal)}
          sub={s && [t.dashboard.activeHosts(s.hostsActive), i && t.dashboard.unstableHosts(i.unstableHosts)].filter(Boolean).join(' · ')}
          to="/assets/hosts"
        />
        <Kpi
          icon={Activity}
          label={t.dashboard.services}
          value={formatNumber(s?.servicesTotal)}
          sub={i && i.timeOfDayVarianceServices > 0 ? t.dashboard.timeOfDayServices(i.timeOfDayVarianceServices) : undefined}
          to="/assets/services"
        />
        <Kpi icon={GitCompare} label={t.dashboard.changes24h} value={formatNumber(s?.changesLast24h)} to="/changes" />
        <Kpi icon={ShieldHalf} label={t.dashboard.openFindings} value={formatNumber(s?.findingsOpen)} to="/findings" />
        <Kpi icon={Bot} label={t.dashboard.agentsOnline} value={agents.data ? `${online}/${agents.data.length}` : '—'} to="/agents" />
      </div>

      <div className="grid items-start gap-[18px] xl:grid-cols-[minmax(0,1fr)_400px]">
        <div className="grid min-w-0 content-start gap-[18px]">
          <Panel title={t.dashboard.changesOverTime} to="/changes" aside={<span className="text-muted-foreground text-[12.5px]">UTC days</span>}>
            <Loadable query={insights}>{(data) => <ChangesChart days={data.changesByDay} />}</Loadable>
          </Panel>

          <Panel
            title={t.dashboard.topFindings}
            aside={
              <Button asChild variant="outline">
                <Link to="/findings">All findings</Link>
              </Button>
            }
          >
            <Loadable query={insights}>
              {(data) =>
                data.topFindings.length === 0 ? (
                  <EmptyState>{t.dashboard.noFindings}</EmptyState>
                ) : (
                  <Table data-testid="top-findings">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Severity</TableHead>
                        <TableHead>Finding</TableHead>
                        <TableHead>Target</TableHead>
                        <TableHead>Detected</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.topFindings.map((f) => (
                        <TableRow key={f.id}>
                          <TableCell>
                            <StatusBadge status={f.severity} />
                          </TableCell>
                          <TableCell className="font-medium">{f.name}</TableCell>
                          <TableCell className="font-mono text-[12.5px] whitespace-nowrap">
                            <TargetLink hostId={f.hostId} address={f.address} port={f.port} />
                          </TableCell>
                          <TableCell className="text-muted-foreground whitespace-nowrap">{formatRelative(f.matchedAt)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )
              }
            </Loadable>
          </Panel>

          <Panel
            title={t.dashboard.recentScans}
            aside={
              <Link className="text-primary inline-flex items-center gap-1 text-[12.5px] font-medium hover:underline" to="/scans">
                All scans <ArrowRight className="size-3.5" aria-hidden />
              </Link>
            }
          >
            <Loadable query={insights}>
              {(data) =>
                data.recentScans.length === 0 ? (
                  <EmptyState />
                ) : (
                  <Table data-testid="recent-scans">
                    <TableHeader>
                      <TableRow>
                        <TableHead>Scan</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Started</TableHead>
                        <TableHead>Duration</TableHead>
                        <TableHead>Changes</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.recentScans.map((run) => (
                        <TableRow key={run.id}>
                          <TableCell>
                            <Link to={`/scans/${run.id}`} className="font-medium hover:underline">
                              {run.name}
                            </Link>
                            {!run.coverageComplete && run.finishedAt && (
                              <div className="text-muted-foreground text-[12px]">{t.dashboard.incompleteCoverage}</div>
                            )}
                          </TableCell>
                          <TableCell>
                            <StatusBadge status={run.status} />
                          </TableCell>
                          <TableCell className="text-muted-foreground whitespace-nowrap">{formatRelative(run.startedAt ?? run.createdAt)}</TableCell>
                          <TableCell className="tabular-nums">
                            {run.durationSeconds === undefined ? '—' : formatDuration(run.durationSeconds * 1000)}
                          </TableCell>
                          <TableCell className="tabular-nums">{run.changesDetected ?? '—'}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )
              }
            </Loadable>
          </Panel>

          <Panel
            title={t.dashboard.latestChanges}
            aside={
              <Link className="text-primary inline-flex items-center gap-1 text-[12.5px] font-medium hover:underline" to="/changes">
                All changes <ArrowRight className="size-3.5" aria-hidden />
              </Link>
            }
          >
            <Loadable query={changes}>
              {(page) =>
                page.items.length === 0 ? (
                  <EmptyState />
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>When</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Target</TableHead>
                        <TableHead>Summary</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {page.items.map((c) => (
                        <TableRow key={c.id}>
                          <TableCell className="text-muted-foreground whitespace-nowrap">{formatRelative(c.detectedAt)}</TableCell>
                          <TableCell>
                            <ChangeTypeBadge type={c.type} />
                          </TableCell>
                          <TableCell className="font-mono text-[12.5px] whitespace-nowrap">
                            <TargetLink hostId={c.hostId} address={c.address} port={c.port} />
                          </TableCell>
                          <TableCell>{c.summary}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )
              }
            </Loadable>
          </Panel>
        </div>

        <div className="grid min-w-0 content-start gap-[18px]">
          <Panel title="Open findings by severity" to="/findings">
            {counts ? <SeverityBreakdown counts={counts} /> : <div className="bg-muted h-10 animate-pulse rounded-md" />}
          </Panel>

          <Panel title={t.dashboard.runningScans}>
            <Loadable query={running}>
              {(page) =>
                page.items.length === 0 ? (
                  <p className="text-muted-foreground m-0 text-[13px]">{t.dashboard.noRunning}</p>
                ) : (
                  <ul className="m-0 grid list-none gap-3 p-0" data-testid="running-scans">
                    {page.items.map((run) => (
                      <li key={run.id}>
                        <div className="mb-1 flex items-center justify-between gap-2 text-[13px]">
                          <Link to={`/scans/${run.id}`} className="font-medium hover:underline">
                            {run.name}
                          </Link>
                          <span className="text-muted-foreground text-[12px]">
                            {run.progress.jobsCompleted}/{run.progress.jobsTotal} jobs
                          </span>
                        </div>
                        <ProgressCell percent={run.progress.percent} label={`${run.name} progress`} />
                      </li>
                    ))}
                  </ul>
                )
              }
            </Loadable>
          </Panel>

          <Panel title={t.dashboard.topServices} to="/assets/services" aside={<span className="text-muted-foreground text-[12.5px]">by interest score</span>}>
            <Loadable query={insights}>
              {(data) =>
                data.topServices.length === 0 ? (
                  <EmptyState>{t.dashboard.noInterestingServices}</EmptyState>
                ) : (
                  <ul className="-my-1 divide-y" data-testid="top-services">
                    {data.topServices.map((svc) => (
                      <li key={svc.id} className="flex items-start gap-3 py-2.5">
                        <InterestBadge score={svc.interestScore} reasons={svc.interestReasons} />
                        <div className="min-w-0 flex-1 text-[13px]">
                          <div className="flex flex-wrap items-baseline gap-x-2">
                            <Link to={`/assets/hosts/${svc.hostId}`} className="font-mono text-[12.5px] font-medium hover:underline">
                              {svc.address}
                            </Link>
                            <span className="font-mono text-[12px]">
                              <EndpointLink address={svc.address} port={svc.port} url={svc.url} serviceName={svc.serviceName} tls={!!svc.tls} />
                            </span>
                          </div>
                          <div className="text-muted-foreground text-[12px]">
                            {svc.serviceName ?? 'unknown'} · zone {zoneLabel(svc.zone)}
                          </div>
                          <div className="text-muted-foreground mt-0.5 text-[12px]">{svc.interestReasons?.slice(0, 3).join(' · ')}</div>
                        </div>
                      </li>
                    ))}
                  </ul>
                )
              }
            </Loadable>
          </Panel>
        </div>
      </div>
    </>
  )
}
