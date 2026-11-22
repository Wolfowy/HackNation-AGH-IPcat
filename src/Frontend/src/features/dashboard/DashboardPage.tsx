import { Link } from 'react-router'
import type { ReactNode } from 'react'
import { useAgents } from '@/api/agents'
import { useChanges, useDashboardInsights, useDashboardSummary } from '@/api/assets'
import { useJoinActiveRuns } from '@/api/scanHub'
import { useScans } from '@/api/scans'
import { EndpointLink, TargetLink } from '@/components/EndpointLink'
import { EmptyState, Loadable } from '@/components/feedback'
import { PageHeader, ProgressCell, StatusBadge } from '@/components/page'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDuration, formatNumber, formatRelative, zoneLabel } from '@/lib/format'
import { InterestBadge } from '../assets/insight'
import { ChangeTypeBadge } from '../changes/ChangesTable'
import { ChangesChart } from './ChangesChart'

function StatCard({ label, value, sub, to }: { label: string; value: ReactNode; sub?: ReactNode; to: string }) {
  return (
    <Link to={to} className="block">
      <Card className="hover:border-primary/50 h-full gap-1 transition-colors">
        <CardHeader>
          <div className="text-muted-foreground text-sm">{label}</div>
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-semibold tabular-nums" data-testid={`stat-${label}`}>
            {value}
          </div>
          {sub && <div className="text-muted-foreground mt-1 text-xs">{sub}</div>}
        </CardContent>
      </Card>
    </Link>
  )
}

export function DashboardPage() {
  const summary = useDashboardSummary()
  const agents = useAgents()
  const running = useScans({ status: 'Running', page: 1, pageSize: 10 })
  useJoinActiveRuns(running.data?.items)
  const changes = useChanges({ page: 1, pageSize: 8 })
  const insights = useDashboardInsights(14)
  const s = summary.data
  const i = insights.data
  const online = agents.data?.filter((a) => a.isOnline).length

  return (
    <>
      <PageHeader title={t.dashboard.title} description={s?.lastScanAt && `${t.dashboard.lastScan}: ${formatRelative(s.lastScanAt)}`} />
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard
          label={t.dashboard.hosts}
          value={formatNumber(s?.hostsTotal)}
          sub={s && [t.dashboard.activeHosts(s.hostsActive), i && t.dashboard.unstableHosts(i.unstableHosts)].filter(Boolean).join(' · ')}
          to="/assets/hosts"
        />
        <StatCard
          label={t.dashboard.services}
          value={formatNumber(s?.servicesTotal)}
          sub={i && i.timeOfDayVarianceServices > 0 ? t.dashboard.timeOfDayServices(i.timeOfDayVarianceServices) : undefined}
          to="/assets/services"
        />
        <StatCard label={t.dashboard.changes24h} value={formatNumber(s?.changesLast24h)} to="/changes" />
        <StatCard label={t.dashboard.openFindings} value={formatNumber(s?.findingsOpen)} to="/findings" />
        <StatCard
          label={t.dashboard.agentsOnline}
          value={agents.data ? `${online}/${agents.data.length}` : '—'}
          to="/agents"
        />
      </div>

      <div className="mb-6 grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>
              <Link to="/findings" className="hover:underline">
                {t.dashboard.topFindings}
              </Link>
            </CardTitle>
          </CardHeader>
          <CardContent>
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
                          <TableCell className="text-xs whitespace-nowrap">
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
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>
              <Link to="/assets/services" className="hover:underline">
                {t.dashboard.topServices}
              </Link>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Loadable query={insights}>
              {(data) =>
                data.topServices.length === 0 ? (
                  <EmptyState>{t.dashboard.noInterestingServices}</EmptyState>
                ) : (
                  <ul className="divide-y" data-testid="top-services">
                    {data.topServices.map((svc) => (
                      <li key={svc.id} className="flex items-start gap-3 py-2">
                        <InterestBadge score={svc.interestScore} reasons={svc.interestReasons} />
                        <div className="min-w-0 flex-1 text-sm">
                          <div className="flex flex-wrap items-baseline gap-x-2">
                            <Link to={`/assets/hosts/${svc.hostId}`} className="font-mono font-medium hover:underline">
                              {svc.address}
                            </Link>
                            <span className="font-mono text-xs">
                              <EndpointLink address={svc.address} port={svc.port} url={svc.url} serviceName={svc.serviceName} tls={!!svc.tls} />
                            </span>
                            <span className="text-muted-foreground text-xs">
                              {svc.serviceName ?? 'unknown'} · zone {zoneLabel(svc.zone)}
                            </span>
                          </div>
                          <div className="text-muted-foreground text-xs">{svc.interestReasons?.slice(0, 3).join(' · ')}</div>
                        </div>
                      </li>
                    ))}
                  </ul>
                )
              }
            </Loadable>
          </CardContent>
        </Card>
      </div>

      <Card className="mb-6">
        <CardHeader>
          <CardTitle>
            <Link to="/changes" className="hover:underline">
              {t.dashboard.changesOverTime}
            </Link>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Loadable query={insights}>{(data) => <ChangesChart days={data.changesByDay} />}</Loadable>
        </CardContent>
      </Card>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>
              <Link to="/scans" className="hover:underline">
                {t.dashboard.recentScans}
              </Link>
            </CardTitle>
          </CardHeader>
          <CardContent>
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
                              <div className="text-muted-foreground text-xs">{t.dashboard.incompleteCoverage}</div>
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
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t.dashboard.runningScans}</CardTitle>
          </CardHeader>
          <CardContent>
            <Loadable query={running}>
              {(page) =>
                page.items.length === 0 ? (
                  <EmptyState>{t.dashboard.noRunning}</EmptyState>
                ) : (
                  <ul className="space-y-3" data-testid="running-scans">
                    {page.items.map((run) => (
                      <li key={run.id}>
                        <div className="mb-1 flex items-center justify-between gap-2 text-sm">
                          <Link to={`/scans/${run.id}`} className="font-medium hover:underline">
                            {run.name}
                          </Link>
                          <span className="text-muted-foreground text-xs">
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
          </CardContent>
        </Card>

        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>
              <Link to="/changes" className="hover:underline">
                {t.dashboard.latestChanges}
              </Link>
            </CardTitle>
          </CardHeader>
          <CardContent>
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
                          <TableCell className="text-xs whitespace-nowrap">
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
          </CardContent>
        </Card>
      </div>
    </>
  )
}
