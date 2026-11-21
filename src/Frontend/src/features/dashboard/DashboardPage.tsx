import { Link } from 'react-router'
import type { ReactNode } from 'react'
import { useAgents } from '@/api/agents'
import { useChanges, useDashboardSummary } from '@/api/assets'
import { useJoinActiveRuns } from '@/api/scanHub'
import { useScans } from '@/api/scans'
import { EmptyState, Loadable } from '@/components/feedback'
import { PageHeader, ProgressCell, StatusBadge } from '@/components/page'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatNumber, formatRelative } from '@/lib/format'

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
  const s = summary.data
  const online = agents.data?.filter((a) => a.isOnline).length

  return (
    <>
      <PageHeader title={t.dashboard.title} description={s?.lastScanAt && `${t.dashboard.lastScan}: ${formatRelative(s.lastScanAt)}`} />
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard label={t.dashboard.hosts} value={formatNumber(s?.hostsTotal)} sub={s && t.dashboard.activeHosts(s.hostsActive)} to="/assets/hosts" />
        <StatCard label={t.dashboard.services} value={formatNumber(s?.servicesTotal)} to="/assets/services" />
        <StatCard label={t.dashboard.changes24h} value={formatNumber(s?.changesLast24h)} to="/changes" />
        <StatCard label={t.dashboard.openFindings} value={formatNumber(s?.findingsOpen)} to="/findings" />
        <StatCard
          label={t.dashboard.agentsOnline}
          value={agents.data ? `${online}/${agents.data.length}` : '—'}
          to="/agents"
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
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

        <Card>
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
                        <TableHead>Summary</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {page.items.map((c) => (
                        <TableRow key={c.id}>
                          <TableCell className="text-muted-foreground whitespace-nowrap">{formatRelative(c.detectedAt)}</TableCell>
                          <TableCell>
                            <StatusBadge status={c.type} />
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
