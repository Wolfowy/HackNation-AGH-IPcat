import { screen, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import type { DashboardInsights } from '@/api/types'
import { server } from '@/mocks/node'
import { renderApp } from '@/test/utils'

const insights: DashboardInsights = {
  topFindings: [
    {
      id: 'f1', signatureId: 'mysql-exposed', name: 'MySQL reachable from DMZ', severity: 'high', hostId: 'h1', zone: 'dmz', address: '10.10.0.7',
      port: 3306, matchedAt: new Date().toISOString(), status: 'Open', firstSeenAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(),
      externalRefs: [], triage: 'None', effectiveSeverity: 'high', userTags: [],
    },
  ],
  topServices: [
    {
      id: 's1', hostId: 'h1', zone: 'dmz', address: '10.10.0.7', port: 3306, transport: 'Tcp', state: 'Open', serviceName: 'mysql', technologies: [],
      firstSeenAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), interestScore: 50,
      interestReasons: ['Open high finding: MySQL reachable from DMZ', 'MySQL exposed on port 3306'],
    },
  ],
  changesByDay: [
    { date: '2026-11-21', total: 0, byType: {} },
    { date: '2026-11-22', total: 3, byType: { NewHost: 1, NewPort: 1, TimeOfDayVariance: 1 } },
  ],
  recentScans: [
    {
      id: 'r1', name: 'Nightly DMZ', status: 'Completed', workflowKey: 'standard-discovery', createdAt: new Date().toISOString(),
      startedAt: new Date(Date.now() - 125_000).toISOString(), finishedAt: new Date().toISOString(), durationSeconds: 125, coverageComplete: true,
      changesDetected: 3,
    },
  ],
  unstableHosts: 2,
  timeOfDayVarianceServices: 1,
}

describe('dashboard insights', () => {
  it('shows the most important findings, interesting services, changes over time and recent scans', async () => {
    server.use(http.get('*/api/dashboard/insights', () => HttpResponse.json(insights)))
    renderApp('/', { role: 'Viewer' })

    const findings = await screen.findByTestId('top-findings')
    expect(within(findings).getByText('MySQL reachable from DMZ')).toBeInTheDocument()
    expect(within(findings).getByText('high')).toBeInTheDocument()

    const services = screen.getByTestId('top-services')
    expect(within(services).getByTestId('interest-badge')).toHaveTextContent('50')
    expect(services).toHaveTextContent('Open high finding: MySQL reachable from DMZ · MySQL exposed on port 3306')

    const chart = screen.getByTestId('changes-chart')
    expect(within(chart).getByRole('table', { hidden: true })).toHaveTextContent('2026-11-22') // screen-reader table view
    expect(chart).toHaveTextContent('Added2') // legend totals: NewHost + NewPort
    expect(chart).toHaveTextContent('Time of day1')

    const scans = screen.getByTestId('recent-scans')
    expect(within(scans).getByRole('link', { name: 'Nightly DMZ' })).toHaveAttribute('href', '/scans/r1')
    expect(scans).toHaveTextContent('2m 5s')
    expect(await screen.findByText(/2 unstable/)).toBeInTheDocument()
    expect(screen.getByText('1 vary by time of day')).toBeInTheDocument()
  })

  it('works against the mock backend', async () => {
    renderApp('/', { role: 'Viewer' })
    expect(await screen.findByTestId('top-services')).toBeInTheDocument()
    expect(screen.getAllByTestId('interest-badge').length).toBeGreaterThan(0)
    expect(screen.getByText('Changes over time (14 days)')).toBeInTheDocument()
  })
})
