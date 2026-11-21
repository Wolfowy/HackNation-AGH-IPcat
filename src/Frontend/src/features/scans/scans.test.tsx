import { act, screen, waitFor, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import type { ScanExecutionEvent, ScanStartRequest } from '@/api/types'
import { getDb } from '@/mocks/handlers'
import { server } from '@/mocks/node'
import { fakeHub } from '@/test/fakeSignalR'
import { renderApp } from '@/test/utils'

describe('start scan form', () => {
  it('submits the expected payload and opens the run', async () => {
    let payload: ScanStartRequest | undefined
    server.events.on('request:start', async ({ request }) => {
      if (request.method === 'POST' && new URL(request.url).pathname === '/api/scans') payload = (await request.clone().json()) as ScanStartRequest
    })
    const db = getDb()
    const { user, router } = renderApp('/scans/new', { role: 'Editor' })

    const name = await screen.findByLabelText('Name')
    await user.clear(name)
    await user.type(name, 'Ad-hoc DMZ check')
    await screen.findByRole('option', { name: /Quick port sweep/ })
    await user.selectOptions(screen.getByLabelText('Workflow'), 'quick-ports')
    await screen.findByRole('option', { name: 'v1' })
    await user.selectOptions(screen.getByLabelText('Version'), '1')
    await user.click(screen.getByRole('checkbox', { name: /DMZ public services/ }))
    await user.click(screen.getByRole('checkbox', { name: /^Lab/ }))
    await user.clear(screen.getByLabelText('Priority'))
    await user.type(screen.getByLabelText('Priority'), '80')
    await user.type(screen.getByLabelText('Rate cap (pps)'), '300')
    await user.type(screen.getByLabelText('Window (minutes)'), '90')
    await user.click(screen.getByRole('button', { name: 'Start scan' }))

    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/scans\/[0-9a-f-]{36}$/))
    expect(payload).toEqual({
      name: 'Ad-hoc DMZ check',
      workflowKey: 'quick-ports',
      workflowVersion: 1,
      networkIds: [db.networks[0].id, db.networks[2].id],
      priority: 80,
      maxRatePerSecond: 300,
      windowMinutes: 90,
    })
    server.events.removeAllListeners()
  })

  it('requires at least one network', async () => {
    const { user } = renderApp('/scans/new', { role: 'Editor' })
    await screen.findByRole('option', { name: /Quick port sweep/ })
    await user.selectOptions(screen.getByLabelText('Workflow'), 'quick-ports')
    await user.click(screen.getByRole('button', { name: 'Start scan' }))
    expect(await screen.findByText('Select at least one network.')).toBeInTheDocument()
  })
})

describe('scan detail live progress', () => {
  it('refreshes progress and the events log when a SignalR scanEvent arrives', async () => {
    const db = getDb()
    const run = db.runs.find((r) => r.status === 'Running')!
    const jobs = db.jobs.filter((j) => j.scanRunId === run.id)
    const { user } = renderApp(`/scans/${run.id}`, { role: 'Viewer' })

    const initial = Math.round((jobs.filter((j) => j.status === 'Completed').length / jobs.length) * 100)
    expect(await screen.findByTestId('scan-percent')).toHaveTextContent(`${initial}%`)
    await waitFor(() => expect(fakeHub.invocations).toContainEqual({ method: 'JoinRun', args: [run.id] }))

    // The backend completes every job, then pushes an event over the hub.
    jobs.forEach((j) => (j.status = 'Completed'))
    const event: ScanExecutionEvent = {
      eventId: 'evt-live-1',
      occurredAt: new Date().toISOString(),
      type: 'JobCompleted',
      scanRunId: run.id,
      stepId: 'ports',
      agentId: 'scanner-dmz-01',
      progress: 100,
    }
    act(() => fakeHub.emit('scanEvent', event))

    await waitFor(() => expect(screen.getByTestId('scan-percent')).toHaveTextContent('100%'), { timeout: 3000 })
    await user.click(screen.getByRole('tab', { name: 'Events' }))
    const log = await screen.findByTestId('events-log')
    expect(within(log).getAllByText('JobCompleted').length).toBeGreaterThan(0)
  })

  it('ignores events of other runs', async () => {
    const db = getDb()
    const run = db.runs.find((r) => r.status === 'Running')!
    let detailRequests = 0
    server.events.on('request:start', ({ request }) => {
      if (new URL(request.url).pathname === `/api/scans/${run.id}`) detailRequests++
    })
    renderApp(`/scans/${run.id}`, { role: 'Viewer' })
    await screen.findByTestId('scan-percent')
    const before = detailRequests
    act(() => fakeHub.emit('scanEvent', { eventId: 'x', occurredAt: new Date().toISOString(), type: 'AgentOnline', agentId: 'scanner-lab-02' }))
    await new Promise((r) => setTimeout(r, 600))
    expect(detailRequests).toBe(before)
    server.events.removeAllListeners()
  })

  it('maps a validation ProblemDetails from POST /api/scans onto the form', async () => {
    server.use(
      http.post('*/api/scans', () =>
        HttpResponse.json({ title: 'Validation failed', status: 400, errors: { Name: ['Name already used today.'] } }, { status: 400 }),
      ),
    )
    const { user } = renderApp('/scans/new', { role: 'Editor' })
    await screen.findByRole('option', { name: /Quick port sweep/ })
    await user.selectOptions(screen.getByLabelText('Workflow'), 'quick-ports')
    await user.click(await screen.findByRole('checkbox', { name: /DMZ public services/ }))
    await user.click(screen.getByRole('button', { name: 'Start scan' }))
    expect(await screen.findByText('Name already used today.')).toBeInTheDocument()
  })
})

describe('live progress outside the detail page', () => {
  const joined = () => fakeHub.invocations.filter((i) => i.method === 'JoinRun').map((i) => i.args[0])

  it.each(['/scans', '/'])('%s joins the hub group of every active run shown, and only those', async (path) => {
    const db = getDb()
    const live = db.runs.find((r) => r.status === 'Running')!
    renderApp(path, { role: 'Viewer' })
    await waitFor(() => expect(joined()).toEqual([live.id]))
  })

  it('leaves the run group once the run is no longer active', async () => {
    const db = getDb()
    const live = db.runs.find((r) => r.status === 'Running')!
    renderApp('/scans', { role: 'Viewer' })
    await waitFor(() => expect(joined()).toEqual([live.id]))
    live.status = 'Completed'
    act(() => fakeHub.emit('scanEvent', { eventId: 'done', occurredAt: new Date().toISOString(), type: 'RunCompleted', scanRunId: live.id }))
    await waitFor(() => expect(fakeHub.invocations).toContainEqual({ method: 'LeaveRun', args: [live.id] }), { timeout: 3000 })
  })
})

describe('scan jobs', () => {
  it('pages the jobs of a run and hides Retry when the run is finished', async () => {
    const db = getDb()
    const run = db.runs.find((r) => r.status === 'Failed')!
    const total = db.jobs.filter((j) => j.scanRunId === run.id).length
    let query = ''
    server.events.on('request:start', ({ request }) => {
      const url = new URL(request.url)
      if (url.pathname === `/api/scans/${run.id}/jobs`) query = url.search
    })
    const { user } = renderApp(`/scans/${run.id}`, { role: 'Editor' })
    await user.click(await screen.findByRole('tab', { name: 'Jobs' }))
    expect(await screen.findByText(`Page 1 of 1 · ${total} total`)).toBeInTheDocument()
    expect(query).toBe('?page=1&pageSize=100')
    expect(screen.getAllByTestId('job-row').some((row) => within(row).queryByText('Cancelled'))).toBe(true) // retryable status
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    server.events.removeAllListeners()
  })

  it('keeps Retry on the jobs page; the server answers 409 for a finished run', async () => {
    const conflicts: string[] = []
    server.events.on('response:mocked', async ({ request, response }) => {
      if (request.url.endsWith('/retry') && response.status === 409) conflicts.push(((await response.clone().json()) as { detail: string }).detail)
    })
    const { user } = renderApp('/jobs', { role: 'Editor' })
    await user.selectOptions(await screen.findByLabelText('Status'), 'Cancelled')
    await waitFor(() => expect(screen.getAllByTestId('job-row').every((row) => within(row).queryByText('Cancelled'))).toBe(true))
    await user.click(screen.getAllByRole('button', { name: 'Retry' })[0]) // mock data: cancelled jobs belong to finished runs
    // The app's MutationCache (not used by renderApp) toasts this detail.
    await waitFor(() => expect(conflicts).toEqual([expect.stringMatching(/^The scan run is already (Failed|WindowExpired)\.$/)]))
    server.events.removeAllListeners()
  })
})
