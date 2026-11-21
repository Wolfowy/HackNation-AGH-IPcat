import { screen, waitFor, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { server } from '@/mocks/node'
import { getDb } from '@/mocks/handlers'
import { renderApp } from '@/test/utils'

// Behaviour that depends on the exact backend contract (upsert/null-delete settings, revoked tokens, approval notes).
describe('backend contracts', () => {
  it('deletes a removed setting by sending it as null', async () => {
    const { user } = renderApp('/admin/settings', { role: 'Administrator' })
    await user.click(await screen.findByRole('button', { name: 'Remove Retention:ObservationDays' }))
    await user.click(screen.getByRole('button', { name: 'Save settings' }))
    await waitFor(() => expect(getDb().settings).not.toHaveProperty('Retention:ObservationDays'))
    expect(getDb().settings).toHaveProperty('Discovery:MissingThreshold', '3')
  })

  it('marks revoked enrollment tokens and hides their Revoke button', async () => {
    const { user } = renderApp('/agents', { role: 'Administrator' })
    await user.click(await screen.findByRole('tab', { name: /enrollment tokens/i }))
    const revoked = (await screen.findByText('old office batch')).closest('tr')!
    expect(within(revoked).getByText('Revoked')).toBeInTheDocument()
    expect(within(revoked).queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument()
    const active = screen.getByText('lab rollout').closest('tr')!
    expect(within(active).getByRole('button', { name: 'Revoke' })).toBeInTheDocument()
  })

  it('requires an approval note for high-severity signatures', async () => {
    const { user } = renderApp('/signatures/mysql-exposed', { role: 'Administrator' })
    await user.click(await screen.findByRole('button', { name: 'Approve v1' }))
    const dialog = await screen.findByRole('dialog')
    const submit = within(dialog).getByRole('button', { name: 'Approve' })
    expect(submit).toBeDisabled()
    await user.type(within(dialog).getByLabelText('Approval note'), 'Accepted risk, ticket SEC-42')
    await user.click(submit)
    await waitFor(() => expect(getDb().signatures.find((s) => s.id === 'mysql-exposed')?.versions[0].approvalNote).toBe('Accepted risk, ticket SEC-42'))
  })

  it('stays on the schedules page with a toast when a manual trigger is queued', async () => {
    const db = getDb()
    const schedule = db.schedules.find((s) => s.overlapPolicy === 'Queue')!
    const live = db.runs.find((r) => r.status === 'Running')!
    schedule.lastRunId = live.id
    const { user, router } = renderApp('/schedules', { role: 'Editor' })
    const row = (await screen.findByText(schedule.name)).closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'Run now' }))
    expect(await screen.findByText(`Queued: Queued behind run ${live.id}`)).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/schedules')
  })

  it('opens the run started by a manual trigger', async () => {
    const schedule = getDb().schedules.find((s) => s.overlapPolicy === 'Queue')!
    const { user, router } = renderApp('/schedules', { role: 'Editor' })
    const row = (await screen.findByText(schedule.name)).closest('tr')!
    await user.click(within(row).getByRole('button', { name: 'Run now' }))
    await waitFor(() => expect(router.state.location.pathname).toMatch(/^\/scans\/[0-9a-f-]{36}$/))
  })

  it('rejects 5-field cron expressions (Quartz needs seconds)', async () => {
    const { user } = renderApp('/schedules', { role: 'Manager' })
    await user.click(await screen.findByRole('button', { name: 'Create schedule' }))
    const cron = await screen.findByLabelText('Cron expression')
    await user.clear(cron)
    await user.type(cron, '0 2 * * *')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/Cron needs 6–7 fields/)).toBeInTheDocument()
  })

  it('validates scan limits with the backend ranges and maps field-keyed server errors', async () => {
    const { user } = renderApp('/admin/settings', { role: 'Administrator' })
    const lease = await screen.findByLabelText('Lease duration (s)')
    await user.clear(lease)
    await user.type(lease, '20')
    const attempts = screen.getByLabelText('Max attempts per job')
    await user.clear(attempts)
    await user.type(attempts, '11')
    await user.click(screen.getByRole('button', { name: 'Save limits' }))
    expect(await screen.findByText('Min 30')).toBeInTheDocument()
    expect(screen.getByText('Max 10')).toBeInTheDocument()

    await user.clear(lease)
    await user.type(lease, '600')
    await user.clear(attempts)
    await user.type(attempts, '5')
    await user.click(screen.getByRole('button', { name: 'Save limits' }))
    await waitFor(() => expect(getDb().scanLimits).toMatchObject({ leaseDurationSeconds: 600, maxAttempts: 5 }))

    server.use(
      http.put('*/api/scan-limits', () =>
        HttpResponse.json({ status: 422, title: 'One or more validation errors occurred.', errors: { subnetPrefixLength: ['subnetPrefixLength must be between 8 and 32.'] } }, { status: 422 }),
      ),
    )
    await user.click(screen.getByRole('button', { name: 'Save limits' }))
    expect(await screen.findByText('subnetPrefixLength must be between 8 and 32.')).toBeInTheDocument()
  })
})
