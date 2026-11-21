import { screen, waitFor, within } from '@testing-library/react'
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
})
