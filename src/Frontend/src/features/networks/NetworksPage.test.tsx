import { screen, within } from '@testing-library/react'
import { renderApp } from '@/test/utils'

async function openCreateDialog() {
  const app = renderApp('/networks', { role: 'Manager' })
  await app.user.click(await screen.findByRole('button', { name: /create network/i }))
  return { ...app, dialog: await screen.findByRole('dialog') }
}

describe('network form', () => {
  it('validates required fields and range formats on the client', async () => {
    const { user, dialog } = await openCreateDialog()
    await user.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect(await within(dialog).findByText('Name is required.')).toBeInTheDocument()
    expect(within(dialog).getByText('Zone is required.')).toBeInTheDocument()
    expect(within(dialog).getByText('At least one entry is required.')).toBeInTheDocument()

    await user.type(within(dialog).getByLabelText('Ranges'), '10.0.0.300/24{enter}10.0.0.9-10.0.0.1')
    await user.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect(await within(dialog).findByText(/"10\.0\.0\.300\/24": invalid CIDR address; "10\.0\.0\.9-10\.0\.0\.1": range start is after its end/)).toBeInTheDocument()
    expect(within(dialog).getByLabelText('Ranges')).toHaveAttribute('aria-invalid', 'true')
  })

  it('shows server-side ProblemDetails errors on the matching field', async () => {
    const { user, dialog } = await openCreateDialog()
    await user.type(within(dialog).getByLabelText('Name'), 'Public range')
    await user.selectOptions(within(dialog).getByLabelText('Zone'), 'dmz')
    await user.type(within(dialog).getByLabelText('Ranges'), '8.8.8.0/24')
    await user.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect(await within(dialog).findByText('8.8.8.0/24 is outside the global scope policy.')).toBeInTheDocument()
  })

  it('creates a valid network', async () => {
    const { user, dialog } = await openCreateDialog()
    await user.type(within(dialog).getByLabelText('Name'), 'Branch office')
    await user.selectOptions(within(dialog).getByLabelText('Zone'), 'office')
    await user.type(within(dialog).getByLabelText('Ranges'), '10.30.0.0/24{enter}10.30.1.10-10.30.1.20')
    await user.type(within(dialog).getByLabelText('Tags'), 'branch, wifi')
    await user.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Branch office')).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})
