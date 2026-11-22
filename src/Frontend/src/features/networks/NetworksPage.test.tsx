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

describe('scope policy ports', () => {
  it('lets administrators restrict ports, with format hints', async () => {
    const { user } = renderApp('/networks', { role: 'Administrator' })
    await user.click(await screen.findByRole('tab', { name: 'Scope policy' }))
    const allowed = await screen.findByLabelText('Allowed ports')
    expect(screen.getByLabelText('Excluded ports')).toHaveValue('23')
    expect(screen.getByText(/Empty = every port/)).toBeInTheDocument()

    await user.type(allowed, '443{enter}9000-8000{enter}70000')
    expect(await screen.findByText(/"9000-8000": range start is after its end; "70000": ports are 1–65535/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save scope policy' })).toBeDisabled()

    await user.clear(allowed)
    await user.type(allowed, '443{enter}8000-8100')
    await user.click(screen.getByRole('button', { name: 'Save scope policy' }))
    expect((await screen.findAllByText('Saved')).length).toBeGreaterThan(0)
    expect(await screen.findByLabelText('Allowed ports')).toHaveValue('443\n8000-8100')
  })

  it('shows the port lists read-only to managers', async () => {
    const { user } = renderApp('/networks', { role: 'Manager' })
    await user.click(await screen.findByRole('tab', { name: 'Scope policy' }))
    expect(await screen.findByLabelText('Allowed ports')).toHaveAttribute('readonly')
    expect(screen.queryByRole('button', { name: 'Save scope policy' })).not.toBeInTheDocument()
  })
})

describe('agent subnets', () => {
  async function openTab(role: 'Manager' | 'Administrator') {
    const app = renderApp('/networks', { role })
    await app.user.click(await screen.findByRole('tab', { name: 'Agent subnets' }))
    await screen.findByLabelText('Select 10.10.8.0/23')
    return app
  }

  it('preselects attached subnets inside the policy and creates networks from them', async () => {
    const { user } = await openTab('Manager')
    expect(screen.getByLabelText('Select 10.10.8.0/23')).toBeChecked()
    expect(screen.getByLabelText('Select 10.99.0.0/24')).not.toBeChecked() // the agent's link to the server
    expect(screen.getByLabelText('Select 10.10.0.0/24')).toBeDisabled() // already covered
    expect(screen.getByText('covered by DMZ public services')).toBeInTheDocument()

    // A routed subnet of a multi-zone agent needs a zone before it can be selected.
    expect(screen.getByLabelText('Select 10.40.0.0/16')).toBeDisabled()
    await user.selectOptions(screen.getByLabelText('Zone for 10.40.0.0/16'), 'office')
    await user.click(screen.getByLabelText('Select 10.40.0.0/16'))

    await user.click(screen.getByRole('button', { name: 'Create 2 networks' }))
    expect(await screen.findByText('covered by dmz 10.10.8.0/23')).toBeInTheDocument()
    expect(screen.getByText('covered by office 10.40.0.0/16')).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: 'Networks' }))
    expect(await screen.findByText('dmz 10.10.8.0/23')).toBeInTheDocument()
  })

  it('lets only administrators widen the scope policy, after a confirmation', async () => {
    const { user } = await openTab('Administrator')
    const row = screen.getByText('100.64.0.0/22').closest('tr')! // not proposed yet: only the subnet column shows it
    expect(within(row).getByText('outside')).toBeInTheDocument()
    await user.click(within(row).getByRole('button', { name: 'Add to scope policy' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/Only allow networks you are authorized to scan/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Add to scope policy' }))
    expect(await within(row).findByText('inside')).toBeInTheDocument()
    expect(within(row).getAllByText('100.64.0.0/22')).toHaveLength(2) // now also the range to create
  })

  it('hides the scope action from managers', async () => {
    await openTab('Manager')
    expect(screen.queryByRole('button', { name: 'Add to scope policy' })).not.toBeInTheDocument()
  })
})
