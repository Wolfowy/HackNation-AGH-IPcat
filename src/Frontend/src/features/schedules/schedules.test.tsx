import { screen, within } from '@testing-library/react'
import { renderApp } from '@/test/utils'

describe('schedule form', () => {
  it('creates a schedule with a time zone and networks picked from the searchable list', async () => {
    const { user } = renderApp('/schedules', { role: 'Manager' })
    await user.click(await screen.findByRole('button', { name: 'Create schedule' }))
    const dialog = await screen.findByRole('dialog')

    await user.type(within(dialog).getByLabelText('Name'), 'Nightly office sweep')
    await user.selectOptions(within(dialog).getByLabelText('Time zone'), 'Europe/Warsaw')
    await within(dialog).findByRole('option', { name: /Standard discovery/ })
    await user.selectOptions(within(dialog).getByLabelText('Workflow'), 'standard-discovery')

    await user.click(within(dialog).getByRole('button', { name: /Save|Create/ }))
    expect(await within(dialog).findByText('Select at least one network.')).toBeInTheDocument()

    await user.type(within(dialog).getByRole('combobox', { name: 'Search networks' }), 'office{enter}')
    await user.click(within(dialog).getByRole('button', { name: /Save|Create/ }))

    expect(await screen.findByText('Nightly office sweep')).toBeInTheDocument()
    expect(screen.getAllByText('Europe/Warsaw').length).toBeGreaterThan(0)
  })
})
