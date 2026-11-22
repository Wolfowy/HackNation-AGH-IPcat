import { screen, waitFor, within } from '@testing-library/react'
import { getDb } from '@/mocks/handlers'
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
    expect(getDb().schedules.find((s) => s.name === 'Nightly office sweep')?.resumeInNextWindow).toBe(true) // on by default
  }, 15_000) // the dialog (time zone list, estimate) is slow in jsdom under load

  it('turns resume-in-next-window off and compares the estimate with the run window', async () => {
    const { user } = renderApp('/schedules', { role: 'Manager' })
    await user.click(await screen.findByRole('button', { name: 'Create schedule' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('Name'), 'Short window sweep')
    await within(dialog).findByRole('option', { name: /Standard discovery/ })
    await user.selectOptions(within(dialog).getByLabelText('Workflow'), 'standard-discovery')
    await user.type(within(dialog).getByRole('combobox', { name: 'Search networks' }), 'DMZ public{enter}')
    await user.type(within(dialog).getByLabelText('Run window (minutes)'), '1')

    const estimate = await within(dialog).findByRole('region', { name: 'Scan estimate' })
    await waitFor(() => expect(estimate).toHaveTextContent('longer than the 1-minute window'))

    const resume = within(dialog).getByRole('checkbox', { name: 'Resume in the next window' })
    expect(resume).toBeChecked()
    await user.click(resume)
    await user.click(within(dialog).getByRole('button', { name: /Save|Create/ }))
    await waitFor(() => expect(getDb().schedules.find((s) => s.name === 'Short window sweep')?.resumeInNextWindow).toBe(false))
  }, 15_000)

  it('shows a pending resume in the list', async () => {
    renderApp('/schedules', { role: 'Viewer' })
    const row = (await screen.findByText('Nightly DMZ discovery')).closest('tr')!
    expect(within(row).getByText(/^Resume pending at/)).toBeInTheDocument()
  })
})
