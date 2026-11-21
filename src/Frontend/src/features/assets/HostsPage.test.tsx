import { screen, within } from '@testing-library/react'
import { getDb } from '@/mocks/handlers'
import { renderApp } from '@/test/utils'

describe('hosts list', () => {
  it('shows zone and MAC; the same IP in two zones is two hosts; group by zone adds zone headers', async () => {
    const { user } = renderApp('/assets/hosts', { role: 'Viewer' })
    const twin = getDb().hosts.find((h) => h.zone === 'lab' && h.address.startsWith('10.10.0.'))!

    const rows = await screen.findAllByTestId('host-row')
    const twins = rows.filter((r) => within(r).queryByRole('link', { name: twin.address }))
    expect(twins.map((r) => within(r).getAllByRole('cell')[0].textContent)).toEqual(['dmz', 'lab'])
    expect(within(twins[1]).getByRole('link')).toHaveAttribute('href', `/assets/hosts/${twin.id}`)
    expect(twins[1]).toHaveTextContent('52:54:00:AB:CD:EF')
    expect(twins[1]).toHaveTextContent('QEMU virtual NIC')

    expect(screen.queryByTestId('zone-group')).not.toBeInTheDocument()
    await user.click(screen.getByLabelText('Group by zone'))
    expect(screen.getAllByTestId('zone-group').map((r) => r.textContent)).toEqual(['Zone dmz', 'Zone lab', 'Zone office'])
  })
})
