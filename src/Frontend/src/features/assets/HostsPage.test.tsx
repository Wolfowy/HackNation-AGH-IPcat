import { screen, waitFor, within } from '@testing-library/react'
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

  it('badges network device interfaces (amber for a locally administered MAC) and filters to them', async () => {
    const { user } = renderApp('/assets/hosts', { role: 'Viewer' })
    await screen.findAllByTestId('host-row')
    const row = (address: string) => screen.getAllByTestId('host-row').find((r) => within(r).queryByRole('link', { name: address }))!

    // Seeded: a router MAC in office + lab (high), a Docker MAC in office + lab (low), a MAC on two office IPs (shared only).
    expect(screen.getAllByTestId('network-device-badge')).toHaveLength(4)
    expect(within(row('192.168.10.1')).getByTestId('network-device-badge')).toHaveAttribute('title', expect.stringContaining('one network device'))
    expect(within(row('172.16.50.251')).getByTestId('network-device-badge')).toHaveAttribute('title', expect.stringContaining('coincidence'))
    expect(within(row('192.168.10.252')).queryByTestId('network-device-badge')).not.toBeInTheDocument()

    await user.click(screen.getByLabelText('Only network devices'))
    await waitFor(() => expect(screen.getAllByTestId('host-row')).toHaveLength(4))
    expect(screen.getAllByTestId('host-row').map((r) => within(r).getByRole('link').textContent)).toEqual([
      '172.16.50.1',
      '172.16.50.251',
      '192.168.10.1',
      '192.168.10.251',
    ])
  })
})
