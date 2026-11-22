import { fireEvent, screen, within } from '@testing-library/react'
import { getDb } from '@/mocks/handlers'
import { renderApp } from '@/test/utils'

describe('topology map', () => {
  it('shows devices, zones, perspectives, subnets and hosts; host and device clicks open their panels', async () => {
    renderApp('/topology', { role: 'Viewer' })
    const db = getDb()
    const host = db.hosts.find((h) => h.status === 'Active' && db.services.some((s) => s.hostId === h.id && s.url))!
    const service = db.services.find((s) => s.hostId === host.id && s.url)!

    expect(await screen.findAllByTestId('topology-perspective')).toHaveLength(3)
    // dmz, office, lab + the lab's reuse of the DMZ range: subnets are per zone.
    expect(screen.getAllByTestId('topology-subnet')).toHaveLength(4)
    expect(screen.getAllByTestId('topology-host')).toHaveLength(db.hosts.length)
    const twin = db.hosts.find((h) => h.zone === 'lab' && h.address.startsWith('10.10.0.'))!
    const dmzCidr = twin.address.replace(/\.\d+$/, '.0/24')
    expect(screen.getAllByText(twin.address, { selector: '[data-testid="topology-host"] div' })).toHaveLength(2)
    expect(screen.getAllByTestId('topology-subnet').map((n) => n.textContent)).toEqual(
      expect.arrayContaining([expect.stringContaining(`dmz · ${dmzCidr}`), expect.stringContaining(`lab · ${dmzCidr}`)]),
    )
    expect(screen.getByTestId('graph-legend')).toHaveTextContent('Unreachable')
    expect(screen.getByTestId('graph-legend')).toHaveTextContent('Network device')

    // Zones are address spaces; devices (one MAC in several zones) link them.
    expect(screen.getAllByTestId('topology-zone').map((n) => n.textContent)).toEqual([
      expect.stringContaining('dmz'),
      expect.stringContaining('lab'),
      expect.stringContaining('office'),
    ])
    const devices = screen.getAllByTestId('topology-device')
    expect(devices.map((n) => n.textContent)).toEqual([
      " 00:1E:BD:4A:10:01Cisco Systems · 2 zones",
      " 02:42:AC:11:00:02Unknown vendor · 2 zones · low confidence",
    ])
    expect(devices[1]).toHaveAttribute('title', expect.stringContaining('may be a coincidence'))
    fireEvent.click(devices[0])
    const devicePanel = await screen.findByTestId('topology-device-panel')
    const labRouter = db.hosts.find((h) => h.address === '172.16.50.1')!
    expect(within(devicePanel).getByRole('link', { name: '172.16.50.1' })).toHaveAttribute('href', `/assets/hosts/${labRouter.id}`)
    fireEvent.click(within(devicePanel).getByRole('button', { name: 'Close device panel' }))
    expect(screen.queryByTestId('topology-device-panel')).not.toBeInTheDocument()

    // fireEvent: d3-zoom's mousedown handler needs `event.view`, which user-event leaves null in jsdom.
    fireEvent.click(screen.getByText(host.address, { selector: '[data-testid="topology-host"] div' }))
    const panel = await screen.findByTestId('topology-host-panel')
    const link = within(panel).getByRole('link', { name: `${host.address}:${service.port}` })
    expect(link).toHaveAttribute('href', service.url)
    expect(link).toHaveAttribute('target', '_blank')
    expect(within(panel).getByRole('link', { name: /Open host details/ })).toHaveAttribute('href', `/assets/hosts/${host.id}`)

    // Clicking a subnet collapses its hosts.
    const subnet = screen.getAllByTestId('topology-subnet')[0]
    const before = screen.getAllByTestId('topology-host').length
    fireEvent.click(subnet)
    expect(await screen.findAllByTestId('topology-host')).not.toHaveLength(before)
  })
})
