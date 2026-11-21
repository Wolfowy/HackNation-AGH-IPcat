import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { getDb } from '@/mocks/handlers'
import { renderApp } from '@/test/utils'

describe('inventory graph', () => {
  it('renders network, host and port cards from the topology endpoint', async () => {
    const { user, router } = renderApp('/assets/graph', { role: 'Viewer' })
    const db = getDb()
    const host = db.hosts.find((h) => h.status === 'Active' && db.services.some((s) => s.hostId === h.id && s.url))!
    const service = db.services.find((s) => s.hostId === host.id && s.url)!

    expect(await screen.findByRole('heading', { name: 'Inventory graph' })).toBeInTheDocument()
    expect(await screen.findAllByTestId('graph-network')).toHaveLength(3)
    // 42 seeded hosts (<= 50): ports start expanded.
    expect(screen.getAllByTestId('graph-host')).toHaveLength(db.hosts.length)
    expect(screen.getAllByTestId('graph-port')).toHaveLength(db.services.filter((s) => s.state === 'Open').length)

    // React Flow keeps nodes visibility:hidden until measured (never in jsdom), so query by test id rather than accessible name.
    const link = screen.getAllByTestId('endpoint-link').find((a) => a.textContent === `${host.address}:${service.port}`)!
    expect(link).toHaveAttribute('href', service.url)
    expect(link).toHaveAttribute('target', '_blank')

    const hostCard = () => screen.getByText(host.address, { selector: '[data-testid="graph-host"] span' }).closest('[data-testid="graph-host"]') as HTMLElement
    fireEvent.click(within(hostCard()).getByText('hide'))
    await waitFor(() => expect(screen.getAllByTestId('graph-port').length).toBeLessThan(db.services.filter((s) => s.state === 'Open').length))

    await user.click(screen.getByLabelText('Only hosts with open ports'))
    await waitFor(() => expect(screen.getAllByTestId('graph-host')).toHaveLength(db.hosts.filter((h) => h.openPortCount > 0).length))

    // Graph canvas clicks via fireEvent: d3-zoom's mousedown handler needs `event.view`, which user-event leaves null in jsdom.
    fireEvent.click(hostCard())
    await waitFor(() => expect(router.state.location.pathname).toBe(`/assets/hosts/${host.id}`))
  })
})
