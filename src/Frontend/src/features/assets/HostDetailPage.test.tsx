import { screen, within } from '@testing-library/react'
import { getDb } from '@/mocks/handlers'
import { renderApp } from '@/test/utils'

describe('host detail', () => {
  it("lists the same device's interfaces in other zones", async () => {
    const hosts = getDb().hosts
    const office = hosts.find((h) => h.address === '192.168.10.1')!
    const lab = hosts.find((h) => h.address === '172.16.50.1')!
    renderApp(`/assets/hosts/${office.id}`, { role: 'Viewer' })

    const section = await screen.findByTestId('device-interfaces')
    expect(section).toHaveTextContent('Same device in other zones')
    expect(within(section).getByRole('link', { name: '172.16.50.1' })).toHaveAttribute('href', `/assets/hosts/${lab.id}`)
    expect(section).toHaveTextContent('zone lab')
    expect(screen.getByTestId('network-device-badge')).toBeInTheDocument()
  })

  it('explains interest and shows per-hour availability and time-of-day responses', async () => {
    const service = getDb().services.find((s) => s.timeOfDayVariance)!
    renderApp(`/assets/hosts/${service.hostId}`, { role: 'Viewer' })

    const section = await screen.findByTestId('time-of-day')
    expect(within(section).getByRole('img', { name: /Availability by hour of day \(UTC\), scanned in 2 of 24 hours/ })).toBeInTheDocument()
    expect(within(section).getByRole('img', { name: 'HTTP response by hour of day (UTC)' })).toBeInTheDocument()
    expect(section).toHaveTextContent("503 'Maintenance'")
    expect(within(section).getAllByTestId('hour-cell')[24 + 2]).toHaveAttribute('title', "02:00–03:00 UTC: 503 'Maintenance' (6 observations)")
    expect(screen.getByTestId('host-interest')).toBeInTheDocument()
    expect(screen.getAllByTestId('interest-badge').some((b) => b.title.includes('Responds differently by time of day'))).toBe(true)
    expect(screen.getAllByText('time of day').length).toBeGreaterThan(0) // badges in the header and the services table
  })

  it('has no device section for a MAC shared only within one zone', async () => {
    const alias = getDb().hosts.find((h) => h.address === '192.168.10.252')!
    renderApp(`/assets/hosts/${alias.id}`, { role: 'Viewer' })

    expect(await screen.findByRole('tab', { name: /Services/ })).toBeInTheDocument()
    expect(screen.queryByTestId('device-interfaces')).not.toBeInTheDocument()
    expect(screen.queryByTestId('network-device-badge')).not.toBeInTheDocument()
  })
})
