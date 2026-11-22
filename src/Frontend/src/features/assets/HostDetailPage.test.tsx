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

  it('has no device section for a MAC shared only within one zone', async () => {
    const alias = getDb().hosts.find((h) => h.address === '192.168.10.252')!
    renderApp(`/assets/hosts/${alias.id}`, { role: 'Viewer' })

    expect(await screen.findByRole('tab', { name: /Services/ })).toBeInTheDocument()
    expect(screen.queryByTestId('device-interfaces')).not.toBeInTheDocument()
    expect(screen.queryByTestId('network-device-badge')).not.toBeInTheDocument()
  })
})
