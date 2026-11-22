import { screen, within } from '@testing-library/react'
import { getDb } from '@/mocks/handlers'
import { renderApp } from '@/test/utils'

describe('service detail', () => {
  it('shows interesting headers highlighted, cookie flags and artifacts', async () => {
    const service = getDb().services.find((s) => s.artifactTags?.includes('internal-ip-leak'))!
    renderApp(`/assets/services/${service.id}`, { role: 'Viewer' })

    const artifacts = await screen.findByTestId('artifacts-section')
    expect(within(artifacts).getAllByTestId('artifact-row')).toHaveLength(3)
    expect(artifacts).toHaveTextContent('internal pool member 10.20.30.41:8080')

    const backend = within(screen.getByTestId('headers-section')).getByText('x-backend-server').closest('tr')!
    expect(backend).toHaveAttribute('data-interesting', 'true')
    expect(backend).toHaveTextContent('Discloses the backend server behind the proxy')
    const server = within(screen.getByTestId('headers-section')).getByText('server').closest('tr')!
    expect(server).not.toHaveAttribute('data-interesting')

    const bigip = within(screen.getByTestId('cookies-section')).getByText('BIGipServerpool_app').closest('tr')!
    expect(within(bigip).getByText('HttpOnly')).toBeInTheDocument()
    expect(within(bigip).getByText('no Secure')).toBeInTheDocument()
    expect(bigip).toHaveTextContent('10.20.30.41:8080')
  })

  it('shows the recog device classification, page type and redirect chain of an IoT device', async () => {
    const camera = getDb().services.find((s) => s.deviceType === 'IP Camera')!
    renderApp(`/assets/services/${camera.id}`, { role: 'Viewer' })

    expect(await screen.findByTestId('device-badge')).toHaveTextContent('IP Camera')
    expect(screen.getByTestId('redirect-chain')).toHaveTextContent('/doc/page/login.asp (200)')
    expect(within(screen.getByTestId('http-section')).getByText('login')).toBeInTheDocument()
    expect(screen.getByText('Hikvision DS-2CD2143G0-I')).toBeInTheDocument()
    expect(screen.getByText('recog')).toBeInTheDocument()
  })

  it('is linked from the services table, which shows artifact badges', async () => {
    const service = getDb().services.find((s) => s.artifactTags?.includes('insecure-cookie'))!
    const { user, router } = renderApp(`/assets/hosts/${service.hostId}`, { role: 'Viewer' })

    const row = (await screen.findAllByTestId('service-row')).find((r) => within(r).queryByText(service.serviceName!) && r.textContent?.includes(String(service.port)))!
    expect(within(row).getByText('insecure-cookie')).toBeInTheDocument()
    await user.click(within(row).getByRole('link', { name: service.serviceName }))
    expect(router.state.location.pathname).toBe(`/assets/services/${service.id}`)
    expect(await screen.findByTestId('artifacts-section')).toBeInTheDocument()
  })
})
