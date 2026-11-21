import { screen, within } from '@testing-library/react'
import { renderApp } from '@/test/utils'

describe('role-gated UI', () => {
  it('redirects anonymous users to the login page', async () => {
    renderApp('/networks')
    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument()
  })

  it('hides "Create network" and import from a Viewer', async () => {
    renderApp('/networks', { role: 'Viewer' })
    expect(await screen.findByText('DMZ public services')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /create network/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /import networks/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^edit$/i })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /export csv/i })).toBeInTheDocument()
  })

  it('shows "Create network" to a Manager', async () => {
    renderApp('/networks', { role: 'Manager' })
    expect(await screen.findByRole('button', { name: /create network/i })).toBeInTheDocument()
  })

  it('hides admin navigation from a Viewer and blocks admin routes', async () => {
    renderApp('/admin/users', { role: 'Viewer' })
    expect(await screen.findByTestId('forbidden')).toBeInTheDocument()
    const nav = screen.getByRole('navigation', { name: 'Main' })
    expect(within(nav).queryByRole('link', { name: /users/i })).not.toBeInTheDocument()
    expect(within(nav).getByRole('link', { name: /hosts/i })).toBeInTheDocument()
  })

  it('lets an Administrator open the users page', async () => {
    renderApp('/admin/users', { role: 'Administrator' })
    expect(await screen.findByRole('heading', { name: 'Users' })).toBeInTheDocument()
    expect(await screen.findByText('Wiktor Viewer')).toBeInTheDocument()
    expect(within(screen.getByRole('navigation', { name: 'Main' })).getByRole('link', { name: /audit log/i })).toBeInTheDocument()
  })

  it('shows enrollment tokens and tool approval only to administrators', async () => {
    const { unmount } = renderApp('/agents', { role: 'Editor' })
    expect(await screen.findByText('dmz-scan-01')).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: /enrollment tokens/i })).not.toBeInTheDocument()
    unmount()
    renderApp('/agents', { role: 'Administrator' })
    expect(await screen.findByRole('tab', { name: /enrollment tokens/i })).toBeInTheDocument()
  })
})
