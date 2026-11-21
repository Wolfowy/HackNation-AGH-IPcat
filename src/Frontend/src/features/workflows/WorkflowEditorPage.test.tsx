import { screen, waitFor } from '@testing-library/react'
import { getDb } from '@/mocks/handlers'
import { renderApp } from '@/test/utils'

describe('workflow editor page', () => {
  it('starts from a template copy and saves it as a new workflow', async () => {
    const { user, router } = renderApp('/workflows/new', { role: 'Manager' })
    await user.click(await screen.findByRole('link', { name: /Copy of Standard discovery/ }))

    expect(await screen.findByLabelText('Key')).toHaveValue('standard-discovery-copy')
    expect(screen.getByRole('button', { name: 'Add DiscoverHosts' })).toBeInTheDocument()
    await user.clear(screen.getByLabelText('Name'))
    await user.type(screen.getByLabelText('Name'), 'Copied discovery')
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(router.state.location.pathname).toBe('/workflows/standard-discovery-copy'))
    const saved = getDb().workflows.find((w) => w.key === 'standard-discovery-copy')
    expect(saved?.definition.name).toBe('Copied discovery')
    expect(saved?.definition.steps.find((s) => s.id === 'http')?.dependsOn).toEqual(['services'])
  })

  it('asks before leaving with unsaved changes', async () => {
    const { user, router } = renderApp('/workflows/new?from=', { role: 'Manager' })
    await user.type(await screen.findByLabelText('Key'), 'draft-wf')
    await router.navigate('/workflows')
    expect(await screen.findByText('Discard unsaved changes?')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Keep editing' }))
    expect(router.state.location.pathname).toBe('/workflows/new')
  })
})
