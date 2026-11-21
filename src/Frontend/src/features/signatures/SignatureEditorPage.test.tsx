import { fireEvent, screen, waitFor } from '@testing-library/react'
import { getDb } from '@/mocks/handlers'
import { renderApp } from '@/test/utils'

describe('signature editor', () => {
  it('shows validation errors and warnings returned by /api/signatures/validate', async () => {
    const { user } = renderApp('/signatures/new', { role: 'Manager' })
    const content = await screen.findByLabelText('Content (YAML)')
    fireEvent.change(content, {
      target: { value: 'id: shell-exec\ninfo:\n  name: Shell\n  severity: high\n  tags: rce,intrusive\ncode:\n  - engine: [sh]\n' },
    })
    await user.click(screen.getByRole('button', { name: 'Validate' }))

    expect(await screen.findByText('Protocol "code" is not allowed.')).toBeInTheDocument()
    expect(screen.getByText('Tag "intrusive" is not allowed.')).toBeInTheDocument()
    expect(screen.getByText('2 errors')).toBeInTheDocument()
    expect(screen.getByText('Severity "high" is above the default info/low.')).toBeInTheDocument()
  })

  it('validates and saves a new JSON classification rule', async () => {
    const { user, router } = renderApp('/signatures/new', { role: 'Manager' })
    await user.type(await screen.findByLabelText('Signature id'), 'linux-ssh-host')
    await user.type(screen.getByLabelText('Name'), 'Linux SSH host')
    await user.selectOptions(screen.getByLabelText('Kind'), 'ClassificationRule')
    fireEvent.change(screen.getByLabelText('Content (JSON)'), { target: { value: '{ "description": "ssh", "when": {} }' } })
    await user.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(router.state.location.pathname).toBe('/signatures/linux-ssh-host'))
    expect(getDb().signatures.find((s) => s.id === 'linux-ssh-host')?.status).toBe('Draft')
  })

  it('does not save content that fails validation', async () => {
    const { user, router } = renderApp('/signatures/new', { role: 'Manager' })
    await user.type(await screen.findByLabelText('Signature id'), 'broken-rule')
    await user.type(screen.getByLabelText('Name'), 'Broken')
    await user.selectOptions(screen.getByLabelText('Kind'), 'ChangeRule')
    fireEvent.change(screen.getByLabelText('Content (JSON)'), { target: { value: '{ not json' } })
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/Invalid JSON/)).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/signatures/new')
  })
})
