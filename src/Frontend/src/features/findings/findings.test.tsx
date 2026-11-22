import { screen, waitFor, within } from '@testing-library/react'
import type { FindingTriageInput } from '@/api/types'
import { getDb } from '@/mocks/handlers'
import { server } from '@/mocks/node'
import { renderApp } from '@/test/utils'

describe('findings triage', () => {
  it('lets an editor triage a finding and shows the effective severity', async () => {
    const finding = getDb().findings.find((f) => f.status === 'Open' && f.severity !== 'critical')!
    let payload: FindingTriageInput | undefined
    server.events.on('request:start', async ({ request }) => {
      if (request.method === 'PUT' && new URL(request.url).pathname === `/api/findings/${finding.id}`)
        payload = (await request.clone().json()) as FindingTriageInput
    })
    const { user } = renderApp('/findings', { role: 'Editor' })

    await user.click((await screen.findAllByRole('button', { name: `Edit ${finding.name} on ${finding.address}` }))[0])
    const dialog = await screen.findByRole('dialog')
    await user.selectOptions(within(dialog).getByLabelText('Triage'), 'FalsePositive')
    await user.selectOptions(within(dialog).getByLabelText('Severity override'), 'critical')
    await user.type(within(dialog).getByLabelText('Notes'), 'Honeypot in the lab')
    await user.type(within(dialog).getByLabelText('Tags'), 'lab, honeypot')
    await user.click(within(dialog).getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(payload).toEqual({ triage: 'FalsePositive', severityOverride: 'critical', notes: 'Honeypot in the lab', userTags: ['lab', 'honeypot'] })
    expect(getDb().findings.find((f) => f.id === finding.id)).toMatchObject({ triage: 'FalsePositive', effectiveSeverity: 'critical', triagedBy: 'editor' })

    const row = (await screen.findByText('Honeypot in the lab')).closest('tr')!
    expect(row).toHaveAttribute('data-triage', 'FalsePositive')
    expect(row).toHaveClass('opacity-60')
    expect(within(row).getByText('critical')).toBeInTheDocument()
    expect(within(row).getByText(finding.severity)).toHaveClass('line-through')
    expect(within(row).getByText('False positive')).toBeInTheDocument()
    expect(within(row).getByText('honeypot')).toBeInTheDocument()
    server.events.removeAllListeners()
  })

  it('filters by triage and hides editing from viewers', async () => {
    const db = getDb()
    const marked = db.findings.find((f) => f.status === 'Open')!
    Object.assign(marked, { triage: 'AcceptedRisk', notes: 'Accepted by the CISO' })
    const { user } = renderApp('/findings', { role: 'Viewer' })

    await screen.findAllByText(marked.name)
    expect(screen.queryByRole('button', { name: /^Edit / })).not.toBeInTheDocument()
    await user.selectOptions(screen.getByLabelText('Triage'), 'AcceptedRisk')
    await waitFor(() => expect(screen.getAllByRole('row')).toHaveLength(2)) // header + the accepted finding
    const row = screen.getByText('Accepted by the CISO').closest('tr')!
    expect(within(row).getByText('Accepted risk')).toBeInTheDocument()
  })
})

describe('service annotation', () => {
  it('saves criticality, owner, notes and tags of a service', async () => {
    const service = getDb().services.find((s) => s.state === 'Open')!
    const { user } = renderApp(`/assets/hosts/${service.hostId}`, { role: 'Editor' })

    await user.click(await screen.findByRole('button', { name: `Annotate ${service.address}:${service.port}` }))
    const dialog = await screen.findByRole('dialog')
    await user.selectOptions(within(dialog).getByLabelText('Criticality'), 'high')
    await user.type(within(dialog).getByLabelText('Owner'), 'team-web')
    await user.type(within(dialog).getByLabelText('Tags'), 'pci, internet')
    await user.click(within(dialog).getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(getDb().services.find((s) => s.id === service.id)?.annotation).toMatchObject({ criticality: 'high', owner: 'team-web', tags: ['pci', 'internet'] }))
    expect(await screen.findByText('team-web')).toBeInTheDocument()
  })
})
