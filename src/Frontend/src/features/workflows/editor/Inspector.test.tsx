import { useState } from 'react'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ScanWorkflowDefinition, WorkflowStep } from '@/api/types'
import { OPERATIONS } from '@/mocks/operations'
import { definitionToGraph, graphToDefinition, type Graph, type WorkflowMeta } from './graph'
import { StepInspector } from './Inspector'

const def: ScanWorkflowDefinition = {
  key: 'wf',
  name: 'WF',
  steps: [
    { id: 'discover', operation: 'DiscoverHosts' },
    { id: 'ports', operation: 'ScanPorts', dependsOn: ['discover'], input: { fromSteps: ['discover'], filter: { field: 'kind', operator: 'Equals', values: ['HostUp'] } }, parameters: { rate: '100' } },
    { id: 'persist', operation: 'PersistObservations', dependsOn: ['ports'] },
  ],
}

/** Renders the inspector for `selected` and exposes the definition it produces. */
function setup(selected = 'ports', initial: ScanWorkflowDefinition = def) {
  let current: ScanWorkflowDefinition = initial
  function Harness() {
    const [{ meta, graph }, setState] = useState<{ meta: WorkflowMeta; graph: Graph }>(() => {
      const s = definitionToGraph(initial)
      return { ...s, graph: { ...s.graph, nodes: s.graph.nodes.map((n) => ({ ...n, selected: n.id === selected })) } }
    })
    current = graphToDefinition(meta, graph)
    const id = graph.nodes.find((n) => n.selected)?.id
    return id ? <StepInspector graph={graph} stepId={id} operations={OPERATIONS} onChange={(g) => setState((s) => ({ ...s, graph: g }))} /> : null
  }
  render(<Harness />)
  return { user: userEvent.setup(), step: (id: string): WorkflowStep | undefined => current.steps.find((s) => s.id === id), definition: () => current }
}

describe('step inspector', () => {
  it('renders parameters from descriptors and writes string values (empty = default)', async () => {
    const { user, step } = setup()
    await user.type(screen.getByLabelText('ports'), 'top-1000')
    await user.selectOptions(screen.getByLabelText('scanType'), 'syn')
    await user.clear(screen.getByLabelText('rate'))
    expect(screen.getByLabelText('retries')).toHaveAttribute('max', '5')
    expect(step('ports')?.parameters).toEqual({ ports: 'top-1000', scanType: 'syn' })
  })

  it('edits execution settings; empty retry fields mean "inherit"', async () => {
    const { user, step } = setup()
    await user.type(screen.getByLabelText('Retry attempts'), '5')
    await user.selectOptions(screen.getByLabelText('On failure'), 'Continue')
    await user.type(screen.getByLabelText('Tool pin (toolId)'), 'naabu')
    expect(step('ports')).toMatchObject({ retry: { maxAttempts: 5 }, onFailure: 'Continue', toolId: 'naabu' })
    await user.clear(screen.getByLabelText('Retry attempts'))
    expect(step('ports')?.retry).toBeUndefined()
  })

  it('renames a step and its references; rejects invalid or duplicate ids', async () => {
    const { user, step, definition } = setup()
    const id = screen.getByLabelText('Step id')
    await user.clear(id)
    await user.type(id, '9bad')
    await user.tab()
    expect(screen.getByText(/Start with a letter/)).toBeInTheDocument()
    await user.clear(id)
    await user.type(id, 'discover')
    expect(screen.getByText('Another step already uses this id.')).toBeInTheDocument()
    await user.clear(id)
    await user.type(id, 'tcp{Enter}')
    expect(definition().steps.map((s) => s.id)).toEqual(['discover', 'tcp', 'persist'])
    expect(step('persist')?.dependsOn).toEqual(['tcp'])
  })

  it('edits dependencies and input sources; cycles are disabled', async () => {
    const { user, step } = setup()
    const deps = within(screen.getByRole('group', { name: 'Depends on' }))
    expect(deps.getByRole('checkbox', { name: /persist/ })).toBeDisabled()
    await user.click(within(screen.getByRole('group', { name: 'Input from' })).getByRole('checkbox', { name: 'discover' }))
    expect(step('ports')?.input).toBeUndefined()
    await user.click(deps.getByRole('checkbox', { name: 'discover' }))
    expect(step('ports')).not.toHaveProperty('dependsOn')
  })

  it('disables dependencies and input sources the data-flow rules refuse, with the reason', async () => {
    const { user, step } = setup('services', {
      key: 'wf',
      name: 'WF',
      steps: [
        { id: 'discover', operation: 'DiscoverHosts' },
        { id: 'ports', operation: 'ScanPorts', dependsOn: ['discover'], input: { fromSteps: ['discover'] }, parameters: { ports: '80' } },
        { id: 'services', operation: 'DetectService' },
      ],
    })
    const deps = within(screen.getByRole('group', { name: 'Depends on' }))
    const discover = deps.getByRole('checkbox', { name: /discover/ })
    expect(discover).toBeDisabled()
    expect(discover.closest('label')).toHaveAttribute('title', expect.stringMatching(/needs host:port endpoints/))
    await user.click(deps.getByRole('checkbox', { name: /ports/ }))
    expect(step('services')).toMatchObject({ dependsOn: ['ports'], input: { fromSteps: ['ports'] } })
  })

  it('hides input and conditions for server steps', () => {
    setup('persist')
    expect(screen.queryByRole('group', { name: 'Input from' })).not.toBeInTheDocument()
    expect(screen.queryByRole('group', { name: 'Run only when' })).not.toBeInTheDocument()
  })
})

describe('condition builder', () => {
  it('builds rules, AND/OR groups and NOT into a ConditionExpression', async () => {
    const { user, step } = setup()
    const when = () => within(screen.getByRole('group', { name: 'Run only when' }))

    await user.click(when().getByRole('button', { name: 'Rule' }))
    await user.type(when().getByLabelText('Add value'), 'http{Enter}https{Enter}')
    expect(step('ports')?.when).toEqual({ field: 'service.name', operator: 'In', values: ['http', 'https'] })

    await user.click(when().getByRole('button', { name: 'AND' }))
    const second = within(when().getAllByTestId('condition-node')[2])
    await user.selectOptions(second.getByLabelText('Field'), 'port')
    await user.selectOptions(second.getByLabelText('Operator'), 'GreaterThan')
    await user.type(second.getByLabelText('Add value'), '1000{Enter}')
    await user.click(second.getByRole('checkbox', { name: 'NOT' }))
    expect(step('ports')?.when).toEqual({
      all: [
        { field: 'service.name', operator: 'In', values: ['http', 'https'] },
        { not: { field: 'port', operator: 'GreaterThan', values: ['1000'] } },
      ],
    })

    await user.selectOptions(when().getByLabelText('Combine with'), 'any')
    await user.click(when().getAllByRole('button', { name: 'Remove value http' })[0])
    await user.selectOptions(when().getAllByLabelText('Operator')[0], 'Exists')
    expect(step('ports')?.when).toEqual({
      any: [
        { field: 'service.name', operator: 'Exists' },
        { not: { field: 'port', operator: 'GreaterThan', values: ['1000'] } },
      ],
    })

    await user.click(when().getAllByRole('button', { name: 'Remove condition' })[0])
    expect(step('ports')?.when).toBeUndefined()
  })

  it('edits the input filter in place (single-value operators keep one value)', async () => {
    const { user, step } = setup()
    const filter = within(screen.getByRole('group', { name: 'Input filter' }))
    await user.type(filter.getByLabelText('Add value'), 'PortOpen{Enter}')
    expect(step('ports')?.input).toEqual({ fromSteps: ['discover'], filter: { field: 'kind', operator: 'Equals', values: ['PortOpen'] } })
  })
})
