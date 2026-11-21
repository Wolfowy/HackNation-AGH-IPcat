import type { ScanWorkflowDefinition } from '@/api/types'
import { OPERATIONS } from '@/mocks/operations'
import {
  addStep,
  connect,
  connectionError,
  decorateEdges,
  definitionToGraph,
  disconnect,
  graphProblem,
  graphToDefinition,
  removeStep,
  renameStep,
  stepErrors,
  uniqueStepId,
} from './graph'

const def: ScanWorkflowDefinition = {
  key: 'wf',
  version: 3,
  name: 'WF',
  defaults: { timeoutSeconds: 600 },
  steps: [
    { id: 'discover', operation: 'DiscoverHosts', parameters: { method: 'icmp' } },
    { id: 'ports', operation: 'ScanPorts', dependsOn: ['discover'], input: { fromSteps: ['discover'], filter: { field: 'kind', operator: 'Equals', values: ['HostUp'] } } },
    {
      id: 'http',
      operation: 'HttpProbe',
      dependsOn: ['ports'],
      input: { fromSteps: ['ports'] },
      when: { field: 'service.name', operator: 'In', values: ['http', 'https'] },
      onFailure: 'Continue',
    },
    { id: 'persist', operation: 'PersistObservations', dependsOn: ['http', 'ports'] },
  ],
}
const op = (name: string) => OPERATIONS.find((o) => o.operation === name)!

describe('definition ↔ graph', () => {
  it('maps steps to nodes and dependsOn to edges, laid out left to right', () => {
    const { meta, graph } = definitionToGraph(def)
    expect(meta).toEqual({ key: 'wf', name: 'WF', defaults: { timeoutSeconds: 600 } })
    expect(graph.nodes.map((n) => n.id)).toEqual(['discover', 'ports', 'http', 'persist'])
    expect(graph.nodes[1].data.step).not.toHaveProperty('dependsOn')
    expect(graph.edges.map((e) => e.id)).toEqual(['discover->ports', 'ports->http', 'http->persist', 'ports->persist'])
    const x = Object.fromEntries(graph.nodes.map((n) => [n.id, n.position.x]))
    expect(x.discover).toBeLessThan(x.ports)
    expect(x.ports).toBeLessThan(x.http)
    expect(x.http).toBeLessThan(x.persist)
  })

  it('round-trips a definition (version dropped, dependsOn order kept)', () => {
    const { meta, graph } = definitionToGraph(def)
    const { version: _version, ...expected } = def
    expect(graphToDefinition(meta, graph)).toEqual(expected)
  })

  it('labels edges that carry input or a when condition, dashes ordering-only edges', () => {
    const edges = decorateEdges(definitionToGraph(def).graph)
    const byId = Object.fromEntries(edges.map((e) => [e.id, e]))
    expect(byId['discover->ports'].label).toBe('where HostUp')
    expect(byId['ports->http'].label).toBe('if http/https')
    expect(byId['http->persist'].label).toBeUndefined()
    expect(byId['http->persist'].style).toEqual({ strokeDasharray: '5 4' })
  })
})

describe('graph edits', () => {
  it('rejects self-loops, duplicates and cycles with a reason', () => {
    const { graph } = definitionToGraph(def)
    expect(connectionError(graph.edges, 'ports', 'ports')).toMatch(/itself/)
    expect(connectionError(graph.edges, 'discover', 'ports')).toMatch(/already depends/)
    expect(connectionError(graph.edges, 'persist', 'discover')).toMatch(/cycle/)
    expect(connectionError(graph.edges, 'discover', 'persist')).toBeNull()
    expect(connect(graph, 'persist', 'discover', true)).toBe(graph)
  })

  it('connect feeds input to a target without input; disconnect prunes input that is no longer upstream', () => {
    const { meta, graph: initial } = definitionToGraph({ key: 'k1', name: 'n', steps: [{ id: 'a', operation: 'DiscoverHosts' }, { id: 'b', operation: 'ScanPorts' }] })
    let graph = connect(initial, 'a', 'b', true)
    expect(graphToDefinition(meta, graph).steps[1]).toEqual({ id: 'b', operation: 'ScanPorts', dependsOn: ['a'], input: { fromSteps: ['a'] } })
    graph = disconnect(graph, 'a', 'b')
    expect(graphToDefinition(meta, graph).steps[1]).toEqual({ id: 'b', operation: 'ScanPorts' })
  })

  it('renaming a step updates edges and input references', () => {
    const { meta, graph } = definitionToGraph(def)
    const steps = graphToDefinition(meta, renameStep(graph, 'ports', 'tcp')).steps
    expect(steps.map((s) => s.id)).toEqual(['discover', 'tcp', 'http', 'persist'])
    expect(steps[2]).toMatchObject({ dependsOn: ['tcp'], input: { fromSteps: ['tcp'] } })
    expect(steps[3].dependsOn).toEqual(['http', 'tcp'])
  })

  it('removing a step drops its edges and references', () => {
    const { meta, graph } = definitionToGraph(def)
    const steps = graphToDefinition(meta, removeStep(graph, 'ports')).steps
    expect(steps.map((s) => s.id)).toEqual(['discover', 'http', 'persist'])
    expect(steps[1]).not.toHaveProperty('dependsOn')
    expect(steps[1]).not.toHaveProperty('input')
    expect(steps[2].dependsOn).toEqual(['http'])
  })

  it('adds steps with unique ids and default parameters', () => {
    expect(uniqueStepId('ScanPorts', ['scanPorts', 'scanPorts2'])).toBe('scanPorts3')
    let { graph } = definitionToGraph({ key: 'k1', name: 'n', steps: [] })
    graph = addStep(graph, op('ScanPorts'), { x: 0, y: 0 })
    graph = addStep(graph, op('ScanPorts'), { x: 300, y: 0 })
    expect(graph.nodes.map((n) => [n.id, n.selected])).toEqual([
      ['scanPorts', false],
      ['scanPorts2', true],
    ])
    expect(graph.nodes[0].data.step.parameters).toEqual({ ports: 'top-100', scanType: 'connect', rate: '500', retries: '1' })
  })
})

describe('validation mapping and JSON checks', () => {
  it('assigns messages to the step they are about', () => {
    const errors = stepErrors(
      ["Step 'http' reads input from 'discover', which must be one of its (transitive) dependencies.", 'steps[1].parameters.x: unknown parameter', 'key must match'],
      ['discover', 'ports', 'http'],
    )
    expect(errors).toEqual({ http: [expect.stringContaining('reads input')], ports: ['steps[1].parameters.x: unknown parameter'] })
  })

  it('reports JSON that cannot become a graph', () => {
    expect(graphProblem(def)).toBeNull()
    expect(graphProblem({ key: 'k', name: 'n', steps: [{ id: 'a', operation: 'DiscoverHosts', dependsOn: ['zzz'] }] })).toMatch(/unknown step 'zzz'/)
    expect(graphProblem({ key: 'k', name: 'n', steps: [{ id: 'a', operation: 'DiscoverHosts' }, { id: 'a', operation: 'ScanPorts' }] })).toMatch(/Duplicate/)
  })
})
