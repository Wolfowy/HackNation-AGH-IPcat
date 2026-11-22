// Pure conversions between ScanWorkflowDefinition and the React Flow graph (nodes = steps, edges = dependsOn).
import dagre from '@dagrejs/dagre'
import { MarkerType, type Edge, type Node } from '@xyflow/react'
import { formatValidationMessage } from '@/api/client'
import type { ConditionExpression, OperationDescriptor, ScanWorkflowDefinition, ValidationMessage, WorkflowStep } from '@/api/types'

/** Step without `dependsOn`: dependencies live on the edges. */
export type StepNodeData = { step: WorkflowStep }
export type StepNode = Node<StepNodeData, 'step'>
export interface Graph {
  nodes: StepNode[]
  edges: Edge[]
}
export type WorkflowMeta = Omit<ScanWorkflowDefinition, 'steps' | 'version'>

export const STEP_ID_PATTERN = /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/
export const KEY_PATTERN = /^[a-z0-9][a-z0-9-]{1,63}$/
export const NODE_WIDTH = 240
const NODE_HEIGHT = 100

export const edgeId = (source: string, target: string) => `${source}->${target}`
const makeEdge = (source: string, target: string): Edge => ({ id: edgeId(source, target), source, target })

export function definitionToGraph(definition: ScanWorkflowDefinition): { meta: WorkflowMeta; graph: Graph } {
  const { steps, version: _version, ...meta } = definition
  const nodes: StepNode[] = steps.map(({ dependsOn: _deps, ...step }) => ({ id: step.id, type: 'step', position: { x: 0, y: 0 }, data: { step } }))
  const edges = steps.flatMap((s) => (s.dependsOn ?? []).map((dep) => makeEdge(dep, s.id)))
  return { meta, graph: layoutGraph({ nodes, edges }) }
}

export function graphToDefinition(meta: WorkflowMeta, { nodes, edges }: Graph): ScanWorkflowDefinition {
  return {
    ...meta,
    steps: nodes.map((n) => {
      const { id, operation, ...rest } = n.data.step
      const dependsOn = edges.filter((e) => e.target === n.id).map((e) => e.source)
      return { id, operation, ...(dependsOn.length ? { dependsOn } : {}), ...rest }
    }),
  }
}

/** Left-to-right dagre layout; returns new node positions (top-left corner). */
export function layoutGraph(graph: Graph): Graph {
  const g = new dagre.graphlib.Graph()
  g.setGraph({ rankdir: 'LR', nodesep: 30, ranksep: 80 })
  g.setDefaultEdgeLabel(() => ({}))
  const ids = new Set(graph.nodes.map((n) => n.id))
  for (const n of graph.nodes) g.setNode(n.id, { width: NODE_WIDTH, height: n.measured?.height ?? NODE_HEIGHT })
  for (const e of graph.edges) if (ids.has(e.source) && ids.has(e.target)) g.setEdge(e.source, e.target)
  dagre.layout(g)
  return {
    ...graph,
    nodes: graph.nodes.map((n) => {
      const { x, y, height } = g.node(n.id)
      return { ...n, position: { x: x - NODE_WIDTH / 2, y: y - height / 2 } }
    }),
  }
}

/** Transitive dependencies of `id`. */
export function ancestorsOf(edges: Edge[], id: string): Set<string> {
  const seen = new Set<string>()
  const stack = [id]
  while (stack.length) {
    const current = stack.pop()!
    for (const e of edges)
      if (e.target === current && !seen.has(e.source)) {
        seen.add(e.source)
        stack.push(e.source)
      }
  }
  return seen
}

/** Why `target` may not depend on `source` (self-loop, duplicate, cycle), or null when the edge is allowed. */
export function connectionError(edges: Edge[], source: string, target: string): string | null {
  if (source === target) return `A step cannot depend on itself ('${source}').`
  if (edges.some((e) => e.source === source && e.target === target)) return `'${target}' already depends on '${source}'.`
  if (ancestorsOf(edges, source).has(target)) return `'${target}' cannot depend on '${source}': '${source}' already depends on '${target}' (cycle).`
  return null
}

/** Agent steps with targets and EvaluateCondition read observations of earlier steps (`input.fromSteps`). */
export const takesInput = (op?: OperationDescriptor) => (op?.plane === 'Agent' && op.inputKind !== 'None') || op?.operation === 'EvaluateCondition'

// Mirrors the server's WorkflowValidator data-flow rules, so the editor refuses what saving would reject.
const ENDPOINT_PRODUCERS = new Set(['ScanPorts', 'DetectService', 'HttpProbe', 'TlsProbe', 'ExecuteSignatures'])
const CLOSING_STEPS = new Set(['PersistObservations', 'ComparePreviousScan', 'PublishFinding'])

/** Whether observations read from step `id` can carry ports (EvaluateCondition passes on what its own inputs produce). */
function yieldsEndpoints(graph: Graph, id: string, seen = new Set<string>()): boolean {
  const step = graph.nodes.find((n) => n.id === id)?.data.step
  if (!step || seen.has(id)) return false
  seen.add(id)
  if (ENDPOINT_PRODUCERS.has(step.operation)) return true
  return step.operation === 'EvaluateCondition' && (step.input?.fromSteps ?? []).some((s) => yieldsEndpoints(graph, s, seen))
}

/** Why step `source` cannot feed or precede step `inputOf` as an input source, or null when it can. */
export function inputSourceError(graph: Graph, ops: ReadonlyMap<string, OperationDescriptor>, source: string, inputOf: string): string | null {
  const s = graph.nodes.find((n) => n.id === source)?.data.step
  const t = graph.nodes.find((n) => n.id === inputOf)?.data.step
  if (!s || !t) return null
  if (ops.get(s.operation)?.plane !== 'Agent' && s.operation !== 'EvaluateCondition')
    return `${s.operation} '${source}' produces no observations, so '${inputOf}' cannot read its targets from it. Connect an agent step or EvaluateCondition.`
  if (ops.get(t.operation)?.inputKind === 'Endpoints' && !yieldsEndpoints(graph, source))
    return `${t.operation} needs host:port endpoints, but ${s.operation} '${source}' only finds hosts. Connect it after ScanPorts (or a later step).`
  return null
}

/**
 * Why `target` may not depend on `source`: structural problems (self-loop, duplicate, cycle) and data-flow incompatibility
 * (closing steps after every agent step, RecheckMissing last, input sources that can feed the target). Null = allowed.
 */
export function compatibilityError(graph: Graph, ops: ReadonlyMap<string, OperationDescriptor>, source: string, target: string): string | null {
  const structural = connectionError(graph.edges, source, target)
  if (structural) return structural
  const s = graph.nodes.find((n) => n.id === source)?.data.step
  const t = graph.nodes.find((n) => n.id === target)?.data.step
  if (!s || !t) return null
  const targetOp = ops.get(t.operation)
  const targetIsAgent = targetOp?.plane === 'Agent'
  if (CLOSING_STEPS.has(s.operation) && targetIsAgent)
    return `${t.operation} '${target}' cannot run after ${s.operation} '${source}': persist, compare and publish steps come after every agent step.`
  if (s.operation === 'RecheckMissing' && targetIsAgent && t.operation !== 'RecheckMissing')
    return `RecheckMissing re-checks after every other agent step, so ${t.operation} '${target}' cannot depend on it.`
  // A target without input starts reading from the step it is connected to (see connect).
  if (takesInput(targetOp) && !t.input) return inputSourceError(graph, ops, source, target)
  return null
}

/** Adds the dependency source → target. With `feedsInput`, a target without input reads its targets from `source`. */
export function connect(graph: Graph, source: string, target: string, feedsInput: boolean): Graph {
  if (connectionError(graph.edges, source, target)) return graph
  const nodes = feedsInput
    ? graph.nodes.map((n) => (n.id === target && !n.data.step.input ? withStep(n, { ...n.data.step, input: { fromSteps: [source] } }) : n))
    : graph.nodes
  return { nodes, edges: [...graph.edges, makeEdge(source, target)] }
}

export function disconnect(graph: Graph, source: string, target: string): Graph {
  return pruneInputs({ ...graph, edges: graph.edges.filter((e) => !(e.source === source && e.target === target)) })
}

/** Drops input.fromSteps entries that are no longer (transitive) dependencies; removes inputs left empty. */
export function pruneInputs(graph: Graph): Graph {
  const nodes = graph.nodes.map((n) => {
    const input = n.data.step.input
    if (!input) return n
    const ancestors = ancestorsOf(graph.edges, n.id)
    const fromSteps = input.fromSteps.filter((s) => ancestors.has(s))
    if (fromSteps.length === input.fromSteps.length) return n
    const { input: _input, ...step } = n.data.step
    return withStep(n, fromSteps.length ? { ...step, input: { ...input, fromSteps } } : step)
  })
  return { ...graph, nodes }
}

export function removeStep(graph: Graph, id: string): Graph {
  return pruneInputs({ nodes: graph.nodes.filter((n) => n.id !== id), edges: graph.edges.filter((e) => e.source !== id && e.target !== id) })
}

/** Renames a step and every reference to it (edges, other steps' input.fromSteps). */
export function renameStep(graph: Graph, from: string, to: string): Graph {
  const sub = (id: string) => (id === from ? to : id)
  return {
    nodes: graph.nodes.map((n) => {
      const { step } = n.data
      const input = step.input && { ...step.input, fromSteps: step.input.fromSteps.map(sub) }
      return { ...withStep(n, { ...step, id: sub(step.id), ...(input && { input }) }), id: sub(n.id) }
    }),
    edges: graph.edges.map((e) => ({ ...e, ...makeEdge(sub(e.source), sub(e.target)) })),
  }
}

export function updateStep(graph: Graph, id: string, patch: Partial<WorkflowStep>): Graph {
  return { ...graph, nodes: graph.nodes.map((n) => (n.id === id ? withStep(n, { ...n.data.step, ...patch }) : n)) }
}

export function uniqueStepId(operation: string, taken: Iterable<string>): string {
  const ids = new Set(taken)
  const base = operation[0].toLowerCase() + operation.slice(1)
  let candidate = base
  for (let i = 2; ids.has(candidate); i++) candidate = `${base}${i}`
  return candidate
}

/** Adds a step with a unique id and the operation's default parameters, selected (others deselected). */
export function addStep(graph: Graph, op: OperationDescriptor, position: { x: number; y: number }): Graph {
  const parameters = Object.fromEntries(op.parameters.flatMap((p) => (p.default !== undefined ? [[p.name, p.default]] : [])))
  const step: WorkflowStep = {
    id: uniqueStepId(op.operation, graph.nodes.map((n) => n.id)),
    operation: op.operation,
    ...(Object.keys(parameters).length ? { parameters } : {}),
  }
  return {
    ...graph,
    nodes: [...graph.nodes.map((n) => (n.selected ? { ...n, selected: false } : n)), { id: step.id, type: 'step', position, data: { step }, selected: true }],
  }
}

const withStep = (n: StepNode, step: WorkflowStep): StepNode => ({ ...n, data: { ...n.data, step } })

/** Structural problems that prevent showing a JSON definition as a graph (the server validates everything else). */
export function graphProblem(definition: ScanWorkflowDefinition): string | null {
  const ids = new Set<string>()
  for (const [i, s] of definition.steps.entries()) {
    if (!s || typeof s !== 'object' || typeof s.id !== 'string' || !s.id) return `Step ${i + 1} needs a string "id".`
    if (typeof s.operation !== 'string') return `Step '${s.id}' needs an "operation".`
    if (s.dependsOn !== undefined && !Array.isArray(s.dependsOn)) return `Step '${s.id}': "dependsOn" must be an array.`
    if (s.input !== undefined && !Array.isArray(s.input?.fromSteps)) return `Step '${s.id}': "input.fromSteps" must be an array.`
    if (ids.has(s.id)) return `Duplicate step id '${s.id}'.`
    ids.add(s.id)
  }
  for (const s of definition.steps)
    for (const dep of s.dependsOn ?? []) if (!ids.has(dep)) return `Step '${s.id}' depends on unknown step '${dep}'.`
  return null
}

/** Assigns each validation message to the step it is about (the earliest step id mentioned, or `steps[i]`). */
export function stepErrors(messages: ValidationMessage[] | undefined, ids: string[]): Record<string, string[]> {
  const result: Record<string, string[]> = {}
  for (const m of messages ?? []) {
    const text = formatValidationMessage(m)
    let best: string | undefined
    let at = Infinity
    ids.forEach((id, i) => {
      for (const token of [`'${id}'`, `"${id}"`, `steps[${i}]`]) {
        const pos = text.indexOf(token)
        if (pos >= 0 && pos < at) [at, best] = [pos, id]
      }
    })
    if (best) (result[best] ??= []).push(text)
  }
  return result
}

export function describeCondition(c?: ConditionExpression): string {
  if (!c) return ''
  if (c.all) return c.all.map(describeCondition).join(' AND ')
  if (c.any) return `(${c.any.map(describeCondition).join(' OR ')})`
  if (c.not) return `NOT ${describeCondition(c.not)}`
  return [c.field, c.operator, c.values?.length ? `[${c.values.join(', ')}]` : ''].filter(Boolean).join(' ')
}

/** Compact form for edge labels, e.g. "http/https | ssl". */
export function shortCondition(c?: ConditionExpression): string {
  if (!c) return ''
  if (c.all) return c.all.map(shortCondition).join(' & ')
  if (c.any) return `(${c.any.map(shortCondition).join(' | ')})`
  if (c.not) return `not ${shortCondition(c.not)}`
  return c.values?.length ? c.values.join('/') : `${c.field} ${c.operator?.toLowerCase() ?? ''}`.trim()
}

const clip = (s: string, max = 28) => (s.length > max ? `${s.slice(0, max - 1)}…` : s)

/** Edge styling: solid + label when the target reads its input from the source; dashed for ordering-only dependencies. */
export function decorateEdges({ nodes, edges }: Graph): Edge[] {
  const steps = new Map(nodes.map((n) => [n.id, n.data.step]))
  return edges.map((e) => {
    const step = steps.get(e.target)
    const feeds = Boolean(step?.input?.fromSteps.includes(e.source))
    const filter = feeds ? step?.input?.filter : undefined
    const when = step?.when
    const label = [
      feeds && (filter && JSON.stringify(filter) !== JSON.stringify(when) ? `where ${clip(shortCondition(filter))}` : !when && 'input'),
      when && `if ${clip(shortCondition(when))}`,
    ]
      .filter(Boolean)
      .join(' · ')
    return {
      ...e,
      label: label || undefined,
      markerEnd: { type: MarkerType.ArrowClosed },
      style: feeds ? { strokeWidth: 2 } : { strokeDasharray: '5 4' },
      labelStyle: { fontSize: 11 },
    }
  })
}
