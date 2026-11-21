import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type DragEvent } from 'react'
import {
  applyEdgeChanges,
  applyNodeChanges,
  Background,
  Controls,
  Handle,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Connection,
  type EdgeChange,
  type NodeChange,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Funnel, LayoutGrid, Pin, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'
import type { OperationDescriptor, ScanOperation } from '@/api/types'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { cn } from '@/lib/utils'
import {
  addStep,
  connect,
  connectionError,
  decorateEdges,
  definitionToGraph,
  describeCondition,
  graphProblem,
  graphToDefinition,
  layoutGraph,
  pruneInputs,
  stepErrors,
  type Graph,
  type StepNode,
} from './graph'
import { StepInspector, takesInput, WorkflowSettings } from './Inspector'
import { JsonWorkflowEditor } from './JsonWorkflowEditor'
import { OperationIcon, planeAccent } from './operationStyle'
import type { WorkflowEditorChange, WorkflowEditorProps } from './types'

const DND_TYPE = 'application/x-webscan-operation'
// minZoom keeps labels readable; wide workflows are panned (minimap) rather than shrunk to illegibility.
const FIT = { padding: 0.15, maxZoom: 1, minZoom: 0.6 }

interface CanvasContext {
  operations: Map<string, OperationDescriptor>
  errors: Record<string, string[]>
}
const Ctx = createContext<CanvasContext>({ operations: new Map(), errors: {} })

function StepNodeView({ data, selected, isConnectable }: NodeProps<StepNode>) {
  const { operations, errors } = useContext(Ctx)
  const { step } = data
  const plane = operations.get(step.operation)?.plane
  const stepErrors = errors[step.id] ?? []
  const params = Object.entries(step.parameters ?? {})
  return (
    <div
      data-testid={`step-node-${step.id}`}
      className={cn(
        'bg-card w-60 rounded-lg border border-l-4 p-2.5 text-xs shadow-sm',
        planeAccent(plane),
        selected && 'ring-ring ring-2',
        stepErrors.length > 0 && 'border-destructive ring-destructive/50 ring-2',
      )}
    >
      <Handle type="target" position={Position.Left} isConnectable={isConnectable} className="size-3!" />
      <div className="flex items-center gap-2">
        <OperationIcon operation={step.operation} plane={plane} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-semibold">{step.id}</div>
          <div className="text-muted-foreground truncate">
            {step.operation} · {plane ?? '…'}
          </div>
        </div>
        {stepErrors.length > 0 && (
          <Badge variant="destructive" title={stepErrors.join('\n')} aria-label={`${stepErrors.length} validation errors`}>
            {stepErrors.length}
          </Badge>
        )}
      </div>
      {params.length > 0 && (
        <div className="text-muted-foreground mt-1.5 truncate font-mono text-[11px]" title={params.map(([k, v]) => `${k}=${v}`).join('\n')}>
          {params.map(([k, v]) => `${k}=${v}`).join(' ')}
        </div>
      )}
      {(step.when || step.input?.filter || step.retry || step.toolId || step.onFailure === 'Continue') && (
        <div className="mt-1.5 flex flex-wrap gap-1">
          {step.when && (
            <Badge variant="warning" title={`when ${describeCondition(step.when)}`}>
              <Funnel /> if
            </Badge>
          )}
          {step.input?.filter && (
            <Badge variant="outline" title={`input where ${describeCondition(step.input.filter)}`}>
              <Funnel /> filter
            </Badge>
          )}
          {step.retry && (
            <Badge variant="outline" title="Retry policy">
              <RotateCcw /> {step.retry.maxAttempts ?? '–'}×
            </Badge>
          )}
          {step.toolId && (
            <Badge variant="outline" title="Pinned tool">
              <Pin /> {step.toolId}
            </Badge>
          )}
          {step.onFailure === 'Continue' && <Badge variant="outline">continue on failure</Badge>}
        </div>
      )}
      <Handle type="source" position={Position.Right} isConnectable={isConnectable} className="size-3!" />
    </div>
  )
}

const nodeTypes = { step: StepNodeView }

function Palette({ operations, onAdd }: { operations: OperationDescriptor[]; onAdd: (op: ScanOperation) => void }) {
  return (
    <aside aria-label="Operations palette" className="grid content-start gap-3 overflow-y-auto">
      {(['Agent', 'Server'] as const).map((plane) => (
        <div key={plane} className="grid gap-1">
          <h3 className="text-muted-foreground text-xs font-semibold tracking-wide uppercase">{plane === 'Agent' ? 'Agent (network)' : 'Server'}</h3>
          {operations
            .filter((o) => o.plane === plane)
            .map((o) => (
              <button
                key={o.operation}
                type="button"
                draggable
                aria-label={`Add ${o.operation}`}
                title="Click to add, or drag onto the canvas"
                onDragStart={(e) => {
                  e.dataTransfer.setData(DND_TYPE, o.operation)
                  e.dataTransfer.effectAllowed = 'move'
                }}
                onClick={() => onAdd(o.operation)}
                className={cn('bg-card hover:bg-accent flex cursor-grab items-center gap-2 rounded-md border border-l-4 px-2 py-1.5 text-left text-xs font-medium', planeAccent(o.plane))}
              >
                <OperationIcon operation={o.operation} plane={o.plane} className="size-6" />
                <span className="truncate">{o.operation}</span>
              </button>
            ))}
        </div>
      ))}
    </aside>
  )
}

function Editor({ initial, onChange, operations, errors, readOnly, keyEditable }: WorkflowEditorProps) {
  const [{ meta, graph }, setState] = useState(() => definitionToGraph(initial))
  const setGraph = useCallback((update: (g: Graph) => Graph) => setState((s) => ({ ...s, graph: update(s.graph) })), [])
  const [tab, setTab] = useState<'visual' | 'json'>('visual')
  const [jsonDraft, setJsonDraft] = useState<WorkflowEditorChange | null>(null)
  const [jsonBlocked, setJsonBlocked] = useState<string | null>(null)
  const flow = useReactFlow()

  const opsByName = useMemo(() => new Map(operations.map((o) => [o.operation as string, o])), [operations])
  const errorMap = useMemo(() => stepErrors(errors, graph.nodes.map((n) => n.id)), [errors, graph.nodes])
  const ctx = useMemo(() => ({ operations: opsByName, errors: errorMap }), [opsByName, errorMap])
  const edges = useMemo(() => decorateEdges(graph), [graph])
  const selected = graph.nodes.filter((n) => n.selected)
  const selectedId = selected.length === 1 ? selected[0].id : undefined

  // Only real definition changes reach the page (not drags or selection).
  const json = useMemo(() => JSON.stringify(graphToDefinition(meta, graph)), [meta, graph])
  const onChangeRef = useRef(onChange)
  useEffect(() => {
    onChangeRef.current = onChange
  })
  useEffect(() => {
    onChangeRef.current({ definition: JSON.parse(json) })
  }, [json])

  // Fit once every node (including a just-added one) has been measured.
  const fitPending = useRef(false)
  const fit = () => {
    fitPending.current = true
  }
  useEffect(() => {
    if (!fitPending.current || !graph.nodes.every((n) => n.measured?.width)) return
    fitPending.current = false
    void flow.fitView(FIT)
  }, [graph.nodes, flow])

  const onNodesChange = useCallback(
    (changes: NodeChange<StepNode>[]) =>
      setGraph((g) => {
        const next = { ...g, nodes: applyNodeChanges(changes, g.nodes) }
        return changes.some((c) => c.type === 'remove') ? pruneInputs(next) : next
      }),
    [setGraph],
  )
  const onEdgesChange = useCallback(
    (changes: EdgeChange[]) =>
      setGraph((g) => {
        const next = { ...g, edges: applyEdgeChanges(changes, g.edges) }
        return changes.some((c) => c.type === 'remove') ? pruneInputs(next) : next
      }),
    [setGraph],
  )
  const onConnect = (c: Connection) => {
    const problem = connectionError(graph.edges, c.source, c.target)
    if (problem) return void toast.error(problem)
    const target = graph.nodes.find((n) => n.id === c.target)
    setGraph((g) => connect(g, c.source, c.target, takesInput(opsByName.get(target?.data.step.operation ?? ''))))
  }

  const add = (operation: string, position?: { x: number; y: number }) => {
    const op = opsByName.get(operation)
    if (!op) return
    setGraph((g) => {
      const anchor = g.nodes.find((n) => n.selected) ?? g.nodes.reduce<StepNode | undefined>((a, n) => (!a || n.position.x > a.position.x ? n : a), undefined)
      return addStep(g, op, position ?? (anchor ? { x: anchor.position.x + 300, y: anchor.position.y } : { x: 0, y: 0 }))
    })
    if (!position) fit()
  }
  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    const operation = e.dataTransfer.getData(DND_TYPE)
    if (operation) add(operation, flow.screenToFlowPosition({ x: e.clientX, y: e.clientY }))
  }

  const switchTab = (next: string) => {
    if (next === 'json') {
      setJsonDraft(null)
      setJsonBlocked(null)
      return setTab('json')
    }
    const def = jsonDraft?.definition
    if (jsonDraft && !def) return setJsonBlocked(`Fix the JSON before switching back: ${jsonDraft.parseError ?? 'invalid definition'}`)
    const problem = def && graphProblem(def)
    if (problem) return setJsonBlocked(`The JSON cannot be shown as a graph: ${problem}`)
    if (def) {
      const loaded = definitionToGraph(def)
      const old = new Map(graph.nodes.map((n) => [n.id, n.position]))
      const sameSteps = loaded.graph.nodes.length === old.size && loaded.graph.nodes.every((n) => old.has(n.id))
      setState(sameSteps ? { ...loaded, graph: { ...loaded.graph, nodes: loaded.graph.nodes.map((n) => ({ ...n, position: old.get(n.id)! })) } } : loaded)
    }
    setJsonBlocked(null)
    setTab('visual')
  }

  const canvas = (
    <div className={cn('grid gap-3', readOnly ? 'lg:grid-cols-[minmax(0,1fr)_20rem]' : 'lg:grid-cols-[11rem_minmax(0,1fr)_20rem]')}>
      {!readOnly && <Palette operations={operations} onAdd={add} />}
      <div className="bg-muted/20 h-[calc(100vh-15rem)] min-h-[26rem] rounded-lg border" data-testid="workflow-canvas" onDrop={onDrop} onDragOver={(e) => e.preventDefault()}>
        <Ctx.Provider value={ctx}>
          <ReactFlow<StepNode>
            nodes={graph.nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={readOnly ? undefined : onConnect}
            nodesConnectable={!readOnly}
            deleteKeyCode={readOnly ? null : ['Backspace', 'Delete']}
            fitView
            fitViewOptions={FIT}
            minZoom={0.2}
            proOptions={{ hideAttribution: true }}
          >
            <Background />
            <Controls showInteractive={false} />
            <MiniMap<StepNode>
              pannable
              zoomable
              className="hidden! md:block!"
              style={{ width: 150, height: 100 }}
              nodeColor={(n) => (opsByName.get(n.data.step.operation)?.plane === 'Server' ? '#8b5cf6' : '#0ea5e9')}
            />
            <Panel position="top-right">
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setGraph(layoutGraph)
                  fit()
                }}
              >
                <LayoutGrid /> Auto-layout
              </Button>
            </Panel>
            {graph.nodes.length === 0 && (
              <Panel position="top-center" className="text-muted-foreground text-sm">
                {readOnly ? 'No steps.' : 'Add operations from the palette (click or drag). Connect a node’s right handle to another node’s left handle.'}
              </Panel>
            )}
          </ReactFlow>
        </Ctx.Provider>
      </div>
      <aside aria-label="Inspector" className="h-[calc(100vh-15rem)] min-h-[26rem] overflow-y-auto rounded-lg border p-3">
        {selectedId && (
          <button type="button" className="text-primary mb-2 text-xs hover:underline" onClick={() => setGraph((g) => ({ ...g, nodes: g.nodes.map((n) => ({ ...n, selected: false })) }))}>
            ← Workflow settings
          </button>
        )}
        <fieldset disabled={readOnly} className="min-w-0">
          {selectedId ? (
            <StepInspector graph={graph} stepId={selectedId} operations={operations} errors={errorMap[selectedId]} defaults={meta.defaults} onChange={(g) => setGraph(() => g)} />
          ) : (
            <WorkflowSettings meta={meta} keyEditable={keyEditable && !readOnly} onChange={(m) => setState((s) => ({ ...s, meta: m }))} />
          )}
        </fieldset>
      </aside>
    </div>
  )

  if (readOnly) return canvas
  return (
    <Tabs value={tab} onValueChange={switchTab}>
      <TabsList>
        <TabsTrigger value="visual">Visual editor</TabsTrigger>
        <TabsTrigger value="json">JSON</TabsTrigger>
      </TabsList>
      {jsonBlocked && (
        <Alert variant="destructive" role="alert">
          <AlertDescription>{jsonBlocked}</AlertDescription>
        </Alert>
      )}
      <TabsContent value="visual">{canvas}</TabsContent>
      <TabsContent value="json">
        <JsonWorkflowEditor
          initial={JSON.parse(json)}
          operations={operations}
          onChange={(c) => {
            setJsonDraft(c)
            setJsonBlocked(null)
            onChange(c)
          }}
        />
      </TabsContent>
    </Tabs>
  )
}

/** n8n-style node-graph editor: palette, React Flow canvas, inspector; JSON tab kept in sync. `readOnly` = viewer. */
export function VisualWorkflowEditor(props: WorkflowEditorProps) {
  return (
    <ReactFlowProvider>
      <Editor {...props} />
    </ReactFlowProvider>
  )
}
