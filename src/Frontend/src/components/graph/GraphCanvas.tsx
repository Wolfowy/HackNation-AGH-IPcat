import '@xyflow/react/dist/style.css'
import { useEffect, type ReactNode } from 'react'
import { Background, Controls, MiniMap, ReactFlow, useNodesInitialized, useReactFlow, type Edge, type Node, type NodeMouseHandler, type NodeTypes } from '@xyflow/react'
import { useNetworks, useZones } from '@/api/networks'
import { FormField } from '@/components/form'
import { Filters } from '@/components/page'
import { Input, NativeSelect } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { cn } from '@/lib/utils'

/** Below this zoom, labels are unreadable: show the top-left part at READABLE_ZOOM and let the user scroll instead. */
const READABLE_ZOOM = 0.6

/** Fits the whole graph when it is readable that way; otherwise anchors the top-left corner at a readable zoom. */
function InitialView() {
  const flow = useReactFlow()
  const initialized = useNodesInitialized()
  useEffect(() => {
    if (!initialized) return
    void flow.fitView({ maxZoom: 1.2 }).then(() => {
      if (flow.getZoom() >= READABLE_ZOOM) return
      const nodes = flow.getNodes().filter((n) => !n.parentId)
      if (nodes.length === 0) return
      const minX = Math.min(...nodes.map((n) => n.position.x))
      const minY = Math.min(...nodes.map((n) => n.position.y))
      void flow.setViewport({ x: 24 - minX * READABLE_ZOOM, y: 24 - minY * READABLE_ZOOM, zoom: READABLE_ZOOM })
    })
  }, [initialized, flow])
  return null
}

/**
 * Read-only React Flow canvas (auto-laid-out nodes): zoom controls, minimap. Opens fitted, or — for graphs too large to read
 * when fitted — at a readable zoom from the top-left; the mouse wheel scrolls (pinch or Ctrl+wheel zooms). Change `fitKey` to re-fit.
 */
export function GraphCanvas<N extends Node>({
  nodes,
  edges,
  nodeTypes,
  onNodeClick,
  nodeColor,
  fitKey,
  className,
  testId,
}: {
  nodes: N[]
  edges: Edge[]
  nodeTypes: NodeTypes
  onNodeClick?: NodeMouseHandler<N>
  nodeColor?: (node: N) => string
  fitKey?: string
  className?: string
  testId?: string
}) {
  return (
    <div className={cn('bg-card h-[calc(100vh-16rem)] min-h-[420px] rounded-lg border', className)} data-testid={testId}>
      <ReactFlow
        key={fitKey}
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        minZoom={0.05}
        panOnScroll
        zoomOnScroll={false}
        zoomOnPinch
        nodesDraggable={false}
        nodesConnectable={false}
        edgesFocusable={false}
        // Large graphs: skip off-screen nodes (small ones render fully, which also keeps them testable in jsdom).
        onlyRenderVisibleElements={nodes.length > 400}
      >
        <InitialView />
        <Background />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable nodeColor={nodeColor} />
      </ReactFlow>
    </div>
  )
}

export function GraphLegend({ items }: { items: { label: string; swatch: string }[] }) {
  return (
    <div className="text-muted-foreground flex flex-wrap items-center gap-4 text-xs" data-testid="graph-legend">
      {items.map((i) => (
        <span key={i.label} className="inline-flex items-center gap-1.5">
          <span className={cn('size-3 rounded-sm border', i.swatch)} aria-hidden />
          {i.label}
        </span>
      ))}
    </div>
  )
}

export interface GraphFilterValues {
  search: string
  zone: string
  networkId: string
}

export const emptyGraphFilters: GraphFilterValues = { search: '', zone: '', networkId: '' }

/** Search / zone / network filters shared by the graph views (topology endpoint parameters). */
export function GraphFilters({
  value,
  onChange,
  children,
}: {
  value: GraphFilterValues
  onChange: (value: GraphFilterValues) => void
  children?: ReactNode
}) {
  const zones = useZones()
  const networks = useNetworks()
  const set = (key: keyof GraphFilterValues) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    onChange({ ...value, [key]: e.target.value })
  return (
    <Filters>
      <FormField label={t.common.search}>
        <Input type="search" placeholder="Address or hostname…" value={value.search} onChange={set('search')} />
      </FormField>
      <FormField label="Zone">
        <NativeSelect value={value.zone} onChange={set('zone')}>
          <option value="">{t.common.all}</option>
          {(zones.data ?? []).map((z) => (
            <option key={z.name}>{z.name}</option>
          ))}
        </NativeSelect>
      </FormField>
      <FormField label="Network">
        <NativeSelect value={value.networkId} onChange={set('networkId')}>
          <option value="">{t.common.all}</option>
          {(networks.data ?? []).map((n) => (
            <option key={n.id} value={n.id}>
              {n.name}
            </option>
          ))}
        </NativeSelect>
      </FormField>
      {children}
    </Filters>
  )
}
