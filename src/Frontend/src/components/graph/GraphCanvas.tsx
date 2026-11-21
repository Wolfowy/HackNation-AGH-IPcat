import '@xyflow/react/dist/style.css'
import type { ReactNode } from 'react'
import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node, type NodeMouseHandler, type NodeTypes } from '@xyflow/react'
import { useNetworks, useZones } from '@/api/networks'
import { FormField } from '@/components/form'
import { Filters } from '@/components/page'
import { Input, NativeSelect } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { cn } from '@/lib/utils'

/** Read-only React Flow canvas (auto-laid-out nodes): fit view, zoom controls, minimap. Change `fitKey` to re-fit. */
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
        fitView
        fitViewOptions={{ maxZoom: 1.2 }}
        minZoom={0.05}
        nodesDraggable={false}
        nodesConnectable={false}
        edgesFocusable={false}
        // Large graphs: skip off-screen nodes (small ones render fully, which also keeps them testable in jsdom).
        onlyRenderVisibleElements={nodes.length > 400}
      >
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
