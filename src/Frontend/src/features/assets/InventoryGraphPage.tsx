import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import { useNavigate } from 'react-router'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { ChevronDown, ChevronRight, Globe, Network, Server } from 'lucide-react'
import { useTopology } from '@/api/topology'
import { EndpointLink } from '@/components/EndpointLink'
import { EmptyState, Loadable } from '@/components/feedback'
import { emptyGraphFilters, GraphCanvas, GraphFilters, GraphLegend } from '@/components/graph/GraphCanvas'
import { PageHeader, StatusBadge } from '@/components/page'
import { t } from '@/i18n/strings'
import { zoneLabel } from '@/lib/format'
import { useDebounced } from '@/lib/useDebounced'
import { cn } from '@/lib/utils'
import { UnstableBadge } from './HostsPage'
import { buildInventoryGraph, COLLAPSE_THRESHOLD, type HostNode, type InventoryNode, type NetworkNode, type PortNode } from './inventoryGraph'

const STYLES = {
  network: 'border-sky-500/60 bg-sky-50 dark:bg-sky-950/40',
  host: 'border-violet-500/50 bg-card',
  port: 'border-amber-500/50 bg-amber-50 dark:bg-amber-950/30',
  web: 'border-emerald-500/70 bg-emerald-50 dark:bg-emerald-950/40',
}
const MINIMAP = { network: '#0ea5e9', host: '#8b5cf6', port: '#f59e0b', web: '#10b981' }

const ToggleHost = createContext<(hostId: string) => void>(() => {})

function NetworkCard({ data }: NodeProps<NetworkNode>) {
  return (
    <div className={cn('h-16 w-[250px] rounded-lg border-2 px-3 py-2', STYLES.network)} data-testid="graph-network">
      <div className="flex items-center gap-1.5 truncate font-mono text-sm font-semibold">
        <Network className="size-4 shrink-0 text-sky-600" /> {zoneLabel(data.subnet.zone)} · {data.subnet.cidr}
      </div>
      <div className="text-muted-foreground text-xs">
        {data.hostCount} {data.hostCount === 1 ? 'host' : 'hosts'}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  )
}

function HostCard({ data: { host: h, collapsed } }: NodeProps<HostNode>) {
  const toggle = useContext(ToggleHost)
  const details = [h.hostnames[0], h.macAddress, h.macVendor].filter(Boolean).join(' · ')
  return (
    <div
      className={cn('h-[88px] w-[240px] cursor-pointer rounded-lg border-2 px-3 py-2 shadow-xs', STYLES.host, h.status === 'Gone' && 'opacity-60')}
      title="Open host details"
      data-testid="graph-host"
    >
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="flex items-center justify-between gap-2">
        <span className="flex min-w-0 items-center gap-1.5 font-mono text-sm font-semibold">
          <Server className="size-4 shrink-0 text-violet-600" />
          <span className="truncate">{h.address}</span>
        </span>
        <StatusBadge status={h.status} />
      </div>
      <div className="text-muted-foreground truncate text-xs">{details || '—'}</div>
      <div className="mt-1 flex items-center justify-between gap-2 text-xs">
        <span className="flex items-center gap-1">
          {h.openPortCount} open {h.openPortCount === 1 ? 'port' : 'ports'} {h.unstable && <UnstableBadge />}
        </span>
        {h.services.length > 0 && (
          <button
            type="button"
            className="nodrag text-primary inline-flex items-center gap-0.5 rounded px-1 hover:underline"
            aria-expanded={!collapsed}
            aria-label={`${collapsed ? 'Show' : 'Hide'} ports of ${h.address}`}
            onClick={(e) => {
              e.stopPropagation()
              toggle(h.id)
            }}
          >
            {collapsed ? <ChevronRight className="size-3" /> : <ChevronDown className="size-3" />}
            {collapsed ? 'ports' : 'hide'}
          </button>
        )}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  )
}

function PortCard({ data: { host, service: s } }: NodeProps<PortNode>) {
  return (
    <div className={cn('h-16 w-[240px] rounded-lg border-2 px-3 py-1.5', s.isWeb ? STYLES.web : STYLES.port)} data-testid="graph-port">
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="flex items-center gap-1.5 text-sm font-semibold">
        {s.isWeb && <Globe className="size-3.5 shrink-0 text-emerald-600" aria-label="web server" />}
        <span className="font-mono">
          {s.port}/{s.transport.toLowerCase()}
        </span>
        <span className="truncate">{s.serviceName ?? 'unknown'}</span>
      </div>
      <div className="text-muted-foreground truncate text-xs">{[s.product, s.version].filter(Boolean).join(' ') || '—'}</div>
      <EndpointLink className="nodrag text-primary text-xs" address={host.address} port={s.port} url={s.url} serviceName={s.serviceName} tls={s.tls} />
    </div>
  )
}

const nodeTypes = { network: NetworkCard, host: HostCard, port: PortCard }

const nodeColor = (n: InventoryNode) => (n.type === 'port' && n.data.service.isWeb ? MINIMAP.web : MINIMAP[n.type])

/** Inventory as a left-to-right tree: network (subnet) cards → host cards → port cards. */
export function InventoryGraphPage() {
  const [filters, setFilters] = useState(emptyGraphFilters)
  const [onlyOpen, setOnlyOpen] = useState(false)
  // Hosts whose ports are toggled away from the default (collapsed above the threshold, expanded below).
  const [toggled, setToggled] = useState<ReadonlySet<string>>(new Set())
  const search = useDebounced(filters.search)
  const topology = useTopology({ zone: filters.zone, networkId: filters.networkId, search })
  const navigate = useNavigate()
  const toggle = useCallback(
    (id: string) =>
      setToggled((prev) => {
        const next = new Set(prev)
        if (!next.delete(id)) next.add(id)
        return next
      }),
    [],
  )

  const data = topology.data
  const view = useMemo(() => {
    if (!data) return null
    const hosts = data.hosts.filter((h) => !onlyOpen || h.openPortCount > 0)
    const collapsedByDefault = hosts.length > COLLAPSE_THRESHOLD
    const graph = buildInventoryGraph(data, { onlyOpen, isCollapsed: (id) => collapsedByDefault !== toggled.has(id) })
    return { ...graph, hosts, collapsedByDefault, fitKey: `${onlyOpen}:${hosts.length}:${hosts[0]?.id}:${hosts.at(-1)?.id}` }
  }, [data, onlyOpen, toggled])

  return (
    <>
      <PageHeader title={t.assets.graph} description="Networks → hosts → open ports. Click a host card for details; port cards open the endpoint in a new tab." />
      <GraphFilters value={filters} onChange={setFilters}>
        <label className="flex h-9 items-center gap-2 text-sm">
          <input type="checkbox" className="accent-primary size-4" checked={onlyOpen} onChange={(e) => setOnlyOpen(e.target.checked)} />
          Only hosts with open ports
        </label>
      </GraphFilters>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <GraphLegend
          items={[
            { label: 'Network', swatch: STYLES.network },
            { label: 'Host', swatch: STYLES.host },
            { label: 'Port', swatch: STYLES.port },
            { label: 'Web server', swatch: STYLES.web },
          ]}
        />
        {view && (
          <span className="text-muted-foreground text-xs" data-testid="graph-summary">
            {view.hosts.length} hosts{view.collapsedByDefault && ` · ports collapsed (more than ${COLLAPSE_THRESHOLD} hosts)`}
            {data?.truncated && ' · truncated to the first 5000 hosts'}
          </span>
        )}
      </div>
      <Loadable query={topology}>
        {() =>
          !view || view.nodes.length === 0 ? (
            <EmptyState>No hosts match the filters.</EmptyState>
          ) : (
            <ToggleHost.Provider value={toggle}>
              <GraphCanvas
                testId="inventory-graph"
                nodes={view.nodes}
                edges={view.edges}
                nodeTypes={nodeTypes}
                nodeColor={nodeColor}
                fitKey={view.fitKey}
                onNodeClick={(_, node) => node.type === 'host' && navigate(`/assets/hosts/${node.data.host.id}`)}
              />
            </ToggleHost.Provider>
          )
        }
      </Loadable>
    </>
  )
}
