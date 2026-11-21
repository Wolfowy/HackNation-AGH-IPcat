import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { Bot, ChevronDown, ChevronRight, Network, X } from 'lucide-react'
import { useTopology } from '@/api/topology'
import type { TopologyHost } from '@/api/types'
import { EndpointLink } from '@/components/EndpointLink'
import { EmptyState, Loadable } from '@/components/feedback'
import { emptyGraphFilters, GraphCanvas, GraphFilters, GraphLegend } from '@/components/graph/GraphCanvas'
import { Chips, KeyValues, PageHeader, StatusBadge } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { t } from '@/i18n/strings'
import { formatRelative, zoneLabel } from '@/lib/format'
import { useDebounced } from '@/lib/useDebounced'
import { cn } from '@/lib/utils'
import { buildTopologyGraph, hostSize, SUBNET_COLLAPSE_THRESHOLD, type HostGridNode, type HostNode, type PerspectiveNode, type SubnetNode, type TopologyNode } from './graph'

const STATUS_STYLES: Record<TopologyHost['status'], string> = {
  Active: 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/40',
  Unreachable: 'border-amber-500 bg-amber-50 dark:bg-amber-950/40',
  Gone: 'border-zinc-400 bg-zinc-100 opacity-60 dark:bg-zinc-800',
  Unknown: 'border-slate-400 bg-card',
}
const PERSPECTIVE_STYLE = 'border-indigo-500/60 bg-indigo-50 dark:bg-indigo-950/40'
const SUBNET_STYLE = 'border-sky-500/60 bg-sky-50 dark:bg-sky-950/40'
const UNSTABLE_STYLE = 'border-dashed ring-2 ring-amber-400/70'
const MINIMAP: Record<string, string> = {
  perspective: '#6366f1',
  subnet: '#0ea5e9',
  Active: '#10b981',
  Unreachable: '#f59e0b',
  Gone: '#a1a1aa',
  Unknown: '#94a3b8',
}

function PerspectiveCard({ data: { perspective: p } }: NodeProps<PerspectiveNode>) {
  return (
    <div className={cn('h-14 w-[200px] rounded-lg border-2 px-3 py-1.5', PERSPECTIVE_STYLE)} data-testid="topology-perspective">
      <div className="flex items-center gap-1.5 truncate text-sm font-semibold">
        <Bot className="size-4 shrink-0 text-indigo-600" /> {p.agentId}
      </div>
      <div className="text-muted-foreground truncate font-mono text-xs">
        {p.interfaceName ?? 'any interface'}
        {p.zone && ` · ${p.zone}`}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  )
}

function SubnetCard({ data: { subnet, collapsed } }: NodeProps<SubnetNode>) {
  return (
    <div
      className={cn('h-14 w-[240px] cursor-pointer rounded-lg border-2 px-3 py-1.5', SUBNET_STYLE)}
      title={collapsed ? 'Click to show hosts' : 'Click to hide hosts'}
      data-testid="topology-subnet"
    >
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="flex items-center gap-1.5 truncate font-mono text-sm font-semibold">
        <Network className="size-4 shrink-0 text-sky-600" /> {zoneLabel(subnet.zone)} · {subnet.cidr}
      </div>
      <div className="text-muted-foreground flex items-center gap-1 text-xs">
        {collapsed ? <ChevronRight className="size-3" /> : <ChevronDown className="size-3" />}
        {subnet.hostCount} {subnet.hostCount === 1 ? 'host' : 'hosts'}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  )
}

function HostBubble({ data: { host: h }, selected }: NodeProps<HostNode>) {
  return (
    <div
      style={hostSize(h)}
      className={cn(
        'flex cursor-pointer flex-col justify-center rounded-2xl border-2 px-3',
        STATUS_STYLES[h.status],
        h.unstable && UNSTABLE_STYLE,
        selected && 'outline-primary outline-2 outline-offset-2',
      )}
      title={`${h.address} · ${h.status}${h.unstable ? ' · unstable' : ''} · ${h.openPortCount} open ports`}
      data-testid="topology-host"
    >
      <div className="truncate font-mono text-xs font-semibold">{h.address}</div>
      <div className="text-muted-foreground truncate text-[11px]">
        {h.openPortCount} {h.openPortCount === 1 ? 'port' : 'ports'}
        {h.hostnames[0] && ` · ${h.hostnames[0]}`}
      </div>
    </div>
  )
}

function HostGridFrame({ data: { subnet, count } }: NodeProps<HostGridNode>) {
  return (
    <div className="h-full w-full rounded-xl border border-dashed border-sky-400/60 bg-sky-50/40 dark:bg-sky-950/20" data-testid="topology-host-grid">
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="text-muted-foreground px-3 pt-1.5 font-mono text-[11px]">
        {zoneLabel(subnet.zone)} · {subnet.cidr} · {plural(count, 'host')}
      </div>
    </div>
  )
}

const nodeTypes = { perspective: PerspectiveCard, subnet: SubnetCard, host: HostBubble, hostGrid: HostGridFrame }

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`

const nodeColor = (n: TopologyNode) => (n.type === 'host' ? MINIMAP[n.data.host.status] : n.type === 'hostGrid' ? 'transparent' : MINIMAP[n.type])

function HostPanel({ host: h, onClose }: { host: TopologyHost; onClose: () => void }) {
  return (
    <Card
      className="absolute top-3 right-3 z-10 max-h-[calc(100%-1.5rem)] w-[min(24rem,calc(100%-1.5rem))] gap-3 overflow-y-auto shadow-lg"
      data-testid="topology-host-panel"
    >
      <CardHeader className="flex-row items-center justify-between gap-2">
        <CardTitle className="flex min-w-0 items-center gap-2 font-mono">
          <span className="truncate">{h.address}</span> <StatusBadge status={h.status} />
        </CardTitle>
        <Button variant="ghost" size="icon" aria-label="Close host panel" onClick={onClose}>
          <X />
        </Button>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <KeyValues
          items={[
            ['Hostnames', h.hostnames.join(', ') || '—'],
            ['MAC', <span className="font-mono">{h.macAddress ?? '—'}</span>],
            ['Vendor', h.macVendor ?? '—'],
            ['Zone', zoneLabel(h.zone)],
            ['Last seen', formatRelative(h.lastSeenAt)],
            ['Seen by', h.observedBy.map((o) => `${o.agentId}${o.interfaceName ? `/${o.interfaceName}` : ''}`).join(', ') || '—'],
          ]}
        />
        <div>
          <div className="mb-1 font-medium">Services ({h.services.length})</div>
          {h.services.length === 0 ? (
            <p className="text-muted-foreground">No open services.</p>
          ) : (
            <ul className="space-y-1">
              {h.services.map((s) => (
                <li key={`${s.port}/${s.transport}`} className="flex items-baseline justify-between gap-2">
                  <EndpointLink address={h.address} port={s.port} url={s.url} serviceName={s.serviceName} tls={s.tls} className="text-xs" />
                  <span className="text-muted-foreground truncate text-xs">
                    {[s.serviceName, s.product, s.version].filter(Boolean).join(' ')}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <div className="mb-1 font-medium">Technologies</div>
          <Chips values={h.technologies} />
        </div>
        <Link to={`/assets/hosts/${h.id}`} className="text-primary inline-block font-medium hover:underline">
          Open host details →
        </Link>
      </CardContent>
    </Card>
  )
}

/** Logical network map: which agent interface sees which subnets and hosts. */
export function TopologyPage() {
  const [filters, setFilters] = useState(emptyGraphFilters)
  const [toggled, setToggled] = useState<ReadonlySet<string>>(new Set())
  const [selectedId, setSelectedId] = useState<string>()
  const search = useDebounced(filters.search)
  const topology = useTopology({ zone: filters.zone, networkId: filters.networkId, search })

  const data = topology.data
  const view = useMemo(() => {
    if (!data) return null
    const collapsedByDefault = data.hosts.length > SUBNET_COLLAPSE_THRESHOLD
    const graph = buildTopologyGraph(data, { isCollapsed: (id) => collapsedByDefault !== toggled.has(id) })
    return { ...graph, collapsedByDefault, fitKey: `${data.hosts.length}:${data.hosts[0]?.id}:${data.hosts.at(-1)?.id}` }
  }, [data, toggled])
  const selected = data?.hosts.find((h) => h.id === selectedId)

  const toggle = (subnetId: string) =>
    setToggled((prev) => {
      const next = new Set(prev)
      if (!next.delete(subnetId)) next.add(subnetId)
      return next
    })

  return (
    <>
      <PageHeader
        title={t.topology.title}
        description="Agent interfaces → subnets (/24, /64) → hosts. Click a subnet to show or hide its hosts, a host for its services."
      />
      <GraphFilters value={filters} onChange={setFilters} />
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <GraphLegend
          items={[
            { label: 'Agent interface', swatch: PERSPECTIVE_STYLE },
            { label: 'Subnet', swatch: SUBNET_STYLE },
            { label: 'Active', swatch: STATUS_STYLES.Active },
            { label: 'Unreachable', swatch: STATUS_STYLES.Unreachable },
            { label: 'Gone', swatch: STATUS_STYLES.Gone },
            { label: 'Unstable', swatch: cn('border-dashed', STATUS_STYLES.Unknown, 'ring-1 ring-amber-400/70') },
          ]}
        />
        {view && data && (
          <span className="text-muted-foreground text-xs" data-testid="topology-summary">
            {plural(data.perspectives.length, 'perspective')} · {plural(data.subnets.length, 'subnet')} · {plural(data.hosts.length, 'host')} · larger
            hosts have more open ports
            {view.collapsedByDefault && ` · subnets collapsed (more than ${SUBNET_COLLAPSE_THRESHOLD} hosts)`}
            {data.truncated && ' · truncated to the first 5000 hosts'}
          </span>
        )}
      </div>
      <Loadable query={topology}>
        {() =>
          !view || view.nodes.length === 0 ? (
            <EmptyState>No hosts match the filters.</EmptyState>
          ) : (
            // The panel overlays the canvas so opening it does not resize (and un-fit) the graph.
            <div className="relative">
              <GraphCanvas
                testId="topology-graph"
                nodes={view.nodes}
                edges={view.edges}
                nodeTypes={nodeTypes}
                nodeColor={nodeColor}
                fitKey={view.fitKey}
                onNodeClick={(_, node) => {
                  if (node.type === 'host') setSelectedId(node.data.host.id)
                  else if (node.type === 'subnet') toggle(node.data.subnet.id)
                }}
              />
              {selected && <HostPanel host={selected} onClose={() => setSelectedId(undefined)} />}
            </div>
          )
        }
      </Loadable>
    </>
  )
}
