import { useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { Bot, ChevronDown, ChevronRight, Layers, Network, Router, X } from 'lucide-react'
import { useTopology } from '@/api/topology'
import type { NetworkDevice, TopologyHost } from '@/api/types'
import { EndpointLink } from '@/components/EndpointLink'
import { EmptyState, Loadable } from '@/components/feedback'
import { emptyGraphFilters, GraphCanvas, GraphFilters, GraphLegend } from '@/components/graph/GraphCanvas'
import { Chips, KeyValues, PageHeader, StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { t } from '@/i18n/strings'
import { formatRelative, zoneLabel } from '@/lib/format'
import { useDebounced } from '@/lib/useDebounced'
import { cn } from '@/lib/utils'
import {
  buildTopologyGraph,
  deviceKey,
  hostSize,
  SUBNET_COLLAPSE_THRESHOLD,
  type DeviceNode,
  type HostGridNode,
  type HostNode,
  type PerspectiveNode,
  type SubnetNode,
  type TopologyNode,
  type ZoneNode,
} from './graph'

const STATUS_STYLES: Record<TopologyHost['status'], string> = {
  Active: 'border-emerald-500 bg-emerald-50 dark:bg-emerald-950/40',
  Unreachable: 'border-amber-500 bg-amber-50 dark:bg-amber-950/40',
  Gone: 'border-zinc-400 bg-zinc-100 opacity-60 dark:bg-zinc-800',
  Unknown: 'border-slate-400 bg-card',
}
const DEVICE_STYLE = 'border-violet-500/70 bg-violet-50 dark:bg-violet-950/40'
const DEVICE_LOW_STYLE = 'border-dashed border-amber-500 bg-amber-50 dark:bg-amber-950/40'
const DEVICE_INTERFACE_STYLE = 'ring-2 ring-violet-500/70'
const LOW_CONFIDENCE_HINT = 'Locally administered MAC — may be a coincidence'
const ZONE_STYLE = 'border-teal-500/60 bg-teal-50 dark:bg-teal-950/40'
const PERSPECTIVE_STYLE = 'border-indigo-500/60 bg-indigo-50 dark:bg-indigo-950/40'
const SUBNET_STYLE = 'border-sky-500/60 bg-sky-50 dark:bg-sky-950/40'
const UNSTABLE_STYLE = 'border-dashed ring-2 ring-amber-400/70'
const MINIMAP: Record<string, string> = {
  device: '#8b5cf6',
  zone: '#14b8a6',
  perspective: '#6366f1',
  subnet: '#0ea5e9',
  Active: '#10b981',
  Unreachable: '#f59e0b',
  Gone: '#a1a1aa',
  Unknown: '#94a3b8',
}

function DeviceCard({ data: { device: d } }: NodeProps<DeviceNode>) {
  const low = d.confidence === 'low'
  return (
    <div
      className={cn('h-16 w-[220px] cursor-pointer rounded-lg border-2 px-3 py-1.5', low ? DEVICE_LOW_STYLE : DEVICE_STYLE)}
      title={low ? LOW_CONFIDENCE_HINT : `Network device: the same MAC in ${plural(d.zones.length, 'zone')}`}
      data-testid="topology-device"
    >
      <div className="flex items-center gap-1.5 truncate font-mono text-sm font-semibold">
        <Router className={cn('size-4 shrink-0', low ? 'text-amber-600' : 'text-violet-600')} /> {d.macAddress}
      </div>
      <div className="text-muted-foreground truncate text-xs">
        {d.macVendor ?? 'Unknown vendor'} · {plural(d.zones.length, 'zone')}
        {low && ' · low confidence'}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  )
}

function ZoneCard({ data: { zone: z } }: NodeProps<ZoneNode>) {
  return (
    <div className={cn('h-14 w-[200px] rounded-lg border-2 px-3 py-1.5', ZONE_STYLE)} title="Zone: a separate IP address space" data-testid="topology-zone">
      <Handle type="target" position={Position.Left} isConnectable={false} />
      <div className="flex items-center gap-1.5 truncate text-sm font-semibold">
        <Layers className="size-4 shrink-0 text-teal-600" /> {zoneLabel(z.name)}
      </div>
      <div className="text-muted-foreground truncate text-xs">
        {plural(z.subnetCount, 'subnet')} · {plural(z.hostCount, 'host')}
      </div>
      <Handle type="source" position={Position.Right} isConnectable={false} />
    </div>
  )
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
        h.deviceId && DEVICE_INTERFACE_STYLE,
        h.unstable && UNSTABLE_STYLE,
        selected && 'outline-primary outline-2 outline-offset-2',
      )}
      title={`${h.address} · ${h.status}${h.unstable ? ' · unstable' : ''}${h.deviceId ? ' · network device interface' : ''} · ${h.openPortCount} open ports`}
      data-testid="topology-host"
    >
      <div className="flex items-center gap-1 truncate font-mono text-xs font-semibold">
        {h.deviceId && <Router className="size-3 shrink-0 text-violet-600" aria-label="network device interface" />}
        {h.address}
      </div>
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

const nodeTypes = { device: DeviceCard, zone: ZoneCard, perspective: PerspectiveCard, subnet: SubnetCard, host: HostBubble, hostGrid: HostGridFrame }

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`

const nodeColor = (n: TopologyNode) => (n.type === 'host' ? MINIMAP[n.data.host.status] : n.type === 'hostGrid' ? 'transparent' : MINIMAP[n.type])

interface SidePanelProps {
  title: ReactNode
  kind: 'host' | 'device'
  onClose: () => void
  children: ReactNode
}

/** Overlays the canvas so opening it does not resize (and un-fit) the graph. */
function SidePanel({ title, kind, onClose, children }: SidePanelProps) {
  return (
    <Card
      className="absolute top-3 right-3 z-10 max-h-[calc(100%-1.5rem)] w-[min(24rem,calc(100%-1.5rem))] gap-3 overflow-y-auto shadow-lg"
      data-testid={`topology-${kind}-panel`}
    >
      <CardHeader className="flex-row items-center justify-between gap-2">
        <CardTitle className="flex min-w-0 items-center gap-2 font-mono">{title}</CardTitle>
        <Button variant="ghost" size="icon" aria-label={`Close ${kind} panel`} onClick={onClose}>
          <X />
        </Button>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">{children}</CardContent>
    </Card>
  )
}

function DevicePanel({ device: d, onClose }: { device: NetworkDevice; onClose: () => void }) {
  const low = d.confidence === 'low'
  return (
    <SidePanel
      kind="device"
      onClose={onClose}
      title={
        <>
          <Router className="size-4 shrink-0" /> <span className="truncate">{d.macAddress}</span>
          {low && <Badge variant="warning">low confidence</Badge>}
        </>
      }
    >
      <KeyValues
        items={[
          ['Vendor', d.macVendor ?? '—'],
          ['Zones', d.zones.map(zoneLabel).join(', ')],
        ]}
      />
      <p className="text-muted-foreground text-xs">
        {low
          ? `${LOW_CONFIDENCE_HINT} (Docker and VM interfaces reuse such MACs).`
          : 'The same MAC answers in several zones: interfaces of one router, L3 switch or firewall.'}
      </p>
      <div>
        <div className="mb-1 font-medium">Interfaces ({d.interfaces.length})</div>
        <ul className="space-y-1">
          {d.interfaces.map((i) => (
            <li key={i.hostId} className="flex items-baseline justify-between gap-2">
              <Link to={`/assets/hosts/${i.hostId}`} className="text-primary font-mono text-xs hover:underline">
                {i.address}
              </Link>
              <span className="text-muted-foreground text-xs">{zoneLabel(i.zone)}</span>
            </li>
          ))}
        </ul>
      </div>
    </SidePanel>
  )
}

function HostPanel({ host: h, onClose }: { host: TopologyHost; onClose: () => void }) {
  return (
    <SidePanel
      kind="host"
      onClose={onClose}
      title={
        <>
          <span className="truncate">{h.address}</span> <StatusBadge status={h.status} />
        </>
      }
    >
      <KeyValues
        items={[
          ['Hostnames', h.hostnames.join(', ') || '—'],
          [
            'MAC',
            <span className="font-mono">
              {h.macAddress ?? '—'}
              {h.sharedMac && ' (also on other IPs of this zone)'}
            </span>,
          ],
          ['Network device', h.deviceId ? <span className="font-mono">{h.deviceId}</span> : '—'],
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
    </SidePanel>
  )
}

/** Hierarchical network map: devices link zones (address spaces), zones hold subnets and hosts; dashed edges show the scanning agent interfaces. */
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
  const selected = data?.hosts.find((h) => `h:${h.id}` === selectedId)
  const selectedDevice = data?.devices.find((d) => deviceKey(d.id) === selectedId)

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
        description="Network devices → zones (address spaces) → subnets (/24, /64) → hosts; dashed lines: the agent interface that scanned a subnet. Click a subnet to show or hide its hosts, a host or device for details."
      />
      <GraphFilters value={filters} onChange={setFilters} />
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <GraphLegend
          items={[
            { label: 'Network device', swatch: DEVICE_STYLE },
            { label: 'Device (low confidence)', swatch: DEVICE_LOW_STYLE },
            { label: 'Zone', swatch: ZONE_STYLE },
            { label: 'Agent interface', swatch: PERSPECTIVE_STYLE },
            { label: 'Subnet', swatch: SUBNET_STYLE },
            { label: 'Active', swatch: STATUS_STYLES.Active },
            { label: 'Unreachable', swatch: STATUS_STYLES.Unreachable },
            { label: 'Gone', swatch: STATUS_STYLES.Gone },
            { label: 'Unstable', swatch: cn('border-dashed', STATUS_STYLES.Unknown, 'ring-1 ring-amber-400/70') },
            { label: 'Device interface', swatch: cn(STATUS_STYLES.Unknown, 'ring-1 ring-violet-500/70') },
          ]}
        />
        {view && data && (
          <span className="text-muted-foreground text-xs" data-testid="topology-summary">
            {plural(data.devices.length, 'network device')} · {plural(data.zones.length, 'zone')} · {plural(data.perspectives.length, 'perspective')} ·{' '}
            {plural(data.subnets.length, 'subnet')} · {plural(data.hosts.length, 'host')} · larger
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
                  if (node.type === 'host' || node.type === 'device') setSelectedId(node.id)
                  else if (node.type === 'subnet') toggle(node.data.subnet.id)
                }}
              />
              {selected && <HostPanel host={selected} onClose={() => setSelectedId(undefined)} />}
              {selectedDevice && <DevicePanel device={selectedDevice} onClose={() => setSelectedId(undefined)} />}
            </div>
          )
        }
      </Loadable>
    </>
  )
}
