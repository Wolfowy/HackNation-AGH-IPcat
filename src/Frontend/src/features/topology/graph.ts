// Pure builder of the hierarchical topology graph, left to right: network devices → zones (address spaces) → subnets → host grids,
// plus dashed edges from the scan perspectives (agent + interface) to the subnets they observed.
import type { Edge, Node } from '@xyflow/react'
import type { NetworkDevice, Topology, TopologyHost, TopologyPerspective, TopologySubnet, TopologyZone } from '@/api/types'
import { layoutGraph } from '@/components/graph/layout'

/** Router / L3 switch / firewall inferred from one MAC in several zones. */
export type DeviceNode = Node<{ device: NetworkDevice }, 'device'>
export type ZoneNode = Node<{ zone: TopologyZone }, 'zone'>
export type PerspectiveNode = Node<{ perspective: TopologyPerspective }, 'perspective'>
export type SubnetNode = Node<{ subnet: TopologySubnet; collapsed: boolean }, 'subnet'>
export type HostNode = Node<{ host: TopologyHost }, 'host'>
/** Frame holding a subnet's hosts as a grid (hosts are its children), so large subnets stay compact and readable. */
export type HostGridNode = Node<{ subnet: TopologySubnet; count: number }, 'hostGrid'>
export type TopologyNode = DeviceNode | ZoneNode | PerspectiveNode | SubnetNode | HostNode | HostGridNode

/** Above this many hosts the subnets start collapsed (only subnet nodes are drawn until expanded). */
export const SUBNET_COLLAPSE_THRESHOLD = 300

export const perspectiveKey = (p: { agentId: string; interfaceName?: string }) => `p:${p.agentId}/${p.interfaceName ?? ''}`
export const deviceKey = (id: string) => `d:${id}`
export const zoneKey = (zone: string) => `z:${zone}`

/** Host node size grows with the number of open ports (capped). */
export const hostSize = (h: TopologyHost) => ({ width: 150, height: 40 + Math.min(h.openPortCount, 16) * 3 })

const SIZES = {
  device: { width: 220, height: 64 },
  zone: { width: 200, height: 56 },
  perspective: { width: 200, height: 56 },
  subnet: { width: 240, height: 56 },
}
// minlen 2: perspectives skip the zone column and sit leftmost, next to the devices.
const PERSPECTIVE_EDGE: Partial<Edge> = { animated: true, style: { strokeDasharray: '4 3' }, data: { minlen: 2 } }
const LOW_CONFIDENCE_EDGE: Partial<Edge> = { style: { stroke: '#f59e0b', strokeDasharray: '6 4' } }

export interface TopologyGraphOptions {
  isCollapsed?: (subnetId: string) => boolean
}

const GRID = { padding: 12, header: 26, gap: 12, maxColumns: 6, hostWidth: 150 }

/** Grid geometry for n hosts: roughly square, at most `maxColumns` wide. */
export function gridColumns(n: number) {
  return Math.min(GRID.maxColumns, Math.max(1, Math.ceil(Math.sqrt(n))))
}

export function buildTopologyGraph(topology: Topology, { isCollapsed = () => false }: TopologyGraphOptions = {}) {
  const nodes: TopologyNode[] = []
  const edges: Edge[] = []
  const edgeIds = new Set<string>()
  const addEdge = (source: string, target: string, extra: Partial<Edge> = {}) => {
    const id = `${source}->${target}`
    if (edgeIds.has(id)) return
    edgeIds.add(id)
    edges.push({ id, source, target, ...extra })
  }
  const position = { x: 0, y: 0 }

  // Zones without devices still appear (dagre places them next to their subnets).
  const zones = new Set<string>()
  for (const zone of topology.zones) {
    zones.add(zone.name)
    nodes.push({ id: zoneKey(zone.name), type: 'zone', position, data: { zone } })
  }
  for (const device of topology.devices) {
    nodes.push({ id: deviceKey(device.id), type: 'device', position, data: { device } })
    for (const zone of device.zones) {
      if (!zones.has(zone)) continue // outside the filtered view
      const label = device.interfaces
        .filter((i) => i.zone === zone)
        .map((i) => i.address)
        .join(', ')
      addEdge(deviceKey(device.id), zoneKey(zone), { label, ...(device.confidence === 'low' && LOW_CONFIDENCE_EDGE) })
    }
  }

  const perspectives = new Set<string>()
  for (const perspective of topology.perspectives) {
    const id = perspectiveKey(perspective)
    perspectives.add(id)
    nodes.push({ id, type: 'perspective', position, data: { perspective } })
  }
  for (const subnet of topology.subnets) {
    nodes.push({ id: `s:${subnet.id}`, type: 'subnet', position, data: { subnet, collapsed: isCollapsed(subnet.id) } })
    if (zones.has(subnet.zone)) addEdge(zoneKey(subnet.zone), `s:${subnet.id}`)
  }

  const hostsBySubnet = new Map<string, TopologyHost[]>()
  for (const host of topology.hosts) {
    for (const seen of host.observedBy) if (perspectives.has(perspectiveKey(seen))) addEdge(perspectiveKey(seen), `s:${host.subnet}`, PERSPECTIVE_EDGE)
    if (isCollapsed(host.subnet)) continue
    hostsBySubnet.set(host.subnet, [...(hostsBySubnet.get(host.subnet) ?? []), host])
  }

  // One grid frame per expanded subnet; dagre lays out devices → zones → subnets → frames, hosts sit inside their frame.
  const frameSizes = new Map<string, { width: number; height: number }>()
  const children: HostNode[] = []
  for (const subnet of topology.subnets) {
    const hosts = hostsBySubnet.get(subnet.id)
    if (!hosts?.length) continue
    const frameId = `g:${subnet.id}`
    const columns = gridColumns(hosts.length)
    const rows = Math.ceil(hosts.length / columns)
    const cellHeight = Math.max(...hosts.map((h) => hostSize(h).height))
    frameSizes.set(frameId, {
      width: GRID.padding * 2 + columns * GRID.hostWidth + (columns - 1) * GRID.gap,
      height: GRID.header + GRID.padding + rows * cellHeight + (rows - 1) * GRID.gap,
    })
    nodes.push({ id: frameId, type: 'hostGrid', position, data: { subnet, count: hosts.length }, selectable: false })
    addEdge(`s:${subnet.id}`, frameId)
    hosts.forEach((host, i) => {
      const column = i % columns
      const row = Math.floor(i / columns)
      children.push({
        id: `h:${host.id}`,
        type: 'host',
        parentId: frameId,
        extent: 'parent',
        draggable: false,
        position: { x: GRID.padding + column * (GRID.hostWidth + GRID.gap), y: GRID.header + row * (cellHeight + GRID.gap) },
        data: { host },
      })
    })
  }

  // dagre ranks each connected part on its own, so a zone without devices would start a column of its own: a hidden root above
  // every zone keeps all zones (and so subnets and grids) in one column each.
  const root: ZoneNode = { id: 'root', type: 'zone', position, data: { zone: { name: '', subnetCount: 0, hostCount: 0 } } }
  const rootEdges = topology.zones.map((z) => ({ id: `root->${zoneKey(z.name)}`, source: root.id, target: zoneKey(z.name) }))
  const sizeOf = (n: TopologyNode) =>
    n === root ? { width: 0, height: 0 } : n.type === 'hostGrid' ? frameSizes.get(n.id)! : n.type === 'host' ? hostSize(n.data.host) : SIZES[n.type]
  const laidOut = layoutGraph([...nodes, root], [...edges, ...rootEdges], sizeOf)
    .filter((n) => n.id !== root.id)
    .map((n) => (n.type === 'hostGrid' ? { ...n, style: frameSizes.get(n.id) } : n))
  // React Flow needs parents before their children.
  return { nodes: [...laidOut, ...children] as TopologyNode[], edges }
}
