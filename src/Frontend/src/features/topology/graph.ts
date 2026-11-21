// Pure builder of the logical topology graph: scan perspectives (agent + interface) → subnets → hosts.
// A physical (L2/L3) view can get its own builder next to this one.
import type { Edge, Node } from '@xyflow/react'
import type { Topology, TopologyHost, TopologyPerspective, TopologySubnet } from '@/api/types'
import { layoutGraph } from '@/components/graph/layout'

export type PerspectiveNode = Node<{ perspective: TopologyPerspective }, 'perspective'>
export type SubnetNode = Node<{ subnet: TopologySubnet; collapsed: boolean }, 'subnet'>
export type HostNode = Node<{ host: TopologyHost }, 'host'>
/** Frame holding a subnet's hosts as a grid (hosts are its children), so large subnets stay compact and readable. */
export type HostGridNode = Node<{ subnet: TopologySubnet; count: number }, 'hostGrid'>
export type TopologyNode = PerspectiveNode | SubnetNode | HostNode | HostGridNode

/** Above this many hosts the subnets start collapsed (only subnet nodes are drawn until expanded). */
export const SUBNET_COLLAPSE_THRESHOLD = 300

export const perspectiveKey = (p: { agentId: string; interfaceName?: string }) => `p:${p.agentId}/${p.interfaceName ?? ''}`

/** Host node size grows with the number of open ports (capped). */
export const hostSize = (h: TopologyHost) => ({ width: 150, height: 40 + Math.min(h.openPortCount, 16) * 3 })

const SIZES = { perspective: { width: 200, height: 56 }, subnet: { width: 190, height: 56 } }

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
  const addEdge = (source: string, target: string, perspective = false) => {
    const id = `${source}->${target}`
    if (edgeIds.has(id)) return
    edgeIds.add(id)
    edges.push(perspective ? { id, source, target, animated: true, style: { strokeDasharray: '4 3' } } : { id, source, target })
  }
  const position = { x: 0, y: 0 }

  const perspectives = new Set<string>()
  for (const perspective of topology.perspectives) {
    const id = perspectiveKey(perspective)
    perspectives.add(id)
    nodes.push({ id, type: 'perspective', position, data: { perspective } })
  }
  for (const subnet of topology.subnets) {
    nodes.push({ id: `s:${subnet.id}`, type: 'subnet', position, data: { subnet, collapsed: isCollapsed(subnet.id) } })
  }

  const hostsBySubnet = new Map<string, TopologyHost[]>()
  for (const host of topology.hosts) {
    for (const seen of host.observedBy) if (perspectives.has(perspectiveKey(seen))) addEdge(perspectiveKey(seen), `s:${host.subnet}`, true)
    if (isCollapsed(host.subnet)) continue
    hostsBySubnet.set(host.subnet, [...(hostsBySubnet.get(host.subnet) ?? []), host])
  }

  // One grid frame per expanded subnet; dagre lays out perspectives → subnets → frames, hosts sit inside their frame.
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

  const sizeOf = (n: TopologyNode) =>
    n.type === 'hostGrid' ? frameSizes.get(n.id)! : n.type === 'host' ? hostSize(n.data.host) : SIZES[n.type]
  const laidOut = layoutGraph(nodes, edges, sizeOf).map((n) => (n.type === 'hostGrid' ? { ...n, style: frameSizes.get(n.id) } : n))
  // React Flow needs parents before their children.
  return { nodes: [...laidOut, ...children] as TopologyNode[], edges }
}
