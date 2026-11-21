// Pure builder of the logical topology graph: scan perspectives (agent + interface) → subnets → hosts.
// A physical (L2/L3) view can get its own builder next to this one.
import type { Edge, Node } from '@xyflow/react'
import type { Topology, TopologyHost, TopologyPerspective, TopologySubnet } from '@/api/types'
import { layoutGraph } from '@/components/graph/layout'

export type PerspectiveNode = Node<{ perspective: TopologyPerspective }, 'perspective'>
export type SubnetNode = Node<{ subnet: TopologySubnet; collapsed: boolean }, 'subnet'>
export type HostNode = Node<{ host: TopologyHost }, 'host'>
export type TopologyNode = PerspectiveNode | SubnetNode | HostNode

/** Above this many hosts the subnets start collapsed (only subnet nodes are drawn until expanded). */
export const SUBNET_COLLAPSE_THRESHOLD = 300

export const perspectiveKey = (p: { agentId: string; interfaceName?: string }) => `p:${p.agentId}/${p.interfaceName ?? ''}`

/** Host node size grows with the number of open ports (capped). */
export const hostSize = (h: TopologyHost) => ({ width: 150, height: 40 + Math.min(h.openPortCount, 16) * 3 })

const SIZES = { perspective: { width: 200, height: 56 }, subnet: { width: 190, height: 56 } }

export interface TopologyGraphOptions {
  isCollapsed?: (subnetId: string) => boolean
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
  const collapsed = new Set(topology.subnets.filter((s) => isCollapsed(s.id)).map((s) => s.id))
  for (const host of topology.hosts) {
    const subnetId = `s:${host.subnet}`
    for (const seen of host.observedBy) if (perspectives.has(perspectiveKey(seen))) addEdge(perspectiveKey(seen), subnetId, true)
    if (collapsed.has(host.subnet)) continue
    const id = `h:${host.id}`
    nodes.push({ id, type: 'host', position, data: { host } })
    addEdge(subnetId, id)
  }
  const sizeOf = (n: TopologyNode) => (n.type === 'host' ? hostSize(n.data.host) : SIZES[n.type])
  return { nodes: layoutGraph(nodes, edges, sizeOf), edges }
}
