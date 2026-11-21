// Pure builder of the inventory graph (network → hosts → ports) from the topology read model.
import type { Edge, Node } from '@xyflow/react'
import type { Topology, TopologyHost, TopologyService, TopologySubnet } from '@/api/types'
import { layoutGraph } from '@/components/graph/layout'

export type NetworkNode = Node<{ subnet: TopologySubnet; hostCount: number }, 'network'>
export type HostNode = Node<{ host: TopologyHost; collapsed: boolean }, 'host'>
export type PortNode = Node<{ host: TopologyHost; service: TopologyService }, 'port'>
export type InventoryNode = NetworkNode | HostNode | PortNode

/** Above this many hosts the port cards start collapsed. */
export const COLLAPSE_THRESHOLD = 50

export const NODE_SIZES = {
  network: { width: 250, height: 64 },
  host: { width: 240, height: 88 },
  port: { width: 240, height: 64 },
} as const

export interface InventoryGraphOptions {
  /** Hide hosts without open ports. */
  onlyOpen?: boolean
  isCollapsed?: (hostId: string) => boolean
}

const edge = (source: string, target: string): Edge => ({ id: `${source}->${target}`, source, target })

export function buildInventoryGraph(topology: Topology, { onlyOpen = false, isCollapsed = () => false }: InventoryGraphOptions = {}) {
  const hosts = topology.hosts.filter((h) => !onlyOpen || h.openPortCount > 0)
  const bySubnet = new Map<string, TopologyHost[]>()
  for (const h of hosts) {
    const list = bySubnet.get(h.subnet)
    if (list) list.push(h)
    else bySubnet.set(h.subnet, [h])
  }
  const nodes: InventoryNode[] = []
  const edges: Edge[] = []
  const position = { x: 0, y: 0 }
  for (const subnet of topology.subnets) {
    const members = bySubnet.get(subnet.id)
    if (!members) continue
    const netId = `net:${subnet.id}`
    nodes.push({ id: netId, type: 'network', position, data: { subnet, hostCount: members.length } })
    for (const host of members) {
      const hostId = `host:${host.id}`
      const collapsed = isCollapsed(host.id)
      nodes.push({ id: hostId, type: 'host', position, data: { host, collapsed } })
      edges.push(edge(netId, hostId))
      if (collapsed) continue
      for (const service of host.services) {
        const portId = `port:${host.id}:${service.port}/${service.transport}`
        nodes.push({ id: portId, type: 'port', position, data: { host, service } })
        edges.push(edge(hostId, portId))
      }
    }
  }
  return { nodes: layoutGraph(nodes, edges, (n) => NODE_SIZES[n.type]), edges }
}
