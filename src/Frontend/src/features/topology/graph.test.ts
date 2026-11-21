import type { Topology, TopologyHost } from '@/api/types'
import { buildInventoryGraph } from '@/features/assets/inventoryGraph'
import { buildTopologyGraph, gridColumns } from './graph'

const host = (id: string, address: string, subnet: string, extra: Partial<TopologyHost> = {}): TopologyHost => ({
  id,
  address,
  hostnames: [],
  status: 'Active',
  unstable: false,
  subnet,
  lastSeenAt: '2026-11-20T10:00:00Z',
  openPortCount: 0,
  services: [],
  technologies: [],
  observedBy: [],
  ...extra,
})

const web = { port: 443, transport: 'Tcp', serviceName: 'https', url: 'https://10.0.1.5:443/', isWeb: true, tls: true } as const
const ssh = { port: 22, transport: 'Tcp', serviceName: 'ssh', isWeb: false, tls: false } as const

const sample: Topology = {
  perspectives: [
    { agentId: 'a1', interfaceName: 'eth0', zone: 'dmz' },
    { agentId: 'a2', interfaceName: 'wg0', zone: 'lab' },
  ],
  subnets: [
    { id: '10.0.1.0/24', cidr: '10.0.1.0/24', zone: 'dmz', hostCount: 2 },
    { id: '2001:db8::/64', cidr: '2001:db8::/64', zone: 'lab', hostCount: 1 },
  ],
  hosts: [
    host('h1', '10.0.1.5', '10.0.1.0/24', { openPortCount: 2, services: [ssh, web], observedBy: [{ agentId: 'a1', interfaceName: 'eth0' }] }),
    host('h2', '10.0.1.9', '10.0.1.0/24', {
      status: 'Gone',
      observedBy: [
        { agentId: 'a1', interfaceName: 'eth0' },
        { agentId: 'a2', interfaceName: 'wg0' },
      ],
    }),
    host('h3', '2001:db8::7', '2001:db8::/64', { observedBy: [{ agentId: 'a2', interfaceName: 'wg0' }] }),
  ],
  truncated: false,
}

const ids = (items: { id: string }[]) => items.map((i) => i.id).sort()

describe('buildTopologyGraph', () => {
  it('connects perspectives to subnets, subnets to a grid frame holding their hosts', () => {
    const { nodes, edges } = buildTopologyGraph(sample)
    expect(ids(nodes)).toEqual(['g:10.0.1.0/24', 'g:2001:db8::/64', 'h:h1', 'h:h2', 'h:h3', 'p:a1/eth0', 'p:a2/wg0', 's:10.0.1.0/24', 's:2001:db8::/64'])
    expect(ids(edges)).toEqual([
      'p:a1/eth0->s:10.0.1.0/24',
      'p:a2/wg0->s:10.0.1.0/24',
      'p:a2/wg0->s:2001:db8::/64',
      's:10.0.1.0/24->g:10.0.1.0/24',
      's:2001:db8::/64->g:2001:db8::/64',
    ])
    expect(nodes.find((n) => n.id === 'h:h1')?.parentId).toBe('g:10.0.1.0/24')
    expect(nodes.find((n) => n.id === 'h:h3')?.parentId).toBe('g:2001:db8::/64')
    // React Flow requires parents before children
    const index = (id: string) => nodes.findIndex((n) => n.id === id)
    expect(index('g:10.0.1.0/24')).toBeLessThan(index('h:h1'))
  })

  it('lays out left to right (perspectives, then subnets, then host grids)', () => {
    const { nodes } = buildTopologyGraph(sample)
    const x = (id: string) => nodes.find((n) => n.id === id)!.position.x
    expect(x('p:a1/eth0')).toBeLessThan(x('s:10.0.1.0/24'))
    expect(x('s:10.0.1.0/24')).toBeLessThan(x('g:10.0.1.0/24'))
  })

  it('wraps many hosts into a non-overlapping grid inside the frame', () => {
    const many: Topology = {
      ...sample,
      hosts: Array.from({ length: 20 }, (_, i) => host(`m${i}`, `10.0.1.${i + 10}`, '10.0.1.0/24')),
    }
    const { nodes } = buildTopologyGraph(many)
    expect(gridColumns(20)).toBe(5)
    const hosts = nodes.filter((n) => n.type === 'host')
    expect(new Set(hosts.map((n) => `${n.position.x},${n.position.y}`)).size).toBe(20)
    expect(new Set(hosts.map((n) => n.position.x)).size).toBe(5) // 5 columns
    expect(new Set(hosts.map((n) => n.position.y)).size).toBe(4) // 4 rows
    const frame = nodes.find((n) => n.id === 'g:10.0.1.0/24')!
    const width = Number(frame.style?.width)
    expect(Math.max(...hosts.map((n) => n.position.x)) + 150).toBeLessThanOrEqual(width)
  })

  it('omits the hosts of collapsed subnets but keeps the subnet and its perspective edges', () => {
    const { nodes, edges } = buildTopologyGraph(sample, { isCollapsed: (id) => id === '10.0.1.0/24' })
    expect(ids(nodes)).toEqual(['g:2001:db8::/64', 'h:h3', 'p:a1/eth0', 'p:a2/wg0', 's:10.0.1.0/24', 's:2001:db8::/64'])
    expect(nodes.find((n) => n.id === 's:10.0.1.0/24')?.data).toMatchObject({ collapsed: true })
    expect(edges.map((e) => e.id)).toContain('p:a1/eth0->s:10.0.1.0/24')
  })
})

describe('buildInventoryGraph', () => {
  it('builds network → host → port cards', () => {
    const { nodes, edges } = buildInventoryGraph(sample)
    expect(ids(nodes)).toEqual([
      'host:h1',
      'host:h2',
      'host:h3',
      'net:10.0.1.0/24',
      'net:2001:db8::/64',
      'port:h1:22/Tcp',
      'port:h1:443/Tcp',
    ])
    expect(edges.map((e) => e.id)).toEqual(expect.arrayContaining(['net:10.0.1.0/24->host:h1', 'host:h1->port:h1:443/Tcp']))
    const x = (id: string) => nodes.find((n) => n.id === id)!.position.x
    expect(x('net:10.0.1.0/24')).toBeLessThan(x('host:h1'))
    expect(x('host:h1')).toBeLessThan(x('port:h1:443/Tcp'))
    // Same-sized cards must not share a position (dagre writes into the size objects it is given).
    expect(new Set(nodes.map((n) => `${n.position.x},${n.position.y}`)).size).toBe(nodes.length)
  })

  it('filters hosts without open ports and collapses ports', () => {
    const { nodes } = buildInventoryGraph(sample, { onlyOpen: true, isCollapsed: () => true })
    expect(ids(nodes)).toEqual(['host:h1', 'net:10.0.1.0/24'])
    expect(nodes.find((n) => n.id === 'host:h1')?.data).toMatchObject({ collapsed: true })
  })
})
