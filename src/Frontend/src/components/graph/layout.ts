import { Graph, layout } from '@dagrejs/dagre'
import type { Edge, Node } from '@xyflow/react'

export interface Size {
  width: number
  height: number
}

/**
 * Positions nodes with dagre (left-to-right by default). Node sizes come from `sizeOf` (React Flow has not measured them yet);
 * dagre returns centres, React Flow wants top-left corners.
 */
export function layoutGraph<N extends Node>(nodes: N[], edges: Edge[], sizeOf: (node: N) => Size, rankdir: 'LR' | 'TB' = 'LR'): N[] {
  const g = new Graph()
  g.setGraph({ rankdir, nodesep: 14, ranksep: 70, marginx: 10, marginy: 10 })
  g.setDefaultEdgeLabel(() => ({}))
  // Copy: dagre writes x/y into the label object, and sizes are often shared constants.
  for (const n of nodes) g.setNode(n.id, { ...sizeOf(n) })
  for (const e of edges) g.setEdge(e.source, e.target)
  layout(g)
  return nodes.map((n) => {
    const { x, y, width, height } = g.node(n.id)
    // Explicit size: controlled nodes never get `measured` back without onNodesChange, and the minimap needs dimensions.
    return { ...n, width, height, position: { x: x - width / 2, y: y - height / 2 } }
  })
}
