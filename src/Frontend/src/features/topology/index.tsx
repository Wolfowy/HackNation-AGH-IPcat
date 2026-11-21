// Module boundary for network topology views: today the logical map (agent interfaces → subnets → hosts, `graph.ts`);
// a physical L2/L3 view can be added next to it. Everything topology-related lives in this folder; the app only imports `topologyRoute`.
import type { RouteObject } from 'react-router'

// Lazy: keeps React Flow and dagre out of the main bundle.
export const topologyRoute: RouteObject = {
  path: 'topology',
  lazy: async () => ({ Component: (await import('./TopologyPage')).TopologyPage }),
}
