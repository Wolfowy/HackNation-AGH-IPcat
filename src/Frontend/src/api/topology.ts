import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from './client'
import type { Topology } from './types'

export interface TopologyParams {
  zone?: string
  networkId?: string
  search?: string
}

export const useTopology = (params: TopologyParams) =>
  useQuery({
    queryKey: ['topology', params],
    queryFn: ({ signal }) => api<Topology>('/api/topology', { query: { ...params }, signal }),
    placeholderData: keepPreviousData,
  })
