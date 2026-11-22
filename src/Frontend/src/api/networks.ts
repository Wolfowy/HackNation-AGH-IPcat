import { useQuery } from '@tanstack/react-query'
import { api, errorMessage } from './client'
import { useApiMutation } from './query'
import type { AgentSubnet, ImportResult, Network, NetworkInput, ScopePolicy, Zone } from './types'

export const useNetworks = () =>
  useQuery({ queryKey: ['networks'], queryFn: ({ signal }) => api<Network[]>('/api/networks', { signal }) })

export const useCreateNetwork = () =>
  useApiMutation((body: NetworkInput) => api<Network>('/api/networks', { method: 'POST', body }), [['networks'], ['zones'], ['agent-subnets']], {
    inlineValidation: true,
  })

export const useUpdateNetwork = () =>
  useApiMutation(
    ({ id, ...body }: NetworkInput & { id: string }) => api<Network>(`/api/networks/${id}`, { method: 'PUT', body }),
    [['networks'], ['zones'], ['agent-subnets']],
    { inlineValidation: true },
  )

export const useDeleteNetwork = () =>
  useApiMutation((id: string) => api(`/api/networks/${id}`, { method: 'DELETE' }), [['networks'], ['zones'], ['agent-subnets']])

export const useImportNetworks = () =>
  useApiMutation(
    ({ file, format }: { file: File; format: 'json' | 'csv' }) =>
      api<ImportResult>('/api/networks/import', {
        method: 'POST',
        query: { format },
        rawBody: file,
        contentType: format === 'csv' ? 'text/csv' : 'application/json',
      }),
    [['networks'], ['zones'], ['agent-subnets']],
  )

export const useZones = () => useQuery({ queryKey: ['zones'], queryFn: ({ signal }) => api<Zone[]>('/api/zones', { signal }) })

export const useCreateZone = () =>
  useApiMutation((body: { name: string; description?: string }) => api('/api/zones', { method: 'POST', body }), [['zones']])

export const useDeleteZone = () =>
  useApiMutation((name: string) => api(`/api/zones/${encodeURIComponent(name)}`, { method: 'DELETE' }), [['zones']])

export const useScopePolicy = () =>
  useQuery({ queryKey: ['scope-policy'], queryFn: ({ signal }) => api<ScopePolicy>('/api/scope-policy', { signal }) })

export const useUpdateScopePolicy = () =>
  useApiMutation(
    (body: Pick<ScopePolicy, 'allowed' | 'excluded'>) => api<ScopePolicy>('/api/scope-policy', { method: 'PUT', body }),
    [['scope-policy'], ['agent-subnets']],
  )

export const useAgentSubnets = () =>
  useQuery({ queryKey: ['agent-subnets'], queryFn: ({ signal }) => api<AgentSubnet[]>('/api/networks/agent-subnets', { signal }) })

/** Creates several networks; failures are collected (not thrown) so the successful ones still count. */
export const useCreateNetworks = () =>
  useApiMutation(
    async (inputs: NetworkInput[]) => {
      const results = await Promise.allSettled(inputs.map((body) => api<Network>('/api/networks', { method: 'POST', body })))
      return {
        created: results.filter((r) => r.status === 'fulfilled').length,
        errors: results.flatMap((r, i) => (r.status === 'rejected' ? [`${inputs[i].name}: ${errorMessage(r.reason)}`] : [])),
      }
    },
    [['networks'], ['zones'], ['agent-subnets']],
  )
