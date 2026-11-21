import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { useApiMutation } from './query'
import type { ImportResult, Network, NetworkInput, ScopePolicy, Zone } from './types'

export const useNetworks = () =>
  useQuery({ queryKey: ['networks'], queryFn: ({ signal }) => api<Network[]>('/api/networks', { signal }) })

export const useCreateNetwork = () =>
  useApiMutation((body: NetworkInput) => api<Network>('/api/networks', { method: 'POST', body }), [['networks'], ['zones']], {
    inlineValidation: true,
  })

export const useUpdateNetwork = () =>
  useApiMutation(
    ({ id, ...body }: NetworkInput & { id: string }) => api<Network>(`/api/networks/${id}`, { method: 'PUT', body }),
    [['networks'], ['zones']],
    { inlineValidation: true },
  )

export const useDeleteNetwork = () =>
  useApiMutation((id: string) => api(`/api/networks/${id}`, { method: 'DELETE' }), [['networks'], ['zones']])

export const useImportNetworks = () =>
  useApiMutation(
    ({ file, format }: { file: File; format: 'json' | 'csv' }) =>
      api<ImportResult>('/api/networks/import', {
        method: 'POST',
        query: { format },
        rawBody: file,
        contentType: format === 'csv' ? 'text/csv' : 'application/json',
      }),
    [['networks'], ['zones']],
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
    [['scope-policy']],
  )
