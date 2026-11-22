import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from './client'
import { useApiMutation } from './query'
import type {
  AssetAnnotation,
  Change,
  ChangeType,
  DashboardSummary,
  Finding,
  Host,
  HostDetail,
  HostStatus,
  ImportResult,
  Paged,
  Service,
  Severity,
  TechnologySummary,
} from './types'

export const useDashboardSummary = () =>
  useQuery({
    queryKey: ['dashboard', 'summary'],
    queryFn: ({ signal }) => api<DashboardSummary>('/api/dashboard/summary', { signal }),
    refetchInterval: 60_000,
  })

export interface HostListParams {
  search?: string
  status?: HostStatus | ''
  zone?: string
  networkDevice?: boolean
  page: number
  pageSize: number
}

export const useHosts = (params: HostListParams) =>
  useQuery({
    queryKey: ['hosts', 'list', params],
    queryFn: ({ signal }) => api<Paged<Host>>('/api/assets/hosts', { query: { ...params }, signal }),
    placeholderData: keepPreviousData,
  })

export const useHost = (id: string) =>
  useQuery({ queryKey: ['hosts', 'detail', id], queryFn: ({ signal }) => api<HostDetail>(`/api/assets/hosts/${id}`, { signal }) })

export const useUpdateAnnotation = () =>
  useApiMutation(
    ({ hostId, ...body }: AssetAnnotation & { hostId: string }) =>
      api(`/api/assets/hosts/${hostId}/annotation`, { method: 'PUT', body }),
    [['hosts']],
  )

export interface ServiceListParams {
  port?: string
  serviceName?: string
  search?: string
  page: number
  pageSize: number
}

export const useServices = (params: ServiceListParams) =>
  useQuery({
    queryKey: ['services', params],
    queryFn: ({ signal }) => api<Paged<Service>>('/api/assets/services', { query: { ...params }, signal }),
    placeholderData: keepPreviousData,
  })

export const useTechnologies = () =>
  useQuery({
    queryKey: ['technologies'],
    queryFn: ({ signal }) => api<TechnologySummary[]>('/api/assets/technologies', { signal }),
  })

export interface ChangeListParams {
  since?: string
  type?: ChangeType | ''
  hostId?: string
  scanRunId?: string
  page: number
  pageSize: number
}

export const useChanges = (params: ChangeListParams) =>
  useQuery({
    queryKey: ['changes', params],
    queryFn: ({ signal }) => api<Paged<Change>>('/api/changes', { query: { ...params }, signal }),
    placeholderData: keepPreviousData,
  })

export interface FindingListParams {
  severity?: Severity | ''
  status?: string
  page: number
  pageSize: number
}

export const useFindings = (params: FindingListParams) =>
  useQuery({
    queryKey: ['findings', params],
    queryFn: ({ signal }) => api<Paged<Finding>>('/api/findings', { query: { ...params }, signal }),
    placeholderData: keepPreviousData,
  })

export const useImportAssets = () =>
  useApiMutation(
    ({ file, format }: { file: File; format: 'json' | 'csv' }) =>
      api<ImportResult>('/api/import/assets', {
        method: 'POST',
        query: { format },
        rawBody: file,
        contentType: format === 'csv' ? 'text/csv' : 'application/json',
      }),
    [['hosts']],
  )
