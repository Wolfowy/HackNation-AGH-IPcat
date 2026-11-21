import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from './client'
import { useApiMutation } from './query'
import type {
  JobStatus,
  Paged,
  PlannerStats,
  ScanDiff,
  ScanExecutionEvent,
  ScanJob,
  ScanLimits,
  ScanRun,
  ScanRunDetail,
  ScanRunStatus,
  ScanStartRequest,
} from './types'

export interface ScanListParams {
  status?: ScanRunStatus | ''
  page: number
  pageSize: number
}

export const useScans = (params: ScanListParams) =>
  useQuery({
    queryKey: ['scans', 'list', params],
    queryFn: ({ signal }) => api<Paged<ScanRun>>('/api/scans', { query: { ...params }, signal }),
    placeholderData: keepPreviousData,
  })

export const useScan = (id: string) =>
  useQuery({ queryKey: ['scans', 'detail', id], queryFn: ({ signal }) => api<ScanRunDetail>(`/api/scans/${id}`, { signal }) })

export const useScanJobs = (id: string) =>
  useQuery({
    queryKey: ['scans', 'jobs', id],
    queryFn: ({ signal }) => api<ScanJob[] | Paged<ScanJob>>(`/api/scans/${id}/jobs`, { signal }),
  })

export const useScanEvents = (id: string) =>
  useQuery({
    queryKey: ['scans', 'events', id],
    queryFn: ({ signal }) => api<ScanExecutionEvent[]>(`/api/scans/${id}/events`, { signal }),
  })

export const useScanDiff = (id: string, baseline: string) =>
  useQuery({
    queryKey: ['scans', 'diff', id, baseline],
    queryFn: ({ signal }) => api<ScanDiff>(`/api/scans/${id}/diff`, { query: { baseline }, signal }),
    enabled: Boolean(id && baseline),
  })

export const useStartScan = () =>
  useApiMutation((body: ScanStartRequest) => api<ScanRun>('/api/scans', { method: 'POST', body }), [['scans'], ['dashboard']], {
    inlineValidation: true,
  })

export const useCancelScan = () =>
  useApiMutation((id: string) => api(`/api/scans/${id}/cancel`, { method: 'POST' }), [['scans'], ['jobs']])

export interface JobListParams {
  status?: JobStatus | ''
  agentId?: string
  page: number
  pageSize: number
}

export const useJobs = (params: JobListParams) =>
  useQuery({
    queryKey: ['jobs', params],
    queryFn: ({ signal }) => api<Paged<ScanJob>>('/api/jobs', { query: { ...params }, signal }),
    placeholderData: keepPreviousData,
  })

export const useCancelJob = () =>
  useApiMutation((id: string) => api(`/api/jobs/${id}/cancel`, { method: 'POST' }), [['jobs'], ['scans']])

export const useRetryJob = () =>
  useApiMutation((id: string) => api(`/api/jobs/${id}/retry`, { method: 'POST' }), [['jobs'], ['scans']])

export const useScanLimits = () =>
  useQuery({ queryKey: ['scan-limits'], queryFn: ({ signal }) => api<ScanLimits>('/api/scan-limits', { signal }) })

export const useUpdateScanLimits = () =>
  useApiMutation((body: ScanLimits) => api('/api/scan-limits', { method: 'PUT', body }), [['scan-limits']], {
    inlineValidation: true,
  })

export const usePlannerStats = () =>
  useQuery({ queryKey: ['stats', 'planner'], queryFn: ({ signal }) => api<PlannerStats>('/api/stats/planner', { signal }) })
