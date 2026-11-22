import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from './client'
import { useApiMutation } from './query'
import {
  ACTIVE_RUN_STATUSES,
  type JobStatus,
  type Paged,
  type PlannerStats,
  type ScanDiff,
  type ScanEstimate,
  type ScanEstimateRequest,
  type ScanExecutionEvent,
  type ScanImportFormat,
  type ScanImportResult,
  type ScanJob,
  type ScanLimits,
  type ScanRun,
  type ScanRunDetail,
  type ScanRunStatus,
  type ScanRunUpdate,
  type ScanStartRequest,
} from './types'

/** Polling fallback while something shown is still active (live hub events can be missed, e.g. while reconnecting). */
const ACTIVE_POLL_MS = 5000

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
    refetchInterval: (q) => (q.state.data?.items.some((r) => ACTIVE_RUN_STATUSES.includes(r.status)) ? ACTIVE_POLL_MS : false),
  })

export const useScan = (id: string) =>
  useQuery({ queryKey: ['scans', 'detail', id], queryFn: ({ signal }) => api<ScanRunDetail>(`/api/scans/${id}`, { signal }) })

export const useScanJobs = (id: string, page: number, pageSize: number) =>
  useQuery({
    queryKey: ['scans', 'jobs', id, { page, pageSize }],
    queryFn: ({ signal }) => api<Paged<ScanJob>>(`/api/scans/${id}/jobs`, { query: { page, pageSize }, signal }),
    placeholderData: keepPreviousData,
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

/** Live estimate while a scan or schedule is being configured (null = not enough input yet). */
export const useScanEstimate = (request: ScanEstimateRequest | null) =>
  useQuery({
    queryKey: ['scans', 'estimate', request],
    queryFn: ({ signal }) => api<ScanEstimate>('/api/scans/estimate', { method: 'POST', body: request, signal }),
    enabled: request !== null,
    placeholderData: keepPreviousData,
  })

export const useStartScan = () =>
  useApiMutation((body: ScanStartRequest) => api<ScanRun>('/api/scans', { method: 'POST', body }), [['scans'], ['dashboard']], {
    inlineValidation: true,
  })

export const useUpdateScan = () =>
  useApiMutation(({ id, ...body }: ScanRunUpdate & { id: string }) => api<ScanRun>(`/api/scans/${id}`, { method: 'PUT', body }), [['scans']], {
    inlineValidation: true,
  })

export interface ScanImportParams {
  file: File
  format: ScanImportFormat
  zone: string
  name?: string
  snapshot: boolean
}

const importContentTypes: Record<ScanImportFormat, string> = {
  json: 'application/json',
  csv: 'text/csv',
  'nmap-xml': 'application/xml',
  'httpx-jsonl': 'application/x-ndjson',
  'naabu-jsonl': 'application/x-ndjson',
  'nuclei-jsonl': 'application/x-ndjson',
}

/** Imports scan results as a finished "import" run (same pipeline as agent results: assets, findings, change detection). */
export const useImportScan = () =>
  useApiMutation(
    ({ file, format, zone, name, snapshot }: ScanImportParams) =>
      api<ScanImportResult>('/api/scans/import', {
        method: 'POST',
        query: { format, zone, name, snapshot },
        rawBody: file,
        contentType: importContentTypes[format],
      }),
    [['scans'], ['hosts'], ['services'], ['findings'], ['changes'], ['dashboard']],
    { inlineValidation: true },
  )

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
    refetchInterval: (q) => (q.state.data?.items.some((j) => j.status === 'Queued' || j.status === 'Leased') ? ACTIVE_POLL_MS : false),
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
