import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api } from './client'
import { useApiMutation } from './query'
import type { AuditEntry, DefectDojoConfig, DefectDojoExportResult, Paged, Settings, User, UserCreate, UserUpdate } from './types'

export const useUsers = () => useQuery({ queryKey: ['users'], queryFn: ({ signal }) => api<User[]>('/api/users', { signal }) })

export const useCreateUser = () =>
  useApiMutation((body: UserCreate) => api<User>('/api/users', { method: 'POST', body }), [['users']], { inlineValidation: true })

export const useUpdateUser = () =>
  useApiMutation(
    ({ id, ...body }: UserUpdate & { id: string }) => api<User>(`/api/users/${id}`, { method: 'PUT', body }),
    [['users']],
    { inlineValidation: true },
  )

export const useDeleteUser = () => useApiMutation((id: string) => api(`/api/users/${id}`, { method: 'DELETE' }), [['users']])

export const useResetPassword = () =>
  useApiMutation(
    ({ id, password }: { id: string; password: string }) => api(`/api/users/${id}/password`, { method: 'POST', body: { password } }),
    [],
  )

export interface AuditParams {
  action?: string
  entityType?: string
  userId?: string
  page: number
  pageSize: number
}

export const useAudit = (params: AuditParams) =>
  useQuery({
    queryKey: ['audit', params],
    queryFn: ({ signal }) => api<Paged<AuditEntry>>('/api/audit', { query: { ...params }, signal }),
    placeholderData: keepPreviousData,
  })

export const useSettings = () =>
  useQuery({ queryKey: ['settings'], queryFn: ({ signal }) => api<Settings>('/api/settings', { signal }) })

export const useUpdateSettings = () =>
  useApiMutation((body: Settings) => api('/api/settings', { method: 'PUT', body }), [['settings']])

export const useDefectDojo = () =>
  useQuery({
    queryKey: ['integrations', 'defectdojo'],
    queryFn: ({ signal }) => api<DefectDojoConfig>('/api/integrations/defectdojo', { signal }),
  })

export const useUpdateDefectDojo = () =>
  useApiMutation(
    (body: DefectDojoConfig) => api('/api/integrations/defectdojo', { method: 'PUT', body }),
    [['integrations']],
    { inlineValidation: true },
  )

export const useTestDefectDojo = () =>
  useApiMutation(() => api<{ ok: boolean; message?: string }>('/api/integrations/defectdojo/test', { method: 'POST' }), [])

export const useExportToDefectDojo = () =>
  useApiMutation(
    (findingIds: string[]) =>
      api<DefectDojoExportResult>('/api/integrations/defectdojo/export', { method: 'POST', body: { findingIds } }),
    [['findings']],
  )
