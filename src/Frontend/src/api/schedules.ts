import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { useApiMutation } from './query'
import type { Schedule, ScheduleInput } from './types'

export const useSchedules = () =>
  useQuery({ queryKey: ['schedules'], queryFn: ({ signal }) => api<Schedule[]>('/api/schedules', { signal }) })

export const useCreateSchedule = () =>
  useApiMutation((body: ScheduleInput) => api<Schedule>('/api/schedules', { method: 'POST', body }), [['schedules']], {
    inlineValidation: true,
  })

export const useUpdateSchedule = () =>
  useApiMutation(
    ({ id, ...body }: ScheduleInput & { id: string }) => api<Schedule>(`/api/schedules/${id}`, { method: 'PUT', body }),
    [['schedules']],
    { inlineValidation: true },
  )

export const useDeleteSchedule = () =>
  useApiMutation((id: string) => api(`/api/schedules/${id}`, { method: 'DELETE' }), [['schedules']])

/** POST /api/schedules/{id}/trigger → 200 (409 when the overlap policy skips it). `Queued` has no run yet. */
export interface TriggerResult {
  scanRunId?: string
  outcome: 'Started' | 'Queued'
  reason?: string
}

export const useTriggerSchedule = () =>
  useApiMutation(
    (id: string) => api<TriggerResult>(`/api/schedules/${id}/trigger`, { method: 'POST' }),
    [['schedules'], ['scans'], ['dashboard']],
  )

export const useSetSchedulePaused = () =>
  useApiMutation(
    ({ id, paused }: { id: string; paused: boolean }) =>
      api(`/api/schedules/${id}/${paused ? 'pause' : 'resume'}`, { method: 'POST' }),
    [['schedules']],
  )
