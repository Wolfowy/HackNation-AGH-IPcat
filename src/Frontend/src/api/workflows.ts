import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { useApiMutation } from './query'
import type { OperationsCatalog, ScanWorkflowDefinition, ValidationResult, WorkflowSummary, WorkflowVersion } from './types'

export const useOperations = () =>
  useQuery({
    queryKey: ['operations'],
    queryFn: ({ signal }) => api<OperationsCatalog>('/api/operations', { signal }),
    staleTime: 5 * 60_000,
  })

export const useWorkflows = () =>
  useQuery({ queryKey: ['workflows'], queryFn: ({ signal }) => api<WorkflowSummary[]>('/api/workflows', { signal }) })

export const useWorkflow = (key: string, version?: number) =>
  useQuery({
    queryKey: ['workflows', key, version ?? 'latest'],
    queryFn: ({ signal }) =>
      api<WorkflowVersion>(version ? `/api/workflows/${key}/versions/${version}` : `/api/workflows/${key}`, { signal }),
    enabled: Boolean(key),
  })

export const useWorkflowVersions = (key: string) =>
  useQuery({
    queryKey: ['workflows', key, 'versions'],
    queryFn: ({ signal }) => api<WorkflowVersion[]>(`/api/workflows/${key}/versions`, { signal }),
    enabled: Boolean(key),
  })

export const validateWorkflow = (definition: ScanWorkflowDefinition) =>
  api<ValidationResult>('/api/workflows/validate', { method: 'POST', body: definition })

/** Creates a workflow (v1) or, when `existingKey` is given, a new version of it. */
export const useSaveWorkflow = () =>
  useApiMutation(
    ({ definition, existingKey }: { definition: ScanWorkflowDefinition; existingKey?: string }) =>
      api<WorkflowVersion>(existingKey ? `/api/workflows/${existingKey}/versions` : '/api/workflows', {
        method: 'POST',
        body: definition,
      }),
    [['workflows']],
  )
