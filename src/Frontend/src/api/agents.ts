import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { useApiMutation } from './query'
import type {
  Agent,
  AgentAssignment,
  AgentStatus,
  EnrollmentToken,
  EnrollmentTokenCreate,
  EnrollmentTokenCreated,
  ToolCatalogEntry,
} from './types'

const enc = encodeURIComponent

export const useAgents = () =>
  useQuery({ queryKey: ['agents'], queryFn: ({ signal }) => api<Agent[]>('/api/agents', { signal }), refetchInterval: 30_000 })

export const useAgent = (agentId: string) =>
  useQuery({ queryKey: ['agents', agentId], queryFn: ({ signal }) => api<Agent>(`/api/agents/${enc(agentId)}`, { signal }) })

export const useSetAgentStatus = () =>
  useApiMutation(
    ({ agentId, status }: { agentId: string; status: AgentStatus }) =>
      api(`/api/agents/${enc(agentId)}/status`, { method: 'POST', body: { status } }),
    [['agents']],
  )

export const useUpdateAgentAssignment = () =>
  useApiMutation(
    ({ agentId, ...body }: AgentAssignment & { agentId: string }) =>
      api(`/api/agents/${enc(agentId)}/assignment`, { method: 'PUT', body }),
    [['agents']],
  )

export const useRotateAgentCredentials = () =>
  useApiMutation((agentId: string) => api(`/api/agents/${enc(agentId)}/rotate-credentials`, { method: 'POST' }), [['agents']])

export const useDeleteAgent = () =>
  useApiMutation((agentId: string) => api(`/api/agents/${enc(agentId)}`, { method: 'DELETE' }), [['agents']])

export const useEnrollmentTokens = (enabled = true) =>
  useQuery({
    queryKey: ['enrollment-tokens'],
    queryFn: ({ signal }) => api<EnrollmentToken[]>('/api/enrollment-tokens', { signal }),
    enabled,
  })

export const useCreateEnrollmentToken = () =>
  useApiMutation(
    (body: EnrollmentTokenCreate) => api<EnrollmentTokenCreated>('/api/enrollment-tokens', { method: 'POST', body }),
    [['enrollment-tokens']],
    { inlineValidation: true },
  )

export const useRevokeEnrollmentToken = () =>
  useApiMutation((id: string) => api(`/api/enrollment-tokens/${enc(id)}`, { method: 'DELETE' }), [['enrollment-tokens']])

export const useTools = () =>
  useQuery({ queryKey: ['tools'], queryFn: ({ signal }) => api<ToolCatalogEntry[]>('/api/tools', { signal }) })

export const useUpdateTool = () =>
  useApiMutation(
    ({ toolId, approved, enabled }: { toolId: string; approved: boolean; enabled: boolean }) =>
      api(`/api/tools/${enc(toolId)}`, { method: 'PUT', body: { approved, enabled } }),
    [['tools'], ['agents']],
  )
