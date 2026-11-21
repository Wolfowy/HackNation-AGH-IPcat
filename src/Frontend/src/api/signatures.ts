import { useQuery } from '@tanstack/react-query'
import { api } from './client'
import { useApiMutation } from './query'
import type { Signature, SignatureDetail, SignatureKind, SignatureStatus, ValidationResult } from './types'

const enc = encodeURIComponent

export const useSignatures = (params: { kind?: SignatureKind | ''; status?: SignatureStatus | '' }) =>
  useQuery({
    queryKey: ['signatures', 'list', params],
    queryFn: ({ signal }) => api<Signature[]>('/api/signatures', { query: { ...params }, signal }),
  })

export const useSignature = (id: string) =>
  useQuery({
    queryKey: ['signatures', 'detail', id],
    queryFn: ({ signal }) => api<SignatureDetail>(`/api/signatures/${enc(id)}`, { signal }),
    enabled: Boolean(id),
  })

export const validateSignature = (body: { kind: SignatureKind; content: string }) =>
  api<ValidationResult>('/api/signatures/validate', { method: 'POST', body })

export const useCreateSignature = () =>
  useApiMutation(
    (body: { id: string; name: string; kind: SignatureKind; content: string }) =>
      api<Signature>('/api/signatures', { method: 'POST', body }),
    [['signatures']],
    { inlineValidation: true },
  )

export const useCreateSignatureVersion = () =>
  useApiMutation(
    ({ id, content }: { id: string; content: string }) =>
      api(`/api/signatures/${enc(id)}/versions`, { method: 'POST', body: { content } }),
    [['signatures']],
  )

export const useApproveSignatureVersion = () =>
  useApiMutation(
    ({ id, version, note }: { id: string; version: number; note?: string }) =>
      api(`/api/signatures/${enc(id)}/versions/${version}/approve`, { method: 'POST', body: { note } }),
    [['signatures']],
  )

export const useRetireSignature = () =>
  useApiMutation((id: string) => api(`/api/signatures/${enc(id)}/retire`, { method: 'POST' }), [['signatures']])
