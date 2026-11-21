import { MutationCache, QueryClient, useMutation, useQueryClient, type QueryKey } from '@tanstack/react-query'
import { toast } from 'sonner'
import { ApiError, errorMessage } from './client'

export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        refetchOnWindowFocus: false,
        retry: (count, err) => !(err instanceof ApiError && err.status >= 400 && err.status < 500) && count < 2,
      },
    },
    mutationCache: new MutationCache({
      onError: (err, _vars, _ctx, mutation) => {
        // Forms that render field errors inline opt out of the generic toast for validation failures.
        if (mutation.meta?.inlineValidation && err instanceof ApiError && Object.keys(err.fieldErrors).length) return
        toast.error(errorMessage(err))
      },
    }),
  })
}

declare module '@tanstack/react-query' {
  interface Register {
    mutationMeta: { inlineValidation?: boolean }
  }
}

/** Mutation that invalidates the given query key prefixes on success. */
export function useApiMutation<TVars = void, TResult = unknown>(
  mutationFn: (vars: TVars) => Promise<TResult>,
  invalidate: QueryKey[],
  meta?: { inlineValidation?: boolean },
) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn,
    meta,
    onSuccess: () => Promise.all(invalidate.map((queryKey) => qc.invalidateQueries({ queryKey }))),
  })
}
