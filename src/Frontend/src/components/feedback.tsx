import type { ReactNode } from 'react'
import type { UseQueryResult } from '@tanstack/react-query'
import { AlertCircle, CheckCircle2, Loader2, TriangleAlert } from 'lucide-react'
import { errorMessage, formatValidationMessage } from '@/api/client'
import type { ValidationMessage } from '@/api/types'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { t } from '@/i18n/strings'

export function Spinner({ label = t.common.loading }: { label?: string }) {
  return (
    <div className="text-muted-foreground flex items-center gap-2 py-6 text-[13px]" role="status">
      <Loader2 className="size-4 animate-spin" /> {label}
    </div>
  )
}

export function ErrorAlert({ error, title = 'Error' }: { error: unknown; title?: string }) {
  return (
    <Alert variant="destructive">
      <AlertCircle />
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{errorMessage(error)}</AlertDescription>
    </Alert>
  )
}

export function EmptyState({ children = t.common.empty }: { children?: ReactNode }) {
  return <p className="text-muted-foreground px-6 py-10 text-center text-[13px]">{children}</p>
}

/** Renders loading / error states of a query and hands the data to `children`. */
export function Loadable<T>({ query, children }: { query: UseQueryResult<T>; children: (data: T) => ReactNode }) {
  if (query.isPending) return <Spinner />
  if (query.isError) return <ErrorAlert error={query.error} />
  return <>{children(query.data)}</>
}

export function ValidationMessages({
  valid,
  errors = [],
  warnings = [],
}: {
  valid: boolean
  errors?: ValidationMessage[]
  warnings?: ValidationMessage[]
}) {
  return (
    <div className="space-y-2" data-testid="validation-result">
      {valid && (
        <Alert>
          <CheckCircle2 className="text-success" />
          <AlertTitle>Valid</AlertTitle>
        </Alert>
      )}
      {errors.length > 0 && (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertTitle>{errors.length === 1 ? '1 error' : `${errors.length} errors`}</AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-4">
              {errors.map((e, i) => (
                <li key={i}>{formatValidationMessage(e)}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
      {warnings.length > 0 && (
        <Alert>
          <TriangleAlert className="text-warning" />
          <AlertTitle>{warnings.length === 1 ? '1 warning' : `${warnings.length} warnings`}</AlertTitle>
          <AlertDescription>
            <ul className="list-disc pl-4">
              {warnings.map((w, i) => (
                <li key={i}>{formatValidationMessage(w)}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
    </div>
  )
}
