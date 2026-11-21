import { cloneElement, isValidElement, useId, type BaseSyntheticEvent, type ReactElement, type ReactNode } from 'react'
import type { FieldValues, Path, SubmitHandler, UseFormReturn } from 'react-hook-form'
import { toast } from 'sonner'
import { ApiError } from '@/api/client'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'

/**
 * Label + control + hint + error. The control gets `id`, `aria-invalid` and `aria-describedby` wired automatically,
 * so `getByLabelText(label)` works in tests.
 */
export function FormField({
  label,
  hint,
  error,
  className,
  children,
}: {
  label: ReactNode
  hint?: ReactNode
  error?: string
  className?: string
  children: ReactElement<Record<string, unknown>>
}) {
  const id = useId()
  const describedBy = [hint && `${id}-hint`, error && `${id}-error`].filter(Boolean).join(' ') || undefined
  const control = isValidElement(children)
    ? cloneElement(children, { id, 'aria-invalid': error ? true : undefined, 'aria-describedby': describedBy })
    : children
  return (
    <div className={cn('grid gap-1.5', className)}>
      <Label htmlFor={id}>{label}</Label>
      {control}
      {hint && (
        <p id={`${id}-hint`} className="text-muted-foreground text-xs">
          {hint}
        </p>
      )}
      {error && (
        <p id={`${id}-error`} className="text-destructive text-xs" role="alert">
          {error}
        </p>
      )}
    </div>
  )
}

export function CheckboxField({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: ReactNode
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
}) {
  return (
    <label className="flex items-center gap-2 text-sm">
      <input
        type="checkbox"
        className="accent-primary size-4"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      {label}
    </label>
  )
}

/** Multi-select rendered as a list of checkboxes (accessible, no portal). */
export function CheckboxList<T extends string>({
  legend,
  options,
  value,
  onChange,
  error,
  emptyText = 'No options available.',
}: {
  legend: ReactNode
  options: { value: T; label: ReactNode }[]
  value: T[]
  onChange: (value: T[]) => void
  error?: string
  emptyText?: string
}) {
  const toggle = (v: T, on: boolean) => onChange(on ? [...value, v] : value.filter((x) => x !== v))
  return (
    <fieldset className="grid gap-1.5">
      <legend className="mb-1.5 text-sm font-medium">{legend}</legend>
      <div className="max-h-48 space-y-1.5 overflow-y-auto rounded-md border p-2">
        {options.length === 0 && <p className="text-muted-foreground text-sm">{emptyText}</p>}
        {options.map((o) => (
          <CheckboxField key={o.value} label={o.label} checked={value.includes(o.value)} onChange={(on) => toggle(o.value, on)} />
        ))}
      </div>
      {error && (
        <p className="text-destructive text-xs" role="alert">
          {error}
        </p>
      )}
    </fieldset>
  )
}

/** Maps ProblemDetails field errors onto form fields; errors for unknown fields are shown as a toast. */
export function applyServerErrors<T extends FieldValues>(err: unknown, form: Pick<UseFormReturn<T>, 'setError' | 'getValues'>) {
  if (!(err instanceof ApiError)) return
  const known = Object.keys(form.getValues())
  const rest: string[] = []
  for (const [field, message] of Object.entries(err.fieldErrors)) {
    if (known.includes(field)) form.setError(field as Path<T>, { message })
    else rest.push(field ? `${field}: ${message}` : message)
  }
  if (rest.length) toast.error(rest.join('\n'))
}

/**
 * `handleSubmit` that first clears stale (server-set) errors — they would otherwise block resubmission —
 * and maps a failed request's validation errors back onto the form.
 */
export function submitHandler<T extends FieldValues>(form: UseFormReturn<T>, onValid: SubmitHandler<T>) {
  return (e?: BaseSyntheticEvent) => {
    form.clearErrors()
    return form.handleSubmit(async (values) => {
      try {
        await onValid(values)
      } catch (err) {
        applyServerErrors(err, form)
      }
    })(e)
  }
}
