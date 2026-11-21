import type { ReactNode } from 'react'
import { Badge, type BadgeVariant } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { t } from '@/i18n/strings'
import { cn } from '@/lib/utils'

export function PageHeader({ title, description, actions }: { title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="truncate text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <div className="text-muted-foreground mt-1 text-sm">{description}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

const statusVariants: Record<string, BadgeVariant> = {
  // scans / steps / jobs
  Pending: 'secondary',
  Queued: 'secondary',
  Running: 'default',
  Leased: 'default',
  Completed: 'success',
  PartiallyCompleted: 'warning',
  Skipped: 'outline',
  Failed: 'destructive',
  Cancelled: 'outline',
  WindowExpired: 'warning',
  // agents
  Active: 'success',
  PendingApproval: 'warning',
  Disabled: 'outline',
  Blocked: 'destructive',
  // assets
  Unreachable: 'warning',
  Gone: 'outline',
  Unknown: 'secondary',
  Open: 'destructive',
  Resolved: 'success',
  // signatures
  Draft: 'secondary',
  Approved: 'success',
  Retired: 'outline',
  // severities
  info: 'secondary',
  low: 'outline',
  medium: 'warning',
  high: 'destructive',
  critical: 'destructive',
}

export function StatusBadge({ status, className }: { status?: string; className?: string }) {
  if (!status) return null
  return (
    <Badge variant={statusVariants[status] ?? 'outline'} className={className}>
      {status}
    </Badge>
  )
}

export function ProgressCell({ percent, label }: { percent: number; label?: string }) {
  const value = Math.round(percent)
  return (
    <div className="flex min-w-32 items-center gap-2">
      <Progress value={value} aria-label={label ?? 'Progress'} />
      <span className="text-muted-foreground w-10 text-right text-xs tabular-nums">{value}%</span>
    </div>
  )
}

export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
}: {
  page: number
  pageSize: number
  total: number
  onPageChange: (page: number) => void
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize))
  return (
    <div className="mt-3 flex items-center justify-between gap-2 text-sm">
      <span className="text-muted-foreground">{t.common.pageOf(page, pages, total)}</span>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>
          {t.common.previous}
        </Button>
        <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => onPageChange(page + 1)}>
          {t.common.next}
        </Button>
      </div>
    </div>
  )
}

export function KeyValues({ items, className }: { items: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={cn('grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-sm', className)}>
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v ?? '—'}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Chips({ values }: { values?: (string | { name: string })[] }) {
  if (!values?.length) return <span className="text-muted-foreground">—</span>
  const labels = [...new Set(values.map((v) => (typeof v === 'string' ? v : v.name)))]
  return (
    <div className="flex flex-wrap gap-1">
      {labels.map((label) => (
        <Badge key={label} variant="outline">
          {label}
        </Badge>
      ))}
    </div>
  )
}

export function Filters({ children }: { children: ReactNode }) {
  return <div className="mb-3 flex flex-wrap items-end gap-3">{children}</div>
}
