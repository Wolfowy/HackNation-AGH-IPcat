import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { t } from '@/i18n/strings'
import { cn } from '@/lib/utils'

/** ipcat-web page header: H1 22/600 + one line of description; actions on the right. */
export function PageHeader({ title, description, actions }: { title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-start gap-3">
      <div className="min-w-[240px] flex-1">
        <h1 className="m-0 truncate text-[22px] font-semibold">{title}</h1>
        {description && <div className="text-muted-foreground mt-[3px] text-[13.5px]">{description}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

/** ipcat-web stat card: label, 24/600 value with an optional icon, hint. */
export function StatCard({
  label,
  value,
  icon: Icon,
  hint,
  className,
  valueClassName,
  testId,
}: {
  label: ReactNode
  value: ReactNode
  icon?: LucideIcon
  hint?: ReactNode
  className?: string
  valueClassName?: string
  testId?: string
}) {
  return (
    <div className={cn('bg-card flex h-full flex-col rounded-lg border px-4 py-3.5', className)}>
      <div className="text-muted-foreground flex items-center gap-2 text-[13px]">
        {Icon && <Icon className="size-4" aria-hidden />}
        {label}
      </div>
      <div className={cn('mt-1.5 text-[24px] leading-tight font-semibold tabular-nums', valueClassName)} data-testid={testId}>
        {value}
      </div>
      {hint && <div className="text-muted-foreground mt-1 text-[12px]">{hint}</div>}
    </div>
  )
}

export function StatGrid({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('mb-[18px] grid gap-3.5 [grid-template-columns:repeat(auto-fit,minmax(170px,1fr))]', className)}>{children}</div>
}

// Full class strings (Tailwind JIT), ipcat-web tokens: status = rounded pill with a dot, severity = rounded-sm badge with a dot.
const BLUE = 'bg-chg-new-bg text-chg-new-fg'
const GREEN = 'bg-chg-same-bg text-chg-same-fg'
const YELLOW = 'bg-chg-changed-bg text-chg-changed-fg'
const GRAY = 'bg-chg-gone-bg text-chg-gone-fg'
const RED = 'bg-sev-high-bg text-sev-high-fg'

const statusColors: Record<string, string> = {
  // scans / steps / jobs
  Pending: GRAY,
  Queued: GRAY,
  Running: BLUE,
  Leased: BLUE,
  Completed: GREEN,
  PartiallyCompleted: YELLOW,
  Skipped: GRAY,
  Failed: RED,
  Cancelled: GRAY,
  WindowExpired: YELLOW,
  // agents
  Active: GREEN,
  PendingApproval: YELLOW,
  Disabled: GRAY,
  Blocked: RED,
  // assets
  Unreachable: YELLOW,
  Gone: GRAY,
  Unknown: GRAY,
  Open: RED,
  Resolved: GREEN,
  // signatures
  Draft: GRAY,
  Approved: GREEN,
  Retired: GRAY,
}

export const severityColors: Record<string, string> = {
  critical: 'bg-sev-critical-bg text-sev-critical-fg',
  high: 'bg-sev-high-bg text-sev-high-fg',
  medium: 'bg-sev-medium-bg text-sev-medium-fg',
  low: 'bg-sev-low-bg text-sev-low-fg',
  info: 'bg-sev-info-bg text-sev-info-fg',
}

/** Solid severity colors for dots, bars and chart segments. */
export const severityDots: Record<string, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
}

export const pillDot = "before:size-1.5 before:shrink-0 before:rounded-full before:bg-current before:content-['']"

export function StatusBadge({ status, className }: { status?: string; className?: string }) {
  if (!status) return null
  const severity = severityColors[status]
  return (
    <span
      data-slot="badge"
      className={cn(
        'inline-flex w-fit shrink-0 items-center gap-[5px] px-2 py-0.5 text-[12px] whitespace-nowrap',
        pillDot,
        severity ? cn('rounded-sm font-medium', severity) : cn('rounded-full', statusColors[status] ?? GRAY),
        className,
      )}
    >
      {status}
    </span>
  )
}

/** Chip for IPs, ports, CIDRs and IDs (ipcat-web MonoChip). */
export function MonoChip({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('bg-muted inline-block rounded-sm px-[7px] py-0.5 font-mono text-[12px] whitespace-nowrap', className)}>{children}</span>
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
    <div className="text-muted-foreground mt-3 flex items-center justify-between gap-2 text-[12.5px]">
      <span>{t.common.pageOf(page, pages, total)}</span>
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
    <dl className={cn('grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-[13px]', className)}>
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
        <Badge key={label} variant="outline" className="rounded-sm px-1.5 py-px text-[11.5px] font-normal">
          {label}
        </Badge>
      ))}
    </div>
  )
}

export function Filters({ children }: { children: ReactNode }) {
  return <div className="bg-card mb-3.5 flex flex-wrap items-end gap-3 rounded-lg border px-4 py-3">{children}</div>
}
