import { useFindings } from '@/api/assets'
import { SEVERITIES, type Severity } from '@/api/types'
import { severityDots } from '@/components/page'
import { cn } from '@/lib/utils'

const open = (severity: Severity) => ({ severity, status: 'Open', page: 1, pageSize: 1 })

/** Open findings per severity (one page-size-1 query each: only `total` is read). Undefined until loaded. */
export function useOpenSeverityCounts(): Record<Severity, number> | undefined {
  const queries = {
    critical: useFindings(open('critical')),
    high: useFindings(open('high')),
    medium: useFindings(open('medium')),
    low: useFindings(open('low')),
    info: useFindings(open('info')),
  }
  if (SEVERITIES.some((s) => queries[s].data === undefined)) return undefined
  return Object.fromEntries(SEVERITIES.map((s) => [s, queries[s].data!.total])) as Record<Severity, number>
}

/** ipcat-web stat tiles as a severity filter: click a tile to filter, click again to clear. */
export function SeverityTiles({ value, onChange }: { value: Severity | ''; onChange: (v: Severity | '') => void }) {
  const counts = useOpenSeverityCounts()
  return (
    <div className="mb-3.5 grid grid-cols-2 gap-3.5 sm:grid-cols-5" role="group" aria-label="Open findings by severity">
      {SEVERITIES.map((s) => (
        <button
          key={s}
          type="button"
          aria-pressed={value === s}
          onClick={() => onChange(value === s ? '' : s)}
          className={cn(
            'bg-card hover:bg-muted focus-visible:outline-ring flex cursor-pointer flex-col rounded-lg border px-4 py-3 text-left outline-none focus-visible:outline-2',
            value === s && 'border-primary shadow-[inset_0_0_0_1px_var(--primary)]',
          )}
        >
          <span className="text-muted-foreground flex items-center gap-2 text-[13px] capitalize">
            <span className={cn('size-2 rounded-full', severityDots[s])} aria-hidden />
            {s}
          </span>
          <span className="mt-1 text-[24px] leading-tight font-semibold tabular-nums">{counts ? counts[s] : '—'}</span>
        </button>
      ))}
    </div>
  )
}
