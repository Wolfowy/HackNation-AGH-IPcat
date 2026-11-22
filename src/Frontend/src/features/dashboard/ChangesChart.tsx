import type { ChangeDay, ChangeType } from '@/api/types'
import { EmptyState } from '@/components/feedback'
import { cn } from '@/lib/utils'

/** Change types folded into four series (more hues would not stay distinguishable); fixed order = fixed colors. */
const GROUPS: { label: string; types: ChangeType[]; color: string }[] = [
  { label: 'Added', types: ['NewHost', 'NewPort', 'NewService', 'HostReappeared'], color: 'bg-chart-1' },
  {
    label: 'Changed',
    types: ['ServiceChanged', 'TechnologyChanged', 'TlsCertificateChanged', 'HttpResponseChanged'],
    color: 'bg-sev-high',
  },
  { label: 'Gone', types: ['HostGone', 'PortGone'], color: 'bg-chart-5' },
  { label: 'Time of day', types: ['TimeOfDayVariance'], color: 'bg-chart-3' },
]

const count = (day: ChangeDay, types: ChangeType[]) => types.reduce((n, type) => n + (day.byType[type] ?? 0), 0)

/** Changes per UTC day as stacked bars; hover a day for its breakdown; a screen-reader table carries the same numbers. */
export function ChangesChart({ days }: { days: ChangeDay[] }) {
  const max = Math.max(0, ...days.map((d) => d.total))
  if (max === 0) return <EmptyState>No changes in this period.</EmptyState>
  const totals = GROUPS.map((g) => days.reduce((n, d) => n + count(d, g.types), 0))
  return (
    <div data-testid="changes-chart">
      <ul className="mb-3 flex flex-wrap gap-x-4 gap-y-1 text-[12.5px]">
        {GROUPS.map((g, i) => (
          <li key={g.label} className="flex items-center gap-1.5">
            <span className={cn('inline-block size-2.5 rounded-sm', g.color)} />
            <span>{g.label}</span>
            <span className="text-muted-foreground tabular-nums">{totals[i]}</span>
          </li>
        ))}
      </ul>
      <div className="flex h-44 items-end gap-1 border-b" aria-hidden>
        {days.map((day) => (
          <div
            key={day.date}
            className="group flex h-full flex-1 flex-col justify-end"
            title={`${day.date}: ${day.total} change(s)\n${GROUPS.map((g) => `${g.label}: ${count(day, g.types)}`).join('\n')}`}
          >
            <div className="flex flex-col-reverse gap-[2px] overflow-hidden rounded-t-[3px] group-hover:opacity-80" style={{ height: `${(day.total / max) * 100}%` }}>
              {GROUPS.map((g) => {
                const n = count(day, g.types)
                return n > 0 && <div key={g.label} className={g.color} style={{ flexGrow: n, minHeight: 2 }} />
              })}
            </div>
          </div>
        ))}
      </div>
      <div className="text-muted-foreground mt-1.5 flex justify-between text-[11px] tabular-nums" aria-hidden>
        <span>{days[0]?.date.slice(5)}</span>
        <span>{days[Math.floor(days.length / 2)]?.date.slice(5)}</span>
        <span>{days.at(-1)?.date.slice(5)}</span>
      </div>
      <table className="sr-only">
        <caption>Changes per day (UTC)</caption>
        <thead>
          <tr>
            <th>Date</th>
            {GROUPS.map((g) => (
              <th key={g.label}>{g.label}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {days.map((day) => (
            <tr key={day.date}>
              <td>{day.date}</td>
              {GROUPS.map((g) => (
                <td key={g.label}>{count(day, g.types)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
