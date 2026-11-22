import { Clock } from 'lucide-react'
import type { HourVisibility } from '@/api/types'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

/** Interest score 0–100 (analytical priority); the reasons are the tooltip. */
export function InterestBadge({ score = 0, reasons = [] }: { score?: number; reasons?: string[] }) {
  const variant = score >= 60 ? 'destructive' : score >= 30 ? 'warning' : score > 0 ? 'secondary' : 'outline'
  return (
    <Badge variant={variant} className="tabular-nums" title={reasons.length ? reasons.join('\n') : 'Nothing notable'} data-testid="interest-badge">
      {score}
    </Badge>
  )
}

export function TimeOfDayBadge() {
  return (
    <Badge variant="warning" title="Responses differ consistently by hour of day (e.g. maintenance page at night)">
      <Clock /> time of day
    </Badge>
  )
}

const hourLabel = (h: number) => `${String(h).padStart(2, '0')}:00–${String((h + 1) % 24).padStart(2, '0')}:00 UTC`

function Strip({ cells, label }: { cells: { hour: number; className: string; title: string }[]; label: string }) {
  return (
    <div>
      <div className="flex gap-px" role="img" aria-label={label}>
        {cells.map((c) => (
          <div key={c.hour} className={cn('h-5 flex-1 rounded-sm', c.className)} title={c.title} data-testid="hour-cell" />
        ))}
      </div>
      <div className="text-muted-foreground mt-1 flex justify-between text-[10px] tabular-nums">
        {[0, 6, 12, 18, 24].map((h) => (
          <span key={h}>{String(h).padStart(2, '0')}h</span>
        ))}
      </div>
    </div>
  )
}

/** Host availability per UTC hour: share of covering scans at that hour that saw the host. */
export function AvailabilityStrip({ hours }: { hours: HourVisibility[] }) {
  const byHour = new Map(hours.map((h) => [h.hour, h]))
  const cells = Array.from({ length: 24 }, (_, hour) => {
    const { seen = 0, missed = 0 } = byHour.get(hour) ?? {}
    const total = seen + missed
    const className = total === 0 ? 'bg-muted' : missed === 0 ? 'bg-success' : seen === 0 ? 'bg-destructive' : 'bg-warning'
    return { hour, className, title: total === 0 ? `${hourLabel(hour)}: not scanned` : `${hourLabel(hour)}: seen ${seen} of ${total} scans` }
  })
  const scanned = cells.filter((c) => c.className !== 'bg-muted').length
  return <Strip cells={cells} label={`Availability by hour of day (UTC), scanned in ${scanned} of 24 hours`} />
}

const RESPONSE_COLORS = ['bg-sky-500', 'bg-amber-500', 'bg-violet-500', 'bg-rose-500', 'bg-emerald-500']

/** Usual HTTP response per UTC hour; one color per distinct response, with a legend. */
export function ResponseStrip({ hours }: { hours: HourVisibility[] }) {
  const responses = [...new Set(hours.map((h) => h.response ?? '?'))]
  const color = (r?: string) => RESPONSE_COLORS[responses.indexOf(r ?? '?') % RESPONSE_COLORS.length]
  const byHour = new Map(hours.map((h) => [h.hour, h]))
  const cells = Array.from({ length: 24 }, (_, hour) => {
    const h = byHour.get(hour)
    return {
      hour,
      className: h ? color(h.response) : 'bg-muted',
      title: h ? `${hourLabel(hour)}: ${h.response} (${h.seen} observations)` : `${hourLabel(hour)}: no HTTP observation`,
    }
  })
  return (
    <div className="space-y-1">
      <Strip cells={cells} label="HTTP response by hour of day (UTC)" />
      <ul className="flex flex-wrap gap-x-3 text-xs">
        {responses.map((r) => (
          <li key={r} className="flex items-center gap-1">
            <span className={cn('inline-block size-2.5 rounded-sm', color(r))} /> <span className="font-mono">{r}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
