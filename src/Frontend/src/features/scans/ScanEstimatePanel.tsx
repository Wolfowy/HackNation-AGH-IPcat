import { AlertTriangle } from 'lucide-react'
import { useScanEstimate } from '@/api/scans'
import type { ScanEstimateRequest } from '@/api/types'
import { formatDuration, formatNumber } from '@/lib/format'

const seconds = (s?: number) => formatDuration((s ?? 0) * 1000)

export function durationRange(min?: number, max?: number): string {
  const [a, b] = [seconds(min), seconds(max)]
  return a === b ? a : `${a} – ${b}`
}

/** Live estimate (POST /api/scans/estimate) for a scan configuration; null request = not enough input yet. */
export function ScanEstimatePanel({ request }: { request: ScanEstimateRequest | null }) {
  const estimate = useScanEstimate(request)
  if (!request) return null
  const e = estimate.data
  return (
    <section aria-label="Scan estimate" className="bg-muted/40 grid gap-1 rounded-md border p-3 text-sm">
      <div className="font-medium">Estimate</div>
      {!e ? (
        <p className="text-muted-foreground">{estimate.isError ? 'No estimate for this configuration.' : 'Estimating…'}</p>
      ) : (
        <>
          <p>
            {formatNumber(e.addressCount)} addresses ·{' '}
            {e.estimatedSecondsMax === undefined || e.estimatedSecondsMax === null
              ? 'duration unknown'
              : `about ${durationRange(e.estimatedSecondsMin, e.estimatedSecondsMax)}`}
            {e.windowMinutes ? ` · window ${e.windowMinutes} min` : ''}
          </p>
          {e.steps.map((s) => (
            <p key={s.stepId} className="text-muted-foreground text-xs">
              {s.stepId}: {formatNumber(s.jobs)} jobs, {s.batchReason}, {s.eligibleAgents} eligible agent{s.eligibleAgents === 1 ? '' : 's'} online
              {s.targetsPerSecond ? `, ${s.targetsPerSecond} targets/s per job` : ''}
            </p>
          ))}
          {e.warnings.map((w) => (
            <p key={w} className="flex items-start gap-1 text-sev-medium-fg">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
              {w}
            </p>
          ))}
          <p className="text-muted-foreground text-xs">Covers the first steps; later steps depend on what they discover.</p>
        </>
      )}
    </section>
  )
}
