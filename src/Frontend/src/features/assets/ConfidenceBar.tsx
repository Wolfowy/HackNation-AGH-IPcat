import { Progress } from '@/components/ui/progress'

/** Confidence score 0.0–1.0 as a bar with percentage. */
export function ConfidenceBar({ score, method }: { score?: number; method?: string }) {
  if (score === undefined) return <span className="text-muted-foreground">—</span>
  const pct = Math.round(score * 100)
  return (
    <div className="flex min-w-36 items-center gap-2" title={method}>
      <Progress value={pct} aria-label="Confidence" />
      <span className="text-muted-foreground w-10 text-right text-xs tabular-nums">{pct}%</span>
    </div>
  )
}
