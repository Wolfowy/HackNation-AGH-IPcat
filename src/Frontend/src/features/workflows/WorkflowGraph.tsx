import { ArrowRight } from 'lucide-react'
import type { ConditionExpression, ScanWorkflowDefinition, WorkflowStep } from '@/api/types'
import { Badge } from '@/components/ui/badge'
import { dagLevels } from './dag'

export function describeCondition(c?: ConditionExpression): string {
  if (!c) return ''
  if (c.all) return c.all.map(describeCondition).join(' AND ')
  if (c.any) return `(${c.any.map(describeCondition).join(' OR ')})`
  if (c.not) return `NOT ${describeCondition(c.not)}`
  return [c.field, c.operator, c.values?.length ? `[${c.values.join(', ')}]` : ''].filter(Boolean).join(' ')
}

function StepCard({ step }: { step: WorkflowStep }) {
  const params = Object.entries(step.parameters ?? {})
  return (
    <div className="bg-card w-60 rounded-lg border p-3 text-sm shadow-xs" data-testid={`dag-step-${step.id}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-semibold">{step.id}</span>
        {step.onFailure === 'Continue' && <Badge variant="outline">continue on failure</Badge>}
      </div>
      <div className="text-primary text-xs font-medium">{step.operation}</div>
      {step.toolId && <div className="text-muted-foreground text-xs">tool: {step.toolId}</div>}
      {step.input && (
        <div className="text-muted-foreground mt-1 text-xs">
          input: {step.input.fromSteps.join(', ')}
          {step.input.filter && <> where {describeCondition(step.input.filter)}</>}
        </div>
      )}
      {step.when && <div className="mt-1 text-xs text-amber-700 dark:text-amber-400">when {describeCondition(step.when)}</div>}
      {params.length > 0 && (
        <div className="mt-1 font-mono text-[11px]">
          {params.map(([k, v]) => (
            <div key={k} className="truncate">
              {k}={v}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/** Read-only DAG: one column per dependency level, left to right. */
export function WorkflowGraph({ definition }: { definition: ScanWorkflowDefinition }) {
  const { levels, unresolved } = dagLevels(definition.steps)
  return (
    <div className="overflow-x-auto pb-2" data-testid="workflow-graph">
      <div className="flex items-start gap-3">
        {levels.map((level, i) => (
          <div key={i} className="flex items-start gap-3">
            {i > 0 && <ArrowRight className="text-muted-foreground mt-8 size-5 shrink-0" />}
            <div className="flex flex-col gap-3">
              <div className="text-muted-foreground text-xs font-medium uppercase">Level {i + 1}</div>
              {level.map((s) => (
                <StepCard key={s.id} step={s} />
              ))}
            </div>
          </div>
        ))}
      </div>
      {unresolved.length > 0 && (
        <p className="text-destructive mt-3 text-sm">
          Unresolved steps (cycle or unknown dependency): {unresolved.map((s) => s.id).join(', ')}
        </p>
      )}
    </div>
  )
}
