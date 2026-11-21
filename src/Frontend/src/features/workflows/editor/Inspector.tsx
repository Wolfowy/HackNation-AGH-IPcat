import { useState, type ReactNode } from 'react'
import { AlertCircle, Trash } from 'lucide-react'
import type { OperationDescriptor, ParameterDescriptor, RetryPolicy, WorkflowStep } from '@/api/types'
import { CheckboxField, FormField } from '@/components/form'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input, NativeSelect, Textarea } from '@/components/ui/input'
import { ConditionBuilder } from './ConditionBuilder'
import {
  ancestorsOf,
  connect,
  connectionError,
  disconnect,
  KEY_PATTERN,
  removeStep,
  renameStep,
  STEP_ID_PATTERN,
  updateStep,
  type Graph,
  type WorkflowMeta,
} from './graph'
import { OperationIcon } from './operationStyle'

const num = (s: string) => (s.trim() === '' ? undefined : Number(s))
/** Retry with both fields empty means "inherit the workflow default" (omit), not "{}" (= server defaults). */
const retryOf = (r: RetryPolicy) => (r.maxAttempts === undefined && r.backoffSeconds === undefined ? undefined : r)
/** Whether the step reads targets (input / when are allowed): agent steps and EvaluateCondition. */
export const takesInput = (op?: OperationDescriptor) => op?.plane === 'Agent' || op?.operation === 'EvaluateCondition'

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="grid gap-3 border-t pt-3">
      <h4 className="text-muted-foreground text-xs font-semibold tracking-wide uppercase">{title}</h4>
      {children}
    </section>
  )
}

function ParameterField({ p, value, onChange }: { p: ParameterDescriptor; value?: string; onChange: (v: string | undefined) => void }) {
  const hint = [p.description, p.type === 'StringList' && 'Comma separated.', p.allowedValues && p.type !== 'Enum' && `Allowed: ${p.allowedValues.join(', ')}.`, p.required && 'Required.']
    .filter(Boolean)
    .join(' ')
  const set = (v: string) => onChange(v === '' ? undefined : v)
  if (p.type === 'Boolean')
    return (
      <div className="grid gap-1">
        <CheckboxField label={p.name} checked={(value ?? p.default) === 'true'} onChange={(c) => onChange(String(c))} />
        {hint && <p className="text-muted-foreground text-xs">{hint}</p>}
      </div>
    )
  return (
    <FormField label={p.name} hint={hint || undefined}>
      {p.type === 'Enum' ? (
        <NativeSelect value={value ?? ''} onChange={(e) => set(e.target.value)}>
          <option value="">{p.default ? `default (${p.default})` : '—'}</option>
          {p.allowedValues?.map((v) => (
            <option key={v}>{v}</option>
          ))}
        </NativeSelect>
      ) : (
        <Input
          type={p.type === 'Integer' ? 'number' : 'text'}
          min={p.min}
          max={p.max}
          placeholder={p.default ?? (p.type === 'PortSpec' ? 'e.g. 80,443,8000-8100' : '')}
          value={value ?? ''}
          onChange={(e) => set(e.target.value)}
        />
      )}
    </FormField>
  )
}

function StepIdField({ graph, id, onChange }: { graph: Graph; id: string; onChange: (g: Graph) => void }) {
  const [draft, setDraft] = useState(id)
  const error = !STEP_ID_PATTERN.test(draft)
    ? 'Start with a letter; then letters, digits, "_" or "-" (max 64).'
    : draft !== id && graph.nodes.some((n) => n.id === draft)
      ? 'Another step already uses this id.'
      : undefined
  const commit = () => {
    if (!error && draft !== id) onChange(renameStep(graph, id, draft))
  }
  return (
    <FormField label="Step id" error={error} hint="Renaming updates dependencies and input references.">
      <Input value={draft} onChange={(e) => setDraft(e.target.value)} onBlur={commit} onKeyDown={(e) => e.key === 'Enter' && commit()} />
    </FormField>
  )
}

/** Settings of one step; every edit produces a new graph (and therefore a new definition). */
export function StepInspector({
  graph,
  stepId,
  operations,
  errors = [],
  defaults,
  onChange,
}: {
  graph: Graph
  stepId: string
  operations: OperationDescriptor[]
  errors?: string[]
  defaults?: WorkflowMeta['defaults']
  onChange: (graph: Graph) => void
}) {
  const node = graph.nodes.find((n) => n.id === stepId)
  if (!node) return null
  const step = node.data.step
  const op = operations.find((o) => o.operation === step.operation)
  const update = (patch: Partial<WorkflowStep>) => onChange(updateStep(graph, stepId, patch))
  const others = graph.nodes.filter((n) => n.id !== stepId).map((n) => n.id)
  const dependsOn = new Set(graph.edges.filter((e) => e.target === stepId).map((e) => e.source))
  const ancestors = ancestorsOf(graph.edges, stepId)
  const fromSteps = step.input?.fromSteps ?? []
  const sources = others.filter((id) => ancestors.has(id) || fromSteps.includes(id))
  const setFromSteps = (next: string[]) => update({ input: next.length ? { ...step.input, fromSteps: next } : undefined })
  const retry = step.retry ?? {}

  return (
    <div className="grid gap-3" data-testid="step-inspector">
      <div className="flex items-center gap-2">
        <OperationIcon operation={step.operation} plane={op?.plane} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-semibold">{step.operation}</div>
          <div className="text-muted-foreground text-xs">
            {op?.plane === 'Server' ? 'Runs on the server' : `Runs on an agent · capability ${op?.requiredCapability ?? '—'} · input ${op?.inputKind ?? '—'}`}
          </div>
        </div>
        <Badge variant={op?.plane === 'Server' ? 'secondary' : 'default'}>{op?.plane ?? '?'}</Badge>
      </div>

      {errors.length > 0 && (
        <Alert variant="destructive">
          <AlertCircle />
          <AlertDescription>
            <ul className="list-disc pl-4 text-xs">
              {errors.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}

      <StepIdField key={stepId} graph={graph} id={stepId} onChange={onChange} />

      <Section title="Dependencies">
        {others.length === 0 ? (
          <p className="text-muted-foreground text-xs">No other steps yet.</p>
        ) : (
          <div className="grid gap-1" role="group" aria-label="Depends on">
            {others.map((id) => {
              const problem = dependsOn.has(id) ? null : connectionError(graph.edges, id, stepId)
              return (
                <label key={id} className="flex items-center gap-2 text-sm" title={problem ?? undefined}>
                  <input
                    type="checkbox"
                    className="accent-primary size-4"
                    checked={dependsOn.has(id)}
                    disabled={Boolean(problem)}
                    onChange={(e) => onChange(e.target.checked ? connect(graph, id, stepId, takesInput(op)) : disconnect(graph, id, stepId))}
                  />
                  <span className="font-mono text-xs">{id}</span>
                  {problem && <span className="text-muted-foreground text-xs">(would create a cycle)</span>}
                </label>
              )
            })}
          </div>
        )}
        {takesInput(op) && (
          <div className="grid gap-1" role="group" aria-label="Input from">
            <span className="text-sm font-medium">Input from</span>
            {sources.length === 0 ? (
              <p className="text-muted-foreground text-xs">
                {op?.inputKind === 'Endpoints' ? 'Needs endpoints: add a dependency on a step that produces them.' : 'None: the scan run scope (networks) is used.'}
              </p>
            ) : (
              sources.map((id) => (
                <label key={id} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    className="accent-primary size-4"
                    checked={fromSteps.includes(id)}
                    onChange={(e) => setFromSteps(e.target.checked ? [...fromSteps, id] : fromSteps.filter((s) => s !== id))}
                  />
                  <span className="font-mono text-xs">{id}</span>
                  {!ancestors.has(id) && <span className="text-destructive text-xs">(not a dependency)</span>}
                </label>
              ))
            )}
          </div>
        )}
      </Section>

      {takesInput(op) && (
        <Section title="Conditions">
          {step.input && (
            <ConditionBuilder
              label="Input filter"
              value={step.input.filter}
              onChange={(filter) => update({ input: { fromSteps: step.input!.fromSteps, ...(filter && { filter }) } })}
            />
          )}
          <ConditionBuilder label="Run only when" value={step.when} onChange={(when) => update({ when })} />
          <p className="text-muted-foreground text-xs">"Run only when" is evaluated on the (filtered) input; the step is skipped when nothing matches.</p>
        </Section>
      )}

      {op && op.parameters.length > 0 && (
        <Section title="Parameters">
          {op.parameters.map((p) => (
            <ParameterField
              key={p.name}
              p={p}
              value={step.parameters?.[p.name]}
              onChange={(v) => {
                const { [p.name]: _old, ...rest } = step.parameters ?? {}
                const parameters = v === undefined ? rest : { ...rest, [p.name]: v }
                update({ parameters: Object.keys(parameters).length ? parameters : undefined })
              }}
            />
          ))}
        </Section>
      )}

      <Section title="Execution">
        {op?.plane === 'Agent' && (
          <FormField label="Tool pin (toolId)" hint={`Optional. Leave empty and the planner picks any approved tool providing '${op.requiredCapability}'.`}>
            <Input value={step.toolId ?? ''} placeholder="any capable tool" onChange={(e) => update({ toolId: e.target.value || undefined })} />
          </FormField>
        )}
        <div className="grid grid-cols-2 gap-2">
          <FormField label="Timeout (s)">
            <Input type="number" min={1} max={86400} placeholder={String(defaults?.timeoutSeconds ?? 3600)} value={step.timeoutSeconds ?? ''} onChange={(e) => update({ timeoutSeconds: num(e.target.value) })} />
          </FormField>
          <FormField label="Max concurrency">
            <Input type="number" min={1} max={1000} placeholder={String(defaults?.maxConcurrency ?? 50)} value={step.maxConcurrency ?? ''} onChange={(e) => update({ maxConcurrency: num(e.target.value) })} />
          </FormField>
          <FormField label="Retry attempts">
            <Input
              type="number"
              min={1}
              max={10}
              placeholder={String(defaults?.retry?.maxAttempts ?? 3)}
              value={retry.maxAttempts ?? ''}
              onChange={(e) => update({ retry: retryOf({ ...retry, maxAttempts: num(e.target.value) }) })}
            />
          </FormField>
          <FormField label="Retry backoff (s)">
            <Input
              type="number"
              min={0}
              max={3600}
              placeholder={String(defaults?.retry?.backoffSeconds ?? 30)}
              value={retry.backoffSeconds ?? ''}
              onChange={(e) => update({ retry: retryOf({ ...retry, backoffSeconds: num(e.target.value) }) })}
            />
          </FormField>
        </div>
        <FormField label="On failure">
          <NativeSelect value={step.onFailure ?? 'FailWorkflow'} onChange={(e) => update({ onFailure: e.target.value === 'Continue' ? 'Continue' : undefined })}>
            <option value="FailWorkflow">Fail the workflow</option>
            <option value="Continue">Continue with the next steps</option>
          </NativeSelect>
        </FormField>
      </Section>

      <div className="border-t pt-3">
        <Button variant="outline" size="sm" className="text-destructive" onClick={() => onChange(removeStep(graph, stepId))}>
          <Trash /> Delete step
        </Button>
      </div>
    </div>
  )
}

/** Workflow-level fields: key (only when creating), name, description, defaults. */
export function WorkflowSettings({ meta, keyEditable, onChange }: { meta: WorkflowMeta; keyEditable?: boolean; onChange: (meta: WorkflowMeta) => void }) {
  const d = meta.defaults ?? {}
  const setDefaults = (patch: Partial<NonNullable<WorkflowMeta['defaults']>>) => onChange({ ...meta, defaults: { ...d, ...patch } })
  const retry = d.retry ?? {}
  return (
    <div className="grid gap-3" data-testid="workflow-settings">
      <h3 className="text-sm font-semibold">Workflow</h3>
      <FormField
        label="Key"
        hint={keyEditable ? 'Lowercase letters, digits and "-"; cannot change after the first save.' : 'Fixed after the first version.'}
        error={keyEditable && meta.key && !KEY_PATTERN.test(meta.key) ? 'Must match ^[a-z0-9][a-z0-9-]{1,63}$.' : undefined}
      >
        <Input value={meta.key} disabled={!keyEditable} placeholder="my-workflow" onChange={(e) => onChange({ ...meta, key: e.target.value })} />
      </FormField>
      <FormField label="Name">
        <Input value={meta.name} placeholder="My workflow" onChange={(e) => onChange({ ...meta, name: e.target.value })} />
      </FormField>
      <FormField label="Description">
        <Textarea value={meta.description ?? ''} rows={2} onChange={(e) => onChange({ ...meta, description: e.target.value || undefined })} />
      </FormField>
      <Section title="Defaults for every step">
        <div className="grid grid-cols-2 gap-2">
          <FormField label="Default timeout (s)">
            <Input type="number" min={1} max={86400} placeholder="3600" value={d.timeoutSeconds ?? ''} onChange={(e) => setDefaults({ timeoutSeconds: num(e.target.value) })} />
          </FormField>
          <FormField label="Default max concurrency">
            <Input type="number" min={1} max={1000} placeholder="50" value={d.maxConcurrency ?? ''} onChange={(e) => setDefaults({ maxConcurrency: num(e.target.value) })} />
          </FormField>
          <FormField label="Default retry attempts">
            <Input type="number" min={1} max={10} placeholder="3" value={retry.maxAttempts ?? ''} onChange={(e) => setDefaults({ retry: retryOf({ ...retry, maxAttempts: num(e.target.value) }) })} />
          </FormField>
          <FormField label="Default retry backoff (s)">
            <Input type="number" min={0} max={3600} placeholder="30" value={retry.backoffSeconds ?? ''} onChange={(e) => setDefaults({ retry: retryOf({ ...retry, backoffSeconds: num(e.target.value) }) })} />
          </FormField>
          <FormField label="Batch size" hint="Hosts per agent job (64–1024).">
            <Input type="number" min={64} max={1024} placeholder="256" value={d.batchSize ?? ''} onChange={(e) => setDefaults({ batchSize: num(e.target.value) })} />
          </FormField>
        </div>
      </Section>
    </div>
  )
}
