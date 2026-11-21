import { useId, useState } from 'react'
import { Plus, X } from 'lucide-react'
import { CONDITION_FIELD_VALUES, CONDITION_FIELDS, CONDITION_OPERATORS, type ConditionExpression, type ConditionOperator } from '@/api/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input, NativeSelect } from '@/components/ui/input'

/** Server limit (WorkflowValidator.MaxConditionDepth); the root condition is depth 1. */
const MAX_DEPTH = 8
type Change = (value: ConditionExpression | undefined) => void

const newRule = (): ConditionExpression => ({ field: 'service.name', operator: 'In', values: [] })
const takesNoValues = (op?: ConditionOperator) => op === 'Exists' || op === 'NotExists'
const takesManyValues = (op?: ConditionOperator) => op === 'In' || op === 'NotIn'

/** Structured editor for a ConditionExpression: rules (field/operator/values), AND/OR groups and NOT, max depth 8. */
export function ConditionBuilder({ label, value, onChange }: { label: string; value?: ConditionExpression; onChange: Change }) {
  return (
    <fieldset className="grid gap-2" aria-label={label}>
      <legend className="mb-1 text-sm font-medium">{label}</legend>
      {value ? (
        <ConditionNode value={value} onChange={onChange} depth={1} />
      ) : (
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => onChange(newRule())}>
            <Plus /> Rule
          </Button>
          <Button size="sm" variant="outline" onClick={() => onChange({ all: [newRule()] })}>
            <Plus /> Group
          </Button>
        </div>
      )}
    </fieldset>
  )
}

function ConditionNode({ value, onChange, depth }: { value: ConditionExpression; onChange: Change; depth: number }) {
  const negated = value.not !== undefined
  const inner = value.not ?? value
  const innerDepth = negated ? depth + 1 : depth
  const setInner: Change = (v) => onChange(v && negated ? { not: v } : v)
  const isGroup = Boolean(inner.all || inner.any)
  return (
    <div className="bg-muted/30 grid gap-2 rounded-md border p-2" data-testid="condition-node">
      <div className="flex items-center gap-2">
        <label className="flex items-center gap-1 text-xs font-medium">
          <input
            type="checkbox"
            className="accent-primary"
            checked={negated}
            disabled={!negated && depth >= MAX_DEPTH}
            onChange={(e) => onChange(e.target.checked ? { not: value } : inner)}
          />
          NOT
        </label>
        <span className="text-muted-foreground flex-1 text-xs">{isGroup ? 'Group' : inner.not ? '' : 'Rule'}</span>
        {!isGroup && !inner.not && (
          <Button size="sm" variant="ghost" className="h-6 px-1.5 text-xs" disabled={innerDepth >= MAX_DEPTH} onClick={() => setInner({ all: [inner, newRule()] })}>
            <Plus /> AND
          </Button>
        )}
        <Button size="icon" variant="ghost" className="size-6" aria-label="Remove condition" onClick={() => onChange(undefined)}>
          <X />
        </Button>
      </div>
      {isGroup ? (
        <Group value={inner} onChange={setInner} depth={innerDepth} />
      ) : inner.not ? (
        <ConditionNode value={inner} onChange={setInner} depth={innerDepth} />
      ) : (
        <Rule value={inner} onChange={setInner} />
      )}
    </div>
  )
}

function Group({ value, onChange, depth }: { value: ConditionExpression; onChange: Change; depth: number }) {
  const kind = value.all ? 'all' : 'any'
  const items = value[kind] ?? []
  const set = (next: ConditionExpression[]) => onChange({ [kind]: next })
  return (
    <div className="grid gap-2">
      <NativeSelect aria-label="Combine with" className="h-8" value={kind} onChange={(e) => onChange({ [e.target.value]: items })}>
        <option value="all">AND — all must match</option>
        <option value="any">OR — any may match</option>
      </NativeSelect>
      <div className="grid gap-2 border-l-2 pl-2">
        {items.map((c, i) => (
          <ConditionNode
            key={i}
            value={c}
            depth={depth + 1}
            onChange={(v) => set(v ? items.map((x, j) => (j === i ? v : x)) : items.filter((_, j) => j !== i))}
          />
        ))}
        {items.length === 0 && <p className="text-destructive text-xs">A group needs at least one condition.</p>}
      </div>
      <div className="flex gap-2">
        <Button size="sm" variant="outline" className="h-7" disabled={depth >= MAX_DEPTH} onClick={() => set([...items, newRule()])}>
          <Plus /> Rule
        </Button>
        <Button size="sm" variant="outline" className="h-7" disabled={depth + 2 > MAX_DEPTH} onClick={() => set([...items, { any: [newRule()] }])}>
          <Plus /> Group
        </Button>
      </div>
    </div>
  )
}

function Rule({ value, onChange }: { value: ConditionExpression; onChange: Change }) {
  const [draft, setDraft] = useState('')
  const listId = useId()
  const op = value.operator
  const values = value.values ?? []
  const add = () => {
    const v = draft.trim()
    if (!v) return
    onChange({ ...value, values: takesManyValues(op) ? [...values.filter((x) => x !== v), v] : [v] })
    setDraft('')
  }
  return (
    <div className="grid gap-2">
      <div className="grid gap-2">
        <NativeSelect aria-label="Field" className="h-8 text-xs" value={value.field ?? ''} onChange={(e) => onChange({ ...value, field: e.target.value })}>
          {!value.field && <option value="">Field…</option>}
          {CONDITION_FIELDS.map((f) => (
            <option key={f}>{f}</option>
          ))}
        </NativeSelect>
        <NativeSelect
          aria-label="Operator"
          className="h-8 text-xs"
          value={op ?? ''}
          onChange={(e) => {
            const operator = e.target.value as ConditionOperator
            onChange(takesNoValues(operator) ? { field: value.field, operator } : { ...value, operator, values: takesManyValues(operator) ? values : values.slice(0, 1) })
          }}
        >
          {CONDITION_OPERATORS.map((o) => (
            <option key={o}>{o}</option>
          ))}
        </NativeSelect>
      </div>
      {!takesNoValues(op) && (
        <div className="flex flex-wrap items-center gap-1">
          {values.map((v) => (
            <Badge key={v} variant="secondary" className="gap-0.5 font-mono">
              {v}
              <button type="button" aria-label={`Remove value ${v}`} className="hover:text-destructive" onClick={() => onChange({ ...value, values: values.filter((x) => x !== v) })}>
                <X />
              </button>
            </Badge>
          ))}
          <Input
            aria-label="Add value"
            list={listId}
            className="h-7 min-w-24 flex-1 text-xs"
            placeholder={takesManyValues(op) ? 'value + Enter' : 'value'}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onBlur={add}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ',') {
                e.preventDefault()
                add()
              }
            }}
          />
          <datalist id={listId}>
            {(CONDITION_FIELD_VALUES[value.field ?? ''] ?? []).map((v) => (
              <option key={v} value={v} />
            ))}
          </datalist>
        </div>
      )}
    </div>
  )
}
