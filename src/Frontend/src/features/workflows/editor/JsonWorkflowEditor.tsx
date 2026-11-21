import { useState } from 'react'
import { Wand2 } from 'lucide-react'
import type { ScanWorkflowDefinition } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { OperationDocs } from '../OperationDocs'
import type { WorkflowEditorChange, WorkflowEditorProps } from './types'

export function parseDefinition(text: string): WorkflowEditorChange {
  try {
    const value = JSON.parse(text) as unknown
    if (!value || typeof value !== 'object' || Array.isArray(value)) return { definition: null, parseError: 'Definition must be a JSON object.' }
    const def = value as ScanWorkflowDefinition
    if (!Array.isArray(def.steps)) return { definition: null, parseError: '"steps" must be an array.' }
    return { definition: def }
  } catch (err) {
    return { definition: null, parseError: err instanceof Error ? err.message : String(err) }
  }
}

/** Text editor for ScanWorkflowDefinition JSON, with formatting and docs for the operations in use. */
export function JsonWorkflowEditor({ initial, onChange, operations }: WorkflowEditorProps) {
  const [text, setText] = useState(() => JSON.stringify(initial, null, 2))
  const parsed = parseDefinition(text)
  const used = new Set(parsed.definition?.steps.map((s) => s.operation))

  const update = (next: string) => {
    setText(next)
    onChange(parseDefinition(next))
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <div className="grid gap-2">
        <div className="flex items-center justify-between">
          <label htmlFor="workflow-json" className="text-sm font-medium">
            Definition (JSON)
          </label>
          <Button
            size="sm"
            variant="outline"
            disabled={!parsed.definition}
            onClick={() => parsed.definition && update(JSON.stringify(parsed.definition, null, 2))}
          >
            <Wand2 /> {t.workflows.format}
          </Button>
        </div>
        <Textarea
          id="workflow-json"
          spellCheck={false}
          className="min-h-[32rem] font-mono text-xs leading-5"
          value={text}
          onChange={(e) => update(e.target.value)}
          aria-invalid={parsed.parseError ? true : undefined}
        />
        {parsed.parseError && (
          <p className="text-destructive text-xs" role="alert">
            {parsed.parseError}
          </p>
        )}
      </div>
      <div className="max-h-[36rem] overflow-y-auto">
        <h3 className="mb-2 text-sm font-medium">Parameters of operations in use</h3>
        <OperationDocs operations={operations.filter((o) => used.has(o.operation))} />
      </div>
    </div>
  )
}
