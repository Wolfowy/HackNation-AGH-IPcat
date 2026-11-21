import { useEffect, useRef, useState } from 'react'
import { Link, useBlocker, useNavigate, useParams, useSearchParams } from 'react-router'
import { toast } from 'sonner'
import { errorMessage } from '@/api/client'
import type { ScanWorkflowDefinition, ValidationResult } from '@/api/types'
import { useOperations, useSaveWorkflow, useWorkflow, useWorkflows, validateWorkflow } from '@/api/workflows'
import { Loadable, ValidationMessages } from '@/components/feedback'
import { PageHeader } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { t } from '@/i18n/strings'
import { WorkflowEditor, type WorkflowEditorChange } from './editor'

const EMPTY: ScanWorkflowDefinition = { key: '', name: '', steps: [] }
const STANDARD = 'standard-discovery'

function EditorScreen({ initial, existingKey }: { initial: ScanWorkflowDefinition; existingKey?: string }) {
  const navigate = useNavigate()
  const operations = useOperations()
  const save = useSaveWorkflow()
  const [change, setChange] = useState<WorkflowEditorChange>({ definition: initial })
  const [validation, setValidation] = useState<ValidationResult | null>(null)
  const [validating, setValidating] = useState(false)
  // Baseline = the editor's first (normalized) emission; anything else is an unsaved change.
  const baseline = useRef<string | null | undefined>(undefined)
  const [dirty, setDirty] = useState(false)
  const leaving = useRef(false)
  const blocker = useBlocker(({ currentLocation, nextLocation }) => dirty && !leaving.current && currentLocation.pathname !== nextLocation.pathname)

  useEffect(() => {
    if (!dirty) return
    const warn = (e: BeforeUnloadEvent) => e.preventDefault()
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [dirty])

  const onChange = (c: WorkflowEditorChange) => {
    const json = c.definition ? JSON.stringify(c.definition) : null
    if (baseline.current === undefined) baseline.current = json
    setDirty(json !== baseline.current)
    setChange(c)
    setValidation(null)
  }

  const validate = async () => {
    if (!change.definition) return
    setValidating(true)
    try {
      setValidation(await validateWorkflow(change.definition))
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setValidating(false)
    }
  }

  const submit = async () => {
    if (!change.definition) return
    const result = await validateWorkflow(change.definition).catch(() => null)
    if (result && !result.valid) return setValidation(result)
    const saved = await save.mutateAsync({ definition: change.definition, existingKey })
    toast.success(`Saved ${saved?.key ?? change.definition.key} v${saved?.version ?? ''}`)
    leaving.current = true
    navigate(`/workflows/${saved?.key ?? existingKey ?? change.definition.key}`)
  }

  return (
    <>
      <PageHeader
        title={existingKey ? `${t.workflows.newVersion}: ${existingKey}` : t.workflows.create}
        description="Workflows contain only catalog operations with schema-validated parameters."
        actions={
          <>
            {dirty && <span className="text-muted-foreground text-xs">Unsaved changes</span>}
            <Button variant="outline" onClick={validate} disabled={!change.definition || validating}>
              {t.workflows.validate}
            </Button>
            <Button onClick={() => submit().catch(() => {})} disabled={!change.definition || save.isPending}>
              {t.common.save}
            </Button>
          </>
        }
      />
      {validation && (
        <div className="mb-4">
          <ValidationMessages valid={validation.valid} errors={validation.errors} warnings={validation.warnings} />
        </div>
      )}
      <WorkflowEditor initial={initial} onChange={onChange} operations={operations.data?.operations ?? []} errors={validation?.errors} keyEditable={!existingKey} />
      <Dialog open={blocker.state === 'blocked'} onOpenChange={(open) => !open && blocker.reset?.()}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Discard unsaved changes?</DialogTitle>
            <DialogDescription>This workflow has changes that have not been saved.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => blocker.reset?.()}>
              Keep editing
            </Button>
            <Button variant="destructive" onClick={() => blocker.proceed?.()}>
              Discard changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

function TemplateCard({ to, title, description }: { to: string; title: string; description?: string }) {
  return (
    <Link to={to} className="bg-card hover:border-primary block rounded-lg border p-4 shadow-xs transition-colors">
      <div className="font-medium">{title}</div>
      {description && <div className="text-muted-foreground mt-1 text-sm">{description}</div>}
    </Link>
  )
}

function TemplatePicker() {
  const workflows = useWorkflows()
  return (
    <>
      <PageHeader title={t.workflows.create} description="Start from an empty canvas or from a copy of an existing workflow." />
      <Loadable query={workflows}>
        {(list) => (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3" data-testid="workflow-templates">
            <TemplateCard to="?from=" title="Empty workflow" description="Start with an empty canvas." />
            {[...list]
              .sort((a, b) => Number(b.key === STANDARD) - Number(a.key === STANDARD))
              .map((w) => (
                <TemplateCard key={w.key} to={`?from=${encodeURIComponent(w.key)}`} title={`Copy of ${w.name}`} description={`${w.key} v${w.latestVersion}${w.description ? ` · ${w.description}` : ''}`} />
              ))}
          </div>
        )}
      </Loadable>
    </>
  )
}

export function WorkflowEditorPage() {
  const { key } = useParams()
  const [params] = useSearchParams()
  const from = params.get('from')
  const source = useWorkflow(key ?? from ?? '')
  if (!key && from === null) return <TemplatePicker />
  if (!key && !from) return <EditorScreen initial={EMPTY} />
  return (
    <Loadable query={source}>
      {(wf) => {
        const { version: _version, ...definition } = wf.definition
        return key ? (
          <EditorScreen initial={definition} existingKey={key} />
        ) : (
          <EditorScreen key={from} initial={{ ...definition, key: `${definition.key}-copy`.slice(0, 64), name: `${definition.name} (copy)` }} />
        )
      }}
    </Loadable>
  )
}
