import { useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import { toast } from 'sonner'
import { errorMessage } from '@/api/client'
import type { ScanWorkflowDefinition, ValidationResult } from '@/api/types'
import { useOperations, useSaveWorkflow, useWorkflow, validateWorkflow } from '@/api/workflows'
import { Loadable, ValidationMessages } from '@/components/feedback'
import { PageHeader } from '@/components/page'
import { Button } from '@/components/ui/button'
import { t } from '@/i18n/strings'
import { WorkflowEditor, type WorkflowEditorChange } from './editor'

const TEMPLATE: ScanWorkflowDefinition = {
  key: 'my-workflow',
  name: 'My workflow',
  description: 'Host discovery followed by a port scan.',
  steps: [
    { id: 'discover', operation: 'DiscoverHosts', parameters: { method: 'default' } },
    { id: 'ports', operation: 'ScanPorts', dependsOn: ['discover'], input: { fromSteps: ['discover'] }, parameters: { ports: 'top-100' } },
    { id: 'persist', operation: 'PersistObservations', dependsOn: ['ports'] },
  ],
}

function EditorScreen({ initial, existingKey }: { initial: ScanWorkflowDefinition; existingKey?: string }) {
  const navigate = useNavigate()
  const operations = useOperations()
  const save = useSaveWorkflow()
  const [change, setChange] = useState<WorkflowEditorChange>({ definition: initial })
  const [validation, setValidation] = useState<ValidationResult | null>(null)
  const [validating, setValidating] = useState(false)

  const onChange = (c: WorkflowEditorChange) => {
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
    navigate(`/workflows/${saved?.key ?? existingKey ?? change.definition.key}`)
  }

  return (
    <>
      <PageHeader
        title={existingKey ? `${t.workflows.newVersion}: ${existingKey}` : t.workflows.create}
        description="Workflows contain only catalog operations with schema-validated parameters."
        actions={
          <>
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
      <WorkflowEditor initial={initial} onChange={onChange} operations={operations.data?.operations ?? []} />
    </>
  )
}

export function WorkflowEditorPage() {
  const { key } = useParams()
  const latest = useWorkflow(key ?? '')
  if (!key) return <EditorScreen initial={TEMPLATE} />
  return (
    <Loadable query={latest}>
      {(wf) => {
        const { version: _version, ...definition } = wf.definition
        return <EditorScreen initial={definition} existingKey={key} />
      }}
    </Loadable>
  )
}
