import type { ScanWorkflowDefinition } from '@/api/types'
import { useOperations } from '@/api/workflows'
import { VisualWorkflowEditor } from './editor/VisualWorkflowEditor'

const ignore = () => {}

/** Read-only workflow canvas (same graph as the editor; steps can be inspected, not edited). */
export function WorkflowGraph({ definition }: { definition: ScanWorkflowDefinition }) {
  const operations = useOperations()
  return (
    <div data-testid="workflow-graph">
      <VisualWorkflowEditor initial={definition} operations={operations.data?.operations ?? []} onChange={ignore} readOnly />
    </div>
  )
}
