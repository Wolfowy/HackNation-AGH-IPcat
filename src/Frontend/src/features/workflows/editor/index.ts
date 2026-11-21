// Editor boundary: pages import `WorkflowEditor` from here. Swap the implementation for a visual DAG editor
// that satisfies `WorkflowEditorProps` without touching the pages.
import { JsonWorkflowEditor } from './JsonWorkflowEditor'
import type { WorkflowEditorComponent } from './types'

export const WorkflowEditor: WorkflowEditorComponent = JsonWorkflowEditor
export type { WorkflowEditorChange, WorkflowEditorProps, WorkflowEditorComponent } from './types'
