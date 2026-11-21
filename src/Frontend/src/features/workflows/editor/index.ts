// Editor boundary: pages import `WorkflowEditor` from here. Default: visual node-graph editor (with a JSON tab).
import { VisualWorkflowEditor } from './VisualWorkflowEditor'
import type { WorkflowEditorComponent } from './types'

export const WorkflowEditor: WorkflowEditorComponent = VisualWorkflowEditor
export type { WorkflowEditorChange, WorkflowEditorProps, WorkflowEditorComponent } from './types'
