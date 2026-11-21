import type { ComponentType } from 'react'
import type { OperationDescriptor, ScanWorkflowDefinition } from '@/api/types'

export interface WorkflowEditorChange {
  /** Parsed definition, or null while the editor content is not a structurally valid definition. */
  definition: ScanWorkflowDefinition | null
  /** Why `definition` is null (e.g. JSON syntax error). */
  parseError?: string
}

/**
 * Contract every workflow editor implements (today: JSON text editor; later: visual DAG editor).
 * The page owns validation (POST /api/workflows/validate) and saving; editors only produce definitions.
 */
export interface WorkflowEditorProps {
  /** Definition the editor starts from (not controlled afterwards). */
  initial: ScanWorkflowDefinition
  onChange: (change: WorkflowEditorChange) => void
  /** Operation catalog (GET /api/operations) for parameter docs, palettes, inline hints. */
  operations: OperationDescriptor[]
}

export type WorkflowEditorComponent = ComponentType<WorkflowEditorProps>
