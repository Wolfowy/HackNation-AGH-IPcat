import type { WorkflowStep } from '@/api/types'

export interface DagLevels {
  /** levels[i] = steps whose dependencies all sit in levels < i. */
  levels: WorkflowStep[][]
  /** Steps that could not be placed (cycle or unknown dependency). */
  unresolved: WorkflowStep[]
}

/** Groups workflow steps by dependency depth (Kahn-style layering), preserving definition order inside a level. */
export function dagLevels(steps: WorkflowStep[]): DagLevels {
  const placed = new Set<string>()
  const levels: WorkflowStep[][] = []
  let remaining = steps
  while (remaining.length) {
    const level = remaining.filter((s) => (s.dependsOn ?? []).every((d) => placed.has(d)))
    if (level.length === 0) break
    level.forEach((s) => placed.add(s.id))
    levels.push(level)
    remaining = remaining.filter((s) => !placed.has(s.id))
  }
  return { levels, unresolved: remaining }
}
