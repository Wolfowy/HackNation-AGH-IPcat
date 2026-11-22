import { createDb } from './data'
import { validateWorkflowDefinition } from './handlers'

describe('mock workflow validation', () => {
  it('accepts every seeded workflow', () => {
    for (const wf of createDb().workflows) expect(validateWorkflowDefinition(wf.definition).errors).toEqual([])
  })

  it('mirrors the server data-flow rules', () => {
    const { errors } = validateWorkflowDefinition({
      key: 'bad-flow',
      name: 'Bad',
      steps: [
        { id: 'discover', operation: 'DiscoverHosts', dependsOn: [] },
        { id: 'services', operation: 'DetectService', dependsOn: ['discover'], input: { fromSteps: ['discover'] } },
        { id: 'compare', operation: 'ComparePreviousScan', dependsOn: ['discover'] },
      ],
    } as never)
    expect(errors).toContainEqual(expect.stringContaining("'services': DetectService needs endpoints"))
    expect(errors).toContainEqual(expect.stringContaining("'compare' (ComparePreviousScan) must run after every agent step"))
    expect(errors).toContainEqual(expect.stringContaining("'compare' (ComparePreviousScan) needs a PersistObservations step"))
  })
})
