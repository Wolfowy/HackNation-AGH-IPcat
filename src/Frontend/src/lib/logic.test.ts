import { hasPermission } from '@/auth/roles'
import { dagLevels } from '@/features/workflows/dag'
import { validateSignatureContent, validateWorkflowDefinition } from '@/mocks/handlers'
import { getDb } from '@/mocks/handlers'
import { validateTarget, validateTargetLines } from './targets'

describe('role helpers mirror backend policies', () => {
  it.each([
    ['Viewer', 'read', true],
    ['Viewer', 'edit', false],
    ['Editor', 'edit', true],
    ['Editor', 'manage', false],
    ['Manager', 'manage', true],
    ['Manager', 'admin', false],
    ['Administrator', 'admin', true],
  ] as const)('%s → %s = %s', (role, permission, expected) => {
    expect(hasPermission([role], permission)).toBe(expected)
  })

  it('denies unknown or missing roles', () => {
    expect(hasPermission([], 'read')).toBe(false)
    expect(hasPermission(undefined, 'read')).toBe(false)
    expect(hasPermission(['Auditor'], 'read')).toBe(false)
  })
})

describe('target format hints', () => {
  it.each(['10.0.0.0/24', '192.168.1.10-192.168.1.50', '10.1.2.3', 'fe80::1', '2001:db8::/32', 'host.example.com', '*.example.com', '2001:db8::1-2001:db8::ff'])('accepts %s', (v) => {
    expect(validateTarget(v)).toBeNull()
  })

  it.each(['10.0.0.300/24', '10.0.0.0/33', '10.0.0.9-10.0.0.1', '1.2.3', 'bad host!', '2001:db8::/129'])('rejects %s', (v) => {
    expect(validateTarget(v)).not.toBeNull()
  })

  it('requires at least one line when asked', () => {
    expect(validateTargetLines([], true)).toMatch(/required/)
    expect(validateTargetLines([], false)).toBe(true)
  })
})

describe('workflow DAG levels', () => {
  it('groups steps by dependency depth and reports cycles', () => {
    const { levels, unresolved } = dagLevels([
      { id: 'a', operation: 'DiscoverHosts' },
      { id: 'b', operation: 'ScanPorts', dependsOn: ['a'] },
      { id: 'c', operation: 'TlsProbe', dependsOn: ['a'] },
      { id: 'd', operation: 'PersistObservations', dependsOn: ['b', 'c'] },
      { id: 'x', operation: 'EvaluateCondition', dependsOn: ['y'] },
      { id: 'y', operation: 'EvaluateCondition', dependsOn: ['x'] },
    ])
    expect(levels.map((l) => l.map((s) => s.id))).toEqual([['a'], ['b', 'c'], ['d']])
    expect(unresolved.map((s) => s.id)).toEqual(['x', 'y'])
  })
})

describe('mock validators', () => {
  it('accepts the seeded workflows and rejects unknown parameters', () => {
    for (const wf of getDb().workflows) expect(validateWorkflowDefinition(wf.definition)).toEqual({ valid: true, errors: [] })
    const bad = validateWorkflowDefinition({ key: 'x1', name: 'x', steps: [{ id: 'a', operation: 'ScanPorts', parameters: { shell: 'rm -rf' } }] })
    expect(bad.valid).toBe(false)
  })

  it('flags forbidden nuclei protocols', () => {
    const result = validateSignatureContent('NucleiTemplate', 'id: x\ninfo:\n  severity: info\ncode:\n  - engine: sh\n')
    expect(result.valid).toBe(false)
    expect(result.errors).toContain('Protocol "code" is not allowed.')
  })
})
