// MSW handlers implementing the UI-facing API (ARCHITECTURE.md §11) on top of an in-memory db.
import { http, HttpResponse, type PathParams } from 'msw'
import type {
  Change,
  FindingTriageInput,
  HostDetail,
  Network,
  NetworkDevice,
  NetworkInput,
  ScanEstimate,
  ScanEstimateRequest,
  ScanRunUpdate,
  ScanStartRequest,
  ScanWorkflowDefinition,
  ScheduleInput,
  ServiceAnnotation,
  ServiceDetail,
  Severity,
  SignatureKind,
  Topology,
  TopologyHost,
  User,
  ValidationResult,
} from '@/api/types'
import { CRITICALITIES, SCAN_IMPORT_FORMATS, SEVERITIES } from '@/api/types'
import { hasPermission, type Permission } from '@/auth/roles'
import { dagLevels } from '@/features/workflows/dag'
import { validateTarget } from '@/lib/targets'
import { buildRunPlan, createDb, mockId, randomGuid, requiresApprovalNote, type MockDb, type MockHost, type MockRun, type MockUser } from './data'
import { OPERATIONS } from './operations'
import { emit, progressOf, startRunSimulation, stopAllSimulations, stopRunSimulation } from './simulation'

let db: MockDb = createDb()
export const getDb = () => db
export function resetDb() {
  stopAllSimulations()
  db = createDb()
}

const TOKEN_PREFIX = 'mock-token.'

// ---------- response helpers ----------
const problem = (status: number, title: string, extra: Record<string, unknown> = {}) =>
  HttpResponse.json({ type: `https://httpstatuses.io/${status}`, title, status, ...extra }, { status, headers: { 'Content-Type': 'application/problem+json' } })
const validationProblem = (errors: Record<string, string[]>) => problem(400, 'One or more validation errors occurred.', { errors })
const notFound = (what = 'Resource') => problem(404, `${what} not found`)
const noContent = () => new HttpResponse(null, { status: 204 })

function paged<T>(items: T[], url: URL, defaultPageSize = 50) {
  const page = Math.max(1, Number(url.searchParams.get('page') ?? 1))
  const pageSize = Math.min(500, Math.max(1, Number(url.searchParams.get('pageSize') ?? defaultPageSize)))
  return { items: items.slice((page - 1) * pageSize, page * pageSize), total: items.length, page, pageSize }
}

/** ScanLimits.Validate() ranges (Scanning/Planning/ClaimSelector.cs). */
const SCAN_LIMIT_RANGES: Record<keyof MockDb['scanLimits'], [number, number]> = {
  defaultBatchSize: [64, 1024],
  leaseDurationSeconds: [30, 3600],
  maxAttempts: [1, 10],
  maxConcurrentJobsPerZone: [1, 100_000],
  maxConcurrentJobsPerInterface: [1, 1000],
  maxConcurrentJobsPerSubnet: [1, 100_000],
  subnetPrefixLength: [8, 32],
  maxRatePerSecondGlobal: [1, 100_000_000],
  unassignedJobTimeoutSeconds: [0, 604_800],
  targetJobSeconds: [30, 3600],
}

/** Mock of POST /api/scans/estimate: first step over the network address counts, agents measured at 2 targets/s per job, 8 slots. */
function estimateScan(req: ScanEstimateRequest): ScanEstimate {
  const addressCount = db.networks.filter((n) => req.networkIds.includes(n.id)).reduce((sum, n) => sum + n.addressCount, 0)
  const batchSize = Math.min(1024, Math.max(64, 2 ** Math.floor(Math.log2(2 * db.scanLimits.targetJobSeconds))))
  const jobs = Math.ceil(addressCount / batchSize)
  const parallel = Math.max(1, Math.min(8, jobs))
  const min = Math.round(addressCount / (4 * parallel))
  const max = Math.max(min, Math.round((Math.ceil(jobs / parallel) * Math.min(batchSize, addressCount)) / 2))
  const exceedsWindow = req.windowMinutes !== undefined && max > req.windowMinutes * 60
  const reason = `batch size ${batchSize} (measured 2 targets/s per job, ${db.scanLimits.targetJobSeconds}s target job duration)`
  return {
    addressCount,
    steps: [{ stepId: 'discover', operation: 'DiscoverHosts', targets: addressCount, jobs, batchSize, batchReason: reason, eligibleAgents: 2, targetsPerSecond: 2, estimatedSecondsMin: min, estimatedSecondsMax: max, unassignable: 0 }],
    estimatedSecondsMin: min,
    estimatedSecondsMax: max,
    windowMinutes: req.windowMinutes,
    exceedsWindow,
    warnings: exceedsWindow ? [`The first steps may take longer than the ${req.windowMinutes}-minute window; the run would be stopped at the window end with partial results.`] : [],
  }
}

const publicUser = ({ password: _password, ...u }: MockUser): User => u

/** Which seeded agent interface scans which zone (topology `observedBy`). */
const MOCK_PERSPECTIVES: Record<string, { agentId: string; interfaceName: string }> = {
  dmz: { agentId: 'scanner-dmz-01', interfaceName: 'eth0' },
  office: { agentId: 'scanner-office-01', interfaceName: 'ens18' },
  lab: { agentId: 'scanner-office-01', interfaceName: 'wg0' },
}

/**
 * Server rule (Topology.InferDevices): a MAC on current hosts of 2+ zones (or a VRRP/HSRP MAC) is one network device; a locally
 * administered MAC gives confidence 'low'; multicast/broadcast/zero MACs are ignored; a MAC on several IPs of one zone is only shared.
 */
function inferDevices(hosts: MockHost[]) {
  const byMac = new Map<string, MockHost[]>()
  for (const h of hosts) {
    const first = parseInt(h.macAddress?.slice(0, 2) ?? '', 16)
    if (!h.macAddress || h.status === 'Gone' || Number.isNaN(first) || first & 1 || h.macAddress === '00:00:00:00:00:00') continue
    byMac.set(h.macAddress, [...(byMac.get(h.macAddress) ?? []), h])
  }
  const devices: NetworkDevice[] = []
  const sharedMac = new Set<string>()
  for (const [mac, nics] of byMac) {
    const zones = [...new Set(nics.map((h) => h.zone))].sort()
    for (const zone of zones) {
      const inZone = nics.filter((h) => h.zone === zone)
      if (inZone.length > 1) inZone.forEach((h) => sharedMac.add(h.id))
    }
    if (zones.length < 2 && !mac.startsWith('00:00:5E:00:01:') && !mac.startsWith('00:00:0C:07:AC:')) continue
    devices.push({
      id: mac,
      macAddress: mac,
      macVendor: nics.find((h) => h.macVendor)?.macVendor,
      confidence: parseInt(mac.slice(0, 2), 16) & 2 ? 'low' : 'high',
      zones,
      interfaces: nics
        .map((h) => ({ hostId: h.id, zone: h.zone, address: h.address }))
        .sort((a, b) => a.zone.localeCompare(b.zone) || a.address.localeCompare(b.address)),
    })
  }
  return { devices, sharedMac, deviceOf: new Map(devices.flatMap((d) => d.interfaces.map((i) => [i.hostId, d] as const))) }
}

const withDeviceFlags = (h: MockHost, deviceOf: Map<string, NetworkDevice>) => ({
  ...h,
  networkDevice: deviceOf.has(h.id),
  networkDeviceConfidence: deviceOf.get(h.id)?.confidence,
})

function inIpv4Cidr(address: string, cidr: string) {
  const [base, bits = '32'] = cidr.split('/')
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(address) || !/^\d+\.\d+\.\d+\.\d+$/.test(base)) return address === cidr
  const size = 2 ** (32 - Number(bits))
  return Math.floor(ipv4ToInt(address) / size) === Math.floor(ipv4ToInt(base) / size)
}

function audit(user: MockUser, action: string, entityType: string, entityId?: string) {
  db.audit.unshift({
    id: randomGuid(),
    occurredAt: new Date().toISOString(),
    userId: user.id,
    userName: user.userName,
    action,
    entityType,
    entityId,
    details: { source: 'ui' },
    ipAddress: '127.0.0.1',
  })
}

interface Ctx {
  request: Request
  params: PathParams
  url: URL
  user: MockUser
}

/** Authenticated route with the backend policy (CanRead/CanEdit/CanManage/AdminOnly). */
function route(permission: Permission, handler: (ctx: Ctx) => Response | Promise<Response>) {
  return async ({ request, params }: { request: Request; params: PathParams }) => {
    const header = request.headers.get('Authorization') ?? ''
    const userId = header.startsWith(`Bearer ${TOKEN_PREFIX}`) ? header.slice(`Bearer ${TOKEN_PREFIX}`.length) : ''
    const user = db.users.find((u) => u.id === userId && u.isActive !== false)
    if (!user) return problem(401, 'Unauthorized')
    if (!hasPermission(user.roles, permission)) return problem(403, 'Forbidden', { detail: `Requires ${permission} permission.` })
    return handler({ request, params, url: new URL(request.url), user })
  }
}

const p = (params: PathParams, key: string) => decodeURIComponent(String(params[key]))
const body = async <T,>(request: Request) => (await request.json()) as T

// ---------- validation helpers ----------
const ipv4ToInt = (ip: string) => ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0)
function insideScope(target: string): boolean {
  const addr = target.split(/[/-]/)[0]
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(addr)) return true // hostnames / IPv6 are not checked by the mock
  return db.scopePolicy.allowed.some((cidr) => {
    const [net, bits] = cidr.split('/')
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(net)) return false
    const mask = Number(bits) === 0 ? 0 : (~0 << (32 - Number(bits))) >>> 0
    return ((ipv4ToInt(addr) & mask) >>> 0) === ((ipv4ToInt(net) & mask) >>> 0)
  })
}

function validateNetwork(input: NetworkInput, ignoreId?: string): Record<string, string[]> {
  const errors: Record<string, string[]> = {}
  const add = (k: string, m: string) => (errors[k] ??= []).push(m)
  if (!input.name?.trim()) add('Name', 'Name is required.')
  else if (db.networks.some((n) => n.name.toLowerCase() === input.name.trim().toLowerCase() && n.id !== ignoreId))
    add('Name', `A network named "${input.name}" already exists.`)
  if (!db.zones.some((z) => z.name === input.zone)) add('Zone', `Unknown zone "${input.zone}".`)
  if (!input.ranges?.length) add('Ranges', 'At least one range is required.')
  input.ranges?.forEach((r, i) => {
    const err = validateTarget(r)
    if (err) add(`Ranges[${i}]`, err)
    else if (!insideScope(r)) add(`Ranges[${i}]`, `${r} is outside the global scope policy.`)
  })
  input.exclusions?.forEach((r, i) => {
    const err = validateTarget(r)
    if (err) add(`Exclusions[${i}]`, err)
  })
  return errors
}

function addressCount(ranges: string[]): number {
  return ranges.reduce((sum, r) => {
    const [, bits] = r.split('/')
    if (bits && r.includes('.')) return sum + Math.max(1, 2 ** (32 - Number(bits)) - 2)
    if (r.includes('-')) {
      const [a, b] = r.split('-')
      return sum + (ipv4ToInt(b) - ipv4ToInt(a) + 1)
    }
    return sum + 1
  }, 0)
}

export function validateWorkflowDefinition(def: ScanWorkflowDefinition): ValidationResult {
  const errors: string[] = []
  if (!def || typeof def !== 'object') return { valid: false, errors: ['Definition must be an object.'] }
  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(def.key ?? '')) errors.push('key: must match ^[a-z0-9][a-z0-9-]{1,63}$')
  if (!def.name?.trim()) errors.push('name: is required')
  if (!Array.isArray(def.steps) || def.steps.length === 0) errors.push('steps: at least one step is required')
  const ids = new Set<string>()
  for (const [i, step] of (def.steps ?? []).entries()) {
    const where = `steps[${i}]`
    if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(step.id ?? '')) errors.push(`${where}.id: invalid step id`)
    if (ids.has(step.id)) errors.push(`${where}.id: duplicate step id "${step.id}"`)
    ids.add(step.id)
    const op = OPERATIONS.find((o) => o.operation === step.operation)
    if (!op) {
      errors.push(`${where}.operation: unknown operation "${step.operation}"`)
      continue
    }
    for (const name of Object.keys(step.parameters ?? {}))
      if (!op.parameters.some((pd) => pd.name === name)) errors.push(`${where}.parameters.${name}: unknown parameter for ${op.operation}`)
    for (const pd of op.parameters) {
      const value = step.parameters?.[pd.name]
      if (value === undefined) continue
      if (pd.type === 'Integer' && (!/^-?\d+$/.test(value) || (pd.min !== undefined && Number(value) < pd.min) || (pd.max !== undefined && Number(value) > pd.max)))
        errors.push(`${where}.parameters.${pd.name}: must be an integer in [${pd.min ?? '-∞'}, ${pd.max ?? '∞'}]`)
      if (pd.type === 'Enum' && !pd.allowedValues?.includes(value)) errors.push(`${where}.parameters.${pd.name}: must be one of ${pd.allowedValues?.join(', ')}`)
      if (pd.type === 'Boolean' && !['true', 'false'].includes(value)) errors.push(`${where}.parameters.${pd.name}: must be true or false`)
    }
    // Same target rules as the server's WorkflowValidator.
    if (op.plane === 'Server' && op.operation !== 'EvaluateCondition' && (step.input || step.when)) errors.push(`${where}: server step ${op.operation} has no targets (input/when are not allowed)`)
    if ((op.inputKind === 'Endpoints' || op.operation === 'EvaluateCondition') && !step.input) errors.push(`${where}: ${op.operation} needs input.fromSteps`)
    if (step.when && !step.input && op.plane === 'Agent') errors.push(`${where}: 'when' requires input.fromSteps`)
  }
  for (const [i, step] of (def.steps ?? []).entries())
    for (const dep of [...(step.dependsOn ?? []), ...(step.input?.fromSteps ?? [])])
      if (!ids.has(dep)) errors.push(`steps[${i}]: unknown step "${dep}" referenced`)
  const steps = def.steps ?? []
  const referencesKnown = steps.every((s) => [...(s.dependsOn ?? []), ...(s.input?.fromSteps ?? [])].every((d) => ids.has(d)))
  const acyclic = referencesKnown && dagLevels(steps).unresolved.length === 0
  if (referencesKnown && !acyclic) errors.push('steps: the dependency graph contains a cycle')
  // Like the server: data-flow problems are reported together with parameter errors once the graph itself is sound.
  if (acyclic && ids.size === steps.length) errors.push(...dataFlowErrors(steps))
  return { valid: errors.length === 0, errors }
}

/** Mirrors WorkflowValidator.ValidateDataFlow: inputs need producers, endpoint steps need ports, closing steps come last. */
function dataFlowErrors(steps: ScanWorkflowDefinition['steps']): string[] {
  const errors: string[] = []
  const byId = new Map(steps.map((s) => [s.id, s]))
  const plane = (s: (typeof steps)[number]) => OPERATIONS.find((o) => o.operation === s.operation)?.plane
  const ancestors = (id: string, seen = new Set<string>()): Set<string> => {
    for (const dep of byId.get(id)?.dependsOn ?? []) if (!seen.has(dep)) ancestors(dep, seen.add(dep))
    return seen
  }
  // `seen` guards against inputs that point at non-ancestors (the server rejects those before this check).
  const producers = (s: (typeof steps)[number], seen = new Set<string>()): (typeof steps)[number][] =>
    (s.input?.fromSteps ?? [])
      .filter((id) => !seen.has(id) && seen.add(id))
      .map((id) => byId.get(id)!)
      .flatMap((p) => (p.operation === 'EvaluateCondition' ? producers(p, seen) : [p]))
  const endpointProducers = ['ScanPorts', 'DetectService', 'HttpProbe', 'TlsProbe', 'ExecuteSignatures']
  for (const s of steps.filter((x) => x.input)) {
    for (const from of s.input!.fromSteps.map((id) => byId.get(id)!))
      if (plane(from) !== 'Agent' && from.operation !== 'EvaluateCondition')
        errors.push(`Step '${s.id}' reads input from '${from.id}' (${from.operation}), which produces no observations; use an agent step or EvaluateCondition.`)
    const op = OPERATIONS.find((o) => o.operation === s.operation)
    if (op?.inputKind === 'Endpoints' && !producers(s).some((p) => endpointProducers.includes(p.operation)))
      errors.push(`Step '${s.id}': ${s.operation} needs endpoints (host:port), but its input only has hosts without ports; read from a step with ports (${endpointProducers.join(', ')}).`)
  }
  const agentSteps = steps.filter((s) => plane(s) === 'Agent').map((s) => s.id)
  const persist = steps.filter((s) => s.operation === 'PersistObservations').map((s) => s.id)
  for (const s of steps.filter((x) => ['PersistObservations', 'ComparePreviousScan', 'PublishFinding'].includes(x.operation))) {
    const before = ancestors(s.id)
    const missing = agentSteps.filter((id) => !before.has(id))
    if (missing.length) errors.push(`Step '${s.id}' (${s.operation}) must run after every agent step; add a dependency path from: ${missing.join(', ')}.`)
    if (s.operation !== 'PersistObservations' && !persist.some((id) => before.has(id)))
      errors.push(`Step '${s.id}' (${s.operation}) needs a PersistObservations step before it (it records coverage and waits for all results).`)
  }
  return errors
}

export function validateSignatureContent(kind: SignatureKind, content: string): ValidationResult {
  const errors: string[] = []
  const warnings: string[] = []
  if (!content?.trim()) return { valid: false, errors: ['Content is empty.'], warnings }
  if (kind === 'NucleiTemplate') {
    if (!/^id:\s*\S+/m.test(content)) errors.push('Template must declare an "id".')
    if (!/^info:/m.test(content)) errors.push('Template must contain an "info" block.')
    for (const protocol of ['code', 'headless', 'javascript', 'file'])
      if (new RegExp(`^\\s*${protocol}:`, 'm').test(content)) errors.push(`Protocol "${protocol}" is not allowed.`)
    if (/interactsh/i.test(content)) errors.push('Out-of-band interactions (interactsh) are not allowed.')
    const tags = /^\s*tags:\s*(.+)$/m.exec(content)?.[1] ?? ''
    for (const bad of ['intrusive', 'dos', 'fuzz']) if (tags.split(',').map((x) => x.trim()).includes(bad)) errors.push(`Tag "${bad}" is not allowed.`)
    const severity = /^\s*severity:\s*(\w+)/m.exec(content)?.[1]
    if (!severity) warnings.push('No severity declared; "info" will be assumed.')
    else if (!['info', 'low'].includes(severity)) warnings.push(`Severity "${severity}" is above the default info/low.`)
  } else {
    try {
      const parsed = JSON.parse(content) as unknown
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) errors.push('Rule must be a JSON object.')
      else if (!('description' in parsed)) warnings.push('Rule has no "description".')
    } catch (err) {
      errors.push(`Invalid JSON: ${err instanceof Error ? err.message : String(err)}`)
    }
  }
  return { valid: errors.length === 0, errors, warnings }
}

// ---------- export helpers ----------
function toCsv(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return ''
  const columns = Object.keys(rows[0])
  const cell = (v: unknown) => {
    const s = v === undefined || v === null ? '' : Array.isArray(v) ? v.join(';') : typeof v === 'object' ? JSON.stringify(v) : String(v)
    return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  return [columns.join(','), ...rows.map((r) => columns.map((c) => cell(r[c])).join(','))].join('\n') + '\n'
}

function exportResponse(name: string, rows: Record<string, unknown>[], format: string | null) {
  const csv = format === 'csv'
  const stamp = new Date().toISOString().slice(0, 10)
  return new HttpResponse(csv ? toCsv(rows) : JSON.stringify(rows, null, 2), {
    headers: {
      'Content-Type': csv ? 'text/csv; charset=utf-8' : 'application/json',
      'Content-Disposition': `attachment; filename="${name}-${stamp}.${csv ? 'csv' : 'json'}"`,
    },
  })
}

function parseCsv(text: string): Record<string, string>[] {
  const [header, ...lines] = text.trim().split(/\r?\n/)
  const cols = header.split(',').map((c) => c.trim())
  return lines.filter(Boolean).map((line) => Object.fromEntries(line.split(',').map((v, i) => [cols[i], v.trim().replace(/^"|"$/g, '')])))
}

const runView = (run: MockRun) => {
  const { steps: _steps, ...rest } = run
  const progress = progressOf(db, run)
  // ETA like the server: open work at the rate achieved so far.
  const elapsed = run.startedAt ? (Date.now() - Date.parse(run.startedAt)) / 1000 : 0
  const active = ['Pending', 'Running'].includes(run.status)
  const remainingSeconds = active && progress.percent > 0 && elapsed > 0 ? Math.round((elapsed * (100 - progress.percent)) / progress.percent) : undefined
  const estimatedFinishAt = remainingSeconds === undefined ? undefined : new Date(Date.now() + remainingSeconds * 1000).toISOString()
  return { ...rest, progress, remainingSeconds, estimatedFinishAt }
}

function createRun(user: MockUser, req: ScanStartRequest, triggeredBy: string): MockRun {
  const wf = db.workflows.filter((w) => w.key === req.workflowKey).sort((a, b) => b.version - a.version)
  const version = req.workflowVersion ?? wf[0]?.version ?? 1
  const now = new Date().toISOString()
  const run: MockRun = {
    id: randomGuid(),
    name: req.name,
    status: 'Pending',
    workflowKey: req.workflowKey,
    workflowVersion: version,
    networkIds: req.networkIds,
    triggeredBy,
    priority: req.priority ?? 50,
    createdAt: now,
    notAfter: req.windowMinutes ? new Date(Date.now() + req.windowMinutes * 60_000).toISOString() : undefined,
    progress: { jobsTotal: 0, jobsQueued: 0, jobsRunning: 0, jobsCompleted: 0, jobsFailed: 0, percent: 0 },
    coverageComplete: false,
    tags: [],
    steps: [],
  }
  const plan = buildRunPlan(db, run, Math.max(2, req.networkIds.length * 2))
  run.steps = plan.steps
  db.jobs.push(...plan.jobs)
  db.runs.unshift(run)
  emit(db, { type: 'RunCreated', scanRunId: run.id, message: `Run created by ${triggeredBy}` })
  audit(user, 'scan.started', 'scan_run', run.id)
  startRunSimulation(db, run)
  return run
}

// ---------- handlers ----------
export const handlers = [
  // Identity
  http.post('*/api/auth/login', async ({ request }) => {
    const { userName, password } = await body<{ userName: string; password: string }>(request)
    const user = db.users.find((u) => u.userName.toLowerCase() === userName?.toLowerCase() && u.password === password && u.isActive !== false)
    if (!user) return problem(401, 'Invalid user name or password.')
    user.lastLoginAt = new Date().toISOString()
    return HttpResponse.json({ accessToken: TOKEN_PREFIX + user.id, expiresAt: new Date(Date.now() + 8 * 3_600_000).toISOString(), user: publicUser(user) })
  }),
  http.get('*/api/auth/me', route('read', ({ user }) => HttpResponse.json(publicUser(user)))),
  http.get('*/api/users', route('admin', () => HttpResponse.json(db.users.map(publicUser)))),
  http.post(
    '*/api/users',
    route('admin', async ({ request, user }) => {
      const input = await body<User & { password: string }>(request)
      if (db.users.some((u) => u.userName.toLowerCase() === input.userName.toLowerCase()))
        return validationProblem({ UserName: [`User "${input.userName}" already exists.`] })
      if (!input.password || input.password.length < 12) return validationProblem({ Password: ['Password must have at least 12 characters.'] })
      const created: MockUser = { ...input, id: randomGuid(), createdAt: new Date().toISOString(), isActive: input.isActive ?? true }
      db.users.push(created)
      audit(user, 'user.created', 'user', created.id)
      return HttpResponse.json(publicUser(created), { status: 201 })
    }),
  ),
  http.put(
    '*/api/users/:id',
    route('admin', async ({ request, params, user }) => {
      const target = db.users.find((u) => u.id === p(params, 'id'))
      if (!target) return notFound('User')
      Object.assign(target, await body<Partial<User>>(request))
      audit(user, 'user.updated', 'user', target.id)
      return HttpResponse.json(publicUser(target))
    }),
  ),
  http.delete(
    '*/api/users/:id',
    route('admin', ({ params, user }) => {
      db.users = db.users.filter((u) => u.id !== p(params, 'id'))
      audit(user, 'user.deleted', 'user', p(params, 'id'))
      return noContent()
    }),
  ),
  http.post(
    '*/api/users/:id/password',
    route('admin', async ({ request, params }) => {
      const target = db.users.find((u) => u.id === p(params, 'id'))
      if (!target) return notFound('User')
      target.password = (await body<{ password: string }>(request)).password
      return noContent()
    }),
  ),

  // Agents & tools
  http.get('*/api/agents', route('read', () => HttpResponse.json(db.agents))),
  http.get(
    '*/api/agents/:agentId',
    route('read', ({ params }) => {
      const agent = db.agents.find((a) => a.agentId === p(params, 'agentId'))
      return agent ? HttpResponse.json(agent) : notFound('Agent')
    }),
  ),
  http.post(
    '*/api/agents/:agentId/status',
    route('admin', async ({ request, params, user }) => {
      const agent = db.agents.find((a) => a.agentId === p(params, 'agentId'))
      if (!agent) return notFound('Agent')
      agent.status = (await body<{ status: typeof agent.status }>(request)).status
      audit(user, `agent.${agent.status.toLowerCase()}`, 'agent', agent.agentId)
      return noContent()
    }),
  ),
  http.put(
    '*/api/agents/:agentId/assignment',
    route('admin', async ({ request, params, user }) => {
      const agent = db.agents.find((a) => a.agentId === p(params, 'agentId'))
      if (!agent) return notFound('Agent')
      const a = await body<{ authorizedZones: string[]; authorizedNetworkIds: string[]; maxConcurrentJobs?: number; maxRatePerSecond?: number }>(request)
      agent.authorizedZones = a.authorizedZones
      agent.authorizedNetworkIds = a.authorizedNetworkIds
      agent.limitOverrides = { maxConcurrentJobs: a.maxConcurrentJobs, maxRatePerSecond: a.maxRatePerSecond }
      const reported = agent.reportedLimits ?? agent.limits
      agent.limits = {
        maxConcurrentJobs: Math.min(reported.maxConcurrentJobs ?? Infinity, a.maxConcurrentJobs ?? Infinity),
        maxRatePerSecond: Math.min(reported.maxRatePerSecond ?? Infinity, a.maxRatePerSecond ?? Infinity),
      }
      audit(user, 'agent.assignment.updated', 'agent', agent.agentId)
      return noContent()
    }),
  ),
  http.post('*/api/agents/:agentId/rotate-credentials', route('admin', () => noContent())),
  http.delete(
    '*/api/agents/:agentId',
    route('admin', ({ params, user }) => {
      db.agents = db.agents.filter((a) => a.agentId !== p(params, 'agentId'))
      audit(user, 'agent.deleted', 'agent', p(params, 'agentId'))
      return noContent()
    }),
  ),
  http.get('*/api/enrollment-tokens', route('admin', () => HttpResponse.json(db.tokens))),
  http.post(
    '*/api/enrollment-tokens',
    route('admin', async ({ request, user }) => {
      const input = await body<{ name: string; expiresInHours: number; maxUses: number; autoApprove: boolean; zones?: string[] }>(request)
      if (!input.name?.trim()) return validationProblem({ Name: ['Name is required.'] })
      const id = randomGuid()
      const expiresAt = new Date(Date.now() + input.expiresInHours * 3_600_000).toISOString()
      db.tokens.unshift({ id, name: input.name, expiresAt, maxUses: input.maxUses, uses: 0, autoApprove: input.autoApprove, zones: input.zones ?? [], revoked: false, createdAt: new Date().toISOString() })
      audit(user, 'enrollment-token.created', 'enrollment_token', id)
      const token = Array.from(crypto.getRandomValues(new Uint8Array(24)), (b) => b.toString(16).padStart(2, '0')).join('')
      return HttpResponse.json({ id, token: `wset_${token}`, expiresAt }, { status: 201 })
    }),
  ),
  http.delete(
    '*/api/enrollment-tokens/:id',
    route('admin', ({ params }) => {
      const token = db.tokens.find((tk) => tk.id === p(params, 'id'))
      if (token) token.revoked = true
      return noContent()
    }),
  ),
  http.get('*/api/tools', route('read', () => HttpResponse.json(db.tools))),
  http.put(
    '*/api/tools/:toolId',
    route('admin', async ({ request, params, user }) => {
      const tool = db.tools.find((tl) => tl.toolId === p(params, 'toolId'))
      if (!tool) return notFound('Tool')
      Object.assign(tool, await body<{ approved: boolean; enabled: boolean }>(request))
      db.agents.forEach((a) => a.tools.filter((tl) => tl.id === tool.toolId).forEach((tl) => (tl.approved = tool.approved)))
      audit(user, tool.approved ? 'tool.approved' : 'tool.unapproved', 'tool', tool.toolId)
      return noContent()
    }),
  ),

  // Networks & scope
  http.get('*/api/networks/export', route('read', ({ url }) => exportResponse('networks', db.networks as unknown as Record<string, unknown>[], url.searchParams.get('format')))),
  http.post(
    '*/api/networks/import',
    route('manage', async ({ request, url, user }) => {
      const text = await request.text()
      let rows: Partial<NetworkInput>[]
      try {
        rows =
          url.searchParams.get('format') === 'csv'
            ? parseCsv(text).map((r) => ({ name: r.name, zone: r.zone, ranges: (r.ranges ?? '').split(';').filter(Boolean), description: r.description }))
            : (JSON.parse(text) as Partial<NetworkInput>[])
      } catch {
        return validationProblem({ File: ['The file could not be parsed.'] })
      }
      const result = { created: 0, updated: 0, errors: [] as string[] }
      rows.forEach((row, i) => {
        const input = { description: '', exclusions: [], tags: [], enabled: true, ranges: [], zone: '', name: '', ...row } as NetworkInput
        const existing = db.networks.find((n) => n.name === input.name)
        const errors = validateNetwork(input, existing?.id)
        if (Object.keys(errors).length) return result.errors.push(`Row ${i + 1}: ${Object.values(errors).flat().join(' ')}`)
        if (existing) {
          Object.assign(existing, input, { addressCount: addressCount(input.ranges), updatedAt: new Date().toISOString() })
          result.updated++
        } else {
          db.networks.push({ ...input, id: randomGuid(), addressCount: addressCount(input.ranges), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() })
          result.created++
        }
      })
      audit(user, 'network.imported', 'network')
      return HttpResponse.json(result)
    }),
  ),
  http.get(
    '*/api/networks/agent-subnets',
    route('read', () =>
      // shortcut: exact-string matching instead of the server's address-set math; enough for the fixtures.
      HttpResponse.json(
        db.agentSubnets.map((subnet) => {
          const allowed = subnet.scope === 'full' || db.scopePolicy.allowed.includes(subnet.cidr)
          const wanted = allowed && subnet.scope !== 'full' ? [subnet.cidr] : subnet.proposedRanges
          const covering = db.networks.filter((n) => subnet.candidateZones.includes(n.zone) && n.ranges.some((r) => r === subnet.cidr || wanted.includes(r)))
          return {
            ...subnet,
            scope: allowed ? 'full' : subnet.scope,
            existingNetworks: [...new Set([...subnet.existingNetworks, ...covering.map((n) => n.name)])],
            proposedRanges: covering.length ? [] : wanted,
          }
        }),
      ),
    ),
  ),
  http.get('*/api/networks', route('read', () => HttpResponse.json(db.networks))),
  http.get(
    '*/api/networks/:id',
    route('read', ({ params }) => {
      const n = db.networks.find((x) => x.id === p(params, 'id'))
      return n ? HttpResponse.json(n) : notFound('Network')
    }),
  ),
  http.post(
    '*/api/networks',
    route('manage', async ({ request, user }) => {
      const input = await body<NetworkInput>(request)
      const errors = validateNetwork(input)
      if (Object.keys(errors).length) return validationProblem(errors)
      const now = new Date().toISOString()
      const network: Network = { ...input, exclusions: input.exclusions ?? [], tags: input.tags ?? [], id: randomGuid(), addressCount: addressCount(input.ranges), createdAt: now, updatedAt: now }
      db.networks.push(network)
      audit(user, 'network.created', 'network', network.id)
      return HttpResponse.json(network, { status: 201 })
    }),
  ),
  http.put(
    '*/api/networks/:id',
    route('edit', async ({ request, params, user }) => {
      const network = db.networks.find((x) => x.id === p(params, 'id'))
      if (!network) return notFound('Network')
      const input = await body<NetworkInput>(request)
      const errors = validateNetwork(input, network.id)
      if (Object.keys(errors).length) return validationProblem(errors)
      Object.assign(network, input, { addressCount: addressCount(input.ranges), updatedAt: new Date().toISOString() })
      audit(user, 'network.updated', 'network', network.id)
      return HttpResponse.json(network)
    }),
  ),
  http.delete(
    '*/api/networks/:id',
    route('manage', ({ params, user }) => {
      db.networks = db.networks.filter((x) => x.id !== p(params, 'id'))
      audit(user, 'network.deleted', 'network', p(params, 'id'))
      return noContent()
    }),
  ),
  http.get('*/api/zones', route('read', () => HttpResponse.json(db.zones.map((z) => ({ ...z, networkCount: db.networks.filter((n) => n.zone === z.name).length }))))),
  http.post(
    '*/api/zones',
    route('manage', async ({ request }) => {
      const z = await body<{ name: string; description?: string }>(request)
      if (db.zones.some((x) => x.name === z.name)) return validationProblem({ Name: [`Zone "${z.name}" already exists.`] })
      db.zones.push(z)
      return HttpResponse.json({ ...z, networkCount: 0 }, { status: 201 })
    }),
  ),
  http.delete(
    '*/api/zones/:name',
    route('manage', ({ params }) => {
      const name = p(params, 'name')
      if (db.networks.some((n) => n.zone === name)) return problem(409, 'Zone is in use by networks.')
      db.zones = db.zones.filter((z) => z.name !== name)
      return noContent()
    }),
  ),
  http.get('*/api/scope-policy', route('read', () => HttpResponse.json(db.scopePolicy))),
  http.put(
    '*/api/scope-policy',
    route('admin', async ({ request, user }) => {
      const input = await body<{ allowed: string[]; excluded: string[]; allowedPorts?: string[]; excludedPorts?: string[] }>(request)
      // Like the server: port lists left out are kept.
      db.scopePolicy = { ...db.scopePolicy, ...input, updatedAt: new Date().toISOString() }
      audit(user, 'scope.updated', 'scope_policy')
      return HttpResponse.json(db.scopePolicy)
    }),
  ),
  http.get('*/api/settings', route('admin', () => HttpResponse.json({ values: db.settings }))),
  http.put(
    '*/api/settings',
    route('admin', async ({ request, user }) => {
      const { values } = await body<{ values: Record<string, string | null> }>(request)
      for (const [key, value] of Object.entries(values)) {
        if (value === null) delete db.settings[key]
        else db.settings[key] = value
      }
      audit(user, 'settings.updated', 'settings')
      return HttpResponse.json({ values: db.settings })
    }),
  ),
  http.get(
    '*/api/audit',
    route('admin', ({ url }) => {
      const action = url.searchParams.get('action')?.toLowerCase()
      const entityType = url.searchParams.get('entityType')?.toLowerCase()
      const userId = url.searchParams.get('userId')
      const items = db.audit.filter(
        (e) => (!action || e.action.toLowerCase().includes(action)) && (!entityType || e.entityType.toLowerCase().includes(entityType)) && (!userId || e.userId === userId),
      )
      return HttpResponse.json(paged(items, url))
    }),
  ),

  // Operations & workflows
  http.get(
    '*/api/operations',
    route('read', () =>
      HttpResponse.json({
        operations: OPERATIONS,
        capabilityMapping: Object.fromEntries(OPERATIONS.filter((o) => o.requiredCapability).map((o) => [o.operation, o.requiredCapability])),
      }),
    ),
  ),
  http.post('*/api/workflows/validate', route('read', async ({ request }) => HttpResponse.json(validateWorkflowDefinition(await body<ScanWorkflowDefinition>(request))))),
  http.get(
    '*/api/workflows',
    route('read', () => {
      const keys = [...new Set(db.workflows.map((w) => w.key))]
      return HttpResponse.json(
        keys.map((key) => {
          const latest = db.workflows.filter((w) => w.key === key).sort((a, b) => b.version - a.version)[0]
          return { key, latestVersion: latest.version, name: latest.definition.name, description: latest.definition.description, updatedAt: latest.createdAt }
        }),
      )
    }),
  ),
  http.get(
    '*/api/workflows/:key',
    route('read', ({ params }) => {
      const latest = db.workflows.filter((w) => w.key === p(params, 'key')).sort((a, b) => b.version - a.version)[0]
      return latest ? HttpResponse.json(latest) : notFound('Workflow')
    }),
  ),
  http.get('*/api/workflows/:key/versions', route('read', ({ params }) => HttpResponse.json(db.workflows.filter((w) => w.key === p(params, 'key')).sort((a, b) => b.version - a.version)))),
  http.get(
    '*/api/workflows/:key/versions/:version',
    route('read', ({ params }) => {
      const wf = db.workflows.find((w) => w.key === p(params, 'key') && w.version === Number(p(params, 'version')))
      return wf ? HttpResponse.json(wf) : notFound('Workflow version')
    }),
  ),
  ...['*/api/workflows', '*/api/workflows/:key/versions'].map((path) =>
    http.post(
      path,
      route('manage', async ({ request, params, user }) => {
        const def = await body<ScanWorkflowDefinition>(request)
        const key = params.key ? p(params, 'key') : def.key
        const result = validateWorkflowDefinition({ ...def, key })
        if (!result.valid) return validationProblem({ Definition: result.errors.map(String) })
        const existing = db.workflows.filter((w) => w.key === key)
        if (!params.key && existing.length) return problem(409, `Workflow "${key}" already exists; create a new version instead.`)
        const version = existing.length + 1
        const saved = { key, version, definition: { ...def, key, version }, createdAt: new Date().toISOString(), createdBy: user.userName }
        db.workflows.push(saved)
        audit(user, 'workflow.saved', 'workflow', `${key}@${version}`)
        return HttpResponse.json(saved, { status: 201 })
      }),
    ),
  ),

  // Schedules
  http.get('*/api/schedules', route('read', () => HttpResponse.json(db.schedules))),
  http.post(
    '*/api/schedules',
    route('manage', async ({ request, user }) => {
      const input = await body<ScheduleInput>(request)
      const schedule = { ...input, id: randomGuid(), nextFireAt: input.enabled ? new Date(Date.now() + 3_600_000).toISOString() : undefined }
      db.schedules.push(schedule)
      audit(user, 'schedule.created', 'schedule', schedule.id)
      return HttpResponse.json(schedule, { status: 201 })
    }),
  ),
  http.put(
    '*/api/schedules/:id',
    route('edit', async ({ request, params }) => {
      const s = db.schedules.find((x) => x.id === p(params, 'id'))
      if (!s) return notFound('Schedule')
      Object.assign(s, await body<ScheduleInput>(request))
      return HttpResponse.json(s)
    }),
  ),
  http.delete(
    '*/api/schedules/:id',
    route('manage', ({ params }) => {
      db.schedules = db.schedules.filter((x) => x.id !== p(params, 'id'))
      return noContent()
    }),
  ),
  http.post(
    '*/api/schedules/:id/trigger',
    route('edit', ({ params, user }) => {
      const s = db.schedules.find((x) => x.id === p(params, 'id'))
      if (!s) return notFound('Schedule')
      // Overlap policy like ScheduleFiringService: Skip → 409, Queue → 200 without a run, CancelPrevious → start anyway.
      const previous = db.runs.find((r) => r.id === s.lastRunId && ['Pending', 'Running'].includes(r.status))
      if (previous && s.overlapPolicy === 'Skip') return problem(409, 'Conflict', { detail: `previous run ${previous.id} is still active` })
      if (previous && s.overlapPolicy === 'Queue') return HttpResponse.json({ outcome: 'Queued', reason: `Queued behind run ${previous.id}` })
      const run = createRun(user, { name: s.name, workflowKey: s.workflowKey, workflowVersion: s.workflowVersion, networkIds: s.networkIds, priority: s.priority }, `schedule:${s.id}`)
      s.lastRunId = run.id
      s.lastRunStatus = run.status
      return HttpResponse.json({ scanRunId: run.id, outcome: 'Started' })
    }),
  ),
  ...(['pause', 'resume'] as const).map((action) =>
    http.post(
      `*/api/schedules/:id/${action}`,
      route('edit', ({ params }) => {
        const s = db.schedules.find((x) => x.id === p(params, 'id'))
        if (!s) return notFound('Schedule')
        s.enabled = action === 'resume'
        s.nextFireAt = s.enabled ? new Date(Date.now() + 3_600_000).toISOString() : undefined
        if (!s.enabled) s.resumeAt = undefined // pausing drops a pending window resume
        return noContent()
      }),
    ),
  ),

  // Scans & jobs
  http.get(
    '*/api/scans',
    route('read', ({ url }) => {
      const status = url.searchParams.get('status')
      return HttpResponse.json(paged(db.runs.filter((r) => !status || r.status === status).map(runView), url))
    }),
  ),
  http.post(
    '*/api/scans/estimate',
    route('read', async ({ request }) => {
      const req = await body<ScanEstimateRequest>(request)
      if (!req.networkIds?.length) return validationProblem({ networkIds: ['At least one network is required.'] })
      if (!db.workflows.some((w) => w.key === req.workflowKey)) return validationProblem({ workflowKey: [`Workflow '${req.workflowKey}' not found.`] })
      return HttpResponse.json(estimateScan(req))
    }),
  ),
  http.post(
    '*/api/scans',
    route('edit', async ({ request, user }) => {
      const req = await body<ScanStartRequest>(request)
      const errors: Record<string, string[]> = {}
      if (!req.name?.trim()) errors.Name = ['Name is required.']
      if (!db.workflows.some((w) => w.key === req.workflowKey)) errors.WorkflowKey = ['Unknown workflow.']
      if (!req.networkIds?.length) errors.NetworkIds = ['At least one network is required.']
      if (Object.keys(errors).length) return validationProblem(errors)
      return HttpResponse.json(runView(createRun(user, req, `manual:${user.userName}`)), { status: 201 })
    }),
  ),
  http.post(
    '*/api/scans/import',
    route('manage', async ({ request, url, user }) => {
      const format = url.searchParams.get('format') ?? ''
      const zone = url.searchParams.get('zone') ?? ''
      const errors: Record<string, string[]> = {}
      if (!(SCAN_IMPORT_FORMATS as readonly string[]).includes(format)) errors.format = [`format must be one of: ${SCAN_IMPORT_FORMATS.join(', ')}.`]
      if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(zone)) errors.zone = ["zone is required (1-64 letters, digits, '_', '.', '-')."]
      if (Object.keys(errors).length) return validationProblem(errors)
      // shortcut: counts non-empty lines as records instead of parsing the formats like the server does.
      const lines = (await request.text()).split(/\r?\n/).filter((l) => l.trim())
      const rows = format === 'csv' ? Math.max(0, lines.length - 1) : lines.length
      if (rows === 0) return validationProblem({ file: ['The file contains no importable results.'] })
      const now = new Date().toISOString()
      const run: MockRun = {
        id: randomGuid(),
        name: url.searchParams.get('name')?.trim() || `Import ${format} ${now.slice(0, 16).replace('T', ' ')}`,
        status: 'Completed',
        workflowKey: 'import',
        workflowVersion: 1,
        networkIds: [],
        triggeredBy: `import:${user.userName}`,
        priority: 50,
        createdAt: now,
        startedAt: now,
        finishedAt: now,
        progress: { jobsTotal: 0, jobsQueued: 0, jobsRunning: 0, jobsCompleted: 0, jobsFailed: 0, percent: 100 },
        coverageComplete: url.searchParams.get('snapshot') === 'true',
        tags: [],
        steps: [],
      }
      db.runs.unshift(run)
      audit(user, 'scan.imported', 'ScanRun', run.id)
      return HttpResponse.json({ scanRunId: run.id, rows, observations: rows * 2, changesDetected: 0, errors: [] }, { status: 201 })
    }),
  ),
  http.put(
    '*/api/scans/:id',
    route('edit', async ({ request, params, user }) => {
      const run = db.runs.find((r) => r.id === p(params, 'id'))
      if (!run) return notFound('Scan')
      const req = await body<ScanRunUpdate>(request)
      const tags = [...new Set((req.tags ?? []).map((tag) => tag.trim()).filter(Boolean))]
      const errors: Record<string, string[]> = {}
      if (!req.name?.trim() || req.name.trim().length > 200) errors.name = ['Name is required (max 200 characters).']
      if (tags.length > 20) errors.tags = ['Max 20 tags.']
      if (Object.keys(errors).length) return validationProblem(errors)
      Object.assign(run, { name: req.name.trim(), notes: req.notes?.trim() || undefined, tags })
      audit(user, 'scan.updated', 'ScanRun', run.id)
      return HttpResponse.json(runView(run))
    }),
  ),
  http.get(
    '*/api/scans/:id',
    route('read', ({ params }) => {
      const run = db.runs.find((r) => r.id === p(params, 'id'))
      return run ? HttpResponse.json({ ...runView(run), steps: run.steps }) : notFound('Scan')
    }),
  ),
  http.post(
    '*/api/scans/:id/cancel',
    route('edit', ({ params, user }) => {
      const run = db.runs.find((r) => r.id === p(params, 'id'))
      if (!run) return notFound('Scan')
      if (!['Pending', 'Running'].includes(run.status)) return problem(409, 'Scan is not active.')
      stopRunSimulation(run.id)
      run.status = 'Cancelled'
      run.finishedAt = new Date().toISOString()
      run.steps.filter((s) => s.status === 'Pending' || s.status === 'Running').forEach((s) => (s.status = 'Cancelled'))
      db.jobs.filter((j) => j.scanRunId === run.id && (j.status === 'Queued' || j.status === 'Leased')).forEach((j) => (j.status = 'Cancelled'))
      emit(db, { type: 'RunCancelled', scanRunId: run.id, message: `Cancelled by ${user.userName}` })
      return noContent()
    }),
  ),
  http.get(
    '*/api/scans/:id/jobs',
    route('read', ({ params, url }) => {
      if (!db.runs.some((r) => r.id === p(params, 'id'))) return notFound('Scan')
      const status = url.searchParams.get('status')
      return HttpResponse.json(paged(db.jobs.filter((j) => j.scanRunId === p(params, 'id') && (!status || j.status === status)), url, 100))
    }),
  ),
  http.get(
    '*/api/scans/:id/events',
    route('read', ({ params, url }) => {
      // Like the server: `after` (event id or timestamp) pages forward from the cursor; without it the latest 1000.
      const events = db.events.filter((e) => e.scanRunId === p(params, 'id'))
      const after = url.searchParams.get('after')
      if (!after) return HttpResponse.json(events.slice(-1000))
      const index = events.findIndex((e) => e.eventId === after)
      return HttpResponse.json((index >= 0 ? events.slice(index + 1) : events.filter((e) => e.occurredAt > after)).slice(0, 1000))
    }),
  ),
  http.get(
    '*/api/scans/:id/diff',
    route('read', ({ params, url }) => {
      if (!url.searchParams.get('baseline')) return validationProblem({ Baseline: ['Baseline run is required.'] })
      const hosts = db.hosts.slice(0, 12)
      const svc = (i: number) => db.services.find((s) => s.hostId === hosts[i].id)
      const endpoint = (address: string, port: number, name?: string, before?: string, after?: string) => ({
        kind: 'endpoint',
        key: `endpoint|${hosts.find((h) => h.address === address)?.zone ?? ''}|${address}|${port}|tcp`,
        zone: hosts.find((h) => h.address === address)?.zone ?? '',
        address,
        port,
        transport: 'tcp',
        name,
        before,
        after,
      })
      return HttpResponse.json({
        scanRunId: p(params, 'id'),
        baselineRunId: url.searchParams.get('baseline'),
        added: [0, 1, 2].map((i) => endpoint(hosts[i].address, svc(i)?.port ?? 80, svc(i)?.serviceName, undefined, svc(i)?.serviceName)),
        removed: [3, 4].map((i) => endpoint(hosts[i].address, 21, 'ftp', 'ftp vsftpd 3.0.5')),
        changed: [
          endpoint(hosts[5].address, 443, 'https', 'https nginx 1.22.1', 'https nginx 1.24.0'),
          { kind: 'technology', key: `technology|${hosts[6].zone}|${hosts[6].address}|443|nginx`, zone: hosts[6].zone, address: hosts[6].address, port: 443, transport: 'tcp', name: 'nginx', before: '1.22.1', after: '1.24.0' },
        ],
      })
    }),
  ),
  http.get(
    '*/api/jobs',
    route('read', ({ url }) => {
      const status = url.searchParams.get('status')
      const agentId = url.searchParams.get('agentId')
      const items = db.jobs.filter((j) => (!status || j.status === status) && (!agentId || j.agentId === agentId)).sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      return HttpResponse.json(paged(items, url))
    }),
  ),
  http.get(
    '*/api/jobs/:id',
    route('read', ({ params }) => {
      const job = db.jobs.find((j) => j.id === p(params, 'id'))
      return job ? HttpResponse.json(job) : notFound('Job')
    }),
  ),
  http.post(
    '*/api/jobs/:id/cancel',
    route('edit', ({ params }) => {
      const job = db.jobs.find((j) => j.id === p(params, 'id'))
      if (!job) return notFound('Job')
      job.status = 'Cancelled'
      emit(db, { type: 'JobCancelled', scanRunId: job.scanRunId, jobId: job.id, stepId: job.stepId })
      return noContent()
    }),
  ),
  http.post(
    '*/api/jobs/:id/retry',
    route('edit', ({ params }) => {
      const job = db.jobs.find((j) => j.id === p(params, 'id'))
      if (!job) return notFound('Job')
      if (job.status !== 'Failed' && job.status !== 'Cancelled')
        return problem(409, 'Conflict', { detail: `Only failed or cancelled jobs can be retried (job is ${job.status}).` })
      const runStatus = db.runs.find((r) => r.id === job.scanRunId)?.status
      if (runStatus && !['Pending', 'Running'].includes(runStatus)) return problem(409, 'Conflict', { detail: `The scan run is already ${runStatus}.` })
      Object.assign(job, { status: 'Queued', attempt: job.attempt + 1, error: undefined, finishedAt: undefined })
      emit(db, { type: 'JobRetryScheduled', scanRunId: job.scanRunId, jobId: job.id, stepId: job.stepId })
      return noContent()
    }),
  ),
  http.get('*/api/scan-limits', route('read', () => HttpResponse.json(db.scanLimits))),
  http.put(
    '*/api/scan-limits',
    route('admin', async ({ request }) => {
      const limits = await body<MockDb['scanLimits']>(request)
      const errors: Record<string, string[]> = {}
      for (const [name, [min, max]] of Object.entries(SCAN_LIMIT_RANGES)) {
        const value = limits[name as keyof typeof limits]
        if (!(value >= min && value <= max)) errors[name] = [`${name} must be between ${min} and ${max}.`]
      }
      if (Object.keys(errors).length) return problem(422, 'One or more validation errors occurred.', { errors })
      db.scanLimits = limits
      return HttpResponse.json(limits)
    }),
  ),
  http.get(
    '*/api/stats/planner',
    route('read', () =>
      HttpResponse.json({
        queue: { queued: db.jobs.filter((j) => j.status === 'Queued').length, leased: db.jobs.filter((j) => j.status === 'Leased').length },
        performance: [
          { agentId: 'scanner-dmz-01', interfaceName: 'eth0', toolId: 'nmap', jobsCompleted: 182, avgDurationMs: 48_200, avgTargetsPerSecond: 5.3 },
          { agentId: 'scanner-dmz-01', interfaceName: 'eth0', toolId: 'naabu', jobsCompleted: 96, avgDurationMs: 12_400, avgTargetsPerSecond: 20.6 },
          { agentId: 'scanner-office-01', interfaceName: 'ens18', toolId: 'nmap', jobsCompleted: 74, avgDurationMs: 61_000, avgTargetsPerSecond: 4.2 },
        ],
      }),
    ),
  ),

  // Discovery & analytics
  http.get(
    '*/api/dashboard/summary',
    route('read', () => {
      const dayAgo = new Date(Date.now() - 86_400_000).toISOString()
      return HttpResponse.json({
        hostsTotal: db.hosts.length,
        hostsActive: db.hosts.filter((h) => h.status === 'Active').length,
        servicesTotal: db.services.filter((s) => s.state === 'Open').length,
        changesLast24h: db.changes.filter((c) => c.detectedAt > dayAgo).length,
        findingsOpen: db.findings.filter((f) => f.status === 'Open' && f.triage !== 'FalsePositive').length,
        lastScanAt: db.runs.find((r) => r.finishedAt)?.finishedAt,
      })
    }),
  ),
  http.get(
    '*/api/assets/hosts',
    route('read', ({ url }) => {
      const search = url.searchParams.get('search')?.toLowerCase()
      const status = url.searchParams.get('status')
      const zone = url.searchParams.get('zone')
      const { deviceOf } = inferDevices(db.hosts)
      const items = db.hosts
        .map((h) => withDeviceFlags(h, deviceOf))
        .filter(
          (h) =>
            (!status || h.status === status) &&
            (!zone || h.zone === zone) &&
            (url.searchParams.get('networkDevice') !== 'true' || h.networkDevice) &&
            (!search || [h.address, ...h.hostnames, ...h.technologies.map(String)].some((v) => v.toLowerCase().includes(search))),
        )
        .sort((a, b) => a.zone.localeCompare(b.zone) || a.address.localeCompare(b.address)) // server order: zone, then address
      return HttpResponse.json(paged(items, url))
    }),
  ),
  http.get(
    '*/api/assets/hosts/:id',
    route('read', ({ params }) => {
      const host = db.hosts.find((h) => h.id === p(params, 'id'))
      if (!host) return notFound('Host')
      const { deviceOf } = inferDevices(db.hosts)
      const detail: HostDetail = {
        ...withDeviceFlags(host, deviceOf),
        deviceInterfaces: deviceOf.get(host.id)?.interfaces.filter((i) => i.hostId !== host.id) ?? [],
        services: db.services.filter((s) => s.hostId === host.id),
        technologies: db.hostTechnologies[host.id] ?? [],
        certificates: db.certificates[host.id] ?? [],
        findings: db.findings.filter((f) => f.hostId === host.id),
        recentChanges: db.changes.filter((c) => c.hostId === host.id).slice(0, 20),
      }
      return HttpResponse.json(detail)
    }),
  ),
  http.put(
    '*/api/assets/hosts/:id/annotation',
    route('edit', async ({ request, params, user }) => {
      const host = db.hosts.find((h) => h.id === p(params, 'id'))
      if (!host) return notFound('Host')
      host.annotation = await body<NonNullable<typeof host.annotation>>(request)
      audit(user, 'asset.annotated', 'host', host.id)
      return noContent()
    }),
  ),
  http.put(
    '*/api/assets/services/:id/annotation',
    route('edit', async ({ request, params, user }) => {
      const service = db.services.find((s) => s.id === p(params, 'id'))
      if (!service) return notFound('Service')
      const req = await body<ServiceAnnotation>(request)
      if (req.criticality && !(CRITICALITIES as readonly string[]).includes(req.criticality))
        return validationProblem({ annotation: [`criticality: must be one of ${CRITICALITIES.join(', ')}.`] })
      service.annotation = { ...req, tags: req.tags ?? [], updatedAt: new Date().toISOString(), updatedBy: user.userName }
      audit(user, 'service.annotation_updated', 'service', service.id)
      return HttpResponse.json(service.annotation)
    }),
  ),
  http.get(
    '*/api/assets/services',
    route('read', ({ url }) => {
      const search = url.searchParams.get('search')?.toLowerCase()
      const port = url.searchParams.get('port')
      const serviceName = url.searchParams.get('serviceName')?.toLowerCase()
      const zone = url.searchParams.get('zone')
      const items = db.services.filter(
        (s) =>
          (!port || String(s.port) === port) &&
          (!zone || s.zone === zone) &&
          (!serviceName || (s.serviceName ?? '').toLowerCase().includes(serviceName)) &&
          (!search || [s.address, s.product ?? '', s.http?.title ?? ''].some((v) => v.toLowerCase().includes(search))),
      )
      return HttpResponse.json(paged(items, url))
    }),
  ),
  http.get(
    '*/api/assets/services/:id',
    route('read', ({ params }) => {
      const service = db.services.find((s) => s.id === p(params, 'id'))
      if (!service) return notFound('Service')
      const detail: ServiceDetail = {
        service,
        ...(db.serviceDetails[service.id] ?? { artifacts: [] }),
        technologies: (db.hostTechnologies[service.hostId] ?? []).filter((x) => x.port === service.port),
        certificate: db.certificates[service.hostId]?.find((c) => c.port === service.port),
        findings: db.findings.filter((f) => f.hostId === service.hostId && f.port === service.port),
      }
      return HttpResponse.json(detail)
    }),
  ),
  http.get(
    '*/api/assets/technologies',
    route('read', () => {
      const map = new Map<string, { name: string; version?: string; category?: string; hosts: Set<string>; serviceCount: number; confidence: number[] }>()
      for (const [hostId, techs] of Object.entries(db.hostTechnologies))
        for (const tech of techs) {
          const key = `${tech.name}@${tech.version ?? ''}`
          const entry = map.get(key) ?? { name: tech.name, version: tech.version, category: tech.category, hosts: new Set(), serviceCount: 0, confidence: [] }
          entry.hosts.add(hostId)
          entry.serviceCount++
          entry.confidence.push(tech.confidence ?? 0.5)
          map.set(key, entry)
        }
      return HttpResponse.json(
        [...map.values()]
          .map((e) => ({ name: e.name, version: e.version, category: e.category, hostCount: e.hosts.size, serviceCount: e.serviceCount, confidence: Math.round((e.confidence.reduce((a, b) => a + b, 0) / e.confidence.length) * 100) / 100 }))
          .sort((a, b) => b.hostCount - a.hostCount),
      )
    }),
  ),
  http.get(
    '*/api/topology',
    route('read', ({ url }) => {
      const q = (k: string) => url.searchParams.get(k)
      const search = q('search')?.toLowerCase()
      const network = q('networkId') ? db.networks.find((n) => n.id === q('networkId')) : undefined
      const { devices: allDevices, deviceOf, sharedMac } = inferDevices(db.hosts)
      const hosts: TopologyHost[] = db.hosts
        .filter(
          (h) =>
            (!q('zone') || h.zone === q('zone')) &&
            (!search || [h.address, ...h.hostnames].some((v) => v.toLowerCase().includes(search))) &&
            (!q('networkId') || (network?.ranges.some((r) => inIpv4Cidr(h.address, r)) ?? false)),
        )
        .map((h) => {
          const services = db.services.filter((s) => s.hostId === h.id && s.state === 'Open').sort((a, b) => a.port - b.port)
          const seenBy = MOCK_PERSPECTIVES[h.zone ?? '']
          return {
            id: h.id,
            address: h.address,
            hostnames: h.hostnames,
            status: h.status,
            unstable: h.unstable,
            // Subnets are per zone: the same range in two zones is two networks.
            subnet: `${h.zone}|${h.address.replace(/\.\d+$/, '.0/24')}`,
            zone: h.zone,
            lastSeenAt: h.lastSeenAt,
            macAddress: h.macAddress,
            macVendor: h.macVendor,
            openPortCount: services.length,
            services: services.map((s) => ({
              port: s.port,
              transport: s.transport,
              serviceName: s.serviceName,
              product: s.product,
              version: s.version,
              url: s.url,
              isWeb: !!s.http || !!s.serviceName?.startsWith('http'),
              tls: !!s.tls || !!s.serviceName?.startsWith('https'),
            })),
            technologies: [...new Set(h.technologies.map((x) => (typeof x === 'string' ? x : x.name)))],
            observedBy: seenBy ? [{ agentId: seenBy.agentId, interfaceName: seenBy.interfaceName }] : [],
            deviceId: deviceOf.get(h.id)?.id,
            sharedMac: sharedMac.has(h.id),
          }
        })
      const subnets = [...new Set(hosts.map((h) => h.subnet))].sort().map((id) => {
        const members = hosts.filter((h) => h.subnet === id)
        return { id, cidr: id.slice(id.indexOf('|') + 1), zone: members[0].zone, hostCount: members.length }
      })
      const perspectives = Object.entries(MOCK_PERSPECTIVES)
        .filter(([zone]) => hosts.some((h) => h.zone === zone))
        .map(([zone, p]) => ({ ...p, zone }))
      const zones = [...new Set(hosts.map((h) => h.zone))].sort().map((name) => {
        const members = hosts.filter((h) => h.zone === name)
        return { name, subnetCount: new Set(members.map((h) => h.subnet)).size, hostCount: members.length }
      })
      // Devices with an interface in the view; their zones/interfaces stay complete.
      const devices = allDevices.filter((d) => hosts.some((h) => h.deviceId === d.id))
      const topology: Topology = { perspectives, zones, devices, subnets, hosts, truncated: false }
      return HttpResponse.json(topology)
    }),
  ),
  http.get('*/api/observations', route('read', ({ url }) => HttpResponse.json(paged([], url)))),
  http.get(
    '*/api/changes',
    route('read', ({ url }) => {
      const q = (k: string) => url.searchParams.get(k)
      const items = db.changes.filter(
        (c: Change) =>
          (!q('type') || c.type === q('type')) &&
          (!q('hostId') || c.hostId === q('hostId')) &&
          (!q('scanRunId') || c.scanRunId === q('scanRunId')) &&
          (!q('zone') || c.zone === q('zone')) &&
          (!q('since') || c.detectedAt >= q('since')!),
      )
      return HttpResponse.json(paged(items, url))
    }),
  ),
  http.get(
    '*/api/findings',
    route('read', ({ url }) => {
      const severity = url.searchParams.get('severity')
      const status = url.searchParams.get('status')
      const zone = url.searchParams.get('zone')
      const triage = url.searchParams.get('triage')
      return HttpResponse.json(
        paged(
          db.findings.filter(
            (f) => (!severity || f.effectiveSeverity === severity) && (!status || f.status === status) && (!zone || f.zone === zone) && (!triage || f.triage === triage),
          ),
          url,
        ),
      )
    }),
  ),
  http.put(
    '*/api/findings/:id',
    route('edit', async ({ request, params, user }) => {
      const f = db.findings.find((x) => x.id === p(params, 'id'))
      if (!f) return notFound('Finding')
      const req = await body<FindingTriageInput>(request)
      const userTags = [...new Set((req.userTags ?? []).map((tag) => tag.trim()).filter(Boolean))]
      const errors: Record<string, string[]> = {}
      if (req.severityOverride && !(SEVERITIES as readonly string[]).includes(req.severityOverride)) errors.severityOverride = [`Must be one of ${SEVERITIES.join(', ')}.`]
      if ((req.notes ?? '').length > 4000) errors.notes = ['Max 4000 characters.']
      if (userTags.length > 20) errors.userTags = ['Max 20 tags.']
      if (Object.keys(errors).length) return validationProblem(errors)
      Object.assign(f, {
        triage: req.triage ?? 'None',
        severityOverride: req.severityOverride || undefined,
        effectiveSeverity: req.severityOverride || f.severity,
        notes: req.notes?.trim() || undefined,
        userTags,
        triagedBy: user.userName,
        triagedAt: new Date().toISOString(),
      })
      audit(user, 'finding.triaged', 'finding', f.id)
      return HttpResponse.json(f)
    }),
  ),
  http.get(
    '*/api/export/:kind',
    route('read', ({ params, url }) => {
      const kind = p(params, 'kind')
      const exporters: Record<string, () => Record<string, unknown>[]> = {
        hosts: () => {
          const { deviceOf } = inferDevices(db.hosts)
          return db.hosts.map(({ annotation, ...h }) => ({ ...h, networkDevice: deviceOf.has(h.id), owner: annotation?.owner, classification: annotation?.classification }))
        },
        services: () => db.services.map(({ http: h, tls, ...s }) => ({ ...s, httpTitle: h?.title, tlsSubject: tls?.subjectCommonName })),
        changes: () => db.changes.map((c) => ({ ...c })),
        findings: () => db.findings.map(({ externalRefs, ...f }) => ({ ...f, externalRefs: externalRefs.map((r) => `${r.system}:${r.externalId}`) })),
      }
      const rows = exporters[kind]?.()
      return rows ? exportResponse(kind, rows, url.searchParams.get('format')) : notFound('Export')
    }),
  ),
  http.post(
    '*/api/import/assets',
    route('manage', async ({ request, url }) => {
      const text = await request.text()
      try {
        const rows: Record<string, unknown>[] = url.searchParams.get('format') === 'csv' ? parseCsv(text) : (JSON.parse(text) as Record<string, unknown>[])
        let updated = 0
        const errors: string[] = []
        rows.forEach((r, i) => {
          // Server rule: without a zone an address matches only when it exists in exactly one zone.
          const matches = db.hosts.filter((h) => h.address === r.address && (!r.zone || h.zone === r.zone))
          if (matches.length > 1) return errors.push(`Row ${i + 1}: address '${String(r.address)}' is ambiguous: it exists in zones ${matches.map((h) => h.zone || 'default').join(', ')}; add a zone.`)
          const host = matches[0]
          if (!host) return errors.push(`Row ${i + 1}: unknown host ${String(r.address)}`)
          host.annotation = { description: String(r.description ?? ''), classification: String(r.classification ?? ''), businessState: String(r.businessState ?? ''), owner: String(r.owner ?? ''), tags: String(r.tags ?? '').split(';').filter(Boolean) }
          updated++
        })
        return HttpResponse.json({ imported: 0, updated, errors })
      } catch {
        return validationProblem({ File: ['The file could not be parsed.'] })
      }
    }),
  ),

  // Signatures
  http.post(
    '*/api/signatures/validate',
    route('read', async ({ request }) => {
      const { kind, content } = await body<{ kind: SignatureKind; content: string }>(request)
      return HttpResponse.json(validateSignatureContent(kind, content))
    }),
  ),
  http.get(
    '*/api/signatures',
    route('read', ({ url }) => {
      const kind = url.searchParams.get('kind')
      const status = url.searchParams.get('status')
      return HttpResponse.json(db.signatures.filter((s) => (!kind || s.kind === kind) && (!status || s.status === status)).map(({ versions: _v, ...s }) => s))
    }),
  ),
  http.get(
    '*/api/signatures/:id',
    route('read', ({ params }) => {
      const s = db.signatures.find((x) => x.id === p(params, 'id'))
      return s ? HttpResponse.json(s) : notFound('Signature')
    }),
  ),
  http.post(
    '*/api/signatures',
    route('manage', async ({ request, user }) => {
      const input = await body<{ id: string; name: string; kind: SignatureKind; content: string }>(request)
      if (db.signatures.some((s) => s.id === input.id)) return problem(409, `Signature '${input.id}' already exists.`)
      const result = validateSignatureContent(input.kind, input.content)
      if (!result.valid) return validationProblem({ Content: result.errors.map(String) })
      const now = new Date().toISOString()
      const severity = /^\s*severity:\s*(\w+)/m.exec(input.content)?.[1] as Severity | undefined
      db.signatures.unshift({
        id: input.id,
        name: input.name,
        kind: input.kind,
        latestVersion: 1,
        status: 'Draft',
        severity,
        tags: (/^\s*tags:\s*(.+)$/m.exec(input.content)?.[1] ?? '').split(',').map((x) => x.trim()).filter(Boolean),
        updatedAt: now,
        versions: [
          {
            version: 1,
            content: input.content,
            sha256: mockId(12).replace(/-/g, '').padEnd(64, '0'),
            requiresApprovalNote: requiresApprovalNote(input.content),
            createdAt: now,
            createdBy: user.userName,
          },
        ],
      })
      audit(user, 'signature.created', 'signature', input.id)
      return HttpResponse.json(db.signatures[0], { status: 201 })
    }),
  ),
  http.post(
    '*/api/signatures/:id/versions',
    route('manage', async ({ request, params, user }) => {
      const s = db.signatures.find((x) => x.id === p(params, 'id'))
      if (!s) return notFound('Signature')
      const { content } = await body<{ content: string }>(request)
      const result = validateSignatureContent(s.kind, content)
      if (!result.valid) return validationProblem({ Content: result.errors.map(String) })
      s.latestVersion += 1
      s.updatedAt = new Date().toISOString()
      if (s.status !== 'Approved') s.status = 'Draft'
      s.versions.push({
        version: s.latestVersion,
        content,
        sha256: mockId(12).replace(/-/g, '').padEnd(64, '0'),
        requiresApprovalNote: requiresApprovalNote(content),
        createdAt: s.updatedAt,
        createdBy: user.userName,
      })
      return HttpResponse.json({ version: s.latestVersion }, { status: 201 })
    }),
  ),
  http.post(
    '*/api/signatures/:id/versions/:version/approve',
    route('admin', async ({ request, params, user }) => {
      const s = db.signatures.find((x) => x.id === p(params, 'id'))
      const v = s?.versions.find((x) => x.version === Number(p(params, 'version')))
      if (!s || !v) return notFound('Signature version')
      const note = (await body<{ note?: string }>(request).catch(() => ({ note: undefined }))).note?.trim()
      if (v.requiresApprovalNote && !note)
        return problem(422, 'One or more validation errors occurred.', { errors: { note: [`Severity '${s.severity}' is above medium: an approval note is required.`] } })
      v.approvedAt = new Date().toISOString()
      v.approvedBy = user.userName
      v.approvalNote = note || undefined
      s.approvedVersion = v.version
      s.status = 'Approved'
      audit(user, 'signature.approved', 'signature', s.id)
      return HttpResponse.json(v)
    }),
  ),
  http.post(
    '*/api/signatures/:id/retire',
    route('manage', ({ params, user }) => {
      const s = db.signatures.find((x) => x.id === p(params, 'id'))
      if (!s) return notFound('Signature')
      s.status = 'Retired'
      audit(user, 'signature.retired', 'signature', s.id)
      return noContent()
    }),
  ),

  // Integrations
  http.get(
    '*/api/integrations/defectdojo',
    route('admin', () => {
      const { apiKeyValue, ...config } = db.defectDojo
      return HttpResponse.json({ ...config, hasApiKey: Boolean(apiKeyValue) })
    }),
  ),
  http.put(
    '*/api/integrations/defectdojo',
    route('admin', async ({ request, user }) => {
      const { apiKey, hasApiKey: _ignored, ...config } = await body<MockDb['defectDojo']>(request)
      if (config.enabled && !/^https?:\/\//.test(config.baseUrl ?? '')) return validationProblem({ BaseUrl: ['A valid http(s) URL is required when enabled.'] })
      db.defectDojo = { ...db.defectDojo, ...config, apiKeyValue: apiKey || db.defectDojo.apiKeyValue }
      audit(user, 'integration.defectdojo.updated', 'integration', 'defectdojo')
      return noContent()
    }),
  ),
  http.post(
    '*/api/integrations/defectdojo/test',
    route('admin', () =>
      HttpResponse.json(db.defectDojo.apiKeyValue ? { ok: true, message: 'Connected to DefectDojo (mock).' } : { ok: false, message: 'Integration is not configured.' }),
    ),
  ),
  http.post(
    '*/api/integrations/defectdojo/export',
    route('manage', async ({ request }) => {
      const { findingIds } = await body<{ findingIds: string[] }>(request)
      let exported = 0
      let skipped = 0
      for (const id of findingIds) {
        const f = db.findings.find((x) => x.id === id)
        if (!f || f.externalRefs.some((r) => r.system === 'defectdojo')) {
          skipped++
          continue
        }
        f.externalRefs.push({ system: 'defectdojo', externalId: String(2000 + Math.floor(Math.random() * 1000)) })
        exported++
      }
      return HttpResponse.json({ exported, skipped, errors: [] })
    }),
  ),
]
