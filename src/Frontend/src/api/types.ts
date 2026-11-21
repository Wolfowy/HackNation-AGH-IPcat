// Wire types mirroring ARCHITECTURE.md §11 and src/Shared/Contracts (camelCase, enums as strings, nulls omitted).
// Optional (`?`) marks fields the server may omit.

export type Guid = string
/** ISO-8601 UTC timestamp (DateTimeOffset). */
export type Instant = string

export interface Paged<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

/** RFC 7807 ProblemDetails (+ ASP.NET `errors` dict for validation). */
export interface ProblemDetails {
  type?: string
  title?: string
  status?: number
  detail?: string
  instance?: string
  errors?: Record<string, string[]>
  [key: string]: unknown
}

// ---------- Identity ----------
export const ROLES = ['Administrator', 'Manager', 'Editor', 'Viewer'] as const
export type Role = (typeof ROLES)[number]

export interface User {
  id: Guid
  userName: string
  displayName: string
  roles: Role[]
  isActive?: boolean
  createdAt?: Instant
  lastLoginAt?: Instant
}

export interface LoginResponse {
  accessToken: string
  expiresAt: Instant
  user: User
}

export interface UserCreate {
  userName: string
  displayName: string
  password: string
  roles: Role[]
  isActive: boolean
}
export type UserUpdate = Omit<UserCreate, 'userName' | 'password'>

// ---------- Agents & tools ----------
export type AgentStatus = 'PendingApproval' | 'Active' | 'Disabled' | 'Blocked'

export interface AgentTool {
  id: string
  version: string
  capabilities: string[]
  approved: boolean
}

export interface NetworkInterfaceInfo {
  name: string
  description?: string
  macAddress?: string
  isUp: boolean
  addresses: string[]
  speedMbps?: number
}

export interface RouteInfo {
  destination: string
  gateway?: string
  interfaceName: string
  metric: number
}

export interface AgentLoad {
  cpuPercent: number
  memoryUsedMb: number
  runningJobs: number
  bufferedBatches: number
  runningJobsPerInterface?: Record<string, number>
}

export interface Agent {
  agentId: string
  hostname: string
  status: AgentStatus
  isOnline: boolean
  lastHeartbeatAt?: Instant
  registeredAt: Instant
  osPlatform: string
  osDescription: string
  agentVersion: string
  tools: AgentTool[]
  interfaces: NetworkInterfaceInfo[]
  routes: RouteInfo[]
  declaredZones: string[]
  authorizedZones: string[]
  authorizedNetworkIds: Guid[]
  /** Effective limits: min(reported, override). */
  limits: { maxConcurrentJobs: number; maxRatePerSecond: number }
  reportedLimits?: { maxConcurrentJobs?: number; maxRatePerSecond?: number }
  limitOverrides?: { maxConcurrentJobs?: number; maxRatePerSecond?: number }
  load?: AgentLoad
  rotateRequested?: boolean
}

export interface AgentAssignment {
  authorizedZones: string[]
  authorizedNetworkIds: Guid[]
  maxConcurrentJobs?: number
  maxRatePerSecond?: number
}

export interface EnrollmentToken {
  id: Guid
  name: string
  expiresAt: Instant
  maxUses: number
  uses: number
  autoApprove: boolean
  zones?: string[]
  createdAt?: Instant
  revoked: boolean
}

export interface EnrollmentTokenCreate {
  name: string
  expiresInHours: number
  maxUses: number
  autoApprove: boolean
  zones: string[]
}

export interface EnrollmentTokenCreated {
  id: Guid
  token: string
  expiresAt: Instant
}

export interface ToolCatalogEntry {
  toolId: string
  approved: boolean
  enabled: boolean
  capabilities: string[]
  versions: string[]
  agentCount: number
  firstSeenAt: Instant
}

// ---------- Networks & scope ----------
export interface Network {
  id: Guid
  name: string
  description?: string
  zone: string
  ranges: string[]
  exclusions: string[]
  tags: string[]
  maxRatePerSecond?: number
  enabled: boolean
  addressCount: number
  createdAt: Instant
  updatedAt: Instant
}

export type NetworkInput = Pick<Network, 'name' | 'description' | 'zone' | 'ranges' | 'exclusions' | 'tags' | 'maxRatePerSecond' | 'enabled'>

export interface Zone {
  name: string
  description?: string
  networkCount: number
}

export interface ScopePolicy {
  allowed: string[]
  excluded: string[]
  updatedAt?: Instant
}

export interface ImportResult {
  created?: number
  updated?: number
  imported?: number
  errors: ValidationMessage[]
}

export interface Settings {
  /** On PUT: sent keys are upserted, `null` deletes, unsent keys stay unchanged. */
  values: Record<string, string | null>
}

export interface AuditEntry {
  id: Guid
  occurredAt: Instant
  userId?: Guid
  userName?: string
  action: string
  entityType: string
  entityId?: string
  /** Arbitrary JSON written by the server. */
  details?: unknown
  ipAddress?: string
}

// ---------- Operations & workflows (Contracts: Operations.cs, ScanWorkflowDefinition.cs) ----------
export const SCAN_OPERATIONS = [
  'DiscoverHosts',
  'ScanPorts',
  'DetectService',
  'HttpProbe',
  'TlsProbe',
  'ExecuteSignatures',
  'EvaluateCondition',
  'PersistObservations',
  'ComparePreviousScan',
  'PublishFinding',
] as const
export type ScanOperation = (typeof SCAN_OPERATIONS)[number]
export type OperationPlane = 'Agent' | 'Server'
export type TargetKind = 'None' | 'Hosts' | 'Endpoints'
export type ParameterType = 'Integer' | 'Boolean' | 'Enum' | 'PortSpec' | 'StringList' | 'String'

export interface ParameterDescriptor {
  name: string
  type: ParameterType
  description?: string
  default?: string
  required?: boolean
  min?: number
  max?: number
  allowedValues?: string[]
  pattern?: string
}

export interface OperationDescriptor {
  operation: ScanOperation
  plane: OperationPlane
  requiredCapability?: string
  inputKind: TargetKind
  parameters: ParameterDescriptor[]
}

export interface OperationsCatalog {
  operations: OperationDescriptor[]
  capabilityMapping: Record<string, string>
}

export type ConditionOperator =
  | 'Equals'
  | 'NotEquals'
  | 'In'
  | 'NotIn'
  | 'Contains'
  | 'StartsWith'
  | 'GreaterThan'
  | 'LessThan'
  | 'Exists'
  | 'NotExists'

export interface ConditionExpression {
  field?: string
  operator?: ConditionOperator
  values?: string[]
  all?: ConditionExpression[]
  any?: ConditionExpression[]
  not?: ConditionExpression
}

export interface RetryPolicy {
  maxAttempts?: number
  backoffSeconds?: number
}

export interface WorkflowStep {
  id: string
  operation: ScanOperation
  dependsOn?: string[]
  input?: { fromSteps: string[]; filter?: ConditionExpression }
  when?: ConditionExpression
  parameters?: Record<string, string>
  toolId?: string
  timeoutSeconds?: number
  maxConcurrency?: number
  retry?: RetryPolicy
  onFailure?: 'FailWorkflow' | 'Continue'
}

export interface ScanWorkflowDefinition {
  key: string
  version?: number
  name: string
  description?: string
  defaults?: { timeoutSeconds?: number; maxConcurrency?: number; retry?: RetryPolicy; batchSize?: number }
  steps: WorkflowStep[]
}

export interface WorkflowSummary {
  key: string
  latestVersion: number
  name: string
  description?: string
  updatedAt: Instant
}

export interface WorkflowVersion {
  key: string
  version: number
  definition: ScanWorkflowDefinition
  createdAt: Instant
  createdBy?: string
}

/** Validation messages are plain strings or `{path?, message}` objects depending on the endpoint. */
export type ValidationMessage = string | { path?: string; field?: string; line?: number; message: string }

export interface ValidationResult {
  valid: boolean
  errors: ValidationMessage[]
  warnings?: ValidationMessage[]
}

// ---------- Schedules ----------
export type OverlapPolicy = 'Skip' | 'CancelPrevious' | 'Queue'
export const DAYS_OF_WEEK = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'] as const
export type DayOfWeek = (typeof DAYS_OF_WEEK)[number]

export interface AllowedWindow {
  daysOfWeek: DayOfWeek[]
  start: string
  end: string
}

export interface Schedule {
  id: Guid
  name: string
  cronExpression: string
  timeZone: string
  workflowKey: string
  workflowVersion?: number
  networkIds: Guid[]
  priority: number
  maxRatePerSecond?: number
  windowDurationMinutes?: number
  allowedWindows: AllowedWindow[]
  overlapPolicy: OverlapPolicy
  enabled: boolean
  nextFireAt?: Instant
  lastRunId?: Guid
  lastRunStatus?: ScanRunStatus
}

export type ScheduleInput = Omit<Schedule, 'id' | 'nextFireAt' | 'lastRunId' | 'lastRunStatus'>

// ---------- Scans & jobs ----------
export type ScanRunStatus =
  | 'Pending'
  | 'Running'
  | 'Completed'
  | 'PartiallyCompleted'
  | 'Failed'
  | 'Cancelled'
  | 'WindowExpired'
export const SCAN_RUN_STATUSES: ScanRunStatus[] = [
  'Pending',
  'Running',
  'Completed',
  'PartiallyCompleted',
  'Failed',
  'Cancelled',
  'WindowExpired',
]
export const ACTIVE_RUN_STATUSES: ScanRunStatus[] = ['Pending', 'Running']

export interface ScanProgress {
  jobsTotal: number
  jobsQueued: number
  jobsRunning: number
  jobsCompleted: number
  jobsFailed: number
  percent: number
}

export interface ScanRun {
  id: Guid
  name: string
  status: ScanRunStatus
  workflowKey: string
  workflowVersion: number
  networkIds: Guid[]
  triggeredBy: string
  priority: number
  createdAt: Instant
  startedAt?: Instant
  finishedAt?: Instant
  notAfter?: Instant
  progress: ScanProgress
  coverageComplete: boolean
}

export type StepStatus = 'Pending' | 'Running' | 'Completed' | 'Skipped' | 'Failed' | 'Cancelled'

export interface ScanStep {
  stepId: string
  operation: ScanOperation
  status: StepStatus
  jobsTotal: number
  jobsCompleted: number
  startedAt?: Instant
  finishedAt?: Instant
  message?: string
}

export interface ScanRunDetail extends ScanRun {
  steps: ScanStep[]
}

export interface ScanStartRequest {
  name: string
  workflowKey: string
  workflowVersion?: number
  networkIds: Guid[]
  priority?: number
  maxRatePerSecond?: number
  windowMinutes?: number
}

export type JobStatus = 'Queued' | 'Leased' | 'Completed' | 'Failed' | 'Cancelled'
export const JOB_STATUSES: JobStatus[] = ['Queued', 'Leased', 'Completed', 'Failed', 'Cancelled']

export interface ScanJob {
  id: Guid
  scanRunId: Guid
  stepId: string
  operation: ScanOperation
  status: JobStatus
  agentId?: string
  interfaceName?: string
  toolId?: string
  targetSummary: string
  targetCount: number
  attempt: number
  maxAttempts: number
  createdAt: Instant
  startedAt?: Instant
  finishedAt?: Instant
  durationMs?: number
  error?: string
  progressPercent?: number
}

export type ScanExecutionEventType =
  | 'RunCreated'
  | 'RunStarted'
  | 'RunCompleted'
  | 'RunPartiallyCompleted'
  | 'RunFailed'
  | 'RunCancelled'
  | 'RunWindowExpired'
  | 'StepStarted'
  | 'StepCompleted'
  | 'StepSkipped'
  | 'StepFailed'
  | 'JobQueued'
  | 'JobAssigned'
  | 'JobProgress'
  | 'JobCompleted'
  | 'JobFailed'
  | 'JobRetryScheduled'
  | 'JobCancelled'
  | 'JobLeaseExpired'
  | 'ResultsReceived'
  | 'AgentOnline'
  | 'AgentOffline'
  | 'ChangeDetected'

export interface ScanExecutionEvent {
  eventId: Guid
  occurredAt: Instant
  type: ScanExecutionEventType
  scanRunId?: Guid
  workflowRunId?: Guid
  stepId?: string
  jobId?: Guid
  agentId?: string
  message?: string
  progress?: number
  data?: Record<string, string>
}

export interface ScanLimits {
  defaultBatchSize: number
  leaseDurationSeconds: number
  maxAttempts: number
  maxConcurrentJobsPerZone: number
  maxConcurrentJobsPerInterface: number
  maxConcurrentJobsPerSubnet: number
  subnetPrefixLength: number
  maxRatePerSecondGlobal: number
}

export interface PlannerStats {
  queue: { queued: number; leased: number }
  performance: {
    agentId: string
    interfaceName: string
    toolId: string
    jobsCompleted: number
    avgDurationMs: number
    avgTargetsPerSecond: number
  }[]
}

// ---------- Discovery & analytics ----------
export interface DashboardSummary {
  hostsTotal: number
  hostsActive: number
  servicesTotal: number
  changesLast24h: number
  findingsOpen: number
  lastScanAt?: Instant
}

export type HostStatus = 'Active' | 'Unreachable' | 'Gone' | 'Unknown'
export const HOST_STATUSES: HostStatus[] = ['Active', 'Unreachable', 'Gone', 'Unknown']

export interface AssetAnnotation {
  description?: string
  classification?: string
  businessState?: string
  owner?: string
  tags: string[]
}

export interface Host {
  id: Guid
  address: string
  hostnames: string[]
  status: HostStatus
  unstable: boolean
  firstSeenAt: Instant
  lastSeenAt: Instant
  lastScannedAt?: Instant
  openPortCount: number
  /** Technology names (the server may also send objects with a `name`). */
  technologies: (string | HostTechnology)[]
  zone?: string
  annotation?: AssetAnnotation
}

export interface HostTechnology {
  name: string
  version?: string
  category?: string
  confidence?: number
  confidenceMethod?: string
  port?: number
}

export interface Certificate {
  fingerprintSha256: string
  subjectCommonName?: string
  subjectAlternativeNames?: string[]
  issuer?: string
  notBefore?: Instant
  notAfter?: Instant
  port?: number
  selfSigned?: boolean
}

export interface HostDetail extends Host {
  services: Service[]
  technologies: HostTechnology[]
  certificates: Certificate[]
  findings: Finding[]
  recentChanges: Change[]
}

export interface Service {
  id: Guid
  hostId: Guid
  address: string
  port: number
  transport: 'Tcp' | 'Udp'
  state: 'Open' | 'Gone'
  serviceName?: string
  product?: string
  version?: string
  http?: { url: string; statusCode?: number; title?: string; webServer?: string }
  tls?: { subjectCommonName?: string; issuer?: string; notAfter?: Instant; fingerprintSha256?: string }
  technologies: (string | HostTechnology)[]
  confidence?: number
  firstSeenAt: Instant
  lastSeenAt: Instant
  /** Best clickable URL derived by the server (HTTP probe URL, else https/http by TLS/service name); absent for non-web services. */
  url?: string
}

export interface TechnologySummary {
  name: string
  version?: string
  category?: string
  hostCount: number
  serviceCount: number
  confidence: number
}

export const CHANGE_TYPES = [
  'NewHost',
  'HostReappeared',
  'HostGone',
  'NewPort',
  'PortGone',
  'NewService',
  'ServiceChanged',
  'TechnologyChanged',
  'TlsCertificateChanged',
  'HttpResponseChanged',
  'TimeOfDayVariance',
] as const
export type ChangeType = (typeof CHANGE_TYPES)[number]

export interface Change {
  id: Guid
  detectedAt: Instant
  scanRunId: Guid
  type: ChangeType
  hostId?: Guid
  address: string
  port?: number
  summary: string
  before?: unknown
  after?: unknown
  severity: string
}

/** Analytics/RunDiff.cs DiffItem. */
export interface DiffEntry {
  kind: 'endpoint' | 'technology'
  key: string
  address: string
  port?: number
  transport?: string
  name?: string
  before?: unknown
  after?: unknown
}

export interface ScanDiff {
  scanRunId?: Guid
  baselineRunId?: Guid
  added: DiffEntry[]
  removed: DiffEntry[]
  changed: DiffEntry[]
}

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const
export type Severity = (typeof SEVERITIES)[number]

export interface Finding {
  id: Guid
  signatureId: string
  signatureVersion?: number
  name: string
  severity: Severity
  hostId: Guid
  address: string
  port?: number
  matchedAt: Instant
  matchedUrl?: string
  evidence?: string
  status: 'Open' | 'Resolved'
  firstSeenAt: Instant
  lastSeenAt: Instant
  externalRefs: { system: string; externalId: string }[]
}

// ---------- Signatures & integrations ----------
export type SignatureKind = 'NucleiTemplate' | 'ClassificationRule' | 'ChangeRule'
export const SIGNATURE_KINDS: SignatureKind[] = ['NucleiTemplate', 'ClassificationRule', 'ChangeRule']
export type SignatureStatus = 'Draft' | 'Approved' | 'Retired'
export const SIGNATURE_STATUSES: SignatureStatus[] = ['Draft', 'Approved', 'Retired']

export interface Signature {
  id: string
  name: string
  kind: SignatureKind
  latestVersion: number
  approvedVersion?: number
  status: SignatureStatus
  severity?: Severity
  tags: string[]
  updatedAt: Instant
}

export interface SignatureVersion {
  version: number
  content: string
  sha256: string
  /** High/critical severity: approving requires a note. */
  requiresApprovalNote: boolean
  createdAt: Instant
  createdBy?: string
  approvedAt?: Instant
  approvedBy?: string
  approvalNote?: string
}

export interface SignatureDetail extends Signature {
  versions: SignatureVersion[]
}

export interface DefectDojoConfig {
  enabled: boolean
  baseUrl: string
  hasApiKey?: boolean
  /** Write-only: send to set/replace, omit to keep the stored key. */
  apiKey?: string
  productId?: number
  engagementId?: number
  minimumSeverity: Severity
  verifyTls: boolean
}

export interface DefectDojoExportResult {
  exported: number
  skipped: number
  errors: ValidationMessage[]
}

// ---------- Workflow conditions (Contracts: ConditionFields, ConditionOperator; Server: ConditionFieldTypes) ----------
export const CONDITION_FIELDS = [
  'kind',
  'address',
  'hostname',
  'port',
  'transport',
  'source.toolId',
  'host.status',
  'port.state',
  'service.name',
  'service.product',
  'service.version',
  'service.tunnel',
  'http.scheme',
  'http.statusCode',
  'http.title',
  'http.webServer',
  'tls.subjectCommonName',
  'tls.issuer',
  'technology.name',
  'technology.category',
  'signature.signatureId',
  'signature.severity',
  'confidence.score',
] as const
export const CONDITION_OPERATORS: ConditionOperator[] = ['Equals', 'NotEquals', 'In', 'NotIn', 'Contains', 'StartsWith', 'GreaterThan', 'LessThan', 'Exists', 'NotExists']
/** Known values of enum-typed condition fields (ObservationKind, TransportProtocol), offered as suggestions. */
export const CONDITION_FIELD_VALUES: Partial<Record<string, string[]>> = {
  kind: ['HostUp', 'HostDown', 'PortOpen', 'PortClosed', 'Service', 'HttpResponse', 'TlsCertificate', 'Technology', 'SignatureMatch', 'DnsRecord', 'Generic'],
  transport: ['Tcp', 'Udp'],
}

// ---------- Topology (GET /api/topology) ----------
export interface TopologyPerspective {
  agentId: string
  interfaceName?: string
  zone?: string
}

/** IPv4 /24 or IPv6 /64 (`id` = `cidr`; "other" groups hosts known only by name). */
export interface TopologySubnet {
  id: string
  cidr: string
  zone?: string
  hostCount: number
}

export interface TopologyService {
  port: number
  transport: 'Tcp' | 'Udp'
  serviceName?: string
  product?: string
  version?: string
  url?: string
  isWeb: boolean
  tls: boolean
}

export interface TopologyHost {
  id: Guid
  address: string
  hostnames: string[]
  status: HostStatus
  unstable: boolean
  subnet: string
  zone?: string
  lastSeenAt: Instant
  macVendor?: string
  openPortCount: number
  services: TopologyService[]
  technologies: string[]
  observedBy: { agentId: string; interfaceName?: string }[]
}

export interface Topology {
  perspectives: TopologyPerspective[]
  subnets: TopologySubnet[]
  hosts: TopologyHost[]
  /** More hosts matched than the server cap (5000). */
  truncated: boolean
}
