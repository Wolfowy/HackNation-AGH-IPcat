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

/** One agent interface (or gateway route) that sees an agent subnet. */
export interface AgentSubnetSource {
  agentId: string
  interfaceName: string
  /** Interface address with prefix, or the route destination. */
  address: string
  online: boolean
  gateway?: string
}

/** Subnet an agent is attached to (`interface`) or routes to through a gateway (`route`), proposed as a network. */
export interface AgentSubnet {
  cidr: string
  source: 'interface' | 'route'
  /** Null when the agent is authorized for several zones: pick one of `candidateZones`. */
  zone?: string | null
  candidateZones: string[]
  addressCount: number
  seenBy: AgentSubnetSource[]
  scope: 'full' | 'partial' | 'none'
  /** Inside the scope policy and not yet covered by networks of the zone: what creating a network adds. */
  proposedRanges: string[]
  existingNetworks: string[]
  /** The agent reaches the server through this subnet (and has other subnets to scan). */
  management: boolean
  /** More than 65 536 IPv4 addresses. */
  large: boolean
}

export interface ScopePolicy {
  allowed: string[]
  excluded: string[]
  /** Port allowlist ("80", "8000-8100"); empty = every port. */
  allowedPorts: string[]
  /** Ports never scanned, even when allowed. */
  excludedPorts: string[]
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
  'RecheckMissing',
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
  /** Values that need raw sockets on the agent (only agents reporting that capability get such jobs). */
  privilegedValues?: string[]
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
  /** Restart a run cut by its window at the next allowed window start (default true). */
  resumeInNextWindow: boolean
  /** Pending one-off resume fire. */
  resumeAt?: Instant
}

export type ScheduleInput = Omit<Schedule, 'id' | 'nextFireAt' | 'lastRunId' | 'lastRunStatus' | 'resumeAt'>

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
  /** User metadata, editable in any state (PUT /api/scans/{id}). */
  notes?: string
  tags: string[]
  /** ETA of an active run from its own rate so far (absent until a job finished). */
  remainingSeconds?: number
  estimatedFinishAt?: Instant
}

export interface ScanRunUpdate {
  name: string
  notes?: string
  tags: string[]
}

/** Raw tool formats and our flat JSON/CSV rows accepted by POST /api/scans/import. */
export const SCAN_IMPORT_FORMATS = ['json', 'csv', 'nmap-xml', 'httpx-jsonl', 'naabu-jsonl', 'nuclei-jsonl'] as const
export type ScanImportFormat = (typeof SCAN_IMPORT_FORMATS)[number]

export interface ScanImportResult {
  scanRunId: Guid
  rows: number
  observations: number
  changesDetected: number
  errors: string[]
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

/** POST /api/scans/estimate */
export interface ScanEstimateRequest {
  workflowKey: string
  workflowVersion?: number
  networkIds: Guid[]
  maxRatePerSecond?: number
  windowMinutes?: number
}

export interface StepEstimate {
  stepId: string
  operation: ScanOperation
  targets: number
  jobs: number
  batchSize: number
  batchReason: string
  eligibleAgents: number
  targetsPerSecond?: number
  estimatedSecondsMin?: number
  estimatedSecondsMax?: number
  unassignable: number
  unassignableReason?: string
}

/** Covers the steps that start first (scope-based); later steps depend on what they discover. */
export interface ScanEstimate {
  addressCount: number
  steps: StepEstimate[]
  estimatedSecondsMin?: number
  estimatedSecondsMax?: number
  windowMinutes?: number
  exceedsWindow: boolean
  warnings: string[]
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
  /** 0 = wait forever for an eligible agent. */
  unassignedJobTimeoutSeconds: number
  /** Job duration the planner aims at when sizing batches from measured throughput. */
  targetJobSeconds: number
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

/** GET /api/dashboard/insights — what deserves attention, in one call. */
export interface DashboardInsights {
  /** Open findings, highest severity first, then most recent. */
  topFindings: Finding[]
  /** Open services with the highest interest score (with reasons). */
  topServices: Service[]
  /** Every UTC day of the window, oldest first (days without changes included). */
  changesByDay: ChangeDay[]
  recentScans: RecentScan[]
  unstableHosts: number
  timeOfDayVarianceServices: number
}

export interface ChangeDay {
  /** yyyy-MM-dd (UTC) */
  date: string
  total: number
  byType: Partial<Record<ChangeType, number>>
}

export interface RecentScan {
  id: Guid
  name: string
  status: ScanRunStatus
  workflowKey: string
  createdAt: Instant
  startedAt?: Instant
  finishedAt?: Instant
  durationSeconds?: number
  coverageComplete: boolean
  /** Changes found by the run's comparison (absent: not compared). */
  changesDetected?: number
}

/** One UTC hour of day: covering scans that saw / missed the asset; for HTTP services the usual response in that hour. */
export interface HourVisibility {
  hour: number
  seen: number
  missed: number
  response?: string
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
  /** Zone of the scanned network ('' = default zone). Hosts are identified by (zone, address): the same IP in two zones is two hosts. */
  zone: string
  /** Latest MAC (AA:BB:CC:DD:EE:FF) — only visible on the scanner's L2 segment; never an identity. */
  macAddress?: string
  macVendor?: string
  /** Interface of a network device: its MAC is on hosts of other zones too (or is a VRRP/HSRP virtual-router MAC). */
  networkDevice: boolean
  /** 'low' when the MAC is locally administered (e.g. Docker/VM 02:42:…) and may repeat by coincidence. */
  networkDeviceConfidence?: DeviceConfidence
  annotation?: AssetAnnotation
  /** Analytical priority 0–100 (max over the host's services) and the reasons behind it. */
  interestScore?: number
  interestReasons?: string[]
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
  /** The other zones' interfaces of the same network device. */
  deviceInterfaces: DeviceInterface[]
  services: Service[]
  technologies: HostTechnology[]
  certificates: Certificate[]
  findings: Finding[]
  recentChanges: Change[]
  /** 24 UTC hours: how often covering scans saw / missed the host at that hour. */
  hourlyVisibility?: HourVisibility[]
}

export interface Service {
  id: Guid
  hostId: Guid
  zone: string
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
  /** User context kept across scans per (zone, address, port, transport). */
  annotation?: ServiceAnnotation
  /** Interesting HTTP artifacts of the latest fingerprinting run (see ServiceDetail.artifacts). */
  artifactCount?: number
  artifactTags?: string[]
  /** recog device classification, e.g. 'IP Camera', 'Printer', 'Router', 'NAS'. */
  deviceType?: string
  /** Responses differ consistently by hour of day (e.g. maintenance page at night). */
  timeOfDayVariance?: boolean
  /** For services with time-of-day variance: observed HTTP responses per UTC hour. */
  hourlyResponses?: HourVisibility[]
  /** Analytical priority 0–100 and the reasons behind it (highest weight first). */
  interestScore?: number
  interestReasons?: string[]
}

export const CRITICALITIES = ['low', 'medium', 'high', 'critical'] as const
export type Criticality = (typeof CRITICALITIES)[number]

export interface ServiceAnnotation {
  notes?: string
  tags: string[]
  criticality?: Criticality
  owner?: string
  updatedAt?: Instant
  updatedBy?: string
}

/** One Set-Cookie header: name and flags only; values never leave the agent. */
export interface HttpCookie {
  name: string
  secure: boolean
  httpOnly: boolean
  sameSite?: string
  domain?: string
  path?: string
  /** Non-secret value decoded on the agent, e.g. the internal pool member of an F5 BIG-IP cookie. */
  decodedValue?: string
}

/** Latest HTTP response of a service as reported by the probe (headers masked). */
export interface HttpDetails {
  url: string
  scheme: string
  statusCode?: number
  title?: string
  webServer?: string
  contentType?: string
  contentLength?: number
  headers: Record<string, string>
  cookies: HttpCookie[]
  redirectChain: string[]
  redirectStatusCodes: number[]
  finalUrl?: string
  faviconHash?: string
  faviconMd5?: string
  /** httpx page classification, e.g. 'login', 'error', 'parked'. */
  pageType?: string
  cdn?: string
  cdnType?: string
}

export type ArtifactKind = 'header' | 'cookie' | 'page' | 'favicon' | 'cert'

export interface ServiceArtifact {
  kind: ArtifactKind
  name: string
  value?: string
  reason: string
  /** e.g. tech-hint, version-leak, internal-ip-leak, debug, insecure-cookie, login-page, admin-page, missing-hsts, permissive-cors. */
  tags: string[]
  severity: 'info' | 'low'
}

export interface DeviceClassification {
  type: string
  vendor?: string
  product?: string
}

export interface ServiceDetail {
  service: Service
  http?: HttpDetails
  artifacts: ServiceArtifact[]
  device?: DeviceClassification
  technologies: HostTechnology[]
  certificate?: Certificate
  findings: Finding[]
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
  zone: string
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
  /** "{kind}|{zone}|{address}|{port}|…" */
  key: string
  zone: string
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
  zone: string
  address: string
  port?: number
  matchedAt: Instant
  matchedUrl?: string
  evidence?: string
  status: 'Open' | 'Resolved'
  firstSeenAt: Instant
  lastSeenAt: Instant
  externalRefs: { system: string; externalId: string }[]
  /** User triage; survives re-detection. FalsePositive findings are not counted as open and never published. */
  triage: FindingTriage
  severityOverride?: Severity
  /** severityOverride ?? severity — used by filters, counts and exports. */
  effectiveSeverity: Severity
  notes?: string
  userTags: string[]
  triagedBy?: string
  triagedAt?: Instant
}

export const FINDING_TRIAGES = ['None', 'Confirmed', 'FalsePositive', 'AcceptedRisk'] as const
export type FindingTriage = (typeof FINDING_TRIAGES)[number]

export interface FindingTriageInput {
  triage: FindingTriage
  severityOverride?: Severity
  notes?: string
  userTags: string[]
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
  'service.banner',
  'http.url',
  'http.contentType',
  'http.finalUrl',
  'http.faviconHash',
  'http.cookieNames',
  'http.redirectChain',
  'http.technologies',
  'tls.subjectAlternativeNames',
] as const
/** Dynamic field `http.header.<Name>` (response header, case-insensitive; Name = RFC 7230 token). */
export const HTTP_HEADER_FIELD_PREFIX = 'http.header.'
/** List fields: a rule matches when any element matches (NotEquals/NotIn: when no element matches). */
export const CONDITION_LIST_FIELDS: readonly string[] = ['http.cookieNames', 'http.redirectChain', 'http.technologies', 'tls.subjectAlternativeNames']
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

/** IPv4 /24 or IPv6 /64 per zone (id = "{zone}|{cidr}"; cidr "other" groups hosts known only by name). */
export interface TopologySubnet {
  id: string
  cidr: string
  zone: string
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
  /** Id of the host's subnet ("{zone}|{cidr}"). */
  subnet: string
  zone: string
  lastSeenAt: Instant
  macAddress?: string
  macVendor?: string
  openPortCount: number
  services: TopologyService[]
  technologies: string[]
  observedBy: { agentId: string; interfaceName?: string }[]
  /** Id (MAC) of the network device this host is an interface of. */
  deviceId?: string
  /** The MAC is on other IPs of the same zone too (aliases or proxy-ARP); not a device by itself. */
  sharedMac: boolean
}

/** A zone is a separate IP address space (routed segment / VLAN / VRF). */
export interface TopologyZone {
  name: string
  subnetCount: number
  hostCount: number
}

export type DeviceConfidence = 'high' | 'low'

export interface DeviceInterface {
  hostId: Guid
  zone: string
  address: string
}

/** Physical device (router, L3 switch, firewall, multi-homed box) inferred from one MAC on hosts of several zones; id = MAC. */
export interface NetworkDevice {
  id: string
  macAddress: string
  macVendor?: string
  confidence: DeviceConfidence
  zones: string[]
  interfaces: DeviceInterface[]
}

export interface Topology {
  perspectives: TopologyPerspective[]
  zones: TopologyZone[]
  devices: NetworkDevice[]
  subnets: TopologySubnet[]
  hosts: TopologyHost[]
  /** More hosts matched than the server cap (5000). */
  truncated: boolean
}
