// Deterministic, realistic seed data for the in-browser / test mock API.
import type {
  AgentSubnet,
  Agent,
  AuditEntry,
  Certificate,
  Change,
  ChangeType,
  DefectDojoConfig,
  DeviceClassification,
  EnrollmentToken,
  Finding,
  Host,
  HostTechnology,
  HttpDetails,
  Network,
  Role,
  ScanExecutionEvent,
  ScanJob,
  ScanLimits,
  ScanRun,
  ScanStep,
  ScanWorkflowDefinition,
  Schedule,
  ScopePolicy,
  Service,
  ServiceArtifact,
  ServiceDetail,
  Severity,
  SignatureDetail,
  ToolCatalogEntry,
  User,
  WorkflowVersion,
  Zone,
} from '@/api/types'
import { OPERATIONS } from './operations'

/** Mirrors the server rule: high/critical severity signatures need an approval note. */
export const requiresApprovalNote = (content: string) => /severity"?\s*:\s*"?(high|critical)\b/i.test(content)

/** Mock-only credentials: every seeded user signs in with this password. */
export const MOCK_PASSWORD = 'webscan'

export interface MockUser extends User {
  password: string
}

export interface MockRun extends ScanRun {
  steps: ScanStep[]
}

export interface MockDb {
  users: MockUser[]
  zones: Omit<Zone, 'networkCount'>[]
  networks: Network[]
  scopePolicy: ScopePolicy
  agents: Agent[]
  /** Server-derived agent subnets (static here; the handler re-evaluates coverage and scope against the mock db). */
  agentSubnets: AgentSubnet[]
  tools: ToolCatalogEntry[]
  tokens: EnrollmentToken[]
  workflows: WorkflowVersion[]
  schedules: Schedule[]
  runs: MockRun[]
  jobs: ScanJob[]
  events: ScanExecutionEvent[]
  hosts: MockHost[]
  services: Service[]
  hostTechnologies: Record<string, HostTechnology[]>
  certificates: Record<string, Certificate[]>
  /** HTTP fingerprint per service id (the handler adds service, technologies, certificate and findings). */
  serviceDetails: Record<string, Pick<ServiceDetail, 'http' | 'artifacts' | 'device'>>
  changes: Change[]
  findings: Finding[]
  signatures: SignatureDetail[]
  settings: Record<string, string>
  scanLimits: ScanLimits
  audit: AuditEntry[]
  defectDojo: DefectDojoConfig & { apiKeyValue?: string }
}

/** Network-device flags are inferred per request (handlers), like the server does on read. */
export type MockHost = Omit<Host, 'networkDevice' | 'networkDeviceConfidence'>

// ---------- helpers ----------
function mulberry32(seed: number) {
  return () => {
    seed |= 0
    seed = (seed + 0x6d2b79f5) | 0
    let x = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296
  }
}

let rand = mulberry32(42)
const pick = <T,>(items: readonly T[]): T => items[Math.floor(rand() * items.length)]
const int = (min: number, max: number) => min + Math.floor(rand() * (max - min + 1))

const mockMac = (octet: number, zone: string) =>
  `00:1A:2B:${zone === 'lab' ? '5A' : '0F'}:00:${octet.toString(16).padStart(2, '0').toUpperCase()}`

let idCounter = 0
/** Deterministic GUID-like ids (stable across reloads, unique within the db). */
export function mockId(prefix = 0): string {
  idCounter += 1
  const hex = (prefix * 1_000_000 + idCounter).toString(16).padStart(12, '0')
  return `00000000-0000-4000-8000-${hex}`
}

export function randomGuid(): string {
  return crypto.randomUUID()
}

const NOW = Date.now()
const ago = (minutes: number) => new Date(NOW - minutes * 60_000).toISOString()
const sha = (n: number) => Array.from({ length: 64 }, (_, i) => ((n * 7 + i * 13) % 16).toString(16)).join('')

// ---------- static catalog ----------
const SERVICE_CATALOG = [
  { port: 22, name: 'ssh', product: 'OpenSSH', version: '9.6p1', tech: { name: 'OpenSSH', version: '9.6p1', category: 'remote-access' } },
  { port: 80, name: 'http', product: 'nginx', version: '1.24.0', tech: { name: 'nginx', version: '1.24.0', category: 'web-server' }, http: { statusCode: 301, title: 'Moved Permanently', webServer: 'nginx/1.24.0' } },
  { port: 443, name: 'https', product: 'nginx', version: '1.24.0', tech: { name: 'nginx', version: '1.24.0', category: 'web-server' }, http: { statusCode: 200, title: 'Customer portal', webServer: 'nginx/1.24.0' }, tls: true },
  { port: 3389, name: 'ms-wbt-server', product: 'Microsoft Terminal Services', tech: { name: 'Windows RDP', category: 'remote-access' } },
  { port: 445, name: 'microsoft-ds', product: 'Microsoft Windows SMB', tech: { name: 'Windows SMB', category: 'file-sharing' } },
  { port: 8080, name: 'http-proxy', product: 'Apache Tomcat', version: '9.0.85', tech: { name: 'Apache Tomcat', version: '9.0.85', category: 'application-server' }, http: { statusCode: 200, title: 'Apache Tomcat/9.0.85', webServer: 'Apache-Coyote/1.1' } },
  { port: 3306, name: 'mysql', product: 'MySQL', version: '8.0.36', tech: { name: 'MySQL', version: '8.0.36', category: 'database' } },
  { port: 5432, name: 'postgresql', product: 'PostgreSQL', version: '16.2', tech: { name: 'PostgreSQL', version: '16.2', category: 'database' } },
  { port: 3000, name: 'http', product: 'Grafana', version: '10.4.1', tech: { name: 'Grafana', version: '10.4.1', category: 'monitoring' }, http: { statusCode: 302, title: 'Grafana', webServer: '' } },
  { port: 9100, name: 'jetdirect', product: 'HP JetDirect', tech: { name: 'HP printer', category: 'network-device' } },
] as const

const HOSTNAME_PARTS = ['web', 'app', 'db', 'mail', 'vpn', 'files', 'print', 'git', 'ci', 'mon', 'dc', 'proxy']

function defaultWorkflows(): WorkflowVersion[] {
  const standardV1: ScanWorkflowDefinition = {
    key: 'standard-discovery',
    version: 1,
    name: 'Standard discovery',
    description: 'Host discovery, port scan and service detection.',
    steps: [
      { id: 'discover', operation: 'DiscoverHosts', parameters: { method: 'default' } },
      { id: 'ports', operation: 'ScanPorts', dependsOn: ['discover'], input: { fromSteps: ['discover'] }, parameters: { ports: 'top-1000' } },
      { id: 'services', operation: 'DetectService', dependsOn: ['ports'], input: { fromSteps: ['ports'] } },
      { id: 'persist', operation: 'PersistObservations', dependsOn: ['services'] },
    ],
  }
  const standardV2: ScanWorkflowDefinition = {
    key: 'standard-discovery',
    version: 2,
    name: 'Standard discovery',
    description: 'Discovery → ports → services → HTTP/TLS probes and signatures → change detection.',
    defaults: { timeoutSeconds: 3600, maxConcurrency: 50, retry: { maxAttempts: 3, backoffSeconds: 30 } },
    steps: [
      { id: 'discover', operation: 'DiscoverHosts', parameters: { method: 'default', probePorts: '22,80,443,3389,8080' } },
      { id: 'ports', operation: 'ScanPorts', dependsOn: ['discover'], input: { fromSteps: ['discover'] }, parameters: { ports: 'top-1000', scanType: 'connect' } },
      { id: 'services', operation: 'DetectService', dependsOn: ['ports'], input: { fromSteps: ['ports'] }, parameters: { versionIntensity: '5' } },
      {
        id: 'http',
        operation: 'HttpProbe',
        dependsOn: ['services'],
        input: { fromSteps: ['services'], filter: { field: 'service.name', operator: 'In', values: ['http', 'https', 'http-proxy'] } },
        when: { field: 'service.name', operator: 'In', values: ['http', 'https', 'http-proxy'] },
        parameters: { techDetect: 'true', paths: '/' },
      },
      {
        id: 'tls',
        operation: 'TlsProbe',
        dependsOn: ['services'],
        input: { fromSteps: ['services'], filter: { any: [{ field: 'service.tunnel', operator: 'Equals', values: ['ssl'] }, { field: 'port', operator: 'In', values: ['443', '8443'] }] } },
        onFailure: 'Continue',
      },
      { id: 'signatures', operation: 'ExecuteSignatures', dependsOn: ['http'], input: { fromSteps: ['http'] }, parameters: { severities: 'info,low,medium' } },
      { id: 'persist', operation: 'PersistObservations', dependsOn: ['signatures', 'tls'] },
      { id: 'compare', operation: 'ComparePreviousScan', dependsOn: ['persist'], parameters: { missingThreshold: '3' } },
      { id: 'publish', operation: 'PublishFinding', dependsOn: ['compare'], parameters: { destination: 'internal', minSeverity: 'medium' } },
    ],
  }
  const quick: ScanWorkflowDefinition = {
    key: 'quick-ports',
    version: 1,
    name: 'Quick port sweep',
    description: 'Fast top-100 port sweep without service detection.',
    steps: [
      { id: 'discover', operation: 'DiscoverHosts', parameters: { method: 'tcp-syn' } },
      { id: 'ports', operation: 'ScanPorts', dependsOn: ['discover'], input: { fromSteps: ['discover'] }, parameters: { ports: 'top-100', scanType: 'syn', rate: '2000' } },
      { id: 'persist', operation: 'PersistObservations', dependsOn: ['ports'] },
      { id: 'compare', operation: 'ComparePreviousScan', dependsOn: ['persist'] },
    ],
  }
  return [
    { key: standardV1.key, version: 1, definition: standardV1, createdAt: ago(60 * 24 * 40), createdBy: 'system' },
    { key: standardV2.key, version: 2, definition: standardV2, createdAt: ago(60 * 24 * 12), createdBy: 'admin' },
    { key: quick.key, version: 1, definition: quick, createdAt: ago(60 * 24 * 20), createdBy: 'manager' },
  ]
}

/** Steps (from the workflow DAG) and jobs (BATCHES per agent step) for a run. */
export function buildRunPlan(db: Pick<MockDb, 'workflows' | 'agents'>, run: ScanRun, batches = 3): { steps: ScanStep[]; jobs: ScanJob[] } {
  const wf = db.workflows.find((w) => w.key === run.workflowKey && w.version === run.workflowVersion)
  const steps: ScanStep[] = []
  const jobs: ScanJob[] = []
  for (const step of wf?.definition.steps ?? []) {
    const op = OPERATIONS.find((o) => o.operation === step.operation)
    const agentStep = op?.plane === 'Agent'
    steps.push({ stepId: step.id, operation: step.operation, status: 'Pending', jobsTotal: agentStep ? batches : 0, jobsCompleted: 0 })
    if (!agentStep) continue
    for (let b = 0; b < batches; b++) {
      jobs.push({
        id: mockId(5),
        scanRunId: run.id,
        stepId: step.id,
        operation: step.operation,
        status: 'Queued',
        targetSummary: `10.10.0.${b * 64}/26`,
        targetCount: 64,
        attempt: 1,
        maxAttempts: 3,
        createdAt: run.createdAt,
      })
    }
  }
  return { steps, jobs }
}

export function createDb(): MockDb {
  rand = mulberry32(42)
  idCounter = 0

  const users: MockUser[] = (
    [
      ['admin', 'Administrator', 'Ada Admin'],
      ['manager', 'Manager', 'Marek Manager'],
      ['editor', 'Editor', 'Ewa Editor'],
      ['viewer', 'Viewer', 'Wiktor Viewer'],
    ] as [string, Role, string][]
  ).map(([userName, role, displayName], i) => ({
    id: mockId(1),
    userName,
    displayName,
    roles: [role],
    isActive: true,
    createdAt: ago(60 * 24 * (90 - i)),
    lastLoginAt: ago(60 * (i + 1)),
    password: MOCK_PASSWORD,
  }))

  const zones = [
    { name: 'dmz', description: 'Internet-facing services' },
    { name: 'office', description: 'Office LAN and VPN pools' },
    { name: 'lab', description: 'Test lab' },
  ]

  const net = (name: string, zone: string, ranges: string[], addressCount: number, extra: Partial<Network> = {}): Network => ({
    id: mockId(2),
    name,
    zone,
    ranges,
    exclusions: [],
    tags: [],
    enabled: true,
    addressCount,
    createdAt: ago(60 * 24 * 60),
    updatedAt: ago(60 * 24 * int(1, 30)),
    ...extra,
  })
  const agentSubnets = (): AgentSubnet[] => {
    const seen = (agentId: string, interfaceName: string, address: string, gateway?: string) => ({ agentId, interfaceName, address, online: true, gateway })
    const subnet = (cidr: string, zone: string | null, candidateZones: string[], addressCount: number, seenBy: AgentSubnet['seenBy'], extra: Partial<AgentSubnet> = {}): AgentSubnet => ({
      cidr, source: 'interface', zone, candidateZones, addressCount, seenBy, scope: 'full', proposedRanges: [cidr], existingNetworks: [], management: false, large: false, ...extra,
    })
    return [
      subnet('10.10.0.0/24', 'dmz', ['dmz'], 256, [seen('scanner-dmz-01', 'eth0', '10.10.0.5/24')], { proposedRanges: [], existingNetworks: ['DMZ public services'] }),
      subnet('10.10.8.0/23', 'dmz', ['dmz'], 512, [seen('scanner-dmz-01', 'eth2', '10.10.8.20/23')]),
      subnet('10.99.0.0/24', 'dmz', ['dmz'], 256, [seen('scanner-dmz-01', 'eth1', '10.99.0.5/24')], { management: true }),
      subnet('172.16.50.0/26', null, ['lab', 'office'], 64, [seen('scanner-office-01', 'wg0', '172.16.50.2/26')], { proposedRanges: [], existingNetworks: ['Lab'] }),
      subnet('192.168.10.0/24', null, ['lab', 'office'], 256, [seen('scanner-office-01', 'ens18', '192.168.10.250/24')], { proposedRanges: [], existingNetworks: ['Office LAN'] }),
      subnet('100.64.0.0/22', 'dmz', ['dmz'], 1024, [seen('scanner-dmz-01', 'eth0', '100.64.0.0/22', '10.10.0.1')], { source: 'route', scope: 'none', proposedRanges: [] }),
      subnet('10.40.0.0/16', null, ['lab', 'office'], 65536, [seen('scanner-office-01', 'ens18', '10.40.0.0/16', '192.168.10.1')], { source: 'route' }),
    ]
  }

  const networks = [
    net('DMZ public services', 'dmz', ['10.10.0.0/24'], 253, { exclusions: ['10.10.0.1'], tags: ['internet-facing', 'pci'], description: 'Reverse proxies and public web apps' }),
    net('Office LAN', 'office', ['192.168.10.0/24', '192.168.11.0/24'], 510, { tags: ['workstations'] }),
    net('Lab', 'lab', ['172.16.50.0/26'], 62, { maxRatePerSecond: 200, tags: ['test'] }),
    net('Legacy VPN pool', 'office', ['10.20.0.0/22'], 1022, { enabled: false, description: 'Decommissioning in Q1' }),
  ]

  const tool = (id: string, version: string, capabilities: string[], approved = true) => ({ id, version, capabilities, approved })
  const nmap = tool('nmap', '7.95', ['host-discovery', 'port-scan', 'service-detection'])
  const naabu = tool('naabu', '2.3.1', ['port-scan'])
  const httpx = tool('httpx', '1.6.9', ['http-probe', 'tls-probe'])
  const nuclei = tool('nuclei', '3.3.5', ['signature-scan'])
  const agents: Agent[] = [
    {
      agentId: 'scanner-dmz-01',
      hostname: 'dmz-scan-01',
      status: 'Active',
      isOnline: true,
      lastHeartbeatAt: ago(0.2),
      registeredAt: ago(60 * 24 * 50),
      osPlatform: 'linux',
      osDescription: 'Debian GNU/Linux 12 (bookworm)',
      agentVersion: '1.0.0',
      tools: [nmap, naabu, httpx, nuclei],
      interfaces: [
        { name: 'eth0', isUp: true, addresses: ['10.10.0.5/24'], macAddress: '52:54:00:12:34:56', speedMbps: 10000 },
        { name: 'eth1', isUp: true, addresses: ['10.99.0.5/24'], macAddress: '52:54:00:12:34:57', speedMbps: 1000, description: 'Management' },
        { name: 'eth2', isUp: true, addresses: ['10.10.8.20/23'], macAddress: '52:54:00:12:34:58', speedMbps: 1000, description: 'Staging' },
      ],
      routes: [
        { destination: '10.10.0.0/24', interfaceName: 'eth0', metric: 0 },
        { destination: '10.99.0.0/24', interfaceName: 'eth1', metric: 0 },
        { destination: '0.0.0.0/0', gateway: '10.10.0.1', interfaceName: 'eth0', metric: 100 },
      ],
      declaredZones: ['dmz'],
      authorizedZones: ['dmz'],
      authorizedNetworkIds: [],
      limits: { maxConcurrentJobs: 4, maxRatePerSecond: 5000 },
      reportedLimits: { maxConcurrentJobs: 8, maxRatePerSecond: 5000 },
      limitOverrides: { maxConcurrentJobs: 4 },
      rotateRequested: false,
      load: { cpuPercent: 23.5, memoryUsedMb: 812, runningJobs: 1, bufferedBatches: 0, runningJobsPerInterface: { eth0: 1 } },
    },
    {
      agentId: 'scanner-office-01',
      hostname: 'office-scan-01',
      status: 'Active',
      isOnline: true,
      lastHeartbeatAt: ago(0.4),
      registeredAt: ago(60 * 24 * 45),
      osPlatform: 'linux',
      osDescription: 'Ubuntu 24.04 LTS',
      agentVersion: '1.0.0',
      tools: [nmap, httpx, tool('testssl', '3.2.0', ['tls-probe', 'tls-audit'], false)],
      interfaces: [
        { name: 'ens18', isUp: true, addresses: ['192.168.10.250/24', 'fe80::5054:ff:fe00:1/64'], speedMbps: 1000 },
        { name: 'wg0', isUp: true, addresses: ['172.16.50.2/26'], description: 'WireGuard to lab' },
      ],
      routes: [
        { destination: '192.168.10.0/23', interfaceName: 'ens18', metric: 0 },
        { destination: '172.16.50.0/26', interfaceName: 'wg0', metric: 10 },
        { destination: '0.0.0.0/0', gateway: '192.168.10.1', interfaceName: 'ens18', metric: 100 },
      ],
      declaredZones: ['office'],
      authorizedZones: ['office', 'lab'],
      authorizedNetworkIds: [],
      limits: { maxConcurrentJobs: 2, maxRatePerSecond: 1000 },
      reportedLimits: { maxConcurrentJobs: 2, maxRatePerSecond: 1000 },
      limitOverrides: {},
      rotateRequested: false,
      load: { cpuPercent: 8.1, memoryUsedMb: 455, runningJobs: 0, bufferedBatches: 0 },
    },
    {
      agentId: 'scanner-lab-02',
      hostname: 'lab-scan-02',
      status: 'PendingApproval',
      isOnline: false,
      lastHeartbeatAt: ago(60 * 5),
      registeredAt: ago(60 * 6),
      osPlatform: 'linux',
      osDescription: 'Alpine Linux 3.20',
      agentVersion: '1.0.0',
      tools: [nmap, tool('masscan-custom', '1.3.2', ['port-scan', 'fast-syn'], false)],
      interfaces: [{ name: 'eth0', isUp: true, addresses: ['172.16.50.10/26'] }],
      routes: [{ destination: '0.0.0.0/0', gateway: '172.16.50.1', interfaceName: 'eth0', metric: 0 }],
      declaredZones: ['lab'],
      authorizedZones: [],
      authorizedNetworkIds: [],
      limits: { maxConcurrentJobs: 2, maxRatePerSecond: 2000 },
      reportedLimits: { maxConcurrentJobs: 2, maxRatePerSecond: 2000 },
      limitOverrides: {},
      rotateRequested: false,
    },
  ]

  const toolEntry = (toolId: string, capabilities: string[], versions: string[], agentCount: number, approved: boolean, days: number): ToolCatalogEntry => ({
    toolId,
    approved,
    enabled: true,
    capabilities,
    versions,
    agentCount,
    firstSeenAt: ago(60 * 24 * days),
  })
  const tools = [
    toolEntry('nmap', nmap.capabilities, ['7.95'], 3, true, 50),
    toolEntry('naabu', naabu.capabilities, ['2.3.1'], 1, true, 50),
    toolEntry('httpx', httpx.capabilities, ['1.6.9'], 2, true, 50),
    toolEntry('nuclei', nuclei.capabilities, ['3.3.5'], 1, true, 50),
    toolEntry('testssl', ['tls-probe', 'tls-audit'], ['3.2.0'], 1, false, 9),
    toolEntry('masscan-custom', ['port-scan', 'fast-syn'], ['1.3.2'], 1, false, 0.25),
  ]

  const tokens: EnrollmentToken[] = [
    { id: mockId(3), name: 'lab rollout', expiresAt: ago(-60 * 20), maxUses: 5, uses: 1, autoApprove: false, zones: ['lab'], revoked: false, createdAt: ago(60 * 7) },
    { id: mockId(3), name: 'dmz replacement', expiresAt: ago(-60 * 2), maxUses: 1, uses: 0, autoApprove: true, zones: ['dmz'], revoked: false, createdAt: ago(60) },
    { id: mockId(3), name: 'old office batch', expiresAt: ago(-60 * 48), maxUses: 10, uses: 3, autoApprove: false, zones: ['office'], revoked: true, createdAt: ago(60 * 24 * 3) },
  ]

  const workflows = defaultWorkflows()

  // ---------- hosts / services ----------
  const hosts: MockHost[] = []
  const services: Service[] = []
  const hostTechnologies: Record<string, HostTechnology[]> = {}
  const certificates: Record<string, Certificate[]> = {}
  const addressPools: [string, string, number][] = [
    ['10.10.0.', 'dmz', 18],
    ['192.168.10.', 'office', 16],
    ['172.16.50.', 'lab', 8],
  ]
  let certN = 0
  for (const [prefix, zone, count] of addressPools) {
    const used = new Set<number>()
    for (let i = 0; i < count; i++) {
      let octet = int(2, 250)
      while (used.has(octet)) octet = int(2, 250)
      used.add(octet)
      const id = mockId(4)
      const address = `${prefix}${octet}`
      const statusRoll = rand()
      const status = statusRoll < 0.78 ? 'Active' : statusRoll < 0.88 ? 'Unreachable' : statusRoll < 0.96 ? 'Gone' : 'Unknown'
      const firstSeen = int(60 * 24, 60 * 24 * 60)
      const lastSeen = status === 'Active' ? int(5, 600) : int(60 * 24 * 2, 60 * 24 * 10)
      const svcCount = int(1, 4)
      const catalog = [...SERVICE_CATALOG].sort(() => rand() - 0.5).slice(0, svcCount)
      const techs: HostTechnology[] = []
      for (const svc of catalog) {
        const sid = mockId(6)
        const hasHttp = 'http' in svc
        const httpUrl = `${svc.port === 443 ? 'https' : 'http'}://${address}:${svc.port}/`
        services.push({
          id: sid,
          hostId: id,
          zone,
          address,
          port: svc.port,
          transport: 'Tcp',
          state: status === 'Gone' ? 'Gone' : 'Open',
          serviceName: svc.name,
          product: svc.product,
          version: 'version' in svc ? svc.version : undefined,
          http: hasHttp ? { url: httpUrl, ...svc.http } : undefined,
          // Server rule: the probed HTTP URL; non-web services (ssh, smb, databases…) get none.
          url: hasHttp ? httpUrl : undefined,
          tls: 'tls' in svc ? { subjectCommonName: `${pick(HOSTNAME_PARTS)}.example.internal`, issuer: 'Example Internal CA', notAfter: ago(-60 * 24 * int(-20, 300)), fingerprintSha256: sha(++certN) } : undefined,
          technologies: [svc.tech.name],
          confidence: Math.round((0.6 + rand() * 0.4) * 100) / 100,
          firstSeenAt: ago(firstSeen),
          lastSeenAt: ago(lastSeen),
        })
        techs.push({ ...svc.tech, port: svc.port, confidence: Math.round((0.55 + rand() * 0.45) * 100) / 100, confidenceMethod: pick(['tool-reported', 'banner-match', 'version-probe', 'signature-match']) })
        if ('tls' in svc) {
          const notAfter = ago(-60 * 24 * int(-20, 300))
          certificates[id] = [
            {
              fingerprintSha256: sha(certN),
              subjectCommonName: `${pick(HOSTNAME_PARTS)}.example.internal`,
              subjectAlternativeNames: [`${address}`],
              issuer: rand() < 0.3 ? `CN=${address}` : 'CN=Example Internal CA',
              notBefore: ago(60 * 24 * 300),
              notAfter,
              port: 443,
              selfSigned: rand() < 0.3,
            },
          ]
        }
      }
      hostTechnologies[id] = techs
      hosts.push({
        id,
        address,
        hostnames: rand() < 0.6 ? [`${pick(HOSTNAME_PARTS)}${int(1, 9)}.${zone}.example.internal`] : [],
        status,
        unstable: rand() < 0.12,
        firstSeenAt: ago(firstSeen),
        lastSeenAt: ago(lastSeen),
        lastScannedAt: ago(int(5, 300)),
        openPortCount: status === 'Gone' ? 0 : catalog.length,
        technologies: techs.map((x) => x.name),
        zone,
        // Scanners see MACs only on their own L2 segment (office/lab), not behind the DMZ router. Derived, not random: keeps the seed stable.
        ...(zone === 'dmz' ? {} : { macAddress: mockMac(octet, zone), macVendor: octet % 3 === 0 ? 'Dell Inc.' : octet % 3 === 1 ? 'Hewlett Packard' : 'Raspberry Pi Trading Ltd' }),
        annotation:
          rand() < 0.35
            ? {
                description: 'Managed by the infrastructure team',
                classification: pick(['production', 'test', 'internal']),
                businessState: pick(['in use', 'planned', 'decommissioning']),
                owner: pick(['infra-team', 'web-team', 'dba-team']),
                tags: [pick(['critical', 'pci', 'legacy', 'monitored'])],
              }
            : undefined,
      })
    }
  }

  // ---------- scans ----------
  const runs: MockRun[] = []
  const jobs: ScanJob[] = []
  const events: ScanExecutionEvent[] = []
  const history: [string, ScanRun['status'], number, string][] = [
    ['Nightly DMZ discovery', 'Completed', 60 * 24 * 6, 'schedule'],
    ['Nightly DMZ discovery', 'Completed', 60 * 24 * 5, 'schedule'],
    ['Office sweep', 'PartiallyCompleted', 60 * 24 * 4, 'manual:manager'],
    ['Lab check', 'Failed', 60 * 24 * 3, 'manual:editor'],
    ['Nightly DMZ discovery', 'WindowExpired', 60 * 24 * 2, 'schedule'],
    ['Office sweep', 'Cancelled', 60 * 30, 'manual:admin'],
    ['Nightly DMZ discovery', 'Completed', 60 * 22, 'schedule'],
  ]
  for (const [name, status, minutesAgo, triggeredBy] of history) {
    const run: MockRun = {
      id: mockId(7),
      name,
      status,
      workflowKey: name.startsWith('Office') ? 'quick-ports' : 'standard-discovery',
      workflowVersion: name.startsWith('Office') ? 1 : 2,
      networkIds: [name.startsWith('Office') ? networks[1].id : name.startsWith('Lab') ? networks[2].id : networks[0].id],
      triggeredBy,
      priority: 50,
      createdAt: ago(minutesAgo),
      startedAt: ago(minutesAgo - 1),
      finishedAt: ago(minutesAgo - int(12, 55)),
      progress: { jobsTotal: 0, jobsQueued: 0, jobsRunning: 0, jobsCompleted: 0, jobsFailed: 0, percent: 0 },
      coverageComplete: status === 'Completed',
      steps: [],
    }
    const plan = buildRunPlan({ workflows, agents }, run)
    const finishedOk = status === 'Completed'
    plan.steps.forEach((s, i) => {
      const done = finishedOk || i < plan.steps.length / 2
      s.status = done ? 'Completed' : status === 'Failed' && Math.floor(plan.steps.length / 2) === i ? 'Failed' : status === 'Cancelled' || status === 'WindowExpired' ? 'Cancelled' : 'Skipped'
      s.jobsCompleted = done ? s.jobsTotal : 0
      s.startedAt = run.startedAt
      s.finishedAt = run.finishedAt
    })
    plan.jobs.forEach((j) => {
      const step = plan.steps.find((s) => s.stepId === j.stepId)!
      const agent = j.operation === 'HttpProbe' || j.operation === 'TlsProbe' ? agents[0] : pick([agents[0], agents[1]])
      j.agentId = agent.agentId
      j.interfaceName = agent.interfaces[0].name
      j.toolId = agent.tools.find((tl) => tl.capabilities.includes(OPERATIONS.find((o) => o.operation === j.operation)?.requiredCapability ?? ''))?.id ?? 'nmap'
      j.startedAt = run.startedAt
      j.finishedAt = run.finishedAt
      j.durationMs = int(4_000, 180_000)
      j.status = step.status === 'Completed' ? 'Completed' : step.status === 'Failed' ? 'Failed' : 'Cancelled'
      if (j.status === 'Failed') {
        j.error = 'Tool exited with code 1: nmap: Failed to resolve given hostname/IP'
        j.attempt = 3
      }
    })
    run.steps = plan.steps
    jobs.push(...plan.jobs)
    runs.push(run)
    events.push(
      { eventId: randomGuid(), occurredAt: run.createdAt, type: 'RunCreated', scanRunId: run.id, message: `Run created by ${triggeredBy}` },
      { eventId: randomGuid(), occurredAt: run.startedAt!, type: 'RunStarted', scanRunId: run.id },
      { eventId: randomGuid(), occurredAt: run.finishedAt!, type: `Run${status === 'PartiallyCompleted' ? 'PartiallyCompleted' : status}` as ScanExecutionEvent['type'], scanRunId: run.id },
    )
  }
  runs.reverse() // newest first

  // One run in progress (driven by the simulation in the browser, static in unit tests).
  const live: MockRun = {
    id: mockId(7),
    name: 'DMZ discovery (manual)',
    status: 'Running',
    workflowKey: 'standard-discovery',
    workflowVersion: 2,
    networkIds: [networks[0].id],
    triggeredBy: 'manual:admin',
    priority: 70,
    createdAt: ago(6),
    startedAt: ago(6),
    progress: { jobsTotal: 0, jobsQueued: 0, jobsRunning: 0, jobsCompleted: 0, jobsFailed: 0, percent: 0 },
    coverageComplete: false,
    steps: [],
  }
  const livePlan = buildRunPlan({ workflows, agents }, live)
  livePlan.steps[0].status = 'Completed'
  livePlan.steps[0].jobsCompleted = livePlan.steps[0].jobsTotal
  livePlan.steps[0].startedAt = ago(6)
  livePlan.steps[0].finishedAt = ago(4)
  livePlan.steps[1].status = 'Running'
  livePlan.steps[1].startedAt = ago(4)
  livePlan.jobs.forEach((j) => {
    if (j.stepId === 'discover') Object.assign(j, { status: 'Completed', agentId: 'scanner-dmz-01', interfaceName: 'eth0', toolId: 'nmap', startedAt: ago(6), finishedAt: ago(4), durationMs: 41_000 })
  })
  const runningJob = livePlan.jobs.find((j) => j.stepId === 'ports')!
  Object.assign(runningJob, { status: 'Leased', agentId: 'scanner-dmz-01', interfaceName: 'eth0', toolId: 'naabu', startedAt: ago(1), progressPercent: 40 })
  live.steps = livePlan.steps
  jobs.push(...livePlan.jobs)
  runs.unshift(live)
  events.push(
    { eventId: randomGuid(), occurredAt: ago(6), type: 'RunCreated', scanRunId: live.id, message: 'Run created by manual:admin' },
    { eventId: randomGuid(), occurredAt: ago(6), type: 'RunStarted', scanRunId: live.id },
    { eventId: randomGuid(), occurredAt: ago(6), type: 'StepStarted', scanRunId: live.id, stepId: 'discover' },
    { eventId: randomGuid(), occurredAt: ago(4), type: 'StepCompleted', scanRunId: live.id, stepId: 'discover' },
    { eventId: randomGuid(), occurredAt: ago(4), type: 'StepStarted', scanRunId: live.id, stepId: 'ports' },
    { eventId: randomGuid(), occurredAt: ago(1), type: 'JobAssigned', scanRunId: live.id, stepId: 'ports', jobId: runningJob.id, agentId: 'scanner-dmz-01' },
  )

  // ---------- changes / findings ----------
  const changeTypes: [ChangeType, string, (h: MockHost) => Pick<Change, 'summary' | 'before' | 'after' | 'port'>][] = [
    ['NewHost', 'info', (h) => ({ summary: `New host ${h.address} discovered` })],
    ['HostGone', 'low', (h) => ({ summary: `Host ${h.address} not seen in 3 complete scans` })],
    ['HostReappeared', 'info', (h) => ({ summary: `Host ${h.address} is reachable again` })],
    ['NewPort', 'medium', () => ({ summary: 'New open port 8080/tcp', port: 8080 })],
    ['PortGone', 'low', () => ({ summary: 'Port 21/tcp closed', port: 21 })],
    ['NewService', 'medium', () => ({ summary: 'New service mysql on 3306/tcp', port: 3306 })],
    ['ServiceChanged', 'info', () => ({ summary: 'nginx version changed', port: 443, before: 'nginx 1.22.1', after: 'nginx 1.24.0' })],
    ['TechnologyChanged', 'info', () => ({ summary: 'Technology WordPress detected', port: 80, before: null, after: 'WordPress 6.5' })],
    ['TlsCertificateChanged', 'medium', () => ({ summary: 'TLS certificate replaced', port: 443, before: 'CN=old.example.internal', after: 'CN=portal.example.internal' })],
    ['HttpResponseChanged', 'info', () => ({ summary: 'HTTP title changed', port: 80, before: 'Welcome', after: 'Maintenance' })],
    ['TimeOfDayVariance', 'low', (h) => ({ summary: `${h.address} is only reachable during office hours` })],
  ]
  const changes: Change[] = []
  for (let i = 0; i < 45; i++) {
    const h = pick(hosts)
    const [type, severity, make] = pick(changeTypes)
    changes.push({ id: mockId(8), detectedAt: ago(int(10, 60 * 24 * 6)), scanRunId: pick(runs).id, type, hostId: h.id, zone: h.zone, address: h.address, severity, ...make(h) })
  }
  changes.sort((a, b) => b.detectedAt.localeCompare(a.detectedAt))

  const findingDefs: [string, string, Severity, number, string][] = [
    ['tomcat-manager-panel', 'Apache Tomcat Manager exposed', 'medium', 8080, '/manager/html'],
    ['nginx-version', 'nginx version disclosure', 'info', 80, 'Server: nginx/1.24.0'],
    ['grafana-login', 'Grafana login panel', 'info', 3000, '/login'],
    ['self-signed-cert', 'Self-signed TLS certificate', 'low', 443, 'issuer == subject'],
    ['mysql-exposed', 'MySQL reachable from DMZ', 'high', 3306, 'mysql_native_password'],
    ['expired-cert', 'Expired TLS certificate', 'medium', 443, 'notAfter < now'],
  ]
  const findings: Finding[] = []
  for (let i = 0; i < 16; i++) {
    const h = pick(hosts)
    const [signatureId, name, severity, port, evidence] = pick(findingDefs)
    const status = rand() < 0.8 ? 'Open' : 'Resolved'
    const firstSeenAt = ago(int(60 * 24, 60 * 24 * 20))
    findings.push({
      id: mockId(9),
      signatureId,
      signatureVersion: i % 7 === 3 ? undefined : 1,
      name,
      severity,
      hostId: h.id,
      zone: h.zone,
      address: h.address,
      port,
      matchedUrl: evidence.startsWith('/') ? `http://${h.address}:${port}${evidence}` : undefined,
      evidence,
      status,
      firstSeenAt,
      matchedAt: firstSeenAt,
      lastSeenAt: ago(int(10, 60 * 24)),
      externalRefs: i % 5 === 0 ? [{ system: 'defectdojo', externalId: String(1200 + i) }] : [],
    })
  }

  // ---------- signatures ----------
  const nuclei1 = (id: string, name: string, severity: string, extra = '') => `id: ${id}

info:
  name: ${name}
  author: webscan
  severity: ${severity}
  tags: panel

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
${extra}    matchers:
      - type: word
        words:
          - "${name}"
`
  const sigVersion = (version: number, content: string, approved: boolean, days: number) => ({
    version,
    content,
    sha256: sha(version * 31 + content.length),
    requiresApprovalNote: requiresApprovalNote(content),
    createdAt: ago(60 * 24 * days),
    createdBy: 'manager',
    approvedAt: approved ? ago(60 * 24 * (days - 1)) : undefined,
    approvedBy: approved ? 'admin' : undefined,
  })
  const signatures: SignatureDetail[] = [
    {
      id: 'tomcat-manager-panel',
      name: 'Apache Tomcat Manager exposed',
      kind: 'NucleiTemplate',
      latestVersion: 2,
      approvedVersion: 2,
      status: 'Approved',
      severity: 'medium',
      tags: ['panel', 'tomcat'],
      updatedAt: ago(60 * 24 * 3),
      versions: [
        sigVersion(1, nuclei1('tomcat-manager-panel', 'Tomcat Manager', 'low'), true, 30),
        sigVersion(2, nuclei1('tomcat-manager-panel', 'Tomcat Manager', 'medium'), true, 4),
      ],
    },
    {
      id: 'nginx-version',
      name: 'nginx version disclosure',
      kind: 'NucleiTemplate',
      latestVersion: 1,
      approvedVersion: 1,
      status: 'Approved',
      severity: 'info',
      tags: ['tech', 'nginx'],
      updatedAt: ago(60 * 24 * 20),
      versions: [sigVersion(1, nuclei1('nginx-version', 'nginx', 'info'), true, 21)],
    },
    {
      id: 'grafana-login',
      name: 'Grafana login panel',
      kind: 'NucleiTemplate',
      latestVersion: 1,
      status: 'Draft',
      severity: 'info',
      tags: ['panel', 'grafana'],
      updatedAt: ago(60 * 5),
      versions: [sigVersion(1, nuclei1('grafana-login', 'Grafana', 'info'), false, 0.2)],
    },
    {
      id: 'mysql-exposed',
      name: 'MySQL reachable from DMZ',
      kind: 'NucleiTemplate',
      latestVersion: 1,
      status: 'Draft',
      severity: 'high',
      tags: ['network', 'mysql'],
      updatedAt: ago(60 * 3),
      versions: [sigVersion(1, nuclei1('mysql-exposed', 'MySQL', 'high'), false, 0.1)],
    },
    {
      id: 'windows-server-rdp',
      name: 'Windows server (RDP)',
      kind: 'ClassificationRule',
      latestVersion: 1,
      approvedVersion: 1,
      status: 'Approved',
      tags: ['classification'],
      updatedAt: ago(60 * 24 * 15),
      versions: [
        sigVersion(1, JSON.stringify({ description: 'Hosts exposing RDP are Windows servers', when: { field: 'port', operator: 'Equals', values: ['3389'] }, assign: { classification: 'windows-server' } }, null, 2), true, 16),
      ],
    },
    {
      id: 'ssh-outside-mgmt',
      name: 'SSH outside management zone',
      kind: 'ChangeRule',
      latestVersion: 1,
      status: 'Draft',
      severity: 'medium',
      tags: ['ssh'],
      updatedAt: ago(60 * 24),
      versions: [
        sigVersion(1, JSON.stringify({ description: 'New SSH services outside mgmt', changeTypes: ['NewService'], when: { field: 'service.name', operator: 'Equals', values: ['ssh'] }, severity: 'medium' }, null, 2), false, 1),
      ],
    },
    {
      id: 'weblogic-console',
      name: 'Oracle WebLogic console (legacy)',
      kind: 'NucleiTemplate',
      latestVersion: 1,
      approvedVersion: 1,
      status: 'Retired',
      severity: 'low',
      tags: ['panel', 'legacy'],
      updatedAt: ago(60 * 24 * 40),
      versions: [sigVersion(1, nuclei1('weblogic-console', 'WebLogic', 'low'), true, 90)],
    },
  ]

  const schedules: Schedule[] = [
    {
      id: mockId(10),
      name: 'Nightly DMZ discovery',
      cronExpression: '0 0 2 * * ?',
      timeZone: 'Europe/Warsaw',
      workflowKey: 'standard-discovery',
      networkIds: [networks[0].id],
      priority: 60,
      windowDurationMinutes: 240,
      allowedWindows: [{ daysOfWeek: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'], start: '01:00', end: '05:00' }],
      overlapPolicy: 'Skip',
      enabled: true,
      nextFireAt: ago(-60 * 7),
      lastRunId: runs[0].id,
      lastRunStatus: runs[0].status,
    },
    {
      id: mockId(10),
      name: 'Weekly office sweep',
      cronExpression: '0 0 3 ? * SUN',
      timeZone: 'Europe/Warsaw',
      workflowKey: 'quick-ports',
      workflowVersion: 1,
      networkIds: [networks[1].id, networks[3].id],
      priority: 40,
      maxRatePerSecond: 500,
      allowedWindows: [],
      overlapPolicy: 'Queue',
      enabled: false,
    },
  ]

  const actions = ['network.created', 'network.updated', 'agent.approved', 'tool.approved', 'signature.approved', 'user.created', 'scope_policy.updated', 'schedule.paused']
  const audit: AuditEntry[] = Array.from({ length: 64 }, (_, i) => {
    const action = actions[i % actions.length]
    const u = users[i % 2]
    return {
      id: mockId(11),
      occurredAt: ago(i * 97 + 5),
      userId: u.id,
      userName: u.userName,
      action,
      entityType: action.split('.')[0],
      entityId: String(1000 + i),
      details: { source: 'ui' },
      ipAddress: `10.99.0.${10 + (i % 5)}`,
    }
  })

  // Overlapping private ranges: the lab reuses a DMZ address. A different machine with the same IP — hosts are keyed by (zone, address).
  // Added last and without rand() so the seeded data above stays unchanged.
  const twin = hosts.filter((h) => h.zone === 'dmz').at(-1)!
  const twinId = mockId(4)
  services.push({
    id: mockId(6),
    hostId: twinId,
    zone: 'lab',
    address: twin.address,
    port: 22,
    transport: 'Tcp',
    state: 'Open',
    serviceName: 'ssh',
    product: 'OpenSSH',
    version: '9.6p1',
    technologies: ['OpenSSH'],
    confidence: 0.9,
    firstSeenAt: ago(60 * 24 * 3),
    lastSeenAt: ago(30),
  })
  hostTechnologies[twinId] = [{ name: 'OpenSSH', version: '9.6p1', category: 'remote-access', port: 22, confidence: 0.9, confidenceMethod: 'version-probe' }]
  hosts.push({
    id: twinId,
    address: twin.address,
    hostnames: ['twin.lab.example.internal'],
    status: 'Active',
    unstable: false,
    firstSeenAt: ago(60 * 24 * 3),
    lastSeenAt: ago(30),
    lastScannedAt: ago(30),
    openPortCount: 1,
    technologies: ['OpenSSH'],
    zone: 'lab',
    macAddress: '52:54:00:AB:CD:EF',
    macVendor: 'QEMU virtual NIC',
  })

  // Network devices (server rule: one MAC on hosts of 2+ zones = interfaces of one physical device). Without rand(), like the twin;
  // .1/.251/.252 are outside the generated 2–250 range.
  const nic = (zone: string, address: string, macAddress: string, macVendor?: string, hostnames: string[] = []): MockHost => ({
    id: mockId(4),
    address,
    hostnames,
    status: 'Active',
    unstable: false,
    firstSeenAt: ago(60 * 24 * 20),
    lastSeenAt: ago(15),
    lastScannedAt: ago(15),
    openPortCount: 0,
    technologies: [],
    zone,
    macAddress,
    macVendor,
  })
  const aliased = hosts.find((h) => h.zone === 'office' && h.status === 'Active' && h.macAddress)!
  hosts.push(
    nic('office', '192.168.10.1', '00:1E:BD:4A:10:01', 'Cisco Systems', ['core-rtr.office.example.internal']), // router office ↔ lab (high)
    nic('lab', '172.16.50.1', '00:1E:BD:4A:10:01', 'Cisco Systems'),
    nic('office', '192.168.10.251', '02:42:AC:11:00:02'), // Docker MAC repeated by accident (low)
    nic('lab', '172.16.50.251', '02:42:AC:11:00:02'),
    nic('office', '192.168.10.252', aliased.macAddress!, aliased.macVendor), // second IP of an office host: shared MAC only
  )

  // HTTP fingerprints (headers, cookie flags, recog device, artifacts) of three seeded web services. Without rand(), like the twin.
  const serviceDetails: MockDb['serviceDetails'] = {}
  const artifact = (kind: ServiceArtifact['kind'], name: string, reason: string, tags: string[], severity: 'info' | 'low' = 'info', value?: string): ServiceArtifact => ({
    kind,
    name,
    value,
    reason,
    tags,
    severity,
  })
  const fingerprint = (s: Service | undefined, http: Partial<HttpDetails>, artifacts: ServiceArtifact[], device?: DeviceClassification) => {
    if (!s) return
    const url = s.http?.url ?? `http://${s.address}:${s.port}/`
    serviceDetails[s.id] = {
      http: {
        url,
        scheme: url.split(':')[0],
        statusCode: s.http?.statusCode,
        title: s.http?.title,
        webServer: s.http?.webServer,
        contentType: 'text/html; charset=utf-8',
        headers: {},
        cookies: [],
        redirectChain: [],
        redirectStatusCodes: [],
        ...http,
      },
      artifacts,
      device,
    }
    s.artifactCount = artifacts.length
    s.artifactTags = [...new Set(artifacts.flatMap((a) => a.tags))]
    s.deviceType = device?.type
  }
  const openWeb = (port: number, zone?: string) => services.find((s) => s.port === port && s.state === 'Open' && s.http && (!zone || s.zone === zone))
  fingerprint(
    openWeb(443),
    {
      headers: { server: 'nginx/1.24.0', 'x-powered-by': 'PHP/8.1.27', 'set-cookie': 'PHPSESSID=***; path=/', 'content-type': 'text/html; charset=utf-8' },
      cookies: [{ name: 'PHPSESSID', secure: false, httpOnly: false, path: '/' }],
      pageType: 'login',
      cdn: 'cloudflare',
      cdnType: 'waf',
      faviconHash: '-1010568750',
      faviconMd5: 'f6a1a6e1d5d7b5f2a3c4e9b0d8a7c6b5',
    },
    [
      artifact('header', 'server', 'Discloses the web server version', ['version-leak'], 'info', 'nginx/1.24.0'),
      artifact('header', 'x-powered-by', 'Discloses the application framework', ['tech-hint', 'version-leak'], 'info', 'PHP/8.1.27'),
      artifact('header', 'strict-transport-security', 'HSTS header missing on HTTPS', ['missing-hsts']),
      artifact('cookie', 'PHPSESSID', 'Cookie reveals PHP; Session cookie without Secure and HttpOnly flag', ['tech-hint', 'insecure-cookie'], 'low'),
      artifact('page', 'login', 'Login page (page classification)', ['login-page'], 'info', 'Customer portal'),
    ],
  )
  fingerprint(
    openWeb(8080),
    {
      headers: { server: 'Apache-Coyote/1.1', 'set-cookie': 'JSESSIONID=***; Path=/, BIGipServerpool_app=***; path=/; Httponly', 'x-backend-server': 'app-02 (10.20.30.41)' },
      cookies: [
        { name: 'JSESSIONID', secure: false, httpOnly: false, path: '/' },
        { name: 'BIGipServerpool_app', secure: false, httpOnly: true, path: '/', decodedValue: '10.20.30.41:8080' },
      ],
    },
    [
      artifact('header', 'x-backend-server', 'Discloses the backend server behind the proxy; Discloses internal address 10.20.30.41', ['tech-hint', 'internal-ip-leak'], 'low', 'app-02 (10.20.30.41)'),
      artifact('cookie', 'JSESSIONID', 'Cookie reveals Java servlet container; Session cookie without HttpOnly flag', ['tech-hint', 'insecure-cookie'], 'low'),
      artifact('cookie', 'BIGipServerpool_app', 'Cookie reveals F5 BIG-IP load balancer; Load balancer cookie discloses internal pool member 10.20.30.41:8080', ['tech-hint', 'internal-ip-leak'], 'low', '10.20.30.41:8080'),
    ],
  )
  const camera = openWeb(80, 'lab')
  if (camera) {
    camera.http = { url: `http://${camera.address}:80/`, statusCode: 200, title: 'Login', webServer: 'App-webs/' }
    fingerprint(
      camera,
      {
        headers: { server: 'App-webs/', 'x-frame-options': 'SAMEORIGIN' },
        redirectChain: [`http://${camera.address}:80/`, `http://${camera.address}/doc/page/login.asp`],
        redirectStatusCodes: [302, 200],
        finalUrl: `http://${camera.address}/doc/page/login.asp`,
        pageType: 'login',
        faviconHash: '999357577',
        faviconMd5: '89b932fcc47cf4ca3faadb0cfdef89cf',
      },
      [
        artifact('favicon', 'favicon', 'Favicon of Hikvision IP Camera', ['tech-hint'], 'info', '89b932fcc47cf4ca3faadb0cfdef89cf'),
        artifact('page', 'login', 'Login page (page classification)', ['login-page'], 'info', 'Login'),
      ],
      { type: 'IP Camera', vendor: 'Hikvision', product: 'DS-2CD2143G0-I' },
    )
    hostTechnologies[camera.hostId] = [
      ...(hostTechnologies[camera.hostId] ?? []),
      { name: 'Hikvision DS-2CD2143G0-I', category: 'device', port: 80, confidence: 0.5, confidenceMethod: 'recog' },
    ]
  }

  return {
    users,
    zones,
    networks,
    scopePolicy: { allowed: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'], excluded: ['10.255.0.0/16'], updatedAt: ago(60 * 24 * 30) },
    agents,
    agentSubnets: agentSubnets(),
    tools,
    tokens,
    workflows,
    schedules,
    runs,
    jobs,
    events,
    hosts,
    services,
    hostTechnologies,
    certificates,
    serviceDetails,
    changes,
    findings,
    signatures,
    settings: {
      'Planner:AllowDefaultRoute': 'false',
      'Tools:AutoApprove': 'nmap,naabu,httpx,nuclei',
      'Discovery:MissingThreshold': '3',
      'Retention:ObservationDays': '180',
    },
    scanLimits: {
      defaultBatchSize: 256,
      leaseDurationSeconds: 120,
      maxAttempts: 3,
      maxConcurrentJobsPerZone: 20,
      maxConcurrentJobsPerInterface: 4,
      maxConcurrentJobsPerSubnet: 2,
      subnetPrefixLength: 16,
      maxRatePerSecondGlobal: 20000,
      unassignedJobTimeoutSeconds: 900,
    },
    audit,
    defectDojo: {
      enabled: false,
      baseUrl: 'https://defectdojo.example.internal',
      hasApiKey: false,
      productId: 3,
      engagementId: 12,
      minimumSeverity: 'medium',
      verifyTls: true,
    },
  }
}
