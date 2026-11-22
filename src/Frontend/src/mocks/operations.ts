// TS copy of Contracts/Operations.cs → OperationCatalog (served by the mock GET /api/operations).
import type { OperationDescriptor, ParameterDescriptor } from '@/api/types'

const portSpecHelp = 'e.g. 80,443,8000-8100 or top-100 / top-1000'
const rate: ParameterDescriptor = {
  name: 'rate',
  type: 'Integer',
  min: 1,
  max: 100_000,
  default: '500',
  description: 'Max packets/requests per second for this job (further capped by agent and global limits).',
}
const retries: ParameterDescriptor = { name: 'retries', type: 'Integer', min: 0, max: 5, default: '1' }
const severities = ['info', 'low', 'medium', 'high', 'critical']

export const OPERATIONS: OperationDescriptor[] = [
  {
    operation: 'DiscoverHosts',
    plane: 'Agent',
    requiredCapability: 'host-discovery',
    inputKind: 'Hosts',
    parameters: [
      {
        name: 'method',
        type: 'Enum',
        allowedValues: ['default', 'icmp', 'tcp-syn', 'tcp-ack', 'arp', 'none'],
        default: 'default',
        privilegedValues: ['icmp', 'tcp-ack', 'arp'],
        description:
          'Probe technique: default/tcp-syn = TCP SYN ping to probePorts, tcp-ack = TCP ACK ping to probePorts, icmp = ICMP echo only, arp = ARP only (same L2 segment), none = treat every target as up (useful behind ICMP filtering). icmp, tcp-ack and arp need raw sockets.',
      },
      {
        name: 'probePorts',
        type: 'PortSpec',
        default: '22,80,443,3389,8080',
        pattern: '^[0-9][0-9,-]*$',
        description: 'Ports used by the TCP ping methods (default, tcp-syn, tcp-ack), e.g. 22,80,443 or 8000-8100 (no top-N).',
      },
      rate,
      retries,
    ],
  },
  {
    operation: 'ScanPorts',
    plane: 'Agent',
    requiredCapability: 'port-scan',
    inputKind: 'Hosts',
    parameters: [
      { name: 'ports', type: 'PortSpec', default: 'top-100', required: true, description: portSpecHelp },
      {
        name: 'scanType',
        type: 'Enum',
        allowedValues: ['connect', 'syn'],
        default: 'connect',
        privilegedValues: ['syn'],
        description: 'connect = full TCP handshake (no privileges); syn = half-open scan, needs raw sockets.',
      },
      rate,
      retries,
    ],
  },
  {
    operation: 'DetectService',
    plane: 'Agent',
    requiredCapability: 'service-detection',
    inputKind: 'Endpoints',
    parameters: [
      { name: 'versionIntensity', type: 'Integer', min: 0, max: 9, default: '5' },
      { name: 'grabBanner', type: 'Boolean', default: 'true' },
      rate,
    ],
  },
  {
    operation: 'HttpProbe',
    plane: 'Agent',
    requiredCapability: 'http-probe',
    inputKind: 'Endpoints',
    parameters: [
      { name: 'followRedirects', type: 'Boolean', default: 'true' },
      { name: 'maxRedirects', type: 'Integer', min: 0, max: 10, default: '3' },
      { name: 'techDetect', type: 'Boolean', default: 'true' },
      { name: 'faviconHash', type: 'Boolean', default: 'true' },
      { name: 'paths', type: 'StringList', default: '/', pattern: '^/[A-Za-z0-9._~/-]{0,200}$', description: 'Relative paths to request on every endpoint.' },
      rate,
    ],
  },
  { operation: 'TlsProbe', plane: 'Agent', requiredCapability: 'tls-probe', inputKind: 'Endpoints', parameters: [rate] },
  {
    operation: 'ExecuteSignatures',
    plane: 'Agent',
    requiredCapability: 'signature-scan',
    inputKind: 'Endpoints',
    parameters: [
      {
        name: 'signatureTags',
        type: 'StringList',
        pattern: '^[a-z0-9_-]{1,40}$',
        description: 'Only approved signatures carrying one of these tags. Empty = all approved active signatures.',
      },
      { name: 'signatureIds', type: 'StringList', pattern: '^[A-Za-z0-9_.-]{1,100}$' },
      { name: 'severities', type: 'StringList', allowedValues: severities, default: 'info,low' },
      rate,
    ],
  },
  {
    // Targets are computed server-side from the previous asset state; jobs run as DiscoverHosts / ScanPorts.
    operation: 'RecheckMissing',
    plane: 'Agent',
    requiredCapability: 'port-scan',
    inputKind: 'None',
    parameters: [
      { name: 'attempts', type: 'Integer', min: 1, max: 5, default: '2', description: 'Re-check rounds; each round probes only what is still missing.' },
      {
        name: 'delaySeconds',
        type: 'Integer',
        min: 0,
        max: 3600,
        default: '30',
        description: 'Wait between rounds (lets briefly unreachable hosts come back).',
      },
      rate,
    ],
  },
  { operation: 'EvaluateCondition', plane: 'Server', inputKind: 'None', parameters: [] },
  { operation: 'PersistObservations', plane: 'Server', inputKind: 'None', parameters: [] },
  {
    operation: 'ComparePreviousScan',
    plane: 'Server',
    inputKind: 'None',
    parameters: [
      {
        name: 'missingThreshold',
        type: 'Integer',
        min: 1,
        max: 20,
        default: '3',
        description: 'Consecutive complete scans without the service before it is reported as gone.',
      },
    ],
  },
  {
    operation: 'PublishFinding',
    plane: 'Server',
    inputKind: 'None',
    parameters: [
      { name: 'destination', type: 'Enum', allowedValues: ['internal', 'defectdojo'], default: 'internal' },
      { name: 'minSeverity', type: 'Enum', allowedValues: severities, default: 'medium' },
    ],
  },
]
