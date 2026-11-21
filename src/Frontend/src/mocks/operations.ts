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
        description: "Probe technique. 'none' treats every target as up (useful behind ICMP filtering).",
      },
      { name: 'probePorts', type: 'PortSpec', default: '22,80,443,3389,8080', description: `Ports used for TCP discovery probes. ${portSpecHelp}` },
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
      { name: 'scanType', type: 'Enum', allowedValues: ['connect', 'syn'], default: 'connect' },
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
