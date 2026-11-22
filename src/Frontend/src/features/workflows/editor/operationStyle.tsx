import { Database, Diff, FingerprintPattern, Globe, Lock, Network, Radar, RefreshCw, Send, ShieldCheck, Split, type LucideIcon } from 'lucide-react'
import type { OperationPlane, ScanOperation } from '@/api/types'
import { cn } from '@/lib/utils'

const ICONS: Record<ScanOperation, LucideIcon> = {
  DiscoverHosts: Radar,
  ScanPorts: Network,
  DetectService: FingerprintPattern,
  HttpProbe: Globe,
  TlsProbe: Lock,
  ExecuteSignatures: ShieldCheck,
  EvaluateCondition: Split,
  PersistObservations: Database,
  ComparePreviousScan: Diff,
  PublishFinding: Send,
  RecheckMissing: RefreshCw,
}

/** Agent-plane (network traffic via scanner agents) vs server-plane operations. */
export const planeAccent = (plane?: OperationPlane) => (plane === 'Server' ? 'border-l-flow-decision' : 'border-l-node-host')

export function OperationIcon({ operation, plane, className }: { operation: ScanOperation; plane?: OperationPlane; className?: string }) {
  const Icon = ICONS[operation] ?? Network
  return (
    <span
      aria-hidden
      className={cn(
        'inline-flex size-7 shrink-0 items-center justify-center rounded-md text-white',
        plane === 'Server' ? 'bg-flow-decision' : 'bg-node-host',
        className,
      )}
    >
      <Icon className="size-4" />
    </span>
  )
}
