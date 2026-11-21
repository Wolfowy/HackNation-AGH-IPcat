import { Database, Diff, FingerprintPattern, Globe, Lock, Network, Radar, Send, ShieldCheck, Split, type LucideIcon } from 'lucide-react'
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
}

/** Agent-plane (network traffic via scanner agents) vs server-plane operations. */
export const planeAccent = (plane?: OperationPlane) => (plane === 'Server' ? 'border-l-violet-500' : 'border-l-sky-500')

export function OperationIcon({ operation, plane, className }: { operation: ScanOperation; plane?: OperationPlane; className?: string }) {
  const Icon = ICONS[operation] ?? Network
  return (
    <span
      aria-hidden
      className={cn(
        'inline-flex size-7 shrink-0 items-center justify-center rounded-md',
        plane === 'Server' ? 'bg-violet-500/15 text-violet-700 dark:text-violet-300' : 'bg-sky-500/15 text-sky-700 dark:text-sky-300',
        className,
      )}
    >
      <Icon className="size-4" />
    </span>
  )
}
