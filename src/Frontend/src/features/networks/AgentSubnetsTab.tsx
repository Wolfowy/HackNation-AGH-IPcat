// Agent subnets: the networks the connected agents sit in (or route to), proposed as scan networks — "scan wide with the agents we have".
import { useState } from 'react'
import { toast } from 'sonner'
import { useAgentSubnets, useCreateNetworks, useScopePolicy, useUpdateScopePolicy } from '@/api/networks'
import type { AgentSubnet, NetworkInput } from '@/api/types'
import { useCan } from '@/auth/AuthProvider'
import { ConfirmButton } from '@/components/actions'
import { EmptyState, Loadable } from '@/components/feedback'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { NativeSelect } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatNumber } from '@/lib/format'

export const subnetKey = (s: AgentSubnet) => `${s.source}|${s.cidr}|${s.candidateZones.join(',')}`

/** Preselected: attached directly, inside the policy, not covered yet, not the agents' link to the server, not huge. */
export const isRecommended = (s: AgentSubnet) => s.source === 'interface' && s.proposedRanges.length > 0 && !s.management && !s.large

function networkInput(s: AgentSubnet, zone: string): NetworkInput {
  const seen = s.seenBy.map((v) => `${v.agentId}/${v.interfaceName}`).join(', ')
  return {
    name: `${zone} ${s.cidr}`,
    zone,
    ranges: s.proposedRanges,
    exclusions: [],
    tags: ['agent-subnet'],
    description: `${s.source === 'route' ? 'Routed' : 'Attached'} subnet of ${seen}`.slice(0, 1000),
    enabled: true,
  }
}

function SubnetTable({ subnets }: { subnets: AgentSubnet[] }) {
  const canManage = useCan('manage')
  const isAdmin = useCan('admin')
  const policy = useScopePolicy()
  const updatePolicy = useUpdateScopePolicy()
  const create = useCreateNetworks()
  const [selected, setSelected] = useState(() => new Set(subnets.filter((s) => isRecommended(s) && s.zone).map(subnetKey)))
  const [zones, setZones] = useState<Record<string, string>>({})

  const zoneOf = (s: AgentSubnet) => s.zone ?? zones[subnetKey(s)]
  const selectable = (s: AgentSubnet) => s.proposedRanges.length > 0 && !!zoneOf(s)
  const chosen = subnets.filter((s) => selected.has(subnetKey(s)) && selectable(s))
  const toggle = (s: AgentSubnet, on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (on) next.add(subnetKey(s))
      else next.delete(subnetKey(s))
      return next
    })

  const addToPolicy = (s: AgentSubnet) =>
    policy.data && updatePolicy.mutateAsync({ allowed: [...policy.data.allowed, s.cidr], excluded: policy.data.excluded })

  const createSelected = () =>
    create.mutate(
      chosen.map((s) => networkInput(s, zoneOf(s)!)),
      {
        onSuccess: ({ created, errors }) => {
          if (created) toast.success(t.networks.agentSubnets.created(created))
          if (errors.length) toast.error(errors.join('\n'))
          setSelected(new Set())
        },
      },
    )

  return (
    <div className="grid gap-3">
      <Table>
        <TableHeader>
          <TableRow>
            {canManage && <TableHead className="w-8" />}
            <TableHead>Subnet</TableHead>
            <TableHead>Zone</TableHead>
            <TableHead>Seen by</TableHead>
            <TableHead>Addresses</TableHead>
            <TableHead>Scope policy</TableHead>
            <TableHead>Network to create</TableHead>
            {isAdmin && <TableHead />}
          </TableRow>
        </TableHeader>
        <TableBody>
          {subnets.map((s) => {
            const key = subnetKey(s)
            return (
              <TableRow key={key}>
                {canManage && (
                  <TableCell>
                    <input
                      type="checkbox"
                      className="accent-primary size-4"
                      aria-label={`Select ${s.cidr}`}
                      disabled={!selectable(s)}
                      checked={selected.has(key) && selectable(s)}
                      onChange={(e) => toggle(s, e.target.checked)}
                    />
                  </TableCell>
                )}
                <TableCell>
                  <div className="font-mono text-xs">{s.cidr}</div>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {s.source === 'route' && <Badge variant="secondary">via gateway</Badge>}
                    {s.management && (
                      <Badge variant="warning" title="The agent reaches the server through this subnet">
                        server link
                      </Badge>
                    )}
                    {s.large && <Badge variant="warning">large</Badge>}
                  </div>
                </TableCell>
                <TableCell>
                  {s.zone ? (
                    <Badge variant="outline">{s.zone}</Badge>
                  ) : (
                    <NativeSelect
                      aria-label={`Zone for ${s.cidr}`}
                      className="h-8 w-32"
                      value={zones[key] ?? ''}
                      disabled={!canManage}
                      onChange={(e) => setZones((z) => ({ ...z, [key]: e.target.value }))}
                    >
                      <option value="">Choose…</option>
                      {s.candidateZones.map((z) => (
                        <option key={z}>{z}</option>
                      ))}
                    </NativeSelect>
                  )}
                </TableCell>
                <TableCell className="text-xs">
                  {s.seenBy.map((v) => (
                    <div key={`${v.agentId}/${v.interfaceName}/${v.address}`} className={v.online ? undefined : 'text-muted-foreground'}>
                      {v.agentId} · {v.interfaceName} <span className="text-muted-foreground font-mono">{v.gateway ? `via ${v.gateway}` : v.address}</span>
                      {!v.online && ' (offline)'}
                    </div>
                  ))}
                </TableCell>
                <TableCell className="tabular-nums">{formatNumber(s.addressCount)}</TableCell>
                <TableCell>
                  {s.scope === 'full' ? (
                    <Badge variant="success">inside</Badge>
                  ) : s.scope === 'partial' ? (
                    <Badge variant="warning">partly inside</Badge>
                  ) : (
                    <Badge variant="outline">outside</Badge>
                  )}
                </TableCell>
                <TableCell className="text-xs">
                  {s.proposedRanges.length > 0 ? (
                    <span className="font-mono">{s.proposedRanges.join(', ')}</span>
                  ) : s.existingNetworks.length > 0 && s.scope !== 'none' ? (
                    <span className="text-muted-foreground">covered by {s.existingNetworks.join(', ')}</span>
                  ) : (
                    <span className="text-muted-foreground">nothing inside the scope policy</span>
                  )}
                  {s.proposedRanges.length > 0 && s.existingNetworks.length > 0 && (
                    <div className="text-muted-foreground">rest is in {s.existingNetworks.join(', ')}</div>
                  )}
                </TableCell>
                {isAdmin && (
                  <TableCell className="text-right">
                    {s.scope !== 'full' && (
                      <ConfirmButton
                        size="sm"
                        variant="outline"
                        destructive={false}
                        title={`Allow scanning ${s.cidr}?`}
                        description={t.networks.agentSubnets.policyWarning(s.cidr, s.addressCount)}
                        confirmLabel="Add to scope policy"
                        disabled={!policy.data}
                        onConfirm={() => addToPolicy(s)}
                      >
                        Add to scope policy
                      </ConfirmButton>
                    )}
                  </TableCell>
                )}
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
      {canManage && (
        <div className="flex items-center gap-3">
          <Button disabled={chosen.length === 0 || create.isPending} onClick={createSelected}>
            {t.networks.agentSubnets.create(chosen.length)}
          </Button>
          <span className="text-muted-foreground text-xs">Networks get the tag “agent-subnet”; start a scan on them as on any network.</span>
        </div>
      )}
    </div>
  )
}

export function AgentSubnetsTab() {
  const subnets = useAgentSubnets()
  return (
    <div className="grid gap-3">
      <p className="text-muted-foreground text-sm">{t.networks.agentSubnets.intro}</p>
      <Loadable query={subnets}>
        {(list) => (list.length === 0 ? <EmptyState>{t.networks.agentSubnets.empty}</EmptyState> : <SubnetTable subnets={list} />)}
      </Loadable>
    </div>
  )
}
