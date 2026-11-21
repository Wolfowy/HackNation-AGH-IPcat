import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { toast } from 'sonner'
import { useAgent, useDeleteAgent, useRotateAgentCredentials, useSetAgentStatus, useUpdateAgentAssignment } from '@/api/agents'
import { useNetworks, useZones } from '@/api/networks'
import type { Agent, AgentStatus } from '@/api/types'
import { useCan } from '@/auth/AuthProvider'
import { ConfirmButton } from '@/components/actions'
import { EmptyState, Loadable } from '@/components/feedback'
import { CheckboxList, FormField } from '@/components/form'
import { Chips, KeyValues, PageHeader, StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDateTime, formatRelative, optionalNumber } from '@/lib/format'
import { OnlineDot } from './AgentsPage'

function AssignmentDialog({ agent, open, onOpenChange }: { agent: Agent; open: boolean; onOpenChange: (v: boolean) => void }) {
  const zones = useZones()
  const networks = useNetworks()
  const update = useUpdateAgentAssignment()
  const [authorizedZones, setZones] = useState(agent.authorizedZones)
  const [authorizedNetworkIds, setNetworks] = useState(agent.authorizedNetworkIds)
  const [maxJobs, setMaxJobs] = useState(String(agent.limitOverrides?.maxConcurrentJobs ?? ''))
  const [maxRate, setMaxRate] = useState(String(agent.limitOverrides?.maxRatePerSecond ?? ''))

  const save = async () => {
    await update.mutateAsync({
      agentId: agent.agentId,
      authorizedZones,
      authorizedNetworkIds,
      maxConcurrentJobs: optionalNumber(maxJobs),
      maxRatePerSecond: optionalNumber(maxRate),
    })
    toast.success(t.common.saved)
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t.agents.assignment}</DialogTitle>
        </DialogHeader>
        <CheckboxList
          legend="Authorized zones"
          options={(zones.data ?? []).map((z) => ({ value: z.name, label: z.name }))}
          value={authorizedZones}
          onChange={setZones}
        />
        <CheckboxList
          legend="Restrict to networks (empty = all networks in authorized zones)"
          options={(networks.data ?? []).map((n) => ({ value: n.id, label: `${n.name} (${n.zone})` }))}
          value={authorizedNetworkIds}
          onChange={setNetworks}
        />
        <div className="grid grid-cols-2 gap-4">
          <FormField label="Max concurrent jobs">
            <Input type="number" min={1} value={maxJobs} onChange={(e) => setMaxJobs(e.target.value)} />
          </FormField>
          <FormField label="Max rate (pps)">
            <Input type="number" min={1} value={maxRate} onChange={(e) => setMaxRate(e.target.value)} />
          </FormField>
        </div>
        <DialogFooter>
          <Button onClick={save} disabled={update.isPending}>
            {t.common.save}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

const STATUS_ACTIONS: { status: AgentStatus; label: string }[] = [
  { status: 'Active', label: 'Activate' },
  { status: 'Disabled', label: 'Disable' },
  { status: 'Blocked', label: 'Block' },
]

function AgentActions({ agent }: { agent: Agent }) {
  const setStatus = useSetAgentStatus()
  const rotate = useRotateAgentCredentials()
  const remove = useDeleteAgent()
  const navigate = useNavigate()
  const [assignOpen, setAssignOpen] = useState(false)
  return (
    <>
      {STATUS_ACTIONS.filter((a) => a.status !== agent.status).map((a) =>
        a.status === 'Active' ? (
          <Button key={a.status} size="sm" onClick={() => setStatus.mutate({ agentId: agent.agentId, status: a.status })}>
            {a.label}
          </Button>
        ) : (
          <ConfirmButton
            key={a.status}
            size="sm"
            variant="outline"
            title={`${a.label} agent ${agent.hostname}?`}
            description={a.status === 'Blocked' ? 'Blocked agents fail authentication immediately.' : 'The agent stops receiving jobs.'}
            confirmLabel={a.label}
            onConfirm={() => setStatus.mutateAsync({ agentId: agent.agentId, status: a.status })}
          >
            {a.label}
          </ConfirmButton>
        ),
      )}
      <Button size="sm" variant="outline" onClick={() => setAssignOpen(true)}>
        {t.agents.assignment}
      </Button>
      <ConfirmButton
        size="sm"
        variant="outline"
        destructive={false}
        title={`${t.agents.rotate}?`}
        description="The agent receives a new secret on its next heartbeat; the old one stays valid for a grace period."
        onConfirm={async () => {
          await rotate.mutateAsync(agent.agentId)
          toast.success(t.agents.rotated)
        }}
      >
        {t.agents.rotate}
      </ConfirmButton>
      <ConfirmButton
        size="sm"
        variant="destructive"
        title={t.common.confirmDelete(`agent ${agent.hostname}`)}
        confirmLabel={t.common.delete}
        onConfirm={async () => {
          await remove.mutateAsync(agent.agentId)
          navigate('/agents')
        }}
      >
        {t.common.delete}
      </ConfirmButton>
      {assignOpen && <AssignmentDialog agent={agent} open={assignOpen} onOpenChange={setAssignOpen} />}
    </>
  )
}

export function AgentDetailPage() {
  const { agentId = '' } = useParams()
  const agent = useAgent(agentId)
  const isAdmin = useCan('admin')
  const networks = useNetworks()
  const networkName = (id: string) => networks.data?.find((n) => n.id === id)?.name ?? id

  return (
    <Loadable query={agent}>
      {(a) => (
        <>
          <PageHeader
            title={
              <span className="flex items-center gap-3">
                {a.hostname} <StatusBadge status={a.status} />
              </span>
            }
            description={
              <>
                <Link to="/agents" className="hover:underline">
                  {t.agents.title}
                </Link>{' '}
                / {a.agentId}
              </>
            }
            actions={isAdmin && <AgentActions agent={a} />}
          />
          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Overview</CardTitle>
              </CardHeader>
              <CardContent>
                <KeyValues
                  items={[
                    ['Connectivity', <OnlineDot online={a.isOnline} />],
                    ['Last heartbeat', `${formatDateTime(a.lastHeartbeatAt)} (${formatRelative(a.lastHeartbeatAt)})`],
                    ['Registered', formatDateTime(a.registeredAt)],
                    ['Agent version', a.agentVersion],
                    ['OS', `${a.osPlatform} — ${a.osDescription}`],
                    ['Declared zones', <Chips values={a.declaredZones} />],
                    ['Authorized zones', <Chips values={a.authorizedZones} />],
                    ['Authorized networks', a.authorizedNetworkIds.length ? <Chips values={a.authorizedNetworkIds.map(networkName)} /> : 'All in zones'],
                  ]}
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Limits & load</CardTitle>
              </CardHeader>
              <CardContent>
                <KeyValues
                  items={[
                    ['Max concurrent jobs', a.limits.maxConcurrentJobs],
                    ['Max rate', `${a.limits.maxRatePerSecond} pps`],
                    ['Running jobs', a.load?.runningJobs ?? '—'],
                    ['CPU', a.load ? `${Math.round(a.load.cpuPercent)}%` : '—'],
                    ['Memory used', a.load ? `${a.load.memoryUsedMb} MB` : '—'],
                    ['Buffered result batches', a.load?.bufferedBatches ?? '—'],
                  ]}
                />
              </CardContent>
            </Card>
          </div>

          <h2 className="mt-6 mb-2 text-lg font-semibold">Tools</h2>
          {a.tools.length === 0 ? (
            <EmptyState />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tool</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Capabilities</TableHead>
                  <TableHead>Approval</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {a.tools.map((tool) => (
                  <TableRow key={tool.id}>
                    <TableCell className="font-mono">{tool.id}</TableCell>
                    <TableCell>{tool.version}</TableCell>
                    <TableCell>
                      <Chips values={tool.capabilities} />
                    </TableCell>
                    <TableCell>
                      <Badge variant={tool.approved ? 'success' : 'warning'}>{tool.approved ? 'Approved' : 'Awaiting approval'}</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          <h2 className="mt-6 mb-2 text-lg font-semibold">Interfaces</h2>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Addresses</TableHead>
                <TableHead>MAC</TableHead>
                <TableHead>Speed</TableHead>
                <TableHead>Running jobs</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {a.interfaces.map((i) => (
                <TableRow key={i.name}>
                  <TableCell className="font-mono">
                    {i.name}
                    {i.description && <div className="text-muted-foreground font-sans text-xs">{i.description}</div>}
                  </TableCell>
                  <TableCell>{i.isUp ? <Badge variant="success">Up</Badge> : <Badge variant="outline">Down</Badge>}</TableCell>
                  <TableCell className="font-mono text-xs">{i.addresses.join(', ')}</TableCell>
                  <TableCell className="font-mono text-xs">{i.macAddress ?? '—'}</TableCell>
                  <TableCell>{i.speedMbps ? `${i.speedMbps} Mbit/s` : '—'}</TableCell>
                  <TableCell>{a.load?.runningJobsPerInterface?.[i.name] ?? 0}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          <h2 className="mt-6 mb-2 text-lg font-semibold">Routes</h2>
          {a.routes.length === 0 ? (
            <EmptyState />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Destination</TableHead>
                  <TableHead>Gateway</TableHead>
                  <TableHead>Interface</TableHead>
                  <TableHead>Metric</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {a.routes.map((r, idx) => (
                  <TableRow key={idx}>
                    <TableCell className="font-mono">{r.destination}</TableCell>
                    <TableCell className="font-mono">{r.gateway ?? '—'}</TableCell>
                    <TableCell className="font-mono">{r.interfaceName}</TableCell>
                    <TableCell>{r.metric}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </>
      )}
    </Loadable>
  )
}
