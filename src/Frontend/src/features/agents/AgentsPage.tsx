import { useState } from 'react'
import { Link } from 'react-router'
import { useForm } from 'react-hook-form'
import { KeyRound } from 'lucide-react'
import { toast } from 'sonner'
import {
  useAgents,
  useCreateEnrollmentToken,
  useEnrollmentTokens,
  useRevokeEnrollmentToken,
  useTools,
  useUpdateTool,
} from '@/api/agents'
import { useZones } from '@/api/networks'
import type { EnrollmentTokenCreated } from '@/api/types'
import { useCan } from '@/auth/AuthProvider'
import { ConfirmButton, CopyButton } from '@/components/actions'
import { EmptyState, Loadable } from '@/components/feedback'
import { CheckboxField, CheckboxList, FormField, submitHandler } from '@/components/form'
import { Chips, PageHeader, StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { t } from '@/i18n/strings'
import { formatDateTime, formatRelative } from '@/lib/format'

export function OnlineDot({ online }: { online: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span className={`size-2 rounded-full ${online ? 'bg-success' : 'bg-muted-foreground/40'}`} />
      {online ? 'Online' : 'Offline'}
    </span>
  )
}

function AgentsTable() {
  const agents = useAgents()
  return (
    <Loadable query={agents}>
      {(list) =>
        list.length === 0 ? (
          <EmptyState>No agents registered yet. Create an enrollment token to add one.</EmptyState>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Agent</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Connectivity</TableHead>
                <TableHead>Last heartbeat</TableHead>
                <TableHead>Load</TableHead>
                <TableHead>Tools</TableHead>
                <TableHead>Zones</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((a) => (
                <TableRow key={a.agentId}>
                  <TableCell>
                    <Link to={`/agents/${encodeURIComponent(a.agentId)}`} className="font-medium hover:underline">
                      {a.hostname}
                    </Link>
                    <div className="text-muted-foreground text-xs">
                      {a.agentId} · v{a.agentVersion}
                    </div>
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={a.status} />
                  </TableCell>
                  <TableCell>
                    <OnlineDot online={a.isOnline} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">{formatRelative(a.lastHeartbeatAt)}</TableCell>
                  <TableCell className="text-sm whitespace-nowrap">
                    {a.load ? (
                      <>
                        {a.load.runningJobs}/{a.limits.maxConcurrentJobs} jobs · CPU {Math.round(a.load.cpuPercent)}%
                      </>
                    ) : (
                      '—'
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {a.tools.map((tool) => (
                        <Badge key={tool.id} variant={tool.approved ? 'outline' : 'warning'} title={tool.capabilities.join(', ')}>
                          {tool.id} {tool.version}
                          {!tool.approved && ' (unapproved)'}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Chips values={a.authorizedZones} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )
      }
    </Loadable>
  )
}

interface TokenForm {
  name: string
  expiresInHours: number
  maxUses: number
  autoApprove: boolean
  zones: string[]
}

function CreateTokenDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const zones = useZones()
  const create = useCreateEnrollmentToken()
  const [created, setCreated] = useState<EnrollmentTokenCreated | null>(null)
  const form = useForm<TokenForm>({ defaultValues: { name: '', expiresInHours: 24, maxUses: 1, autoApprove: false, zones: [] } })
  const { register, formState, watch, setValue, reset } = form

  const close = (next: boolean) => {
    if (!next) {
      setCreated(null)
      reset()
    }
    onOpenChange(next)
  }

  const submit = submitHandler(form, async (values) => {
    setCreated(await create.mutateAsync({ ...values, expiresInHours: Number(values.expiresInHours), maxUses: Number(values.maxUses) }))
  })

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{created ? t.agents.tokenCreated : t.agents.newToken}</DialogTitle>
          {created && <DialogDescription>{t.agents.tokenOnce}</DialogDescription>}
        </DialogHeader>
        {created ? (
          <div className="grid gap-3">
            <code className="bg-muted rounded-md p-3 font-mono text-sm break-all" data-testid="enrollment-token">
              {created.token}
            </code>
            <p className="text-muted-foreground text-sm">Expires {formatDateTime(created.expiresAt)}</p>
            <DialogFooter>
              <CopyButton value={created.token} label="Copy token" />
              <Button onClick={() => close(false)}>{t.common.close}</Button>
            </DialogFooter>
          </div>
        ) : (
          <form className="grid gap-4" onSubmit={submit}>
            <FormField label="Name" error={formState.errors.name?.message}>
              <Input {...register('name', { required: 'Name is required.' })} />
            </FormField>
            <div className="grid grid-cols-2 gap-4">
              <FormField label="Expires in (hours)" error={formState.errors.expiresInHours?.message}>
                <Input type="number" min={1} max={8760} {...register('expiresInHours', { required: true, min: { value: 1, message: 'Min 1' } })} />
              </FormField>
              <FormField label="Max uses" error={formState.errors.maxUses?.message}>
                <Input type="number" min={1} max={1000} {...register('maxUses', { required: true, min: { value: 1, message: 'Min 1' } })} />
              </FormField>
            </div>
            <CheckboxField label="Auto-approve agents enrolled with this token" checked={watch('autoApprove')} onChange={(v) => setValue('autoApprove', v)} />
            <CheckboxList
              legend="Authorized zones"
              options={(zones.data ?? []).map((z) => ({ value: z.name, label: z.name }))}
              value={watch('zones')}
              onChange={(v) => setValue('zones', v)}
              error={formState.errors.zones?.message}
            />
            <DialogFooter>
              <Button type="submit" disabled={create.isPending}>
                {t.common.create}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

function EnrollmentTokens() {
  const tokens = useEnrollmentTokens()
  const revoke = useRevokeEnrollmentToken()
  const [open, setOpen] = useState(false)
  return (
    <>
      <div className="mb-3 flex justify-end">
        <Button onClick={() => setOpen(true)}>
          <KeyRound /> {t.agents.newToken}
        </Button>
      </div>
      <CreateTokenDialog open={open} onOpenChange={setOpen} />
      <Loadable query={tokens}>
        {(list) =>
          list.length === 0 ? (
            <EmptyState />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Uses</TableHead>
                  <TableHead>Auto-approve</TableHead>
                  <TableHead>Zones</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((tok) => (
                  <TableRow key={tok.id}>
                    <TableCell className="font-medium">
                      {tok.name}
                      {tok.revoked && (
                        <Badge variant="destructive" className="ml-2">
                          Revoked
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>{formatDateTime(tok.expiresAt)}</TableCell>
                    <TableCell>
                      {tok.uses}/{tok.maxUses}
                    </TableCell>
                    <TableCell>{tok.autoApprove ? t.common.yes : t.common.no}</TableCell>
                    <TableCell>
                      <Chips values={tok.zones} />
                    </TableCell>
                    <TableCell className="text-right">
                      {!tok.revoked && (
                        <ConfirmButton
                          variant="outline"
                          size="sm"
                          title={`Revoke token "${tok.name}"?`}
                          description="Agents can no longer enroll with it. Already enrolled agents are not affected."
                          confirmLabel={t.agents.revoke}
                          onConfirm={() => revoke.mutateAsync(tok.id)}
                        >
                          {t.agents.revoke}
                        </ConfirmButton>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )
        }
      </Loadable>
    </>
  )
}

function ToolsCatalog() {
  const tools = useTools()
  const update = useUpdateTool()
  const isAdmin = useCan('admin')
  const save = (toolId: string, approved: boolean, enabled: boolean) =>
    update.mutate({ toolId, approved, enabled }, { onSuccess: () => toast.success(`${toolId} updated`) })
  return (
    <Loadable query={tools}>
      {(list) =>
        list.length === 0 ? (
          <EmptyState>No tools reported by agents yet.</EmptyState>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Tool</TableHead>
                <TableHead>Capabilities</TableHead>
                <TableHead>Versions</TableHead>
                <TableHead>Agents</TableHead>
                <TableHead>First seen</TableHead>
                <TableHead>State</TableHead>
                {isAdmin && <TableHead className="text-right">{t.common.actions}</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((tool) => (
                <TableRow key={tool.toolId} data-testid={`tool-${tool.toolId}`}>
                  <TableCell className="font-mono font-medium">{tool.toolId}</TableCell>
                  <TableCell>
                    <Chips values={tool.capabilities} />
                  </TableCell>
                  <TableCell className="text-sm">{tool.versions.join(', ') || '—'}</TableCell>
                  <TableCell>{tool.agentCount}</TableCell>
                  <TableCell className="text-muted-foreground">{formatDateTime(tool.firstSeenAt)}</TableCell>
                  <TableCell className="space-x-1">
                    <Badge variant={tool.approved ? 'success' : 'warning'}>{tool.approved ? 'Approved' : 'Unapproved'}</Badge>
                    {!tool.enabled && <Badge variant="outline">Disabled</Badge>}
                  </TableCell>
                  {isAdmin && (
                    <TableCell className="space-x-2 text-right whitespace-nowrap">
                      {tool.approved ? (
                        <Button size="sm" variant="outline" onClick={() => save(tool.toolId, false, tool.enabled)}>
                          Revoke approval
                        </Button>
                      ) : (
                        <Button size="sm" variant="outline" onClick={() => save(tool.toolId, true, true)}>
                          {t.agents.approve}
                        </Button>
                      )}
                      <Button size="sm" variant="outline" onClick={() => save(tool.toolId, tool.approved, !tool.enabled)}>
                        {tool.enabled ? t.agents.disable : t.agents.enable}
                      </Button>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )
      }
    </Loadable>
  )
}

export function AgentsPage() {
  const isAdmin = useCan('admin')
  return (
    <>
      <PageHeader title={t.agents.title} description="Scanner agents connect to the server; tools are reported from agent manifests." />
      <Tabs defaultValue="agents">
        <TabsList>
          <TabsTrigger value="agents">{t.agents.tabs.agents}</TabsTrigger>
          {isAdmin && <TabsTrigger value="tokens">{t.agents.tabs.tokens}</TabsTrigger>}
          <TabsTrigger value="tools">{t.agents.tabs.tools}</TabsTrigger>
        </TabsList>
        <TabsContent value="agents">
          <AgentsTable />
        </TabsContent>
        {isAdmin && (
          <TabsContent value="tokens">
            <EnrollmentTokens />
          </TabsContent>
        )}
        <TabsContent value="tools">
          <ToolsCatalog />
        </TabsContent>
      </Tabs>
    </>
  )
}

