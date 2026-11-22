import { useState } from 'react'
import { Plus } from 'lucide-react'
import { toast } from 'sonner'
import { formatValidationMessage } from '@/api/client'
import {
  useCreateZone,
  useDeleteNetwork,
  useDeleteZone,
  useImportNetworks,
  useNetworks,
  useScopePolicy,
  useUpdateScopePolicy,
  useZones,
} from '@/api/networks'
import type { Network, ScopePolicy } from '@/api/types'
import { Can, useCan } from '@/auth/AuthProvider'
import { ConfirmButton, ExportButtons, FileImportButton } from '@/components/actions'
import { EmptyState, Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Chips, PageHeader } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input, Textarea } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { t } from '@/i18n/strings'
import { formatDateTime, formatNumber, splitLines } from '@/lib/format'
import { validateTargetLines } from '@/lib/targets'
import { AgentSubnetsTab } from './AgentSubnetsTab'
import { NetworkFormDialog } from './NetworkFormDialog'

function NetworksTable({ onEdit }: { onEdit: (n: Network) => void }) {
  const networks = useNetworks()
  const remove = useDeleteNetwork()
  const canEdit = useCan('edit')
  const canManage = useCan('manage')
  return (
    <Loadable query={networks}>
      {(list) =>
        list.length === 0 ? (
          <EmptyState>No networks defined.</EmptyState>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Zone</TableHead>
                <TableHead>Ranges</TableHead>
                <TableHead>Exclusions</TableHead>
                <TableHead>Addresses</TableHead>
                <TableHead>Tags</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Updated</TableHead>
                {canEdit && <TableHead className="text-right">{t.common.actions}</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((n) => (
                <TableRow key={n.id}>
                  <TableCell>
                    <div className="font-medium">{n.name}</div>
                    {n.description && <div className="text-muted-foreground text-xs">{n.description}</div>}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{n.zone}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {n.ranges.slice(0, 3).join(', ')}
                    {n.ranges.length > 3 && ` +${n.ranges.length - 3}`}
                  </TableCell>
                  <TableCell>{n.exclusions.length}</TableCell>
                  <TableCell className="tabular-nums">{formatNumber(n.addressCount)}</TableCell>
                  <TableCell>
                    <Chips values={n.tags} />
                  </TableCell>
                  <TableCell>{n.enabled ? <Badge variant="success">Enabled</Badge> : <Badge variant="outline">Disabled</Badge>}</TableCell>
                  <TableCell className="text-muted-foreground">{formatDateTime(n.updatedAt)}</TableCell>
                  {canEdit && (
                    <TableCell className="space-x-2 text-right whitespace-nowrap">
                      <Button size="sm" variant="outline" onClick={() => onEdit(n)}>
                        {t.common.edit}
                      </Button>
                      {canManage && (
                        <ConfirmButton
                          size="sm"
                          variant="outline"
                          title={t.common.confirmDelete(`network "${n.name}"`)}
                          confirmLabel={t.common.delete}
                          onConfirm={() => remove.mutateAsync(n.id)}
                        >
                          {t.common.delete}
                        </ConfirmButton>
                      )}
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

function ZonesTab() {
  const zones = useZones()
  const create = useCreateZone()
  const remove = useDeleteZone()
  const canManage = useCan('manage')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  return (
    <div className="grid gap-4">
      {canManage && (
        <form
          className="flex flex-wrap items-end gap-3"
          onSubmit={(e) => {
            e.preventDefault()
            create.mutate(
              { name: name.trim(), description: description.trim() || undefined },
              {
                onSuccess: () => {
                  setName('')
                  setDescription('')
                },
              },
            )
          }}
        >
          <FormField label="Zone name">
            <Input required pattern="[A-Za-z0-9_.\-]{1,64}" value={name} onChange={(e) => setName(e.target.value)} />
          </FormField>
          <FormField label="Description" className="min-w-64 flex-1">
            <Input value={description} onChange={(e) => setDescription(e.target.value)} />
          </FormField>
          <Button type="submit" disabled={create.isPending}>
            <Plus /> Add zone
          </Button>
        </form>
      )}
      <Loadable query={zones}>
        {(list) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Zone</TableHead>
                <TableHead>Description</TableHead>
                <TableHead>Networks</TableHead>
                {canManage && <TableHead />}
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((z) => (
                <TableRow key={z.name}>
                  <TableCell className="font-medium">{z.name}</TableCell>
                  <TableCell>{z.description ?? '—'}</TableCell>
                  <TableCell>{z.networkCount}</TableCell>
                  {canManage && (
                    <TableCell className="text-right">
                      <ConfirmButton
                        size="sm"
                        variant="outline"
                        disabled={z.networkCount > 0}
                        title={t.common.confirmDelete(`zone "${z.name}"`)}
                        confirmLabel={t.common.delete}
                        onConfirm={() => remove.mutateAsync(z.name)}
                      >
                        {t.common.delete}
                      </ConfirmButton>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Loadable>
    </div>
  )
}

function ScopePolicyForm({ policy }: { policy: ScopePolicy }) {
  const isAdmin = useCan('admin')
  const update = useUpdateScopePolicy()
  const [allowed, setAllowed] = useState(policy.allowed.join('\n'))
  const [excluded, setExcluded] = useState(policy.excluded.join('\n'))
  const allowedCheck = validateTargetLines(splitLines(allowed), false)
  const excludedCheck = validateTargetLines(splitLines(excluded), false)
  const valid = allowedCheck === true && excludedCheck === true
  return (
    <Card>
      <CardHeader>
        <CardTitle>Global scope policy</CardTitle>
        <CardDescription>
          Networks must fall inside the allowed CIDRs/domains; global exclusions are never scanned. Last updated{' '}
          {formatDateTime(policy.updatedAt)}.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid gap-4 md:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault()
            update.mutate({ allowed: splitLines(allowed), excluded: splitLines(excluded) }, { onSuccess: () => toast.success(t.common.saved) })
          }}
        >
          <FormField label="Allowed" hint={t.networks.rangesHint} error={allowedCheck === true ? undefined : allowedCheck}>
            <Textarea rows={8} className="font-mono" readOnly={!isAdmin} value={allowed} onChange={(e) => setAllowed(e.target.value)} />
          </FormField>
          <FormField label="Global exclusions" error={excludedCheck === true ? undefined : excludedCheck}>
            <Textarea rows={8} className="font-mono" readOnly={!isAdmin} value={excluded} onChange={(e) => setExcluded(e.target.value)} />
          </FormField>
          {isAdmin && (
            <div className="md:col-span-2">
              <Button type="submit" disabled={!valid || update.isPending}>
                Save scope policy
              </Button>
            </div>
          )}
        </form>
      </CardContent>
    </Card>
  )
}

export function NetworksPage() {
  const [editing, setEditing] = useState<Network | null | undefined>(undefined)
  const importNetworks = useImportNetworks()

  const onImport = (file: File, format: 'json' | 'csv') =>
    importNetworks.mutate(
      { file, format },
      {
        onSuccess: (result) => {
          toast.success(t.networks.importDone(result.created, result.updated))
          if (result.errors.length) toast.warning(result.errors.map(formatValidationMessage).join('\n'))
        },
      },
    )

  const scope = useScopePolicy()
  return (
    <>
      <PageHeader
        title={t.networks.title}
        actions={
          <>
            <ExportButtons path="/api/networks/export" baseName="networks" />
            <Can permission="manage">
              <FileImportButton label="Import networks" onFile={onImport} disabled={importNetworks.isPending} />
              <Button onClick={() => setEditing(null)}>
                <Plus /> {t.networks.create}
              </Button>
            </Can>
          </>
        }
      />
      <Tabs defaultValue="networks">
        <TabsList>
          <TabsTrigger value="networks">{t.networks.tabs.networks}</TabsTrigger>
          <TabsTrigger value="agent-subnets">{t.networks.tabs.agentSubnets}</TabsTrigger>
          <TabsTrigger value="zones">{t.networks.tabs.zones}</TabsTrigger>
          <TabsTrigger value="scope">{t.networks.tabs.scope}</TabsTrigger>
        </TabsList>
        <TabsContent value="networks">
          <NetworksTable onEdit={setEditing} />
        </TabsContent>
        <TabsContent value="agent-subnets">
          <AgentSubnetsTab />
        </TabsContent>
        <TabsContent value="zones">
          <ZonesTab />
        </TabsContent>
        <TabsContent value="scope">
          <Loadable query={scope}>{(policy) => <ScopePolicyForm key={policy.updatedAt ?? ''} policy={policy} />}</Loadable>
        </TabsContent>
      </Tabs>
      {editing !== undefined && (
        <NetworkFormDialog
          key={editing?.id ?? 'new'}
          network={editing ?? undefined}
          open
          onOpenChange={(open) => !open && setEditing(undefined)}
        />
      )}
    </>
  )
}
