import { Link, useParams } from 'react-router'
import { useForm } from 'react-hook-form'
import { toast } from 'sonner'
import { useHost, useUpdateAnnotation } from '@/api/assets'
import type { HostDetail } from '@/api/types'
import { useCan } from '@/auth/AuthProvider'
import { EndpointLink } from '@/components/EndpointLink'
import { EmptyState, Loadable } from '@/components/feedback'
import { FormField, submitHandler } from '@/components/form'
import { Chips, KeyValues, PageHeader, StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input, Textarea } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { t } from '@/i18n/strings'
import { formatDateTime, formatRelative, splitList, zoneLabel } from '@/lib/format'
import { ChangesTable } from '../changes/ChangesTable'
import { FindingsTable } from '../findings/FindingsTable'
import { ConfidenceBar } from './ConfidenceBar'
import { NetworkDeviceBadge, UnstableBadge } from './HostsPage'
import { ServicesTable } from './ServicesTable'

interface AnnotationValues {
  description: string
  classification: string
  businessState: string
  owner: string
  tags: string
}

function AnnotationEditor({ host }: { host: HostDetail }) {
  const canEdit = useCan('edit')
  const update = useUpdateAnnotation()
  const a = host.annotation
  const form = useForm<AnnotationValues>({
    defaultValues: {
      description: a?.description ?? '',
      classification: a?.classification ?? '',
      businessState: a?.businessState ?? '',
      owner: a?.owner ?? '',
      tags: a?.tags.join(', ') ?? '',
    },
  })
  const submit = submitHandler(form, async (v) => {
    await update.mutateAsync({
      hostId: host.id,
      description: v.description.trim(),
      classification: v.classification.trim(),
      businessState: v.businessState.trim(),
      owner: v.owner.trim(),
      tags: splitList(v.tags),
    })
    toast.success(t.common.saved)
  })
  const { register, formState } = form
  return (
    <Card>
      <CardHeader>
        <CardTitle>Annotation</CardTitle>
      </CardHeader>
      <CardContent>
        <form className="grid gap-3" onSubmit={submit}>
          <fieldset disabled={!canEdit} className="grid gap-3">
            <FormField label="Description">
              <Textarea rows={2} {...register('description')} />
            </FormField>
            <div className="grid grid-cols-2 gap-3">
              <FormField label="Classification">
                <Input placeholder="e.g. production, test" {...register('classification')} />
              </FormField>
              <FormField label="Business state">
                <Input placeholder="e.g. in use, decommissioning" {...register('businessState')} />
              </FormField>
              <FormField label="Owner" error={formState.errors.owner?.message}>
                <Input {...register('owner')} />
              </FormField>
              <FormField label="Tags" hint="Comma separated">
                <Input {...register('tags')} />
              </FormField>
            </div>
          </fieldset>
          {canEdit && (
            <Button type="submit" className="w-fit" disabled={formState.isSubmitting}>
              Save annotation
            </Button>
          )}
        </form>
      </CardContent>
    </Card>
  )
}

export function HostDetailPage() {
  const { id = '' } = useParams()
  const host = useHost(id)
  return (
    <Loadable query={host}>
      {(h) => (
        <>
          <PageHeader
            title={
              <span className="flex items-center gap-3 font-mono">
                {h.address} <StatusBadge status={h.status} />
                {h.unstable && <UnstableBadge />}
                {h.networkDevice && <NetworkDeviceBadge confidence={h.networkDeviceConfidence} />}
              </span>
            }
            description={
              <>
                <Link to="/assets/hosts" className="hover:underline">
                  {t.assets.hosts}
                </Link>
                {h.hostnames.length > 0 && ` / ${h.hostnames.join(', ')}`}
              </>
            }
          />
          <div className="grid gap-6 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Overview</CardTitle>
              </CardHeader>
              <CardContent>
                <KeyValues
                  items={[
                    ['Zone', zoneLabel(h.zone)],
                    ['MAC address', <span className="font-mono">{h.macAddress ?? '—'}</span>],
                    ['MAC vendor', h.macVendor ?? '—'],
                    ['First seen', formatDateTime(h.firstSeenAt)],
                    ['Last seen', `${formatDateTime(h.lastSeenAt)} (${formatRelative(h.lastSeenAt)})`],
                    ['Last scanned', formatDateTime(h.lastScannedAt)],
                    ['Open ports', h.openPortCount],
                    ['Tags', <Chips values={h.annotation?.tags} />],
                  ]}
                />
              </CardContent>
            </Card>
            <AnnotationEditor host={h} />
          </div>
          {h.deviceInterfaces.length > 0 && (
            <Card className="mt-6" data-testid="device-interfaces">
              <CardHeader>
                <CardTitle>Same device in other zones</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                <p className="text-muted-foreground">
                  MAC <span className="font-mono">{h.macAddress}</span> also answers at these addresses, so they are interfaces of one router, L3
                  switch or firewall{h.networkDeviceConfidence === 'low' && ' (locally administered MAC — may be a coincidence)'}.
                </p>
                <ul className="space-y-1">
                  {h.deviceInterfaces.map((i) => (
                    <li key={i.hostId}>
                      <Link to={`/assets/hosts/${i.hostId}`} className="text-primary font-mono hover:underline">
                        {i.address}
                      </Link>
                      <span className="text-muted-foreground"> · zone {zoneLabel(i.zone)}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}
          <Tabs defaultValue="services" className="mt-6">
            <TabsList>
              <TabsTrigger value="services">Services ({h.services.length})</TabsTrigger>
              <TabsTrigger value="technologies">Technologies ({h.technologies.length})</TabsTrigger>
              <TabsTrigger value="certificates">Certificates ({h.certificates.length})</TabsTrigger>
              <TabsTrigger value="findings">Findings ({h.findings.length})</TabsTrigger>
              <TabsTrigger value="changes">Recent changes ({h.recentChanges.length})</TabsTrigger>
            </TabsList>
            <TabsContent value="services">
              <ServicesTable services={h.services} showHost={false} />
            </TabsContent>
            <TabsContent value="technologies">
              {h.technologies.length === 0 ? (
                <EmptyState />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Technology</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Port</TableHead>
                      <TableHead>Confidence</TableHead>
                      <TableHead>Method</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {h.technologies.map((x, i) => (
                      <TableRow key={`${x.name}-${x.port ?? ''}-${i}`}>
                        <TableCell className="font-medium">{x.name}</TableCell>
                        <TableCell>{x.version ?? '—'}</TableCell>
                        <TableCell>{x.category ?? '—'}</TableCell>
                        <TableCell>{x.port ?? '—'}</TableCell>
                        <TableCell>
                          <ConfidenceBar score={x.confidence} method={x.confidenceMethod} />
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">{x.confidenceMethod ?? '—'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </TabsContent>
            <TabsContent value="certificates">
              {h.certificates.length === 0 ? (
                <EmptyState />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Subject</TableHead>
                      <TableHead>Issuer</TableHead>
                      <TableHead>Endpoint</TableHead>
                      <TableHead>Valid</TableHead>
                      <TableHead>SHA-256</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {h.certificates.map((c) => {
                      const expired = c.notAfter ? Date.parse(c.notAfter) < Date.now() : false
                      return (
                        <TableRow key={c.fingerprintSha256}>
                          <TableCell>
                            {c.subjectCommonName ?? '—'}
                            {c.subjectAlternativeNames?.length ? (
                              <div className="text-muted-foreground text-xs">{c.subjectAlternativeNames.join(', ')}</div>
                            ) : null}
                          </TableCell>
                          <TableCell className="text-sm">
                            {c.issuer ?? '—'} {c.selfSigned && <Badge variant="warning">self-signed</Badge>}
                          </TableCell>
                          <TableCell>
                            {c.port === undefined ? (
                              '—'
                            ) : (
                              <EndpointLink address={h.address} port={c.port} url={h.services.find((s) => s.port === c.port)?.url} tls />
                            )}
                          </TableCell>
                          <TableCell className="text-xs whitespace-nowrap">
                            {c.notBefore?.slice(0, 10)} → <span className={expired ? 'text-destructive' : undefined}>{c.notAfter?.slice(0, 10)}</span>
                          </TableCell>
                          <TableCell className="max-w-48 truncate font-mono text-xs" title={c.fingerprintSha256}>
                            {c.fingerprintSha256}
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              )}
            </TabsContent>
            <TabsContent value="findings">
              <FindingsTable findings={h.findings} urlFor={(port) => h.services.find((s) => s.port === port)?.url} />
            </TabsContent>
            <TabsContent value="changes">
              <ChangesTable changes={h.recentChanges} />
            </TabsContent>
          </Tabs>
        </>
      )}
    </Loadable>
  )
}
