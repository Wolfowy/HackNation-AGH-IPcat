import { useState } from 'react'
import { Link } from 'react-router'
import { toast } from 'sonner'
import { formatValidationMessage } from '@/api/client'
import { useHosts, useImportAssets } from '@/api/assets'
import { useZones } from '@/api/networks'
import { HOST_STATUSES, type HostStatus } from '@/api/types'
import { Can } from '@/auth/AuthProvider'
import { ExportButtons, FileImportButton } from '@/components/actions'
import { EmptyState, Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Chips, Filters, PageHeader, Pagination, StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Input, NativeSelect } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatRelative } from '@/lib/format'
import { useDebounced } from '@/lib/useDebounced'

export function UnstableBadge() {
  return (
    <Badge variant="warning" title="Host state changes frequently (flapping)">
      unstable
    </Badge>
  )
}

export function HostsPage() {
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState<HostStatus | ''>('')
  const [zone, setZone] = useState('')
  const [page, setPage] = useState(1)
  const pageSize = 50
  const debouncedSearch = useDebounced(search)
  const hosts = useHosts({ search: debouncedSearch, status, zone, page, pageSize })
  const zones = useZones()
  const importAssets = useImportAssets()

  const onImport = (file: File, format: 'json' | 'csv') =>
    importAssets.mutate(
      { file, format },
      {
        onSuccess: (r) => {
          toast.success(`Annotations imported: ${r.imported ?? 0} new, ${r.updated ?? 0} updated`)
          if (r.errors.length) toast.warning(r.errors.map(formatValidationMessage).join('\n'))
        },
      },
    )

  return (
    <>
      <PageHeader
        title={t.assets.hosts}
        actions={
          <>
            <ExportButtons path="/api/export/hosts" baseName="hosts" />
            <Can permission="manage">
              <FileImportButton label={t.assets.importAnnotations} onFile={onImport} disabled={importAssets.isPending} />
            </Can>
          </>
        }
      />
      <Filters>
        <FormField label={t.common.search}>
          <Input
            type="search"
            placeholder="Address, hostname, technology…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(1)
            }}
          />
        </FormField>
        <FormField label="Status">
          <NativeSelect
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as HostStatus | '')
              setPage(1)
            }}
          >
            <option value="">{t.common.all}</option>
            {HOST_STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </NativeSelect>
        </FormField>
        <FormField label="Zone">
          <NativeSelect
            value={zone}
            onChange={(e) => {
              setZone(e.target.value)
              setPage(1)
            }}
          >
            <option value="">{t.common.all}</option>
            {(zones.data ?? []).map((z) => (
              <option key={z.name}>{z.name}</option>
            ))}
          </NativeSelect>
        </FormField>
      </Filters>
      <Loadable query={hosts}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState>No hosts match the filters.</EmptyState>
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Address</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Open ports</TableHead>
                    <TableHead>Technologies</TableHead>
                    <TableHead>Zone</TableHead>
                    <TableHead>Owner / classification</TableHead>
                    <TableHead>Last seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((h) => (
                    <TableRow key={h.id} data-testid="host-row">
                      <TableCell>
                        <Link to={`/assets/hosts/${h.id}`} className="font-mono font-medium hover:underline">
                          {h.address}
                        </Link>
                        {h.hostnames.length > 0 && <div className="text-muted-foreground text-xs">{h.hostnames.join(', ')}</div>}
                      </TableCell>
                      <TableCell className="space-x-1 whitespace-nowrap">
                        <StatusBadge status={h.status} />
                        {h.unstable && <UnstableBadge />}
                      </TableCell>
                      <TableCell className="tabular-nums">{h.openPortCount}</TableCell>
                      <TableCell>
                        <Chips values={h.technologies.slice(0, 4)} />
                      </TableCell>
                      <TableCell>{h.zone ?? '—'}</TableCell>
                      <TableCell className="text-sm">
                        {h.annotation ? [h.annotation.owner, h.annotation.classification].filter(Boolean).join(' · ') || '—' : '—'}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{formatRelative(h.lastSeenAt)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <Pagination page={page} pageSize={pageSize} total={data.total} onPageChange={setPage} />
            </>
          )
        }
      </Loadable>
    </>
  )
}
