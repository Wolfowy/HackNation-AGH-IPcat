import { useState } from 'react'
import { useAudit, useUsers } from '@/api/admin'
import { EmptyState, Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Filters, PageHeader, Pagination } from '@/components/page'
import { Input, NativeSelect } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDateTime } from '@/lib/format'
import { useDebounced } from '@/lib/useDebounced'

export function AuditPage() {
  const [action, setAction] = useState('')
  const [entityType, setEntityType] = useState('')
  const [userId, setUserId] = useState('')
  const [page, setPage] = useState(1)
  const pageSize = 50
  const users = useUsers()
  const audit = useAudit({ action: useDebounced(action), entityType: useDebounced(entityType), userId, page, pageSize })
  const filter = (set: (v: string) => void) => (value: string) => {
    set(value)
    setPage(1)
  }

  return (
    <>
      <PageHeader title={t.admin.audit} />
      <Filters>
        <FormField label="Action">
          <Input placeholder="e.g. network.created" value={action} onChange={(e) => filter(setAction)(e.target.value)} />
        </FormField>
        <FormField label="Entity type">
          <Input placeholder="e.g. Network" value={entityType} onChange={(e) => filter(setEntityType)(e.target.value)} />
        </FormField>
        <FormField label="User">
          <NativeSelect value={userId} onChange={(e) => filter(setUserId)(e.target.value)}>
            <option value="">{t.common.all}</option>
            {(users.data ?? []).map((u) => (
              <option key={u.id} value={u.id}>
                {u.userName}
              </option>
            ))}
          </NativeSelect>
        </FormField>
      </Filters>
      <Loadable query={audit}>
        {(data) =>
          data.items.length === 0 ? (
            <EmptyState />
          ) : (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>When</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Entity</TableHead>
                    <TableHead>Details</TableHead>
                    <TableHead>IP</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((e) => (
                    <TableRow key={e.id}>
                      <TableCell className="text-muted-foreground whitespace-nowrap">{formatDateTime(e.occurredAt)}</TableCell>
                      <TableCell>{e.userName ?? e.userId ?? 'system'}</TableCell>
                      <TableCell className="font-mono text-xs">{e.action}</TableCell>
                      <TableCell className="text-xs">
                        {e.entityType}
                        {e.entityId && <div className="text-muted-foreground font-mono">{e.entityId}</div>}
                      </TableCell>
                      <TableCell className="max-w-96 truncate font-mono text-xs" title={e.details}>
                        {e.details ?? ''}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{e.ipAddress ?? '—'}</TableCell>
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
