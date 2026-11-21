import { useState } from 'react'
import { Link } from 'react-router'
import { Plus } from 'lucide-react'
import { useSignatures } from '@/api/signatures'
import { SIGNATURE_KINDS, SIGNATURE_STATUSES, type SignatureKind, type SignatureStatus } from '@/api/types'
import { Can } from '@/auth/AuthProvider'
import { EmptyState, Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Chips, Filters, PageHeader, StatusBadge } from '@/components/page'
import { Button } from '@/components/ui/button'
import { NativeSelect } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDateTime } from '@/lib/format'

export function SignaturesPage() {
  const [kind, setKind] = useState<SignatureKind | ''>('')
  const [status, setStatus] = useState<SignatureStatus | ''>('')
  const signatures = useSignatures({ kind, status })
  return (
    <>
      <PageHeader
        title={t.signatures.title}
        description="Only approved versions are executed (Nuclei templates) or applied (classification and change rules)."
        actions={
          <Can permission="manage">
            <Button asChild>
              <Link to="/signatures/new">
                <Plus /> {t.signatures.create}
              </Link>
            </Button>
          </Can>
        }
      />
      <Filters>
        <FormField label="Kind">
          <NativeSelect value={kind} onChange={(e) => setKind(e.target.value as SignatureKind | '')}>
            <option value="">{t.common.all}</option>
            {SIGNATURE_KINDS.map((k) => (
              <option key={k}>{k}</option>
            ))}
          </NativeSelect>
        </FormField>
        <FormField label="Status">
          <NativeSelect value={status} onChange={(e) => setStatus(e.target.value as SignatureStatus | '')}>
            <option value="">{t.common.all}</option>
            {SIGNATURE_STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </NativeSelect>
        </FormField>
      </Filters>
      <Loadable query={signatures}>
        {(list) =>
          list.length === 0 ? (
            <EmptyState />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Signature</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Versions</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Tags</TableHead>
                  <TableHead>Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <Link to={`/signatures/${encodeURIComponent(s.id)}`} className="font-medium hover:underline">
                        {s.name}
                      </Link>
                      <div className="text-muted-foreground font-mono text-xs">{s.id}</div>
                    </TableCell>
                    <TableCell className="text-sm">{s.kind}</TableCell>
                    <TableCell>
                      <StatusBadge status={s.status} />
                    </TableCell>
                    <TableCell className="text-sm whitespace-nowrap">
                      latest v{s.latestVersion}
                      {s.approvedVersion ? ` · approved v${s.approvedVersion}` : ''}
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={s.severity} />
                    </TableCell>
                    <TableCell>
                      <Chips values={s.tags} />
                    </TableCell>
                    <TableCell className="text-muted-foreground">{formatDateTime(s.updatedAt)}</TableCell>
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
