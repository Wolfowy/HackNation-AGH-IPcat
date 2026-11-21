import { useSearchParams } from 'react-router'
import { useScanDiff, useScans } from '@/api/scans'
import type { DiffEntry } from '@/api/types'
import { TargetLink } from '@/components/EndpointLink'
import { EmptyState, Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Filters, PageHeader } from '@/components/page'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { NativeSelect } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDateTime } from '@/lib/format'

const show = (v: unknown) => (v === undefined || v === null ? '' : typeof v === 'string' ? v : JSON.stringify(v))

function DiffSection({ title, entries, tone }: { title: string; entries: DiffEntry[]; tone: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className={tone}>
          {title} ({entries.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <EmptyState>None.</EmptyState>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Target</TableHead>
                <TableHead>Kind</TableHead>
                <TableHead>Name</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {entries.map((e) => (
                <TableRow key={e.key}>
                  <TableCell className="font-mono text-xs whitespace-nowrap">
                    <TargetLink address={e.address} port={e.port} serviceName={e.kind === 'endpoint' ? e.name : undefined} />
                    {e.transport && `/${e.transport.toLowerCase()}`}
                  </TableCell>
                  <TableCell className="text-xs">{e.kind}</TableCell>
                  <TableCell>{e.name ?? '—'}</TableCell>
                  <TableCell className="text-xs">
                    {(e.before !== undefined || e.after !== undefined) && (
                      <div className="text-muted-foreground font-mono">
                        {show(e.before) || '∅'} → {show(e.after) || '∅'}
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  )
}

export function RunDiffPage() {
  const [params, setParams] = useSearchParams()
  const run = params.get('run') ?? ''
  const baseline = params.get('baseline') ?? ''
  const scans = useScans({ page: 1, pageSize: 100 })
  const diff = useScanDiff(run, baseline)
  const finished = (scans.data?.items ?? []).filter((s) => s.finishedAt)

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }
  const option = (s: (typeof finished)[number]) => (
    <option key={s.id} value={s.id}>
      {s.name} — {formatDateTime(s.finishedAt)} ({s.status})
    </option>
  )

  return (
    <>
      <PageHeader title={t.changes.diffTitle} description="Compare the observations of two scan runs." />
      <Filters>
        <FormField label="Baseline run">
          <NativeSelect value={baseline} onChange={(e) => set('baseline', e.target.value)}>
            <option value="">Select…</option>
            {finished.filter((s) => s.id !== run).map(option)}
          </NativeSelect>
        </FormField>
        <FormField label="Compared run">
          <NativeSelect value={run} onChange={(e) => set('run', e.target.value)}>
            <option value="">Select…</option>
            {(scans.data?.items ?? []).filter((s) => s.id !== baseline).map(option)}
          </NativeSelect>
        </FormField>
      </Filters>
      {!run || !baseline ? (
        <EmptyState>Select two runs to compare.</EmptyState>
      ) : (
        <Loadable query={diff}>
          {(d) => (
            <div className="grid gap-4">
              <DiffSection title="Added" entries={d.added} tone="text-success" />
              <DiffSection title="Removed" entries={d.removed} tone="text-destructive" />
              <DiffSection title="Changed" entries={d.changed} tone="text-amber-600" />
            </div>
          )}
        </Loadable>
      )}
    </>
  )
}
