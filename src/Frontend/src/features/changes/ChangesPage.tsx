import { useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useChanges } from '@/api/assets'
import { CHANGE_TYPES, type ChangeType } from '@/api/types'
import { ExportButtons } from '@/components/actions'
import { Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Filters, PageHeader, Pagination } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Input, NativeSelect } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { ChangesTable } from './ChangesTable'

const SINCE_OPTIONS = [
  { label: 'Last 24 hours', hours: 24 },
  { label: 'Last 7 days', hours: 24 * 7 },
  { label: 'Last 30 days', hours: 24 * 30 },
]

/** Filters live in the URL so links like /changes?hostId=… or ?scanRunId=… work. */
export function ChangesPage() {
  const [params, setParams] = useSearchParams()
  const [sinceHours, setSinceHours] = useState('')
  const type = (params.get('type') ?? '') as ChangeType | ''
  const hostId = params.get('hostId') ?? ''
  const scanRunId = params.get('scanRunId') ?? ''
  const page = Number(params.get('page') ?? 1)
  const pageSize = 50
  // Rounded to the minute so the query key stays stable between renders.
  const since = sinceHours ? new Date(Math.floor(Date.now() / 60_000) * 60_000 - Number(sinceHours) * 3_600_000).toISOString() : ''
  const changes = useChanges({ type, hostId, scanRunId, since, page, pageSize })

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    if (key !== 'page') next.delete('page')
    setParams(next, { replace: true })
  }

  return (
    <>
      <PageHeader
        title={t.changes.title}
        actions={
          <>
            <ExportButtons path="/api/export/changes" baseName="changes" />
            <Button variant="outline" size="sm" asChild>
              <Link to="/changes/diff">{t.changes.diffTitle}</Link>
            </Button>
          </>
        }
      />
      <Filters>
        <FormField label="Type">
          <NativeSelect value={type} onChange={(e) => setParam('type', e.target.value)}>
            <option value="">{t.common.all}</option>
            {CHANGE_TYPES.map((c) => (
              <option key={c}>{c}</option>
            ))}
          </NativeSelect>
        </FormField>
        <FormField label="Since">
          <NativeSelect value={sinceHours} onChange={(e) => setSinceHours(e.target.value)}>
            <option value="">Any time</option>
            {SINCE_OPTIONS.map((o) => (
              <option key={o.hours} value={o.hours}>
                {o.label}
              </option>
            ))}
          </NativeSelect>
        </FormField>
        <FormField label="Host id">
          <Input className="w-72 font-mono text-xs" value={hostId} onChange={(e) => setParam('hostId', e.target.value.trim())} />
        </FormField>
        <FormField label="Scan run id">
          <Input className="w-72 font-mono text-xs" value={scanRunId} onChange={(e) => setParam('scanRunId', e.target.value.trim())} />
        </FormField>
      </Filters>
      <Loadable query={changes}>
        {(data) => (
          <>
            <ChangesTable changes={data.items} />
            <Pagination page={page} pageSize={pageSize} total={data.total} onPageChange={(p) => setParam('page', String(p))} />
          </>
        )}
      </Loadable>
    </>
  )
}
