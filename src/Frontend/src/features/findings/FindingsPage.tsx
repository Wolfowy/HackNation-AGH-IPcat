import { useState } from 'react'
import { Send } from 'lucide-react'
import { toast } from 'sonner'
import { formatValidationMessage } from '@/api/client'
import { useExportToDefectDojo } from '@/api/admin'
import { useFindings } from '@/api/assets'
import { SEVERITIES, type Severity } from '@/api/types'
import { Can, useCan } from '@/auth/AuthProvider'
import { ExportButtons } from '@/components/actions'
import { Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Filters, PageHeader, Pagination } from '@/components/page'
import { Button } from '@/components/ui/button'
import { NativeSelect } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { FindingsTable } from './FindingsTable'

export function FindingsPage() {
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [status, setStatus] = useState('Open')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const pageSize = 50
  const findings = useFindings({ severity, status, page, pageSize })
  const exportDojo = useExportToDefectDojo()
  const canManage = useCan('manage')

  const exportSelected = async () => {
    const r = await exportDojo.mutateAsync([...selected])
    toast.success(`DefectDojo: ${r.exported} exported, ${r.skipped} skipped`)
    if (r.errors.length) toast.warning(r.errors.map(formatValidationMessage).join('\n'))
    setSelected(new Set())
  }
  const resetSelection = <T,>(set: (v: T) => void) => (v: T) => {
    set(v)
    setPage(1)
    setSelected(new Set())
  }

  return (
    <>
      <PageHeader
        title={t.findings.title}
        actions={
          <>
            <ExportButtons path="/api/export/findings" baseName="findings" />
            <Can permission="manage">
              <Button size="sm" disabled={selected.size === 0 || exportDojo.isPending} onClick={() => exportSelected().catch(() => {})}>
                <Send /> {t.findings.exportDojo} {selected.size > 0 && `(${selected.size})`}
              </Button>
            </Can>
          </>
        }
      />
      <Filters>
        <FormField label="Severity">
          <NativeSelect value={severity} onChange={(e) => resetSelection(setSeverity)(e.target.value as Severity | '')}>
            <option value="">{t.common.all}</option>
            {SEVERITIES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </NativeSelect>
        </FormField>
        <FormField label="Status">
          <NativeSelect value={status} onChange={(e) => resetSelection(setStatus)(e.target.value)}>
            <option value="">{t.common.all}</option>
            <option>Open</option>
            <option>Resolved</option>
          </NativeSelect>
        </FormField>
      </Filters>
      <Loadable query={findings}>
        {(data) => (
          <>
            <FindingsTable
              findings={data.items}
              selection={
                canManage
                  ? {
                      selected,
                      onToggle: (id, on) =>
                        setSelected((prev) => {
                          const next = new Set(prev)
                          if (on) next.add(id)
                          else next.delete(id)
                          return next
                        }),
                      onToggleAll: (on) => setSelected(on ? new Set(data.items.map((f) => f.id)) : new Set()),
                    }
                  : undefined
              }
            />
            <Pagination page={page} pageSize={pageSize} total={data.total} onPageChange={setPage} />
          </>
        )}
      </Loadable>
    </>
  )
}
