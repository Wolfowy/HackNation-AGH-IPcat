import { useForm } from 'react-hook-form'
import { useNavigate } from 'react-router'
import { useNetworks } from '@/api/networks'
import { useStartScan } from '@/api/scans'
import type { ScanStartRequest } from '@/api/types'
import { useWorkflowVersions, useWorkflows } from '@/api/workflows'
import { FormField, submitHandler } from '@/components/form'
import { MultiSelect, networkOption } from '@/components/MultiSelect'
import { PageHeader } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input, NativeSelect } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { optionalNumber } from '@/lib/format'

interface StartScanValues {
  name: string
  workflowKey: string
  workflowVersion: string
  networkIds: string[]
  priority: string
  maxRatePerSecond: string
  windowMinutes: string
}

export function StartScanPage() {
  const navigate = useNavigate()
  const workflows = useWorkflows()
  const networks = useNetworks()
  const start = useStartScan()
  const form = useForm<StartScanValues>({
    defaultValues: {
      name: `Manual scan ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`,
      workflowKey: '',
      workflowVersion: '',
      networkIds: [],
      priority: '50',
      maxRatePerSecond: '',
      windowMinutes: '',
    },
  })
  const { register, watch, setValue, setError, clearErrors, formState } = form
  const workflowKey = watch('workflowKey')
  const versions = useWorkflowVersions(workflowKey)
  const errors = formState.errors

  const submit = submitHandler(form, async (v) => {
    if (v.networkIds.length === 0) {
      setError('networkIds', { message: 'Select at least one network.' })
      return
    }
    const body: ScanStartRequest = {
      name: v.name.trim(),
      workflowKey: v.workflowKey,
      workflowVersion: optionalNumber(v.workflowVersion),
      networkIds: v.networkIds,
      priority: optionalNumber(v.priority),
      maxRatePerSecond: optionalNumber(v.maxRatePerSecond),
      windowMinutes: optionalNumber(v.windowMinutes),
    }
    const run = await start.mutateAsync(body)
    navigate(`/scans/${run.id}`)
  })

  return (
    <>
      <PageHeader title={t.scans.start} />
      <Card className="max-w-2xl">
        <CardContent>
          <form className="grid gap-4" onSubmit={submit} noValidate>
            <FormField label="Name" error={errors.name?.message}>
              <Input {...register('name', { required: 'Name is required.' })} />
            </FormField>
            <div className="grid grid-cols-2 gap-4">
              <FormField label="Workflow" error={errors.workflowKey?.message}>
                <NativeSelect
                  {...register('workflowKey', {
                    required: 'Select a workflow.',
                    onChange: () => setValue('workflowVersion', ''),
                  })}
                >
                  <option value="">Select…</option>
                  {(workflows.data ?? []).map((w) => (
                    <option key={w.key} value={w.key}>
                      {w.name} ({w.key})
                    </option>
                  ))}
                </NativeSelect>
              </FormField>
              <FormField label="Version" error={errors.workflowVersion?.message}>
                <NativeSelect {...register('workflowVersion')} disabled={!workflowKey}>
                  <option value="">Latest</option>
                  {(versions.data ?? []).map((v) => (
                    <option key={v.version} value={v.version}>
                      v{v.version}
                    </option>
                  ))}
                </NativeSelect>
              </FormField>
            </div>
            <MultiSelect
              legend="Networks"
              placeholder="Search by name, zone, range or #tag…"
              options={(networks.data ?? []).filter((n) => n.enabled).map(networkOption)}
              value={watch('networkIds')}
              onChange={(v) => {
                setValue('networkIds', v)
                clearErrors('networkIds')
              }}
              error={errors.networkIds?.message}
              emptyText="No enabled networks."
            />
            <div className="grid grid-cols-3 gap-4">
              <FormField label="Priority" hint="0–100, higher runs first" error={errors.priority?.message}>
                <Input
                  type="number"
                  min={0}
                  max={100}
                  {...register('priority', { min: { value: 0, message: 'Min 0' }, max: { value: 100, message: 'Max 100' } })}
                />
              </FormField>
              <FormField label="Rate cap (pps)" hint="Optional run-level cap" error={errors.maxRatePerSecond?.message}>
                <Input type="number" min={1} {...register('maxRatePerSecond', { min: { value: 1, message: 'Min 1' } })} />
              </FormField>
              <FormField label="Window (minutes)" hint="Optional; run stops when it ends" error={errors.windowMinutes?.message}>
                <Input type="number" min={1} {...register('windowMinutes', { min: { value: 1, message: 'Min 1' } })} />
              </FormField>
            </div>
            <div className="flex gap-2">
              <Button type="submit" disabled={formState.isSubmitting}>
                {t.scans.start}
              </Button>
              <Button variant="outline" onClick={() => navigate(-1)}>
                {t.common.cancel}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </>
  )
}
