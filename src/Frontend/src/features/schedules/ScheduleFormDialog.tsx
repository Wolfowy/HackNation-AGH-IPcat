import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { useNetworks } from '@/api/networks'
import { useCreateSchedule, useUpdateSchedule } from '@/api/schedules'
import { DAYS_OF_WEEK, type AllowedWindow, type OverlapPolicy, type Schedule, type ScheduleInput } from '@/api/types'
import { useWorkflowVersions, useWorkflows } from '@/api/workflows'
import { CheckboxField, FormField, submitHandler } from '@/components/form'
import { MultiSelect, networkOption } from '@/components/MultiSelect'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input, NativeSelect } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { optionalNumber } from '@/lib/format'

// Quartz.NET cron format: second minute hour day-of-month month day-of-week [year].
export const CRON_PRESETS = [
  { label: 'Every 30 minutes', value: '0 0/30 * * * ?' },
  { label: 'Every 6 hours', value: '0 0 0/6 * * ?' },
  { label: 'Daily at 02:00', value: '0 0 2 * * ?' },
  { label: 'Weekdays at 22:00', value: '0 0 22 ? * MON-FRI' },
  { label: 'Weekly, Sunday 03:00', value: '0 0 3 ? * SUN' },
  { label: 'Monthly, 1st at 01:00', value: '0 0 1 1 * ?' },
]

export function timeZones(): string[] {
  const zones = typeof Intl.supportedValuesOf === 'function' ? Intl.supportedValuesOf('timeZone') : ['Europe/Warsaw']
  return zones.includes('UTC') ? zones : ['UTC', ...zones]
}

const OVERLAP: { value: OverlapPolicy; label: string }[] = [
  { value: 'Skip', label: 'Skip — do not start while previous run is active' },
  { value: 'CancelPrevious', label: 'Cancel previous run' },
  { value: 'Queue', label: 'Queue after previous run' },
]

interface Values {
  name: string
  cronExpression: string
  timeZone: string
  workflowKey: string
  workflowVersion: string
  networkIds: string[]
  priority: string
  maxRatePerSecond: string
  windowDurationMinutes: string
  overlapPolicy: OverlapPolicy
  enabled: boolean
}

const validateCron = (v: string) => {
  const fields = v.trim().split(/\s+/).length
  return (fields >= 6 && fields <= 7) || 'Cron needs 6–7 fields (Quartz: sec min hour day month weekday [year]).'
}

function WindowsEditor({ windows, onChange }: { windows: AllowedWindow[]; onChange: (w: AllowedWindow[]) => void }) {
  const update = (i: number, patch: Partial<AllowedWindow>) => onChange(windows.map((w, idx) => (idx === i ? { ...w, ...patch } : w)))
  return (
    <fieldset className="grid gap-2">
      <legend className="mb-1 text-sm font-medium">Allowed windows</legend>
      <p className="text-muted-foreground text-xs">Runs only start inside these windows (in the schedule time zone). Empty = any time.</p>
      {windows.map((w, i) => (
        <div key={i} className="grid gap-2 rounded-md border p-2" data-testid="window-row">
          <div className="flex flex-wrap gap-3">
            {DAYS_OF_WEEK.map((d) => (
              <CheckboxField
                key={d}
                label={d.slice(0, 3)}
                checked={w.daysOfWeek.includes(d)}
                onChange={(on) => update(i, { daysOfWeek: on ? [...w.daysOfWeek, d] : w.daysOfWeek.filter((x) => x !== d) })}
              />
            ))}
          </div>
          <div className="flex items-end gap-2">
            <FormField label="From">
              <Input type="time" value={w.start} onChange={(e) => update(i, { start: e.target.value })} />
            </FormField>
            <FormField label="To">
              <Input type="time" value={w.end} onChange={(e) => update(i, { end: e.target.value })} />
            </FormField>
            <Button variant="ghost" size="icon" aria-label="Remove window" onClick={() => onChange(windows.filter((_, idx) => idx !== i))}>
              <Trash2 />
            </Button>
          </div>
        </div>
      ))}
      <Button
        variant="outline"
        size="sm"
        className="w-fit"
        onClick={() => onChange([...windows, { daysOfWeek: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'], start: '22:00', end: '06:00' }])}
      >
        <Plus /> Add window
      </Button>
    </fieldset>
  )
}

export function ScheduleFormDialog({ schedule, onClose }: { schedule?: Schedule; onClose: () => void }) {
  const workflows = useWorkflows()
  const networks = useNetworks()
  const create = useCreateSchedule()
  const update = useUpdateSchedule()
  const [windows, setWindows] = useState<AllowedWindow[]>(schedule?.allowedWindows ?? [])
  const form = useForm<Values>({
    defaultValues: {
      name: schedule?.name ?? '',
      cronExpression: schedule?.cronExpression ?? CRON_PRESETS[2].value,
      timeZone: schedule?.timeZone ?? Intl.DateTimeFormat().resolvedOptions().timeZone,
      workflowKey: schedule?.workflowKey ?? '',
      workflowVersion: schedule?.workflowVersion?.toString() ?? '',
      networkIds: schedule?.networkIds ?? [],
      priority: String(schedule?.priority ?? 50),
      maxRatePerSecond: schedule?.maxRatePerSecond?.toString() ?? '',
      windowDurationMinutes: schedule?.windowDurationMinutes?.toString() ?? '',
      overlapPolicy: schedule?.overlapPolicy ?? 'Skip',
      enabled: schedule?.enabled ?? true,
    },
  })
  const { register, watch, setValue, setError, clearErrors, formState } = form
  const errors = formState.errors
  const versions = useWorkflowVersions(watch('workflowKey'))

  const submit = submitHandler(form, async (v) => {
    if (v.networkIds.length === 0) return setError('networkIds', { message: 'Select at least one network.' })
    const body: ScheduleInput = {
      name: v.name.trim(),
      cronExpression: v.cronExpression.trim(),
      timeZone: v.timeZone,
      workflowKey: v.workflowKey,
      workflowVersion: optionalNumber(v.workflowVersion),
      networkIds: v.networkIds,
      priority: optionalNumber(v.priority) ?? 50,
      maxRatePerSecond: optionalNumber(v.maxRatePerSecond),
      windowDurationMinutes: optionalNumber(v.windowDurationMinutes),
      allowedWindows: windows,
      overlapPolicy: v.overlapPolicy,
      enabled: v.enabled,
    }
    if (schedule) await update.mutateAsync({ id: schedule.id, ...body })
    else await create.mutateAsync(body)
    toast.success(t.common.saved)
    onClose()
  })

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{schedule ? `Edit schedule ${schedule.name}` : t.schedules.create}</DialogTitle>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={submit} noValidate>
          <FormField label="Name" error={errors.name?.message}>
            <Input {...register('name', { required: 'Name is required.' })} />
          </FormField>
          <div className="grid gap-4 sm:grid-cols-2">
            <FormField label="Cron expression" hint="Quartz format, e.g. 0 0 2 * * ? = daily at 02:00" error={errors.cronExpression?.message}>
              <Input className="font-mono" {...register('cronExpression', { required: 'Cron is required.', validate: validateCron })} />
            </FormField>
            <FormField label="Preset">
              <NativeSelect value="" onChange={(e) => e.target.value && setValue('cronExpression', e.target.value, { shouldValidate: true })}>
                <option value="">Choose a preset…</option>
                {CRON_PRESETS.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.label}
                  </option>
                ))}
              </NativeSelect>
            </FormField>
            <FormField label="Time zone" error={errors.timeZone?.message}>
              <NativeSelect {...register('timeZone', { required: true })}>
                {timeZones().map((z) => (
                  <option key={z}>{z}</option>
                ))}
              </NativeSelect>
            </FormField>
            <FormField label="Overlap policy">
              <NativeSelect {...register('overlapPolicy')}>
                {OVERLAP.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </NativeSelect>
            </FormField>
            <FormField label="Workflow" error={errors.workflowKey?.message}>
              <NativeSelect {...register('workflowKey', { required: 'Select a workflow.', onChange: () => setValue('workflowVersion', '') })}>
                <option value="">Select…</option>
                {(workflows.data ?? []).map((w) => (
                  <option key={w.key} value={w.key}>
                    {w.name} ({w.key})
                  </option>
                ))}
              </NativeSelect>
            </FormField>
            <FormField label="Workflow version">
              <NativeSelect {...register('workflowVersion')}>
                <option value="">Latest at fire time</option>
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
            options={(networks.data ?? []).map(networkOption)}
            value={watch('networkIds')}
            onChange={(v) => {
              setValue('networkIds', v)
              clearErrors('networkIds')
            }}
            error={errors.networkIds?.message}
          />
          <div className="grid grid-cols-3 gap-4">
            <FormField label="Priority" error={errors.priority?.message}>
              <Input type="number" min={0} max={100} {...register('priority', { min: { value: 0, message: 'Min 0' }, max: { value: 100, message: 'Max 100' } })} />
            </FormField>
            <FormField label="Rate cap (pps)" error={errors.maxRatePerSecond?.message}>
              <Input type="number" min={1} {...register('maxRatePerSecond', { min: { value: 1, message: 'Min 1' } })} />
            </FormField>
            <FormField label="Run window (minutes)" error={errors.windowDurationMinutes?.message}>
              <Input type="number" min={1} {...register('windowDurationMinutes', { min: { value: 1, message: 'Min 1' } })} />
            </FormField>
          </div>
          <WindowsEditor windows={windows} onChange={setWindows} />
          <CheckboxField label="Enabled" checked={watch('enabled')} onChange={(v) => setValue('enabled', v)} />
          <DialogFooter>
            <Button type="submit" disabled={formState.isSubmitting}>
              {t.common.save}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
