import { useForm } from 'react-hook-form'
import { toast } from 'sonner'
import { useCreateNetwork, useUpdateNetwork, useZones } from '@/api/networks'
import type { Network } from '@/api/types'
import { CheckboxField, FormField, submitHandler } from '@/components/form'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input, NativeSelect, Textarea } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { optionalNumber, splitLines, splitList } from '@/lib/format'
import { validateTargetLines } from '@/lib/targets'

interface NetworkFormValues {
  name: string
  description: string
  zone: string
  ranges: string
  exclusions: string
  tags: string
  maxRatePerSecond: string
  enabled: boolean
}

const toValues = (n?: Network): NetworkFormValues => ({
  name: n?.name ?? '',
  description: n?.description ?? '',
  zone: n?.zone ?? '',
  ranges: n?.ranges.join('\n') ?? '',
  exclusions: n?.exclusions.join('\n') ?? '',
  tags: n?.tags.join(', ') ?? '',
  maxRatePerSecond: n?.maxRatePerSecond?.toString() ?? '',
  enabled: n?.enabled ?? true,
})

export function NetworkFormDialog({
  network,
  open,
  onOpenChange,
}: {
  network?: Network
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const zones = useZones()
  const create = useCreateNetwork()
  const update = useUpdateNetwork()
  const form = useForm<NetworkFormValues>({ defaultValues: toValues(network) })
  const { register, formState, watch, setValue } = form
  const errors = formState.errors

  const submit = submitHandler(form, async (v) => {
    const body = {
      name: v.name.trim(),
      description: v.description.trim() || undefined,
      zone: v.zone,
      ranges: splitLines(v.ranges),
      exclusions: splitLines(v.exclusions),
      tags: splitList(v.tags),
      maxRatePerSecond: optionalNumber(v.maxRatePerSecond),
      enabled: v.enabled,
    }
    if (network) await update.mutateAsync({ id: network.id, ...body })
    else await create.mutateAsync(body)
    toast.success(t.common.saved)
    onOpenChange(false)
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{network ? t.networks.edit : t.networks.create}</DialogTitle>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={submit} noValidate>
          <FormField label="Name" error={errors.name?.message}>
            <Input {...register('name', { required: 'Name is required.', maxLength: { value: 200, message: 'Max 200 characters.' } })} />
          </FormField>
          <FormField label="Description" error={errors.description?.message}>
            <Input {...register('description')} />
          </FormField>
          <FormField label="Zone" error={errors.zone?.message}>
            <NativeSelect {...register('zone', { required: 'Zone is required.' })}>
              <option value="">Select a zone…</option>
              {(zones.data ?? []).map((z) => (
                <option key={z.name} value={z.name}>
                  {z.name}
                </option>
              ))}
            </NativeSelect>
          </FormField>
          <FormField label="Ranges" hint={t.networks.rangesHint} error={errors.ranges?.message}>
            <Textarea
              rows={5}
              className="font-mono"
              placeholder={'10.0.0.0/24\n192.168.1.10-192.168.1.50'}
              {...register('ranges', { validate: (text) => validateTargetLines(splitLines(text), true) })}
            />
          </FormField>
          <FormField label="Exclusions" hint="Same formats as ranges; excluded from every scan of this network." error={errors.exclusions?.message}>
            <Textarea rows={3} className="font-mono" {...register('exclusions', { validate: (text) => validateTargetLines(splitLines(text), false) })} />
          </FormField>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Tags" hint="Comma separated" error={errors.tags?.message}>
              <Input {...register('tags')} />
            </FormField>
            <FormField label="Max rate (pps)" error={errors.maxRatePerSecond?.message}>
              <Input type="number" min={1} {...register('maxRatePerSecond', { min: { value: 1, message: 'Must be at least 1.' } })} />
            </FormField>
          </div>
          <CheckboxField label="Enabled" checked={watch('enabled')} onChange={(v) => setValue('enabled', v)} />
          <DialogFooter>
            <Button type="submit" disabled={formState.isSubmitting}>
              {formState.isSubmitting ? t.common.saving : t.common.save}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
