import { useForm } from 'react-hook-form'
import { toast } from 'sonner'
import { useUpdateServiceAnnotation } from '@/api/assets'
import { CRITICALITIES, type Criticality, type Service } from '@/api/types'
import { FormField, submitHandler } from '@/components/form'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input, NativeSelect, Textarea } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { splitList } from '@/lib/format'

interface ServiceAnnotationValues {
  criticality: Criticality | ''
  owner: string
  notes: string
  tags: string
}

/** User context of an endpoint, kept across scans per (zone, address, port, transport). */
export function ServiceAnnotationDialog({ service, onClose }: { service: Service; onClose: () => void }) {
  const update = useUpdateServiceAnnotation()
  const a = service.annotation
  const form = useForm<ServiceAnnotationValues>({
    defaultValues: { criticality: a?.criticality ?? '', owner: a?.owner ?? '', notes: a?.notes ?? '', tags: a?.tags.join(', ') ?? '' },
  })
  const { register, formState } = form
  const errors = formState.errors

  const submit = submitHandler(form, async (v) => {
    await update.mutateAsync({
      serviceId: service.id,
      criticality: v.criticality || undefined,
      owner: v.owner.trim() || undefined,
      notes: v.notes.trim() || undefined,
      tags: splitList(v.tags),
    })
    toast.success(t.common.saved)
    onClose()
  })

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t.assets.editServiceAnnotation}</DialogTitle>
          <DialogDescription>
            {service.address}:{service.port}/{service.transport.toLowerCase()} {service.serviceName && `· ${service.serviceName}`}
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={submit} noValidate>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Criticality">
              <NativeSelect {...register('criticality')}>
                <option value="">—</option>
                {CRITICALITIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </NativeSelect>
            </FormField>
            <FormField label="Owner" error={errors.owner?.message}>
              <Input {...register('owner', { maxLength: { value: 200, message: 'Max 200 characters.' } })} />
            </FormField>
          </div>
          <FormField label="Notes" error={errors.notes?.message}>
            <Textarea rows={3} {...register('notes', { maxLength: { value: 4000, message: 'Max 4000 characters.' } })} />
          </FormField>
          <FormField label="Tags" hint="Comma separated" error={errors.tags?.message}>
            <Input {...register('tags', { validate: (v) => splitList(v).length <= 50 || 'Max 50 tags.' })} />
          </FormField>
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
