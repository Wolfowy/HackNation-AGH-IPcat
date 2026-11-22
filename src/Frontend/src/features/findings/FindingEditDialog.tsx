import { useForm } from 'react-hook-form'
import { toast } from 'sonner'
import { useUpdateFindingTriage } from '@/api/assets'
import { FINDING_TRIAGES, SEVERITIES, type Finding, type FindingTriage, type Severity } from '@/api/types'
import { FormField, submitHandler } from '@/components/form'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input, NativeSelect, Textarea } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { splitList } from '@/lib/format'

export const triageLabels: Record<FindingTriage, string> = {
  None: 'Not triaged',
  Confirmed: 'Confirmed',
  FalsePositive: 'False positive',
  AcceptedRisk: 'Accepted risk',
}

interface FindingFormValues {
  triage: FindingTriage
  severityOverride: Severity | ''
  notes: string
  userTags: string
}

/** User triage of one finding; detection fields stay as scanned and the triage survives later scans. */
export function FindingEditDialog({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const update = useUpdateFindingTriage()
  const form = useForm<FindingFormValues>({
    defaultValues: {
      triage: finding.triage,
      severityOverride: finding.severityOverride ?? '',
      notes: finding.notes ?? '',
      userTags: finding.userTags.join(', '),
    },
  })
  const { register, formState } = form
  const errors = formState.errors

  const submit = submitHandler(form, async (v) => {
    await update.mutateAsync({
      id: finding.id,
      triage: v.triage,
      severityOverride: v.severityOverride || undefined,
      notes: v.notes.trim() || undefined,
      userTags: splitList(v.userTags),
    })
    toast.success(t.common.saved)
    onClose()
  })

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t.findings.edit}</DialogTitle>
          <DialogDescription>
            {finding.name} · {finding.address}
            {finding.port !== undefined && `:${finding.port}`}
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={submit} noValidate>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Triage" error={errors.triage?.message}>
              <NativeSelect {...register('triage')}>
                {FINDING_TRIAGES.map((v) => (
                  <option key={v} value={v}>
                    {triageLabels[v]}
                  </option>
                ))}
              </NativeSelect>
            </FormField>
            <FormField label="Severity override" error={errors.severityOverride?.message}>
              <NativeSelect {...register('severityOverride')}>
                <option value="">Detected ({finding.severity})</option>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </NativeSelect>
            </FormField>
          </div>
          <FormField label="Notes" error={errors.notes?.message}>
            <Textarea rows={4} {...register('notes', { maxLength: { value: 4000, message: 'Max 4000 characters.' } })} />
          </FormField>
          <FormField label="Tags" hint="Comma separated, up to 20" error={errors.userTags?.message}>
            <Input {...register('userTags', { validate: (v) => splitList(v).length <= 20 || 'Max 20 tags.' })} />
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
