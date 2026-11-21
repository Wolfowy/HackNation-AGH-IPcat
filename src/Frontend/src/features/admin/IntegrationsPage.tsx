import { useForm } from 'react-hook-form'
import { toast } from 'sonner'
import { useDefectDojo, useTestDefectDojo, useUpdateDefectDojo } from '@/api/admin'
import { SEVERITIES, type DefectDojoConfig, type Severity } from '@/api/types'
import { Loadable } from '@/components/feedback'
import { CheckboxField, FormField, submitHandler } from '@/components/form'
import { PageHeader } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input, NativeSelect } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { optionalNumber } from '@/lib/format'

interface Values {
  enabled: boolean
  baseUrl: string
  apiKey: string
  productId: string
  engagementId: string
  minimumSeverity: Severity
  verifyTls: boolean
}

function DefectDojoForm({ config }: { config: DefectDojoConfig }) {
  const update = useUpdateDefectDojo()
  const test = useTestDefectDojo()
  const form = useForm<Values>({
    defaultValues: {
      enabled: config.enabled,
      baseUrl: config.baseUrl ?? '',
      apiKey: '',
      productId: config.productId?.toString() ?? '',
      engagementId: config.engagementId?.toString() ?? '',
      minimumSeverity: config.minimumSeverity ?? 'medium',
      verifyTls: config.verifyTls ?? true,
    },
  })
  const { register, watch, setValue, formState, resetField } = form
  const errors = formState.errors

  const submit = submitHandler(form, async (v) => {
    await update.mutateAsync({
      enabled: v.enabled,
      baseUrl: v.baseUrl.trim(),
      apiKey: v.apiKey || undefined, // omitted = keep the stored key
      productId: optionalNumber(v.productId),
      engagementId: optionalNumber(v.engagementId),
      minimumSeverity: v.minimumSeverity,
      verifyTls: v.verifyTls,
    })
    resetField('apiKey')
    toast.success(t.common.saved)
  })

  return (
    <form className="grid gap-4" onSubmit={submit} noValidate>
      <CheckboxField label="Enabled" checked={watch('enabled')} onChange={(v) => setValue('enabled', v)} />
      <FormField label="Base URL" error={errors.baseUrl?.message}>
        <Input
          placeholder="https://defectdojo.example.com"
          {...register('baseUrl', {
            validate: (v) => !watch('enabled') || /^https?:\/\/\S+$/.test(v.trim()) || 'Enter an http(s) URL.',
          })}
        />
      </FormField>
      <FormField
        label="API key"
        hint={
          config.hasApiKey ? (
            <>
              <Badge variant="success">stored</Badge> Leave empty to keep the stored key.
            </>
          ) : (
            'No key stored yet.'
          )
        }
        error={errors.apiKey?.message}
      >
        <Input type="password" autoComplete="off" {...register('apiKey')} />
      </FormField>
      <div className="grid grid-cols-2 gap-4">
        <FormField label="Product id" error={errors.productId?.message}>
          <Input type="number" min={1} {...register('productId')} />
        </FormField>
        <FormField label="Engagement id" error={errors.engagementId?.message}>
          <Input type="number" min={1} {...register('engagementId')} />
        </FormField>
      </div>
      <FormField label="Minimum severity">
        <NativeSelect {...register('minimumSeverity')}>
          {SEVERITIES.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </NativeSelect>
      </FormField>
      <CheckboxField label="Verify TLS certificate" checked={watch('verifyTls')} onChange={(v) => setValue('verifyTls', v)} />
      <div className="flex gap-2">
        <Button type="submit" disabled={formState.isSubmitting}>
          {t.common.save}
        </Button>
        <Button
          variant="outline"
          disabled={test.isPending}
          onClick={() =>
            test.mutate(undefined, {
              onSuccess: (r) => {
                if (!r.ok) toast.error(r.message ?? 'Connection failed')
                else toast.success(r.message ?? 'Connection OK')
              },
            })
          }
        >
          Test connection
        </Button>
      </div>
    </form>
  )
}

export function IntegrationsPage() {
  const config = useDefectDojo()
  return (
    <>
      <PageHeader title={t.nav.integrations} />
      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle>{t.admin.defectDojo}</CardTitle>
          <CardDescription>Only selected signature findings are exported; plain open ports never are.</CardDescription>
        </CardHeader>
        <CardContent>
          <Loadable query={config}>{(c) => <DefectDojoForm config={c} />}</Loadable>
        </CardContent>
      </Card>
    </>
  )
}
