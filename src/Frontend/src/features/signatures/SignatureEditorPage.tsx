import { useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import { toast } from 'sonner'
import { errorMessage } from '@/api/client'
import { useCreateSignature, useCreateSignatureVersion, useSignature, validateSignature } from '@/api/signatures'
import { SIGNATURE_KINDS, type SignatureKind, type ValidationResult } from '@/api/types'
import { Loadable, ValidationMessages } from '@/components/feedback'
import { FormField } from '@/components/form'
import { PageHeader } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input, NativeSelect, Textarea } from '@/components/ui/input'
import { t } from '@/i18n/strings'

export const SIGNATURE_TEMPLATES: Record<SignatureKind, string> = {
  NucleiTemplate: `id: example-panel-detect

info:
  name: Example admin panel detection
  author: webscan
  severity: info
  tags: panel,example

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/"
    matchers:
      - type: word
        part: body
        words:
          - "Example Admin"
`,
  ClassificationRule: `{
  "description": "Classify hosts exposing RDP as Windows servers",
  "when": { "field": "port", "operator": "Equals", "values": ["3389"] },
  "assign": { "classification": "windows-server" }
}
`,
  ChangeRule: `{
  "description": "Flag new SSH services outside the management zone",
  "changeTypes": ["NewService"],
  "when": { "field": "service.name", "operator": "Equals", "values": ["ssh"] },
  "severity": "medium"
}
`,
}

const ID_PATTERN = /^[A-Za-z0-9_.-]{1,100}$/

function Editor({ existing }: { existing?: { id: string; name: string; kind: SignatureKind; content: string } }) {
  const navigate = useNavigate()
  const create = useCreateSignature()
  const createVersion = useCreateSignatureVersion()
  const [id, setId] = useState(existing?.id ?? '')
  const [name, setName] = useState(existing?.name ?? '')
  const [kind, setKind] = useState<SignatureKind>(existing?.kind ?? 'NucleiTemplate')
  const [content, setContent] = useState(existing?.content ?? SIGNATURE_TEMPLATES.NucleiTemplate)
  const [validation, setValidation] = useState<ValidationResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  const runValidation = async () => {
    setBusy(true)
    try {
      const result = await validateSignature({ kind, content })
      setValidation(result)
      return result
    } catch (err) {
      toast.error(errorMessage(err))
      return null
    } finally {
      setBusy(false)
    }
  }

  const save = async () => {
    const errors: Record<string, string> = {}
    if (!existing && !ID_PATTERN.test(id)) errors.id = 'Use 1–100 letters, digits, ".", "_" or "-".'
    if (!existing && !name.trim()) errors.name = 'Name is required.'
    if (!content.trim()) errors.content = 'Content is required.'
    setFieldErrors(errors)
    if (Object.keys(errors).length) return
    const result = await runValidation()
    if (!result?.valid) return
    try {
      if (existing) await createVersion.mutateAsync({ id: existing.id, content })
      else await create.mutateAsync({ id, name: name.trim(), kind, content })
      toast.success(t.common.saved)
      navigate(`/signatures/${encodeURIComponent(existing?.id ?? id)}`)
    } catch {
      // reported by the mutation cache
    }
  }

  return (
    <>
      <PageHeader
        title={existing ? `${t.signatures.newVersion}: ${existing.name}` : t.signatures.create}
        description="New versions are drafts until an administrator approves them."
        actions={
          <>
            <Button variant="outline" onClick={runValidation} disabled={busy || !content.trim()}>
              {t.signatures.validate}
            </Button>
            <Button onClick={save} disabled={busy || create.isPending || createVersion.isPending}>
              {t.common.save}
            </Button>
          </>
        }
      />
      <Card>
        <CardContent className="grid gap-4">
          {!existing && (
            <div className="grid gap-4 md:grid-cols-3">
              <FormField label="Signature id" error={fieldErrors.id}>
                <Input className="font-mono" value={id} onChange={(e) => setId(e.target.value)} />
              </FormField>
              <FormField label="Name" error={fieldErrors.name}>
                <Input value={name} onChange={(e) => setName(e.target.value)} />
              </FormField>
              <FormField label="Kind">
                <NativeSelect
                  value={kind}
                  onChange={(e) => {
                    const next = e.target.value as SignatureKind
                    if (content === SIGNATURE_TEMPLATES[kind]) setContent(SIGNATURE_TEMPLATES[next])
                    setKind(next)
                    setValidation(null)
                  }}
                >
                  {SIGNATURE_KINDS.map((k) => (
                    <option key={k}>{k}</option>
                  ))}
                </NativeSelect>
              </FormField>
            </div>
          )}
          {validation && <ValidationMessages valid={validation.valid} errors={validation.errors} warnings={validation.warnings} />}
          <FormField label={kind === 'NucleiTemplate' ? 'Content (YAML)' : 'Content (JSON)'} error={fieldErrors.content}>
            <Textarea
              spellCheck={false}
              className="min-h-[28rem] font-mono text-xs leading-5"
              value={content}
              onChange={(e) => {
                setContent(e.target.value)
                setValidation(null)
              }}
            />
          </FormField>
        </CardContent>
      </Card>
    </>
  )
}

export function SignatureEditorPage() {
  const { id } = useParams()
  const signature = useSignature(id ?? '')
  if (!id) return <Editor />
  return (
    <Loadable query={signature}>
      {(s) => {
        const latest = s.versions.reduce((a, b) => (b.version > a.version ? b : a), s.versions[0])
        return <Editor existing={{ id: s.id, name: s.name, kind: s.kind, content: latest?.content ?? '' }} />
      }}
    </Loadable>
  )
}
