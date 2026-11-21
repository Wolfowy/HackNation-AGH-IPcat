import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { toast } from 'sonner'
import { useApproveSignatureVersion, useRetireSignature, useSignature } from '@/api/signatures'
import { Can } from '@/auth/AuthProvider'
import { ConfirmButton } from '@/components/actions'
import { Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Chips, PageHeader, StatusBadge } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Textarea } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { formatDateTime } from '@/lib/format'
import { cn } from '@/lib/utils'

function ApproveButton({ id, version, requiresNote }: { id: string; version: number; requiresNote: boolean }) {
  const approve = useApproveSignatureVersion()
  const [open, setOpen] = useState(false)
  const [note, setNote] = useState('')
  const label = `${t.signatures.approve} v${version}`
  const submit = (n?: string) =>
    approve.mutate(
      { id, version, note: n },
      {
        onSuccess: () => {
          toast.success(`Approved v${version}`)
          setOpen(false)
        },
      },
    )

  if (!requiresNote)
    return (
      <Button size="sm" onClick={() => submit()} disabled={approve.isPending}>
        {label}
      </Button>
    )
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">{label}</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{label}</DialogTitle>
          <DialogDescription>High and critical severity signatures need an approval note.</DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault()
            if (note.trim()) submit(note.trim())
          }}
        >
          <FormField label="Approval note">
            <Textarea required value={note} onChange={(e) => setNote(e.target.value)} />
          </FormField>
          <DialogFooter>
            <Button type="submit" disabled={approve.isPending || !note.trim()}>
              {t.signatures.approve}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export function SignatureDetailPage() {
  const { id = '' } = useParams()
  const signature = useSignature(id)
  const retire = useRetireSignature()
  const [selected, setSelected] = useState<number | null>(null)

  return (
    <Loadable query={signature}>
      {(s) => {
        const versions = [...s.versions].sort((a, b) => b.version - a.version)
        const current = versions.find((v) => v.version === (selected ?? s.latestVersion)) ?? versions[0]
        return (
          <>
            <PageHeader
              title={
                <span className="flex items-center gap-3">
                  {s.name} <StatusBadge status={s.status} />
                </span>
              }
              description={
                <>
                  <Link to="/signatures" className="hover:underline">
                    {t.signatures.title}
                  </Link>{' '}
                  / <span className="font-mono">{s.id}</span> · {s.kind}
                  {s.severity && <> · severity {s.severity}</>}
                </>
              }
              actions={
                s.status !== 'Retired' && (
                  <>
                    <Can permission="manage">
                      <Button variant="outline" asChild>
                        <Link to={`/signatures/${encodeURIComponent(s.id)}/new-version`}>{t.signatures.newVersion}</Link>
                      </Button>
                      <ConfirmButton
                        variant="outline"
                        title={`${t.signatures.retire} ${s.name}?`}
                        description="Retired signatures are no longer executed or applied."
                        confirmLabel={t.signatures.retire}
                        onConfirm={() => retire.mutateAsync(s.id)}
                      >
                        {t.signatures.retire}
                      </ConfirmButton>
                    </Can>
                  </>
                )
              }
            />
            <div className="mb-3">
              <Chips values={s.tags} />
            </div>
            <div className="grid gap-6 lg:grid-cols-[16rem_minmax(0,1fr)]">
              <Card className="h-fit py-3">
                <CardContent className="px-2">
                  <ul className="space-y-1" aria-label="Versions">
                    {versions.map((v) => (
                      <li key={v.version}>
                        <button
                          type="button"
                          onClick={() => setSelected(v.version)}
                          className={cn(
                            'hover:bg-accent w-full rounded-md px-2 py-1.5 text-left text-sm',
                            current?.version === v.version && 'bg-accent font-medium',
                          )}
                        >
                          <span className="flex items-center justify-between gap-2">
                            v{v.version}
                            {v.version === s.approvedVersion && <Badge variant="success">approved</Badge>}
                          </span>
                          <span className="text-muted-foreground block text-xs">
                            {formatDateTime(v.createdAt)}
                            {v.createdBy && ` · ${v.createdBy}`}
                          </span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
              {current && (
                <Card>
                  <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
                    <CardTitle>Version {current.version}</CardTitle>
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground font-mono text-xs" title="SHA-256">
                        {current.sha256.slice(0, 16)}…
                      </span>
                      {current.approvedAt ? (
                        <span className="text-muted-foreground text-xs" title={current.approvalNote}>
                          approved {formatDateTime(current.approvedAt)} {current.approvedBy && `by ${current.approvedBy}`}
                        </span>
                      ) : (
                        s.status !== 'Retired' && (
                          <Can permission="admin">
                            <ApproveButton key={current.version} id={s.id} version={current.version} requiresNote={current.requiresApprovalNote} />
                          </Can>
                        )
                      )}
                    </div>
                  </CardHeader>
                  <CardContent>
                    <pre className="bg-muted max-h-[36rem] overflow-auto rounded-md p-4 font-mono text-xs" data-testid="signature-content">
                      {current.content}
                    </pre>
                  </CardContent>
                </Card>
              )}
            </div>
          </>
        )
      }}
    </Loadable>
  )
}
