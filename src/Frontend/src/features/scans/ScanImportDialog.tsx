import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router'
import { Upload } from 'lucide-react'
import { toast } from 'sonner'
import { ApiError } from '@/api/client'
import { useZones } from '@/api/networks'
import { useImportScan } from '@/api/scans'
import { SCAN_IMPORT_FORMATS, type ScanImportFormat } from '@/api/types'
import { CheckboxField, FormField } from '@/components/form'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Input, NativeSelect } from '@/components/ui/input'
import { t } from '@/i18n/strings'

const formatLabels: Record<ScanImportFormat, string> = {
  json: 'JSON rows (WebScan export)',
  csv: 'CSV rows (WebScan export)',
  'nmap-xml': 'Nmap XML',
  'httpx-jsonl': 'httpx JSONL',
  'naabu-jsonl': 'naabu JSONL',
  'nuclei-jsonl': 'Nuclei JSONL',
}

/** Format from the file extension; '' for JSONL (several tools write it — the user picks). */
export function detectImportFormat(fileName: string): ScanImportFormat | '' {
  const ext = fileName.toLowerCase().split('.').pop()
  return ext === 'csv' ? 'csv' : ext === 'json' ? 'json' : ext === 'xml' ? 'nmap-xml' : ''
}

export function ScanImportDialog() {
  const zones = useZones()
  const importScan = useImportScan()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [format, setFormat] = useState<ScanImportFormat | ''>('')
  const [zone, setZone] = useState('')
  const [name, setName] = useState('')
  const [snapshot, setSnapshot] = useState(false)
  const [errors, setErrors] = useState<string[]>([])

  const reset = (next: boolean) => {
    setOpen(next)
    if (!next) {
      setFile(null)
      setFormat('')
      setName('')
      setSnapshot(false)
      setErrors([])
    }
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    const missing = [!file && 'Choose a file.', !format && 'Choose the file format.', !zone && 'Choose a zone.'].filter((m): m is string => !!m)
    setErrors(missing)
    if (missing.length || !file || !format) return
    try {
      const r = await importScan.mutateAsync({ file, format, zone, name: name.trim() || undefined, snapshot })
      toast.success(t.scans.imported(r.observations, r.changesDetected))
      if (r.errors.length) toast.warning(`${r.errors.length} records skipped:\n${r.errors.slice(0, 5).join('\n')}`)
      reset(false)
      void navigate(`/scans/${r.scanRunId}`)
    } catch (err) {
      if (err instanceof ApiError) setErrors(Object.values(err.problem.errors ?? {}).flat())
    }
  }

  return (
    <Dialog open={open} onOpenChange={reset}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <Upload /> {t.scans.importResults}
        </Button>
      </DialogTrigger>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t.scans.importResults}</DialogTitle>
          <DialogDescription>
            Results go through the same pipeline as agent scans: assets, findings and change detection. The import becomes a finished scan run.
          </DialogDescription>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={submit} noValidate>
          <FormField label="File" hint=".json, .csv, .xml (nmap) or .jsonl (httpx, naabu, nuclei)">
            <Input
              type="file"
              accept=".json,.csv,.xml,.jsonl,.ndjson"
              onChange={(e) => {
                const picked = e.target.files?.[0] ?? null
                setFile(picked)
                if (picked) setFormat(detectImportFormat(picked.name))
              }}
            />
          </FormField>
          <div className="grid grid-cols-2 gap-4">
            <FormField label="Format">
              <NativeSelect value={format} onChange={(e) => setFormat(e.target.value as ScanImportFormat | '')}>
                <option value="">Select a format…</option>
                {SCAN_IMPORT_FORMATS.map((f) => (
                  <option key={f} value={f}>
                    {formatLabels[f]}
                  </option>
                ))}
              </NativeSelect>
            </FormField>
            <FormField label="Zone">
              <NativeSelect value={zone} onChange={(e) => setZone(e.target.value)}>
                <option value="">Select a zone…</option>
                {(zones.data ?? []).map((z) => (
                  <option key={z.name} value={z.name}>
                    {z.name}
                  </option>
                ))}
              </NativeSelect>
            </FormField>
          </div>
          <FormField label="Name" hint="Optional; defaults to the format and time">
            <Input maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
          </FormField>
          <div className="grid gap-1">
            <CheckboxField label="Snapshot" checked={snapshot} onChange={setSnapshot} />
            <p className="text-muted-foreground text-xs">{t.scans.snapshotHint}</p>
          </div>
          {errors.length > 0 && (
            <ul className="text-destructive list-disc space-y-0.5 pl-5 text-sm" role="alert">
              {errors.map((m, i) => (
                <li key={i}>{m}</li>
              ))}
            </ul>
          )}
          <DialogFooter>
            <Button type="submit" disabled={importScan.isPending}>
              {importScan.isPending ? 'Importing…' : t.common.import}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
