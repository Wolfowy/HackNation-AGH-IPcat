import { useRef, useState, type ReactNode } from 'react'
import { Copy, Download, Upload } from 'lucide-react'
import { toast } from 'sonner'
import { downloadFile, errorMessage, type QueryParams } from '@/api/client'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { t } from '@/i18n/strings'

type ButtonProps = React.ComponentProps<typeof Button>

/** Button that asks for confirmation in a dialog before running `onConfirm`. */
export function ConfirmButton({
  title,
  description,
  confirmLabel = t.common.confirm,
  onConfirm,
  children,
  destructive = true,
  ...buttonProps
}: Omit<ButtonProps, 'onClick'> & {
  title: string
  description?: ReactNode
  confirmLabel?: string
  destructive?: boolean
  onConfirm: () => Promise<unknown> | void
}) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    try {
      await onConfirm()
      setOpen(false)
    } catch {
      // the mutation cache already reports the error
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button {...buttonProps}>{children}</Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline">{t.common.cancel}</Button>
          </DialogClose>
          <Button variant={destructive ? 'destructive' : 'default'} onClick={run} disabled={busy}>
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function CopyButton({ value, label = t.common.copy }: { value: string; label?: string }) {
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          toast.success(t.common.copied)
        } catch {
          toast.error('Clipboard is not available; select and copy the value manually.')
        }
      }}
    >
      <Copy /> {label}
    </Button>
  )
}

/** JSON + CSV export buttons for `GET {path}?format=json|csv`. */
export function ExportButtons({ path, baseName, query }: { path: string; baseName: string; query?: QueryParams }) {
  const [busy, setBusy] = useState<string | null>(null)
  const run = async (format: 'json' | 'csv') => {
    setBusy(format)
    try {
      await downloadFile(path, { ...query, format }, `${baseName}.${format}`)
    } catch (err) {
      toast.error(errorMessage(err))
    } finally {
      setBusy(null)
    }
  }
  return (
    <>
      <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => run('json')}>
        <Download /> {t.common.exportJson}
      </Button>
      <Button variant="outline" size="sm" disabled={busy !== null} onClick={() => run('csv')}>
        <Download /> {t.common.exportCsv}
      </Button>
    </>
  )
}

/** Hidden file input behind a button; format is derived from the file extension. */
export function FileImportButton({
  label = t.common.import,
  onFile,
  disabled,
}: {
  label?: string
  onFile: (file: File, format: 'json' | 'csv') => void
  disabled?: boolean
}) {
  const input = useRef<HTMLInputElement>(null)
  return (
    <>
      <input
        ref={input}
        type="file"
        accept=".json,.csv,application/json,text/csv"
        className="hidden"
        aria-label={label}
        onChange={(e) => {
          const file = e.target.files?.[0]
          e.target.value = ''
          if (file) onFile(file, file.name.toLowerCase().endsWith('.csv') ? 'csv' : 'json')
        }}
      />
      <Button variant="outline" size="sm" disabled={disabled} onClick={() => input.current?.click()}>
        <Upload /> {label}
      </Button>
    </>
  )
}
