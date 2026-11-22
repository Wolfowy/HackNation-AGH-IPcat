import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { Plus, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { useSettings, useUpdateSettings } from '@/api/admin'
import { usePlannerStats, useScanLimits, useUpdateScanLimits } from '@/api/scans'
import type { ScanLimits, Settings } from '@/api/types'
import { EmptyState, Loadable } from '@/components/feedback'
import { FormField, submitHandler } from '@/components/form'
import { PageHeader } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDuration } from '@/lib/format'

function SettingsEditor({ values }: { values: Settings['values'] }) {
  const update = useUpdateSettings()
  const [rows, setRows] = useState(() => Object.entries(values).map(([key, value]) => ({ key, value: value ?? '' })))
  const setRow = (i: number, patch: Partial<{ key: string; value: string }>) =>
    setRows((r) => r.map((row, idx) => (idx === i ? { ...row, ...patch } : row)))
  const keys = rows.map((r) => r.key.trim()).filter(Boolean)
  const duplicate = keys.length !== new Set(keys).size

  return (
    <form
      className="grid gap-2"
      onSubmit={(e) => {
        e.preventDefault()
        const next: Settings['values'] = Object.fromEntries(rows.filter((r) => r.key.trim()).map((r) => [r.key.trim(), r.value]))
        // The server upserts sent keys and only deletes keys sent as null.
        for (const key of Object.keys(values)) if (!(key in next)) next[key] = null
        update.mutate({ values: next }, { onSuccess: () => toast.success(t.common.saved) })
      }}
    >
      {rows.length === 0 && <EmptyState>No settings.</EmptyState>}
      {rows.map((row, i) => (
        <div key={i} className="flex gap-2">
          <Input aria-label="Setting key" className="w-2/5 shrink-0 font-mono text-xs" value={row.key} onChange={(e) => setRow(i, { key: e.target.value })} />
          <Input aria-label={`Value of ${row.key}`} className="font-mono text-xs" value={row.value} onChange={(e) => setRow(i, { value: e.target.value })} />
          <Button variant="ghost" size="icon" aria-label={`Remove ${row.key}`} onClick={() => setRows((r) => r.filter((_, idx) => idx !== i))}>
            <Trash2 />
          </Button>
        </div>
      ))}
      {duplicate && <p className="text-destructive text-xs">Keys must be unique.</p>}
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={() => setRows((r) => [...r, { key: '', value: '' }])}>
          <Plus /> Add setting
        </Button>
        <Button type="submit" size="sm" disabled={duplicate || update.isPending}>
          Save settings
        </Button>
      </div>
    </form>
  )
}

// Ranges mirror ScanLimits.Validate() (Scanning/Planning/ClaimSelector.cs).
const LIMIT_FIELDS: { name: keyof ScanLimits; label: string; min: number; max: number; hint?: string }[] = [
  { name: 'defaultBatchSize', label: 'Default batch size', min: 64, max: 1024, hint: '64–1024 hosts, rounded to a power of two' },
  {
    name: 'targetJobSeconds',
    label: 'Target job duration (s)',
    min: 30,
    max: 3600,
    hint: 'Batch size follows measured agent throughput to aim at this job duration (default size until measured; a workflow batchSize wins).',
  },
  { name: 'leaseDurationSeconds', label: 'Lease duration (s)', min: 30, max: 3600 },
  { name: 'maxAttempts', label: 'Max attempts per job', min: 1, max: 10 },
  { name: 'maxConcurrentJobsPerZone', label: 'Max concurrent jobs per zone', min: 1, max: 100_000 },
  { name: 'maxConcurrentJobsPerInterface', label: 'Max concurrent jobs per interface', min: 1, max: 1000 },
  { name: 'maxConcurrentJobsPerSubnet', label: 'Max concurrent jobs per subnet', min: 1, max: 100_000 },
  { name: 'subnetPrefixLength', label: 'Subnet prefix length', min: 8, max: 32 },
  { name: 'maxRatePerSecondGlobal', label: 'Global max rate (pps)', min: 1, max: 100_000_000 },
  {
    name: 'unassignedJobTimeoutSeconds',
    label: 'Wait for an eligible agent (s)',
    min: 0,
    max: 604_800,
    hint: 'Queued jobs no online agent can reach are skipped after this time (not covered); the scan continues. 0 = wait forever, otherwise ≥ 60.',
  },
]

function ScanLimitsForm({ limits }: { limits: ScanLimits }) {
  const update = useUpdateScanLimits()
  const form = useForm<Record<keyof ScanLimits, string>>({
    defaultValues: Object.fromEntries(Object.entries(limits).map(([k, v]) => [k, String(v)])) as Record<keyof ScanLimits, string>,
  })
  const submit = submitHandler(form, async (v) => {
    await update.mutateAsync(Object.fromEntries(LIMIT_FIELDS.map((f) => [f.name, Number(v[f.name])])) as unknown as ScanLimits)
    toast.success(t.common.saved)
  })
  return (
    <form className="grid gap-4 sm:grid-cols-2" onSubmit={submit} noValidate>
      {LIMIT_FIELDS.map((f) => (
        <FormField key={f.name} label={f.label} hint={f.hint} error={form.formState.errors[f.name]?.message}>
          <Input
            type="number"
            {...form.register(f.name, {
              required: 'Required',
              min: { value: f.min, message: `Min ${f.min}` },
              max: { value: f.max, message: `Max ${f.max}` },
            })}
          />
        </FormField>
      ))}
      <div className="sm:col-span-2">
        <Button type="submit" disabled={form.formState.isSubmitting}>
          Save limits
        </Button>
      </div>
    </form>
  )
}

function PlannerStatsCard() {
  const stats = usePlannerStats()
  return (
    <Card>
      <CardHeader>
        <CardTitle>Planner statistics</CardTitle>
      </CardHeader>
      <CardContent>
        <Loadable query={stats}>
          {(s) => (
            <>
              <p className="mb-3 text-sm">
                Queue: <b>{s.queue.queued}</b> queued · <b>{s.queue.leased}</b> leased
              </p>
              {s.performance.length === 0 ? (
                <EmptyState />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Agent</TableHead>
                      <TableHead>Interface</TableHead>
                      <TableHead>Tool</TableHead>
                      <TableHead>Jobs</TableHead>
                      <TableHead>Avg duration</TableHead>
                      <TableHead>Targets/s</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {s.performance.map((p) => (
                      <TableRow key={`${p.agentId}-${p.interfaceName}-${p.toolId}`}>
                        <TableCell>{p.agentId}</TableCell>
                        <TableCell className="font-mono text-xs">{p.interfaceName}</TableCell>
                        <TableCell className="font-mono text-xs">{p.toolId}</TableCell>
                        <TableCell>{p.jobsCompleted}</TableCell>
                        <TableCell>{formatDuration(p.avgDurationMs)}</TableCell>
                        <TableCell>{p.avgTargetsPerSecond.toFixed(1)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </>
          )}
        </Loadable>
      </CardContent>
    </Card>
  )
}

export function SettingsPage() {
  const settings = useSettings()
  const limits = useScanLimits()
  return (
    <>
      <PageHeader title={t.admin.settings} />
      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>{t.admin.scanLimits}</CardTitle>
            <CardDescription>Global caps applied by the task planner.</CardDescription>
          </CardHeader>
          <CardContent>
            <Loadable query={limits}>{(l) => <ScanLimitsForm limits={l} />}</Loadable>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Settings</CardTitle>
            <CardDescription>Runtime key/value settings stored by the server.</CardDescription>
          </CardHeader>
          <CardContent>
            <Loadable query={settings}>{(s) => <SettingsEditor values={s.values} />}</Loadable>
          </CardContent>
        </Card>
        <div className="xl:col-span-2">
          <PlannerStatsCard />
        </div>
      </div>
    </>
  )
}
