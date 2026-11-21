import { useState } from 'react'
import { useTechnologies } from '@/api/assets'
import { EmptyState, Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Filters, PageHeader } from '@/components/page'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { ConfidenceBar } from './ConfidenceBar'

export function TechnologiesPage() {
  const technologies = useTechnologies()
  const [filter, setFilter] = useState('')
  const needle = filter.trim().toLowerCase()
  return (
    <>
      <PageHeader title={t.assets.technologies} />
      <Filters>
        <FormField label={t.common.search}>
          <Input type="search" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </FormField>
      </Filters>
      <Loadable query={technologies}>
        {(list) => {
          const rows = list.filter((x) => !needle || `${x.name} ${x.category ?? ''}`.toLowerCase().includes(needle))
          return rows.length === 0 ? (
            <EmptyState />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Technology</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Hosts</TableHead>
                  <TableHead>Services</TableHead>
                  <TableHead>Confidence</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((x) => (
                  <TableRow key={`${x.name}@${x.version ?? ''}`}>
                    <TableCell className="font-medium">{x.name}</TableCell>
                    <TableCell>{x.version ?? '—'}</TableCell>
                    <TableCell>{x.category ?? '—'}</TableCell>
                    <TableCell>{x.hostCount}</TableCell>
                    <TableCell>{x.serviceCount}</TableCell>
                    <TableCell>
                      <ConfidenceBar score={x.confidence} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )
        }}
      </Loadable>
    </>
  )
}
