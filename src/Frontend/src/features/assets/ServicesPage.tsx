import { useState } from 'react'
import { useServices } from '@/api/assets'
import { InterestFilters } from './HostsPage'
import { ExportButtons } from '@/components/actions'
import { Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Filters, PageHeader, Pagination } from '@/components/page'
import { Input } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { useDebounced } from '@/lib/useDebounced'
import { ServicesTable } from './ServicesTable'

export function ServicesPage() {
  const [search, setSearch] = useState('')
  const [port, setPort] = useState('')
  const [serviceName, setServiceName] = useState('')
  const [byInterest, setByInterest] = useState(false)
  const [minInterest, setMinInterest] = useState(0)
  const [page, setPage] = useState(1)
  const pageSize = 50
  const debouncedPort = useDebounced(port)
  const services = useServices({
    search: useDebounced(search),
    // The server binds `port` as an int: anything non-numeric would be a 400.
    port: /^\d+$/.test(debouncedPort) ? debouncedPort : undefined,
    serviceName: useDebounced(serviceName),
    sort: byInterest ? 'interest' : '',
    minInterest: minInterest || undefined,
    page,
    pageSize,
  })
  const onFilter = (set: (v: string) => void) => (e: React.ChangeEvent<HTMLInputElement>) => {
    set(e.target.value)
    setPage(1)
  }

  return (
    <>
      <PageHeader title={t.assets.services} actions={<ExportButtons path="/api/export/services" baseName="services" />} />
      <Filters>
        <FormField label={t.common.search}>
          <Input type="search" placeholder="Address, product, title…" value={search} onChange={onFilter(setSearch)} />
        </FormField>
        <FormField label="Port">
          <Input inputMode="numeric" className="w-28" value={port} onChange={onFilter(setPort)} />
        </FormField>
        <FormField label="Service name">
          <Input className="w-40" placeholder="http, ssh…" value={serviceName} onChange={onFilter(setServiceName)} />
        </FormField>
        <InterestFilters
          byInterest={byInterest}
          minInterest={minInterest}
          onChange={(sort, min) => {
            setByInterest(sort)
            setMinInterest(min)
            setPage(1)
          }}
        />
      </Filters>
      <Loadable query={services}>
        {(data) => (
          <>
            <ServicesTable services={data.items} />
            <Pagination page={page} pageSize={pageSize} total={data.total} onPageChange={setPage} />
          </>
        )}
      </Loadable>
    </>
  )
}
