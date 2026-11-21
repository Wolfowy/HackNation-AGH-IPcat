import { useState } from 'react'
import { useAgents } from '@/api/agents'
import { useJobs } from '@/api/scans'
import { JOB_STATUSES, type JobStatus } from '@/api/types'
import { Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { Filters, PageHeader, Pagination } from '@/components/page'
import { NativeSelect } from '@/components/ui/input'
import { t } from '@/i18n/strings'
import { JobsTable } from './JobsTable'

export function JobsPage() {
  const [status, setStatus] = useState<JobStatus | ''>('')
  const [agentId, setAgentId] = useState('')
  const [page, setPage] = useState(1)
  const pageSize = 50
  const jobs = useJobs({ status, agentId, page, pageSize })
  const agents = useAgents()

  return (
    <>
      <PageHeader title={t.scans.jobsTitle} />
      <Filters>
        <FormField label="Status">
          <NativeSelect
            value={status}
            onChange={(e) => {
              setStatus(e.target.value as JobStatus | '')
              setPage(1)
            }}
          >
            <option value="">{t.common.all}</option>
            {JOB_STATUSES.map((s) => (
              <option key={s}>{s}</option>
            ))}
          </NativeSelect>
        </FormField>
        <FormField label="Agent">
          <NativeSelect
            value={agentId}
            onChange={(e) => {
              setAgentId(e.target.value)
              setPage(1)
            }}
          >
            <option value="">{t.common.all}</option>
            {(agents.data ?? []).map((a) => (
              <option key={a.agentId} value={a.agentId}>
                {a.hostname} ({a.agentId})
              </option>
            ))}
          </NativeSelect>
        </FormField>
      </Filters>
      <Loadable query={jobs}>
        {(data) => (
          <>
            <JobsTable jobs={data.items} showRun />
            <Pagination page={page} pageSize={pageSize} total={data.total} onPageChange={setPage} />
          </>
        )}
      </Loadable>
    </>
  )
}
