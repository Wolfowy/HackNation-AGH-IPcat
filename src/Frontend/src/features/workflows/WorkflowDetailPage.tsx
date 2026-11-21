import { useState } from 'react'
import { Link, useParams } from 'react-router'
import { useWorkflow, useWorkflowVersions } from '@/api/workflows'
import { Can } from '@/auth/AuthProvider'
import { Loadable } from '@/components/feedback'
import { FormField } from '@/components/form'
import { PageHeader } from '@/components/page'
import { Button } from '@/components/ui/button'
import { NativeSelect } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { t } from '@/i18n/strings'
import { formatDateTime } from '@/lib/format'
import { WorkflowGraph } from './WorkflowGraph'

export function WorkflowDetailPage() {
  const { key = '' } = useParams()
  const [version, setVersion] = useState<number | undefined>(undefined)
  const workflow = useWorkflow(key, version)
  const versions = useWorkflowVersions(key)

  return (
    <Loadable query={workflow}>
      {(wf) => (
        <>
          <PageHeader
            title={wf.definition.name}
            description={
              <>
                <Link to="/workflows" className="hover:underline">
                  {t.workflows.title}
                </Link>{' '}
                / {wf.key} v{wf.version} · created {formatDateTime(wf.createdAt)}
                {wf.createdBy && ` by ${wf.createdBy}`}
                {wf.definition.description && <div className="mt-1">{wf.definition.description}</div>}
              </>
            }
            actions={
              <>
                <FormField label="Version" className="w-32">
                  <NativeSelect value={version ?? ''} onChange={(e) => setVersion(e.target.value ? Number(e.target.value) : undefined)}>
                    <option value="">Latest</option>
                    {(versions.data ?? []).map((v) => (
                      <option key={v.version} value={v.version}>
                        v{v.version}
                      </option>
                    ))}
                  </NativeSelect>
                </FormField>
                <Can permission="manage">
                  <Button asChild className="self-end">
                    <Link to={`/workflows/${wf.key}/new-version`}>{t.workflows.newVersion}</Link>
                  </Button>
                </Can>
              </>
            }
          />
          <Tabs defaultValue="graph">
            <TabsList>
              <TabsTrigger value="graph">Graph</TabsTrigger>
              <TabsTrigger value="json">JSON</TabsTrigger>
            </TabsList>
            <TabsContent value="graph">
              <WorkflowGraph key={`${wf.key}@${wf.version}`} definition={wf.definition} />
            </TabsContent>
            <TabsContent value="json">
              <pre className="bg-muted max-h-[36rem] overflow-auto rounded-md p-4 font-mono text-xs" data-testid="workflow-json">
                {JSON.stringify(wf.definition, null, 2)}
              </pre>
            </TabsContent>
          </Tabs>
        </>
      )}
    </Loadable>
  )
}
