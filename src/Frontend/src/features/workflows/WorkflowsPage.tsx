import { Link } from 'react-router'
import { Plus } from 'lucide-react'
import { useOperations, useWorkflows } from '@/api/workflows'
import { Can } from '@/auth/AuthProvider'
import { EmptyState, Loadable } from '@/components/feedback'
import { PageHeader } from '@/components/page'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { t } from '@/i18n/strings'
import { formatDateTime } from '@/lib/format'
import { OperationDocs } from './OperationDocs'

export function WorkflowsPage() {
  const workflows = useWorkflows()
  const operations = useOperations()
  return (
    <>
      <PageHeader
        title={t.workflows.title}
        actions={
          <Can permission="manage">
            <Button asChild>
              <Link to="/workflows/new">
                <Plus /> {t.workflows.create}
              </Link>
            </Button>
          </Can>
        }
      />
      <Tabs defaultValue="workflows">
        <TabsList>
          <TabsTrigger value="workflows">{t.workflows.title}</TabsTrigger>
          <TabsTrigger value="operations">Operations catalog</TabsTrigger>
        </TabsList>
        <TabsContent value="workflows">
          <Loadable query={workflows}>
            {(list) =>
              list.length === 0 ? (
                <EmptyState />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Key</TableHead>
                      <TableHead>Latest version</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead>Updated</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {list.map((w) => (
                      <TableRow key={w.key}>
                        <TableCell>
                          <Link to={`/workflows/${w.key}`} className="font-medium hover:underline">
                            {w.name}
                          </Link>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{w.key}</TableCell>
                        <TableCell>v{w.latestVersion}</TableCell>
                        <TableCell className="text-muted-foreground">{w.description ?? ''}</TableCell>
                        <TableCell className="text-muted-foreground">{formatDateTime(w.updatedAt)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )
            }
          </Loadable>
        </TabsContent>
        <TabsContent value="operations">
          <Loadable query={operations}>
            {(catalog) => <OperationDocs operations={catalog.operations} capabilityMapping={catalog.capabilityMapping} />}
          </Loadable>
        </TabsContent>
      </Tabs>
    </>
  )
}
