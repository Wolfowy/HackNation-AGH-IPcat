import type { OperationDescriptor, ParameterDescriptor } from '@/api/types'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

function constraints(p: ParameterDescriptor): string {
  return [
    p.required && 'required',
    p.min !== undefined && `min ${p.min}`,
    p.max !== undefined && `max ${p.max}`,
    p.allowedValues?.length && `one of: ${p.allowedValues.join(', ')}`,
    p.pattern && `pattern ${p.pattern}`,
  ]
    .filter(Boolean)
    .join(' · ')
}

/** Parameter documentation for operations, rendered from GET /api/operations. */
export function OperationDocs({
  operations,
  capabilityMapping = {},
}: {
  operations: OperationDescriptor[]
  capabilityMapping?: Record<string, string>
}) {
  return (
    <div className="space-y-5">
      {operations.map((op) => (
        <section key={op.operation} data-testid={`operation-${op.operation}`}>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <h3 className="font-semibold">{op.operation}</h3>
            <Badge variant={op.plane === 'Agent' ? 'default' : 'secondary'}>{op.plane}</Badge>
            {op.plane === 'Agent' && (
              <span className="text-muted-foreground text-xs">
                capability: <code>{capabilityMapping[op.operation] ?? op.requiredCapability ?? '—'}</code> · input: {op.inputKind}
              </span>
            )}
          </div>
          {op.parameters.length === 0 ? (
            <p className="text-muted-foreground text-sm">No parameters.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Parameter</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Default</TableHead>
                  <TableHead>Constraints</TableHead>
                  <TableHead>Description</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {op.parameters.map((p) => (
                  <TableRow key={p.name}>
                    <TableCell className="font-mono text-xs">{p.name}</TableCell>
                    <TableCell className="text-xs">{p.type}</TableCell>
                    <TableCell className="font-mono text-xs">{p.default ?? '—'}</TableCell>
                    <TableCell className="text-xs">{constraints(p) || '—'}</TableCell>
                    <TableCell className="text-xs">{p.description ?? ''}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </section>
      ))}
    </div>
  )
}
