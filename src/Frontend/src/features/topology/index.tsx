// Module boundary for the future network topology map (agents ↔ interfaces ↔ networks ↔ hosts).
// Everything topology-related lives in this folder; the app only imports `topologyRoute`.
import type { RouteObject } from 'react-router'
import { Share2 } from 'lucide-react'
import { PageHeader } from '@/components/page'
import { Card, CardContent } from '@/components/ui/card'
import { t } from '@/i18n/strings'

export function TopologyPage() {
  return (
    <>
      <PageHeader title={t.topology.title} />
      <Card>
        <CardContent className="text-muted-foreground flex items-center gap-3">
          <Share2 className="size-5" /> <span data-testid="topology-planned">{t.topology.planned}</span>
        </CardContent>
      </Card>
    </>
  )
}

export const topologyRoute: RouteObject = { path: 'topology', element: <TopologyPage /> }
