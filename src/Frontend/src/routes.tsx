import type { ReactNode } from 'react'
import type { RouteObject } from 'react-router'
import { RequireAuth, RequirePermission } from '@/auth/AuthProvider'
import type { Permission } from '@/auth/roles'
import { Layout } from '@/components/Layout'
import { t } from '@/i18n/strings'
import { AuditPage } from '@/features/admin/AuditPage'
import { IntegrationsPage } from '@/features/admin/IntegrationsPage'
import { SettingsPage } from '@/features/admin/SettingsPage'
import { UsersPage } from '@/features/admin/UsersPage'
import { AgentDetailPage } from '@/features/agents/AgentDetailPage'
import { AgentsPage } from '@/features/agents/AgentsPage'
import { HostDetailPage } from '@/features/assets/HostDetailPage'
import { HostsPage } from '@/features/assets/HostsPage'
import { ServiceDetailPage } from '@/features/assets/ServiceDetailPage'
import { ServicesPage } from '@/features/assets/ServicesPage'
import { TechnologiesPage } from '@/features/assets/TechnologiesPage'
import { LoginPage } from '@/features/auth/LoginPage'
import { ChangesPage } from '@/features/changes/ChangesPage'
import { RunDiffPage } from '@/features/changes/RunDiffPage'
import { DashboardPage } from '@/features/dashboard/DashboardPage'
import { FindingsPage } from '@/features/findings/FindingsPage'
import { NetworksPage } from '@/features/networks/NetworksPage'
import { JobsPage } from '@/features/scans/JobsPage'
import { ScanDetailPage } from '@/features/scans/ScanDetailPage'
import { ScansPage } from '@/features/scans/ScansPage'
import { StartScanPage } from '@/features/scans/StartScanPage'
import { SchedulesPage } from '@/features/schedules/SchedulesPage'
import { SignatureDetailPage } from '@/features/signatures/SignatureDetailPage'
import { SignatureEditorPage } from '@/features/signatures/SignatureEditorPage'
import { SignaturesPage } from '@/features/signatures/SignaturesPage'
import { topologyRoute } from '@/features/topology'
import { WorkflowDetailPage } from '@/features/workflows/WorkflowDetailPage'
import { WorkflowEditorPage } from '@/features/workflows/WorkflowEditorPage'
import { WorkflowsPage } from '@/features/workflows/WorkflowsPage'

const guard = (permission: Permission, element: ReactNode) => <RequirePermission permission={permission}>{element}</RequirePermission>

export const routes: RouteObject[] = [
  { path: '/login', element: <LoginPage /> },
  {
    path: '/',
    element: (
      <RequireAuth>
        <Layout />
      </RequireAuth>
    ),
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'agents', element: <AgentsPage /> },
      { path: 'agents/:agentId', element: <AgentDetailPage /> },
      { path: 'networks', element: <NetworksPage /> },
      { path: 'scans', element: <ScansPage /> },
      { path: 'scans/new', element: guard('edit', <StartScanPage />) },
      { path: 'scans/:id', element: <ScanDetailPage /> },
      { path: 'jobs', element: <JobsPage /> },
      { path: 'schedules', element: <SchedulesPage /> },
      { path: 'workflows', element: <WorkflowsPage /> },
      { path: 'workflows/new', element: guard('manage', <WorkflowEditorPage />) },
      { path: 'workflows/:key', element: <WorkflowDetailPage /> },
      { path: 'workflows/:key/new-version', element: guard('manage', <WorkflowEditorPage />) },
      { path: 'assets/hosts', element: <HostsPage /> },
      { path: 'assets/hosts/:id', element: <HostDetailPage /> },
      { path: 'assets/services', element: <ServicesPage /> },
      { path: 'assets/services/:id', element: <ServiceDetailPage /> },
      { path: 'assets/technologies', element: <TechnologiesPage /> },
      // Lazy: keeps React Flow and dagre out of the main bundle.
      { path: 'assets/graph', lazy: async () => ({ Component: (await import('@/features/assets/InventoryGraphPage')).InventoryGraphPage }) },
      { path: 'changes', element: <ChangesPage /> },
      { path: 'changes/diff', element: <RunDiffPage /> },
      { path: 'findings', element: <FindingsPage /> },
      { path: 'signatures', element: <SignaturesPage /> },
      { path: 'signatures/new', element: guard('manage', <SignatureEditorPage />) },
      { path: 'signatures/:id', element: <SignatureDetailPage /> },
      { path: 'signatures/:id/new-version', element: guard('manage', <SignatureEditorPage />) },
      { path: 'admin/users', element: guard('admin', <UsersPage />) },
      { path: 'admin/audit', element: guard('admin', <AuditPage />) },
      { path: 'admin/settings', element: guard('admin', <SettingsPage />) },
      { path: 'admin/integrations', element: guard('admin', <IntegrationsPage />) },
      topologyRoute,
      { path: '*', element: <p className="py-16 text-center">{t.common.notFound}</p> },
    ],
  },
]
