import { NavLink, Outlet } from 'react-router'
import {
  Activity,
  Bot,
  CalendarClock,
  Cpu,
  FileSearch,
  GitBranch,
  GitCompare,
  LayoutDashboard,
  ListChecks,
  LogOut,
  Network,
  Radar,
  ScrollText,
  Server,
  Settings,
  ShieldAlert,
  Share2,
  Users,
  Workflow,
  Plug,
  type LucideIcon,
} from 'lucide-react'
import { ScanHubProvider, useScanHubStatus } from '@/api/scanHub'
import { useAuth } from '@/auth/AuthProvider'
import { hasPermission, type Permission } from '@/auth/roles'
import { Button } from '@/components/ui/button'
import { t } from '@/i18n/strings'
import { cn } from '@/lib/utils'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  permission?: Permission
}

const sections: { title: string; items: NavItem[] }[] = [
  { title: t.nav.overview, items: [{ to: '/', label: t.nav.dashboard, icon: LayoutDashboard }] },
  {
    title: t.nav.inventory,
    items: [
      { to: '/assets/hosts', label: t.nav.hosts, icon: Server },
      { to: '/assets/services', label: t.nav.services, icon: Activity },
      { to: '/assets/technologies', label: t.nav.technologies, icon: Cpu },
      { to: '/assets/graph', label: t.nav.graph, icon: GitBranch },
      { to: '/changes', label: t.nav.changes, icon: GitCompare },
      { to: '/findings', label: t.nav.findings, icon: ShieldAlert },
    ],
  },
  {
    title: t.nav.scanning,
    items: [
      { to: '/scans', label: t.nav.scans, icon: Radar },
      { to: '/jobs', label: t.nav.jobs, icon: ListChecks },
      { to: '/schedules', label: t.nav.schedules, icon: CalendarClock },
      { to: '/workflows', label: t.nav.workflows, icon: Workflow },
      { to: '/signatures', label: t.nav.signatures, icon: FileSearch },
    ],
  },
  {
    title: t.nav.infrastructure,
    items: [
      { to: '/agents', label: t.nav.agents, icon: Bot },
      { to: '/networks', label: t.nav.networks, icon: Network },
      { to: '/topology', label: t.nav.topology, icon: Share2 },
    ],
  },
  {
    title: t.nav.administration,
    items: [
      { to: '/admin/users', label: t.nav.users, icon: Users, permission: 'admin' },
      { to: '/admin/audit', label: t.nav.audit, icon: ScrollText, permission: 'admin' },
      { to: '/admin/settings', label: t.nav.settings, icon: Settings, permission: 'admin' },
      { to: '/admin/integrations', label: t.nav.integrations, icon: Plug, permission: 'admin' },
    ],
  },
]

function HubIndicator() {
  const status = useScanHubStatus()
  const label = status === 'connected' ? t.common.live : status === 'disconnected' ? t.common.offline : t.common.reconnecting
  return (
    <span className="text-muted-foreground flex items-center gap-1.5 text-xs" data-testid="hub-status" data-status={status}>
      <span
        className={cn(
          'size-2 rounded-full',
          status === 'connected' ? 'bg-success' : status === 'disconnected' ? 'bg-destructive' : 'bg-warning',
        )}
      />
      {label}
    </span>
  )
}

function NavList({ roles, label = 'Main' }: { roles: string[]; label?: string }) {
  return (
    <nav aria-label={label}>
      {sections.map((section) => {
        const items = section.items.filter((i) => !i.permission || hasPermission(roles, i.permission))
        if (items.length === 0) return null
        return (
          <div key={section.title} className="mb-4">
            <div className="text-muted-foreground mb-1 px-2 text-xs font-medium tracking-wide uppercase">{section.title}</div>
            <ul className="space-y-0.5">
              {items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.to === '/'}
                    className={({ isActive }) =>
                      cn(
                        'hover:bg-accent flex items-center gap-2 rounded-md px-2 py-1.5 text-sm',
                        isActive && 'bg-accent text-accent-foreground font-medium',
                      )
                    }
                  >
                    <item.icon className="size-4" /> {item.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        )
      })}
    </nav>
  )
}

export function Layout() {
  const { user, logout } = useAuth()
  const roles = user?.roles ?? []
  return (
    <ScanHubProvider>
      <div className="flex min-h-screen">
        <aside className="bg-sidebar sticky top-0 hidden h-screen w-56 shrink-0 overflow-y-auto border-r p-3 md:block">
          <div className="mb-4 flex items-center gap-2 px-2 py-1 text-lg font-semibold">
            <GitBranch className="text-primary size-5" /> {t.appName}
          </div>
          <NavList roles={roles} />
        </aside>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="bg-background/95 sticky top-0 z-10 flex h-12 items-center justify-end gap-4 border-b px-4 backdrop-blur">
            <details className="mr-auto md:hidden">
              <summary className="cursor-pointer text-sm font-medium">{t.appName} ☰</summary>
              <div className="bg-sidebar absolute left-0 mt-2 max-h-[80vh] w-64 overflow-y-auto border p-3 shadow-lg">
                <NavList roles={roles} label="Mobile" />
              </div>
            </details>
            <HubIndicator />
            <span className="text-sm" data-testid="current-user">
              {user?.displayName || user?.userName}
              <span className="text-muted-foreground ml-1 text-xs">({roles.join(', ')})</span>
            </span>
            <Button variant="ghost" size="sm" onClick={logout}>
              <LogOut /> {t.common.logout}
            </Button>
          </header>
          <main className="min-w-0 flex-1 p-4 md:p-6">
            <Outlet />
          </main>
        </div>
      </div>
    </ScanHubProvider>
  )
}
