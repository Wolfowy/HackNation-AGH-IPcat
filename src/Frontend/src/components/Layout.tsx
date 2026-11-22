import { useState } from 'react'
import { NavLink, Outlet } from 'react-router'
import {
  Activity,
  Bot,
  CalendarClock,
  Cpu,
  FileSearch,
  GitBranch,
  GitCompare,
  LayoutGrid,
  ListChecks,
  LogOut,
  Moon,
  Network,
  PanelLeft,
  Plug,
  Radar,
  ScrollText,
  Server,
  Settings,
  Share2,
  ShieldAlert,
  Sun,
  Users,
  Workflow,
  type LucideIcon,
} from 'lucide-react'
import { ScanHubProvider, useScanHubStatus } from '@/api/scanHub'
import { useAuth } from '@/auth/AuthProvider'
import { hasPermission, type Permission } from '@/auth/roles'
import { t } from '@/i18n/strings'
import { useTheme } from '@/lib/theme'
import { cn } from '@/lib/utils'

interface NavItem {
  to: string
  label: string
  icon: LucideIcon
  permission?: Permission
}

const sections: { title: string; items: NavItem[] }[] = [
  { title: t.nav.overview, items: [{ to: '/', label: t.nav.dashboard, icon: LayoutGrid }] },
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

const SIDEBAR_KEY = 'webscan-sidebar'
const initials = (name: string) =>
  name
    .split(/[\s._-]+/)
    .filter(Boolean)
    .map((p) => p[0])
    .join('')
    .slice(0, 2)
    .toUpperCase()

/** ip_cat brand: the white lockup on the always-dark sidebar; the emblem alone when collapsed (filtered to white). */
function Logo({ collapsed }: { collapsed: boolean }) {
  return collapsed ? (
    <img src="/brand/ipcat-emblem.svg" alt="ip_cat" className="size-[30px] brightness-0 invert" />
  ) : (
    <img src="/brand/ipcat-lockup-horizontal-dark.svg" alt="ip_cat" className="h-[34px] w-auto" />
  )
}

function HubIndicator() {
  const status = useScanHubStatus()
  const label = status === 'connected' ? t.common.live : status === 'disconnected' ? t.common.offline : t.common.reconnecting
  return (
    <span className="text-muted-foreground flex items-center gap-1.5 text-[12.5px]" data-testid="hub-status" data-status={status}>
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

function NavList({ roles, label = 'Main', collapsed = false }: { roles: string[]; label?: string; collapsed?: boolean }) {
  return (
    <nav aria-label={label}>
      {sections.map((section) => {
        const items = section.items.filter((i) => !i.permission || hasPermission(roles, i.permission))
        if (items.length === 0) return null
        return (
          <div key={section.title} role="group" aria-label={section.title}>
            {collapsed ? (
              <div className="bg-sidebar-border mx-2 my-3 h-px" />
            ) : (
              <div className="text-sidebar-foreground/60 px-2.5 pt-3 pb-1.5 text-[12px]">{section.title}</div>
            )}
            <ul>
              {items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.to === '/'}
                    title={collapsed ? item.label : undefined}
                    aria-label={collapsed ? item.label : undefined}
                    className={({ isActive }) =>
                      cn(
                        'text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:outline-sidebar-ring relative flex items-center gap-2.5 rounded-sm px-2.5 py-[7px] text-[14px] outline-none focus-visible:outline-2',
                        collapsed && 'justify-center px-0',
                        isActive &&
                          "bg-sidebar-accent text-sidebar-accent-foreground before:bg-sidebar-primary before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:rounded-l-sm before:content-['']",
                      )
                    }
                  >
                    <item.icon className="size-4 shrink-0" aria-hidden />
                    {!collapsed && <span className="truncate">{item.label}</span>}
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

function UserBlock({ collapsed }: { collapsed: boolean }) {
  const { user, logout } = useAuth()
  const name = user?.displayName || user?.userName || ''
  const roles = user?.roles ?? []
  return (
    <div className={cn('border-sidebar-border mt-auto flex items-center gap-2.5 border-t p-2.5 text-[13px]', collapsed && 'flex-col px-0')}>
      <span
        className="bg-sidebar-accent text-sidebar-accent-foreground grid size-7 shrink-0 place-items-center rounded-full text-[12px]"
        title={collapsed ? `${name} (${roles.join(', ')})` : undefined}
        aria-hidden
      >
        {initials(name)}
      </span>
      <span className={cn('min-w-0 flex-1', collapsed && 'sr-only')} data-testid="current-user">
        <span className="text-sidebar-accent-foreground block truncate">{name}</span>
        <span className="block truncate text-[12px]">{roles.join(', ')}</span>
      </span>
      <button
        type="button"
        onClick={logout}
        aria-label={t.common.logout}
        title={t.common.logout}
        className="hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:outline-sidebar-ring grid size-7 shrink-0 cursor-pointer place-items-center rounded-md outline-none focus-visible:outline-2"
      >
        <LogOut className="size-4" />
      </button>
    </div>
  )
}

function readCollapsed() {
  try {
    return localStorage.getItem(SIDEBAR_KEY) === 'collapsed'
  } catch {
    return false
  }
}

export function Layout() {
  const { user, logout } = useAuth()
  const roles = user?.roles ?? []
  const { theme, toggle } = useTheme()
  const [collapsed, setCollapsed] = useState(readCollapsed)
  const toggleSidebar = () => {
    setCollapsed((c) => {
      try {
        localStorage.setItem(SIDEBAR_KEY, c ? 'open' : 'collapsed')
      } catch {
        /* private mode */
      }
      return !c
    })
  }

  return (
    <ScanHubProvider>
      <div className="flex min-h-screen">
        {/* Sidebar: always dark (sidebar-* tokens), 236 px or 60 px collapsed. */}
        <aside
          className={cn(
            'bg-sidebar text-sidebar-foreground sticky top-0 hidden h-screen shrink-0 flex-col py-4 md:flex',
            collapsed ? 'w-[60px] px-2' : 'w-[236px] px-2.5',
          )}
        >
          <div className={cn('pt-0.5 pb-[14px]', collapsed ? 'flex justify-center' : 'px-2.5')}>
            <Logo collapsed={collapsed} />
          </div>
          <div className="-mx-1 min-h-0 flex-1 overflow-y-auto px-1 pb-2 [scrollbar-color:var(--sidebar-accent)_transparent] [scrollbar-width:thin]">
            <NavList roles={roles} collapsed={collapsed} />
          </div>
          <UserBlock collapsed={collapsed} />
        </aside>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="bg-card sticky top-0 z-30 flex h-[52px] items-center gap-3 border-b px-4 md:px-6">
            <button
              type="button"
              onClick={toggleSidebar}
              aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
              aria-expanded={!collapsed}
              className="hover:bg-muted focus-visible:outline-ring hidden size-8 cursor-pointer place-items-center rounded-md outline-none focus-visible:outline-2 md:grid"
            >
              <PanelLeft className="size-4" />
            </button>
            <details className="relative md:hidden">
              <summary className="cursor-pointer list-none">
                <span className="bg-sidebar inline-flex rounded-md px-2 py-1">
                  <Logo collapsed={false} />
                </span>
              </summary>
              <div className="bg-sidebar text-sidebar-foreground absolute left-0 z-40 mt-2 max-h-[80vh] w-64 overflow-y-auto rounded-lg p-2.5 shadow-lg">
                <NavList roles={roles} label="Mobile" />
                <button
                  type="button"
                  onClick={logout}
                  className="hover:bg-sidebar-accent mt-2 flex w-full cursor-pointer items-center gap-2.5 rounded-sm px-2.5 py-[7px] text-[14px]"
                >
                  <LogOut className="size-4" /> {t.common.logout}
                </button>
              </div>
            </details>
            <div className="flex-1" />
            <HubIndicator />
            <button
              type="button"
              onClick={toggle}
              aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
              className="bg-card hover:bg-muted focus-visible:outline-ring grid size-8 cursor-pointer place-items-center rounded-md border outline-none focus-visible:outline-2"
            >
              {theme === 'dark' ? <Sun className="size-4" /> : <Moon className="size-4" />}
            </button>
          </header>
          <main className="min-w-0 flex-1 px-4 pt-6 pb-12 md:px-7">
            <Outlet />
          </main>
        </div>
      </div>
    </ScanHubProvider>
  )
}
