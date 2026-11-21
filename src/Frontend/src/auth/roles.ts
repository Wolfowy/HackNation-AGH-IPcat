import type { Role } from '@/api/types'

/** Mirrors backend policies (Kernel/Security): hierarchical roles Administrator ⊃ Manager ⊃ Editor ⊃ Viewer. */
export type Permission = 'read' | 'edit' | 'manage' | 'admin'

const roleRank: Record<Role, number> = { Viewer: 1, Editor: 2, Manager: 3, Administrator: 4 }
const permissionRank: Record<Permission, number> = { read: 1, edit: 2, manage: 3, admin: 4 }

export function highestRank(roles: readonly string[] | undefined): number {
  return Math.max(0, ...(roles ?? []).map((r) => roleRank[r as Role] ?? 0))
}

export function hasPermission(roles: readonly string[] | undefined, permission: Permission): boolean {
  return highestRank(roles) >= permissionRank[permission]
}
