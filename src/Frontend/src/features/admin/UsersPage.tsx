import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { Plus } from 'lucide-react'
import { toast } from 'sonner'
import { useCreateUser, useDeleteUser, useResetPassword, useUpdateUser, useUsers } from '@/api/admin'
import { ROLES, type Role, type User } from '@/api/types'
import { useAuth } from '@/auth/AuthProvider'
import { ConfirmButton } from '@/components/actions'
import { Loadable } from '@/components/feedback'
import { CheckboxField, FormField, submitHandler } from '@/components/form'
import { Chips, PageHeader } from '@/components/page'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input, NativeSelect } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { t } from '@/i18n/strings'
import { formatDateTime } from '@/lib/format'

const MIN_PASSWORD = 12

interface UserValues {
  userName: string
  displayName: string
  password: string
  role: Role
  isActive: boolean
}

function UserDialog({ user, onClose }: { user?: User; onClose: () => void }) {
  const create = useCreateUser()
  const update = useUpdateUser()
  const form = useForm<UserValues>({
    defaultValues: {
      userName: user?.userName ?? '',
      displayName: user?.displayName ?? '',
      password: '',
      role: user?.roles[0] ?? 'Viewer',
      isActive: user?.isActive ?? true,
    },
  })
  const { register, formState, watch, setValue } = form
  const errors = formState.errors
  // Roles are hierarchical on the server, so one role per user is enough.
  const submit = submitHandler(form, async (v) => {
    const common = { displayName: v.displayName.trim(), roles: [v.role], isActive: v.isActive }
    if (user) await update.mutateAsync({ id: user.id, ...common })
    else await create.mutateAsync({ ...common, userName: v.userName.trim(), password: v.password })
    toast.success(t.common.saved)
    onClose()
  })

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{user ? `Edit ${user.userName}` : t.admin.createUser}</DialogTitle>
        </DialogHeader>
        <form className="grid gap-4" onSubmit={submit} noValidate>
          {!user && (
            <FormField label="User name" error={errors.userName?.message}>
              <Input
                autoComplete="off"
                {...register('userName', {
                  required: 'User name is required.',
                  pattern: { value: /^[A-Za-z0-9_.@-]{3,64}$/, message: '3–64 letters, digits or _ . @ -' },
                })}
              />
            </FormField>
          )}
          <FormField label="Display name" error={errors.displayName?.message}>
            <Input {...register('displayName', { required: 'Display name is required.' })} />
          </FormField>
          {!user && (
            <FormField label="Initial password" hint={`At least ${MIN_PASSWORD} characters.`} error={errors.password?.message}>
              <Input
                type="password"
                autoComplete="new-password"
                {...register('password', { required: 'Password is required.', minLength: { value: MIN_PASSWORD, message: `At least ${MIN_PASSWORD} characters.` } })}
              />
            </FormField>
          )}
          <FormField label="Role" hint="Administrator ⊃ Manager ⊃ Editor ⊃ Viewer" error={errors.role?.message}>
            <NativeSelect {...register('role')}>
              {ROLES.map((r) => (
                <option key={r}>{r}</option>
              ))}
            </NativeSelect>
          </FormField>
          <CheckboxField label="Active" checked={watch('isActive')} onChange={(v) => setValue('isActive', v)} />
          <DialogFooter>
            <Button type="submit" disabled={formState.isSubmitting}>
              {t.common.save}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ResetPasswordDialog({ user, onClose }: { user: User; onClose: () => void }) {
  const reset = useResetPassword()
  const [password, setPassword] = useState('')
  const tooShort = password.length < MIN_PASSWORD
  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset password for {user.userName}</DialogTitle>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault()
            reset.mutate(
              { id: user.id, password },
              {
                onSuccess: () => {
                  toast.success('Password reset')
                  onClose()
                },
              },
            )
          }}
        >
          <FormField label="New password" hint={`At least ${MIN_PASSWORD} characters.`}>
            <Input type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </FormField>
          <DialogFooter>
            <Button type="submit" disabled={tooShort || reset.isPending}>
              Reset password
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export function UsersPage() {
  const users = useUsers()
  const remove = useDeleteUser()
  const { user: me } = useAuth()
  const [editing, setEditing] = useState<User | null | undefined>(undefined)
  const [resetting, setResetting] = useState<User | null>(null)

  return (
    <>
      <PageHeader
        title={t.admin.users}
        actions={
          <Button onClick={() => setEditing(null)}>
            <Plus /> {t.admin.createUser}
          </Button>
        }
      />
      <Loadable query={users}>
        {(list) => (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Roles</TableHead>
                <TableHead>State</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Last login</TableHead>
                <TableHead className="text-right">{t.common.actions}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((u) => (
                <TableRow key={u.id}>
                  <TableCell>
                    <div className="font-medium">{u.displayName}</div>
                    <div className="text-muted-foreground text-xs">{u.userName}</div>
                  </TableCell>
                  <TableCell>
                    <Chips values={u.roles} />
                  </TableCell>
                  <TableCell>{u.isActive === false ? <Badge variant="outline">Inactive</Badge> : <Badge variant="success">Active</Badge>}</TableCell>
                  <TableCell className="text-muted-foreground">{formatDateTime(u.createdAt)}</TableCell>
                  <TableCell className="text-muted-foreground">{formatDateTime(u.lastLoginAt)}</TableCell>
                  <TableCell className="space-x-2 text-right whitespace-nowrap">
                    <Button size="sm" variant="outline" onClick={() => setEditing(u)}>
                      {t.common.edit}
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setResetting(u)}>
                      Reset password
                    </Button>
                    {u.id !== me?.id && (
                      <ConfirmButton
                        size="sm"
                        variant="outline"
                        title={t.common.confirmDelete(`user ${u.userName}`)}
                        confirmLabel={t.common.delete}
                        onConfirm={() => remove.mutateAsync(u.id)}
                      >
                        {t.common.delete}
                      </ConfirmButton>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Loadable>
      {editing !== undefined && <UserDialog key={editing?.id ?? 'new'} user={editing ?? undefined} onClose={() => setEditing(undefined)} />}
      {resetting && <ResetPasswordDialog user={resetting} onClose={() => setResetting(null)} />}
    </>
  )
}
