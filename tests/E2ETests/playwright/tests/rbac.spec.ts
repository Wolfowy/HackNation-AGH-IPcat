import { expect, login, logout, mainNav, navigate, unique, test } from './fixtures'

test.describe('role-based access', () => {
  test('a viewer cannot see admin pages or mutating actions', async ({ page, admin }) => {
    // Create the viewer through the UI (works for mocks and the real stack alike).
    await login(page, admin)
    await mainNav(page).getByRole('link', { name: 'Users' }).click()
    await page.getByRole('button', { name: 'Create user' }).click()
    const viewer = { userName: unique('e2e-viewer'), password: `E2e!${Math.random().toString(36).slice(2)}${Date.now()}` }
    const dialog = page.getByRole('dialog')
    await dialog.getByLabel('User name').fill(viewer.userName)
    await dialog.getByLabel('Display name').fill('E2E Viewer')
    await dialog.getByLabel('Initial password').fill(viewer.password)
    await dialog.getByLabel('Role').selectOption('Viewer')
    await dialog.getByRole('button', { name: 'Save' }).click()
    await expect(dialog).toBeHidden()
    await expect(page.getByText(viewer.userName)).toBeVisible()
    await logout(page)

    // Sign in again without reloading (the mocked backend keeps state in page memory).
    await page.getByLabel('User name').fill(viewer.userName)
    await page.getByLabel('Password').fill(viewer.password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByTestId('current-user')).toContainText('Viewer')

    const nav = mainNav(page)
    await expect(nav.getByRole('link', { name: 'Hosts' })).toBeVisible()
    for (const adminLink of ['Users', 'Audit log', 'Settings', 'Integrations']) await expect(nav.getByRole('link', { name: adminLink })).toHaveCount(0)

    await navigate(page, '/admin/users')
    await expect(page.getByTestId('forbidden')).toBeVisible()
    await navigate(page, '/admin/audit')
    await expect(page.getByTestId('forbidden')).toBeVisible()

    await nav.getByRole('link', { name: 'Networks' }).click()
    await expect(page.getByRole('heading', { name: 'Networks' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Create network' })).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Export CSV' })).toBeVisible()

    await nav.getByRole('link', { name: 'Scans' }).click()
    await expect(page.getByRole('heading', { name: 'Scans' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Start scan' })).toHaveCount(0)

    await nav.getByRole('link', { name: 'Agents' }).click()
    await expect(page.getByRole('tab', { name: 'Enrollment tokens' })).toHaveCount(0)
  })
})
