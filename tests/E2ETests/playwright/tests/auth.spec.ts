import { expect, login, logout, test } from './fixtures'

test.describe('authentication', () => {
  test('signs in, shows the dashboard and signs out', async ({ page, admin }) => {
    await login(page, admin)
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
    await expect(page.getByTestId('current-user')).toContainText('Administrator')
    await expect(page.getByText('Hosts', { exact: true }).first()).toBeVisible()
    await logout(page)
    await expect(page).toHaveURL(/\/login$/)
  })

  test('rejects a wrong password', async ({ page, admin }) => {
    await page.goto('/login')
    await page.getByLabel('User name').fill(admin.userName)
    await page.getByLabel('Password').fill(`${admin.password}-wrong`)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByRole('alert')).toContainText('Invalid user name or password.')
  })

  test('redirects anonymous visitors to the login page', async ({ page }) => {
    await page.goto('/scans')
    await expect(page).toHaveURL(/\/login$/)
    await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
  })
})
