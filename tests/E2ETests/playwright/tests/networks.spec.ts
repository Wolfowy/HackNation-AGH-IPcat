import { ensureNetwork, expect, login, test } from './fixtures'

test.describe('networks', () => {
  test('adds a network with ranges', async ({ page, admin }) => {
    await login(page, admin)
    const name = await ensureNetwork(page)
    const row = page.getByRole('row').filter({ hasText: name })
    await expect(row).toContainText('e2e')
    await expect(row).toContainText(/\d+\.\d+\.\d+\.\d+\/28/)
  })

  test('shows client-side format errors for invalid ranges', async ({ page, admin }) => {
    await login(page, admin)
    await page.getByRole('navigation', { name: 'Main' }).getByRole('link', { name: 'Networks' }).click()
    await page.getByRole('button', { name: 'Create network' }).click()
    const dialog = page.getByRole('dialog')
    await dialog.getByLabel('Name').fill('invalid')
    await dialog.getByLabel('Ranges').fill('10.0.0.300/24')
    await dialog.getByRole('button', { name: 'Save' }).click()
    await expect(dialog.getByText('"10.0.0.300/24": invalid CIDR address')).toBeVisible()
    await expect(dialog).toBeVisible()
  })
})
