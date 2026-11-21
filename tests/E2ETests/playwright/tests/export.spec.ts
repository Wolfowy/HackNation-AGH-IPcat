import { readFile } from 'node:fs/promises'
import { expect, login, mainNav, test } from './fixtures'

test.describe('export', () => {
  test('downloads hosts as CSV', async ({ page, admin, mocked }) => {
    await login(page, admin)
    await mainNav(page).getByRole('link', { name: 'Hosts' }).click()
    await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible()

    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export CSV' }).click()])
    expect(download.suggestedFilename()).toMatch(/\.csv$/)
    const text = await readFile((await download.path())!, 'utf8')
    if (mocked) {
      const [header, ...rows] = text.trim().split('\n')
      expect(header).toContain('address')
      expect(rows.length).toBeGreaterThan(0)
    }
  })

  test('downloads networks as JSON', async ({ page, admin }) => {
    await login(page, admin)
    await mainNav(page).getByRole('link', { name: 'Networks' }).click()
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export JSON' }).click()])
    expect(download.suggestedFilename()).toMatch(/\.json$/)
    const parsed: unknown = JSON.parse(await readFile((await download.path())!, 'utf8'))
    expect(Array.isArray(parsed) || typeof parsed === 'object').toBe(true)
  })
})
