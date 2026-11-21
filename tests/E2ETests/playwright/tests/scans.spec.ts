import { ensureNetwork, expect, login, mainNav, unique, test } from './fixtures'

test.describe('scans', () => {
  test('starts a scan and shows live progress', async ({ page, admin, mocked }) => {
    test.setTimeout(120_000)
    await login(page, admin)
    const network = await ensureNetwork(page)

    await mainNav(page).getByRole('link', { name: 'Scans' }).click()
    await page.getByRole('link', { name: 'Start scan' }).click()
    const name = unique('e2e-scan')
    await page.getByLabel('Name').fill(name)
    const workflow = page.getByLabel('Workflow')
    await expect(workflow.locator('option')).not.toHaveCount(1)
    await workflow.selectOption({ index: 1 })
    await page.getByRole('checkbox', { name: new RegExp(network) }).check()
    await page.getByRole('button', { name: 'Start scan' }).click()

    await expect(page).toHaveURL(/\/scans\/[0-9a-f-]{36}$/)
    await expect(page.getByRole('heading', { name })).toBeVisible()
    await expect(page.getByRole('progressbar', { name: 'Scan progress' })).toBeVisible()
    await expect(page.getByTestId('hub-status')).toHaveAttribute('data-status', 'connected')

    if (mocked) {
      // The mock backend simulates agents: progress advances through SignalR events until the run completes.
      await expect.poll(async () => parseFloat((await page.getByTestId('scan-percent').textContent()) ?? '0'), { timeout: 30_000 }).toBeGreaterThan(0)
      await expect(page.getByTestId('scan-percent')).toHaveText('100%', { timeout: 60_000 })
      await expect(page.getByRole('heading', { name }).getByText('Completed')).toBeVisible({ timeout: 30_000 })
      await page.getByRole('tab', { name: 'Events' }).click()
      await expect(page.getByTestId('events-log')).toContainText('RunCompleted')
      await page.getByRole('tab', { name: 'Jobs' }).click()
      await expect(page.getByTestId('job-row').first()).toContainText('Completed')
    } else {
      await expect(page.getByRole('heading', { name }).getByText(/Pending|Running|Completed|PartiallyCompleted|Failed/)).toBeVisible()
    }
  })

  test('lists scans with a status filter', async ({ page, admin }) => {
    await login(page, admin)
    await mainNav(page).getByRole('link', { name: 'Scans' }).click()
    await expect(page.getByRole('heading', { name: 'Scans' })).toBeVisible()
    await page.getByLabel('Status').selectOption('Completed')
    await expect(page.getByRole('row').nth(1).or(page.getByText('No scans found.'))).toBeVisible()
  })
})
