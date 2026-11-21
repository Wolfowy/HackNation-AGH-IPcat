import { expect, login, mainNav, test } from './fixtures'

test.describe('inventory graph', () => {
  test('shows network → host → port cards; port links open in a new tab; host card opens the detail', async ({ page, admin, mocked }) => {
    await login(page, admin)
    await mainNav(page).getByRole('link', { name: 'Graph' }).click()
    await expect(page.getByRole('heading', { name: 'Inventory graph' })).toBeVisible()
    await expect(page.getByTestId('graph-legend')).toContainText('Web server')

    if (!mocked) {
      await expect(page.getByTestId('graph-host').first().or(page.getByText('No hosts match the filters.'))).toBeVisible()
      return
    }

    await expect(page.getByTestId('graph-network').first()).toBeVisible()
    const port = page.getByTestId('graph-port').first()
    await expect(port).toBeVisible()
    const link = port.getByTestId('endpoint-link')
    await expect(link).toHaveAttribute('target', '_blank')
    await expect(link).toHaveAttribute('rel', 'noopener noreferrer')
    await expect(link).toHaveAttribute('href', /^https?:\/\//)

    const hosts = page.getByTestId('graph-host')
    const total = await hosts.count()
    await page.getByLabel('Only hosts with open ports').check()
    await expect.poll(() => hosts.count()).toBeLessThan(total)

    await page.getByLabel('Zone').selectOption('lab')
    await expect(page.getByTestId('graph-network')).toHaveCount(1)
    await hosts.first().click()
    await expect(page).toHaveURL(/\/assets\/hosts\/[0-9a-f-]+$/)
    await expect(page.getByRole('tab', { name: /Services/ })).toBeVisible()
  })
})
