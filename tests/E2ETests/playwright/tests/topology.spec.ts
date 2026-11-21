import { expect, login, mainNav, test } from './fixtures'

test.describe('topology map', () => {
  test('maps agent interfaces → subnets → hosts; a host opens its services panel', async ({ page, admin, mocked }) => {
    await login(page, admin)
    await mainNav(page).getByRole('link', { name: 'Topology' }).click()
    await expect(page.getByRole('heading', { name: 'Topology map' })).toBeVisible()
    await expect(page.getByTestId('graph-legend')).toContainText('Agent interface')

    if (!mocked) {
      await expect(page.getByTestId('topology-subnet').first().or(page.getByText('No hosts match the filters.'))).toBeVisible()
      return
    }

    await expect(page.getByTestId('topology-perspective')).toHaveCount(3)
    await expect(page.getByTestId('topology-subnet')).toHaveCount(4) // per zone: the lab reuses the DMZ range

    // A host with open ports (its label reads "N ports", N > 0).
    const host = page.getByTestId('topology-host').filter({ has: page.locator('div', { hasText: /^[1-9]\d* ports?/ }) }).first()
    await host.click()
    const panel = page.getByTestId('topology-host-panel')
    await expect(panel).toBeVisible()
    const endpoint = panel.getByTestId('endpoint-link').first()
    await expect(endpoint).toHaveAttribute('target', '_blank')
    await expect(endpoint).toHaveAttribute('href', /^https?:\/\//)
    await expect(panel.getByRole('link', { name: /Open host details/ })).toHaveAttribute('href', /\/assets\/hosts\//)

    await page.getByLabel('Zone').selectOption('dmz')
    await expect(page.getByTestId('topology-perspective')).toHaveCount(1)
    await expect(page.getByTestId('topology-subnet')).toHaveCount(1)
  })
})
