import { expect, login, mainNav, test } from './fixtures'

test.describe('topology map', () => {
  test('maps devices → zones → subnets → hosts with agent interfaces; devices and hosts open panels', async ({ page, admin, mocked }) => {
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
    await expect(page.getByTestId('topology-zone')).toHaveCount(3)

    // The seeded router MAC answers in office and lab: one device linked to both zones, each edge labelled with its IP there.
    const router = page.getByTestId('topology-device').filter({ hasText: '00:1E:BD:4A:10:01' })
    await expect(router).toContainText('2 zones')
    for (const [zone, ip] of [
      ['lab', '172.16.50.1'],
      ['office', '192.168.10.1'],
    ]) {
      await expect(page.getByTestId(`rf__edge-d:00:1E:BD:4A:10:01->z:${zone}`)).toContainText(ip)
    }
    await expect(page.getByTestId('topology-device').filter({ hasText: 'low confidence' })).toHaveCount(1) // Docker MAC
    await router.click()
    const devicePanel = page.getByTestId('topology-device-panel')
    await expect(devicePanel.getByRole('link', { name: '172.16.50.1' })).toHaveAttribute('href', /\/assets\/hosts\//)
    await devicePanel.getByRole('button', { name: 'Close device panel' }).click()

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
    await expect(page.getByTestId('topology-device')).toHaveCount(0) // no device has an interface in the DMZ
  })
})
