import { expect, login, mainNav, test } from './fixtures'

test.describe('inventory', () => {
  test('views hosts, a host detail, services and changes', async ({ page, admin, mocked }) => {
    await login(page, admin)

    await mainNav(page).getByRole('link', { name: 'Hosts' }).click()
    await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible()
    const hostRows = page.getByTestId('host-row')
    if (mocked) {
      await expect(hostRows.first()).toBeVisible()
      await page.getByLabel('Status').selectOption('Active')
      await expect(hostRows.first()).toContainText('Active')
      const address = (await hostRows.first().getByRole('link').textContent())!.trim()
      await hostRows.first().getByRole('link').click()
      await expect(page.getByRole('heading', { name: new RegExp(address.replace(/\./g, '\\.')) })).toBeVisible()
      await expect(page.getByRole('tab', { name: /Services/ })).toBeVisible()
      await expect(page.getByTestId('service-row').first()).toBeVisible()
      await page.getByRole('tab', { name: /Technologies/ }).click()
      await expect(page.getByRole('progressbar', { name: 'Confidence' }).first()).toBeVisible()
    } else {
      await expect(hostRows.first().or(page.getByText('No hosts match the filters.'))).toBeVisible()
    }

    await mainNav(page).getByRole('link', { name: 'Services' }).click()
    await expect(page.getByRole('heading', { name: 'Services' })).toBeVisible()
    if (mocked) {
      await page.getByLabel('Port').fill('22')
      await expect(page.getByTestId('service-row').first()).toContainText('22/tcp')
    } else {
      await expect(page.getByTestId('service-row').first().or(page.getByText('No services.'))).toBeVisible()
    }

    await mainNav(page).getByRole('link', { name: 'Changes' }).click()
    await expect(page.getByRole('heading', { name: 'Changes' })).toBeVisible()
    if (mocked) {
      await page.getByLabel('Type').selectOption('NewPort')
      await expect(page.getByTestId('change-row').first()).toContainText('NewPort')
    } else {
      await expect(page.getByTestId('change-row').first().or(page.getByText('No changes.'))).toBeVisible()
    }
  })
})
