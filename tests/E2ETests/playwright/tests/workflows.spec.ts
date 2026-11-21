import { expect, login, mainNav, test, unique } from './fixtures'

test.describe('workflow editor', () => {
  test.use({ viewport: { width: 1366, height: 768 } })

  test('creates a workflow visually: palette, connect, parameter, validate, save', async ({ page, admin }) => {
    await login(page, admin)
    await mainNav(page).getByRole('link', { name: 'Workflows' }).click()
    await page.getByRole('link', { name: 'New workflow' }).click()
    await page.getByRole('link', { name: /Empty workflow/ }).click()

    const key = unique('e2e-wf')
    await page.getByLabel('Key').fill(key)
    await page.getByLabel('Name', { exact: true }).fill('E2E visual workflow')

    await page.getByRole('button', { name: 'Add DiscoverHosts' }).click()
    await page.getByRole('button', { name: 'Add ScanPorts' }).click()
    await expect(page.getByTestId('step-node-discoverHosts')).toBeVisible()
    await expect(page.getByTestId('step-node-scanPorts')).toBeVisible()

    // Drag from DiscoverHosts' output handle to ScanPorts' input handle.
    const source = page.locator('.react-flow__node[data-id="discoverHosts"] .react-flow__handle.source')
    const target = page.locator('.react-flow__node[data-id="scanPorts"] .react-flow__handle.target')
    const from = (await source.boundingBox())!
    const to = (await target.boundingBox())!
    await page.mouse.move(from.x + from.width / 2, from.y + from.height / 2)
    await page.mouse.down()
    await page.mouse.move(to.x + to.width / 2, to.y + to.height / 2, { steps: 15 })
    await page.mouse.up()
    await expect(page.locator('.react-flow__edge[data-id="discoverHosts->scanPorts"]')).toHaveCount(1)

    await page.getByTestId('step-node-scanPorts').click()
    const inspector = page.getByTestId('step-inspector')
    await expect(inspector.getByRole('checkbox', { name: 'discoverHosts' }).first()).toBeChecked()
    await inspector.getByLabel('ports', { exact: true }).fill('top-1000')
    await expect(page.getByTestId('step-node-scanPorts')).toContainText('ports=top-1000')

    await page.getByRole('button', { name: 'Validate' }).click()
    await expect(page.getByTestId('validation-result')).toContainText('Valid')

    await page.getByRole('button', { name: 'Save' }).click()
    await expect(page).toHaveURL(new RegExp(`/workflows/${key}$`))
    await expect(page.getByTestId('step-node-scanPorts')).toBeVisible()
    await page.getByRole('tab', { name: 'JSON' }).click()
    await expect(page.getByTestId('workflow-json')).toContainText('"ports": "top-1000"')
  })

  test('blocks switching back from invalid JSON and highlights validation errors on nodes', async ({ page, admin }) => {
    await login(page, admin)
    await mainNav(page).getByRole('link', { name: 'Workflows' }).click()
    await page.getByRole('link', { name: 'New workflow' }).click()
    await page.getByRole('link', { name: /Copy of Standard discovery/ }).click()
    await expect(page.getByTestId('step-node-http')).toBeVisible()

    await page.getByRole('tab', { name: 'JSON' }).click()
    const json = page.getByLabel('Definition (JSON)')
    const text = await json.inputValue()
    await json.fill(text.replace('"steps": [', '"steps": '))
    await page.getByRole('tab', { name: 'Visual editor' }).click()
    await expect(page.getByRole('alert').filter({ hasText: 'Fix the JSON before switching back' })).toBeVisible()

    await json.fill(text.replace('"ports": "top-1000"', '"ports": "top-1000", "bogus": "1"'))
    await page.getByRole('tab', { name: 'Visual editor' }).click()
    await page.getByRole('button', { name: 'Validate' }).click()
    await expect(page.getByTestId('validation-result')).toContainText('error')
    await expect(page.getByTestId('step-node-ports').getByLabel(/validation error/)).toBeVisible()
  })
})
