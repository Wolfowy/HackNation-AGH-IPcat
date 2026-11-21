import { expect, login, mainNav, unique, test } from './fixtures'

const template = (id: string, extra = '') => `id: ${id}

info:
  name: E2E panel detection
  author: e2e
  severity: info
  tags: panel,e2e

http:
  - method: GET
    path:
      - "{{BaseURL}}/e2e-panel"
    matchers:
      - type: word
        words:
          - "E2E Panel"
${extra}`

test.describe('signatures', () => {
  test('creates a Nuclei template after validation', async ({ page, admin }) => {
    await login(page, admin)
    await mainNav(page).getByRole('link', { name: 'Signatures' }).click()
    await page.getByRole('link', { name: 'New signature' }).click()

    const id = unique('e2e-sig')
    await page.getByLabel('Signature id').fill(id)
    await page.getByLabel('Name', { exact: true }).fill('E2E panel detection')
    await page.getByLabel('Kind').selectOption('NucleiTemplate')

    const content = page.getByLabel('Content (YAML)')
    await content.fill(template(id, 'code:\n  - engine:\n      - sh\n    source: id\n'))
    await page.getByRole('button', { name: 'Validate' }).click()
    const result = page.getByTestId('validation-result')
    await expect(result.getByText(/\d+ errors?/)).toBeVisible()
    await expect(result).toContainText(/code/i)

    await content.fill(template(id))
    await page.getByRole('button', { name: 'Validate' }).click()
    await expect(result.getByText('Valid', { exact: true })).toBeVisible()

    await page.getByRole('button', { name: 'Save' }).click()
    await expect(page).toHaveURL(new RegExp(`/signatures/${id}$`))
    await expect(page.getByRole('heading', { name: 'E2E panel detection' })).toContainText('Draft')
    await expect(page.getByTestId('signature-content')).toContainText(`id: ${id}`)
  })
})
