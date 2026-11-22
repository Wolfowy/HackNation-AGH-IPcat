import { expect, test as base, type Page } from '@playwright/test'

export interface Credentials {
  userName: string
  password: string
}

/** Mocked project: seeded MSW users (src/Frontend/src/mocks/data.ts). Stack project: E2E_ADMIN_USER / E2E_ADMIN_PASSWORD. */
function adminCredentials(mocked: boolean): Credentials {
  const userName = process.env.E2E_ADMIN_USER ?? (mocked ? 'admin' : undefined)
  const password = process.env.E2E_ADMIN_PASSWORD ?? (mocked ? 'webscan' : undefined)
  if (!userName || !password) throw new Error('Set E2E_ADMIN_USER and E2E_ADMIN_PASSWORD for the stack project.')
  return { userName, password }
}

export const unique = (prefix: string) => `${prefix}-${Date.now().toString(36)}${Math.floor(Math.random() * 1e4)}`

export async function login(page: Page, { userName, password }: Credentials) {
  await page.goto('/login')
  await page.getByLabel('User name').fill(userName)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByTestId('current-user')).toBeVisible()
}

export async function logout(page: Page) {
  await page.getByRole('button', { name: 'Log out' }).click()
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
}

/** Client-side navigation (no reload): the mocked project keeps its in-memory data across pages this way. */
export async function navigate(page: Page, path: string) {
  await page.evaluate((p) => {
    window.history.pushState({}, '', p)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
  await expect(page).toHaveURL(new RegExp(`${path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`))
}

export const mainNav = (page: Page) => page.getByRole('navigation', { name: 'Main' })

/** A random /28 inside the first allowed IPv4 CIDR (prefix <= 28) of the scope policy, if any. */
export function rangeInside(allowed: string[]): string | null {
  const cidr = allowed.map((a) => a.trim()).find((a) => /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(a) && Number(a.split('/')[1]) <= 28)
  if (!cidr) return null
  const [ip, bits] = cidr.split('/')
  const base = ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0) >>> 0
  const size = 2 ** (32 - Number(bits))
  const offset = Math.floor((Math.random() * size) / 16) * 16
  const n = (base - (base % size) + offset) >>> 0
  return `${[24, 16, 8, 0].map((sh) => (n >>> sh) & 255).join('.')}/28`
}

/**
 * Makes sure an e2e zone and one network exist; returns the network name. The network range is placed inside the
 * existing scope policy; the policy is only extended when it has no IPv4 CIDR to place it in (never on an empty policy).
 */
export async function ensureNetwork(page: Page): Promise<string> {
  await mainNav(page).getByRole('link', { name: 'Networks' }).click()

  await page.getByRole('tab', { name: 'Scope policy' }).click()
  const allowedField = page.getByLabel('Allowed', { exact: true })
  const allowed = (await allowedField.inputValue()).split('\n').filter((l) => l.trim())
  let range = rangeInside(allowed)
  if (!range) {
    range = `10.250.${Math.floor(Math.random() * 250)}.0/28`
    if (allowed.length > 0) {
      await allowedField.fill([...allowed, '10.250.0.0/16'].join('\n'))
      await page.getByRole('button', { name: 'Save scope policy' }).click()
      await expect(page.getByText('Saved').first()).toBeVisible()
    }
  }

  await page.getByRole('tab', { name: 'Zones' }).click()
  await expect(page.getByRole('columnheader', { name: 'Zone', exact: true })).toBeVisible()
  if (!(await page.getByRole('cell', { name: 'e2e', exact: true }).isVisible())) {
    await page.getByLabel('Zone name').fill('e2e')
    await page.getByRole('button', { name: 'Add zone' }).click()
    await expect(page.getByRole('cell', { name: 'e2e', exact: true })).toBeVisible()
  }

  await page.getByRole('tab', { name: 'Networks', exact: true }).click()
  const name = unique('e2e-net')
  await page.getByRole('button', { name: 'Create network' }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Name').fill(name)
  await dialog.getByLabel('Zone').selectOption('e2e')
  await dialog.getByLabel('Ranges').fill(range)
  await dialog.getByRole('button', { name: 'Save' }).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByRole('cell', { name })).toBeVisible()
  return name
}

export const test = base.extend<{ mocked: boolean; admin: Credentials }>({
  mocked: async ({}, use, testInfo) => use(testInfo.project.name === 'mocked'),
  admin: async ({ mocked }, use) => use(adminCredentials(mocked)),
})

export { expect }
