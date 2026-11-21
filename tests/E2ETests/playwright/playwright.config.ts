import { defineConfig, devices } from '@playwright/test'

/**
 * Projects:
 *  - mocked: starts the Vite dev server with VITE_USE_MOCKS=true (MSW in the browser, simulated live scans).
 *      npx playwright test --project=mocked
 *  - stack:  runs against a deployed stack (docker compose). No web server is started when BASE_URL is set.
 *      BASE_URL=https://localhost:8443 E2E_ADMIN_USER=admin E2E_ADMIN_PASSWORD=... npx playwright test --project=stack
 */
const stackUrl = process.env.BASE_URL
const mockPort = Number(process.env.E2E_MOCK_PORT ?? 5175)

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: { trace: 'retain-on-failure', screenshot: 'only-on-failure', acceptDownloads: true },
  projects: [
    { name: 'mocked', use: { ...devices['Desktop Chrome'], baseURL: `http://localhost:${mockPort}` } },
    { name: 'stack', use: { ...devices['Desktop Chrome'], baseURL: stackUrl ?? 'http://localhost:8080', ignoreHTTPSErrors: true } },
  ],
  webServer: stackUrl
    ? undefined
    : {
        command: `npm run dev -- --port ${mockPort} --strictPort`,
        cwd: '../../../src/Frontend',
        url: `http://localhost:${mockPort}`,
        env: { VITE_USE_MOCKS: 'true' },
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
})
