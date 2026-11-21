import { setupWorker } from 'msw/browser'
import { getDb, handlers } from './handlers'
import { hubHandlers } from './hub'
import { enableSimulation } from './simulation'

export async function startMockWorker() {
  const worker = setupWorker(...handlers, ...hubHandlers)
  await worker.start({ onUnhandledRequest: 'bypass', quiet: true })
  enableSimulation(getDb())
  console.info('[WebScan] Mock API enabled (VITE_USE_MOCKS=true). Seeded users: admin, manager, editor, viewer.')
}
