import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { sessionStore } from '@/api/session'
import { resetDb } from '@/mocks/handlers'
import { server } from '@/mocks/node'
import { fakeHub } from './fakeSignalR'

vi.mock('@microsoft/signalr', () => import('./fakeSignalR'))

// jsdom gaps used by Radix / sonner.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.matchMedia ??= ((query: string) => ({
  matches: false,
  media: query,
  onchange: null,
  addEventListener: () => {},
  removeEventListener: () => {},
  addListener: () => {},
  removeListener: () => {},
  dispatchEvent: () => false,
})) as typeof window.matchMedia
Element.prototype.scrollIntoView ??= () => {}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  cleanup()
  server.resetHandlers()
  resetDb()
  sessionStore.clear()
  fakeHub.reset()
})
afterAll(() => server.close())
