import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import './index.css'
import { applyInitialTheme } from './lib/theme'

applyInitialTheme()

async function enableMocks() {
  if (import.meta.env.VITE_USE_MOCKS !== 'true') return
  try {
    const { startMockWorker } = await import('./mocks/browser')
    await startMockWorker()
  } catch (err) {
    console.error('[WebScan] Mock API could not start; requests go to the real API.', err)
  }
}

void enableMocks().then(() => {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
})
