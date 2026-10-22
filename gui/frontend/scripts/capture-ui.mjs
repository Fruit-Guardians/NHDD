import { chromium } from '@playwright/test'
import { preview } from 'vite'
import { mkdir } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

// Capture the real built frontend in its no-device state. This is a documented
// browser preview, not a fabricated native window or a device capture result.
const directory = fileURLToPath(new URL('../../../NHDD-cpp-modular/assets/screenshots/', import.meta.url))
await mkdir(directory, { recursive: true })
const server = await preview({ preview: { host: '127.0.0.1', port: 4180, strictPort: true } })
const browser = await chromium.launch()
try {
  const page = await browser.newPage({ viewport: { width: 1100, height: 780 }, deviceScaleFactor: 1 })
  await page.addInitScript(() => {
    window.runtime = { EventsOnMultiple: () => {} }
    window.go = { main: { App: { GetNhddPath: async () => 'nhdd' } } }
  })
  await page.goto('http://127.0.0.1:4180')
  await page.getByRole('heading', { name: 'NHDD', exact: true }).waitFor()
  await page.screenshot({ path: directory + '/gui.png' })
} finally {
  await browser.close()
  await new Promise(resolve => server.httpServer.close(resolve))
}
