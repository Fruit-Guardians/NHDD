import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests',
  outputDir: '../../NHDD-cpp-modular/.test-bin/ui-tests',
  fullyParallel: true,
  use: { baseURL: 'http://127.0.0.1:4179', viewport: { width: 1100, height: 780 } },
  webServer: {
    command: 'npm run preview -- --host 127.0.0.1 --port 4179 --strictPort',
    url: 'http://127.0.0.1:4179',
    reuseExistingServer: false,
  },
})
