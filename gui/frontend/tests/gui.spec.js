import { test, expect } from '@playwright/test'

// Only the Wails transport is mocked. The built Vue application is unchanged.
// No real ADB, application process, device identifier or private dump is used.
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    const listeners = {}
    window.__fixture = { params: null, failApps: false, failDump: false }
    window.runtime = {
      EventsOnMultiple: (name, callback) => { listeners[name] = callback },
    }
    window.go = { main: { App: {
      GetNhddPath: async () => 'nhdd',
      ConnectADB: async () => ['fixture-device'],
      GetAppList: async () => window.__fixture.failApps
        ? { packages: [], error: 'fixture list failure' }
        : { packages: ['com.example.fixture', 'com.example.remote'], error: '' },
      SelectDirectory: async () => './fixture-output',
      StartDump: async params => {
        window.__fixture.params = params
        if (window.__fixture.failDump) throw new Error('fixture capture failure')
        listeners['watch-progress']?.({ round: 2, newThis: 1, total: 2, dry: 1,
          dryLimit: 3, dedup: 0, processes: 1, dexFiles: 2, soFiles: 1, done: true })
        return { success: true, dexCount: 2, soCount: 1, outputDir: './fixture-output' }
      },
      RepackAPK: async () => ({ success: true, replacedDex: 2, outputApk: './fixture-output/analysis.apk' }),
    } } }
  })
  await page.goto('/')
})

test('startup and public metadata render without device access', async ({ page }) => {
  await expect(page.getByRole('heading', { name: 'NHDD', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'DUMP!', exact: true })).toBeDisabled()
  await expect(page.locator('.device-status')).toHaveText('未连接')
  await expect(page.locator('.info-label')).toHaveText('nhdd: nhdd')
  await expect(page.locator('.disclaimer')).not.toContainText('作者：')
  await expect(page.locator('.disclaimer a')).toHaveAttribute('href', 'https://github.com/Fruit-Guardians/NHDD')
  await expect(page.locator('.disclaimer a')).toHaveAttribute('rel', 'noopener noreferrer')
})

test('device, app search and selection survive the Vue upgrade', async ({ page }) => {
  await page.getByRole('button', { name: '连接', exact: true }).click()
  await expect(page.locator('.device-status')).toContainText('fixture-device')
  await page.getByRole('button', { name: '刷新', exact: true }).click()
  await expect(page.locator('.app-item')).toHaveCount(2)
  await page.getByPlaceholder('搜索应用包名...').fill('remote')
  await expect(page.locator('.app-item')).toHaveCount(1)
  await page.locator('.app-item').click()
  await expect(page.locator('.app-item')).toHaveClass(/selected/)
  await expect(page.getByRole('button', { name: 'DUMP!', exact: true })).toBeEnabled()
})

test('watch, JNI, directory and dump parameters keep their types and defaults', async ({ page }) => {
  await page.getByRole('button', { name: '刷新', exact: true }).click()
  await page.getByText('com.example.fixture', { exact: true }).click()
  await page.getByRole('button', { name: '浏览', exact: true }).click()
  await page.getByLabel('DEX', { exact: true }).check()
  await page.getByLabel('JNIMAP(Native方法扫描)', { exact: true }).check()
  await page.getByPlaceholder('留空=全部扫描, 如 libnative-lib.so').fill('libfixture.so')
  await page.locator('.form-group').filter({ hasText: '最小连续条目数:' }).getByRole('spinbutton').fill('1')
  await page.getByRole('button', { name: 'DUMP!', exact: true }).click()
  await expect(page.locator('.log-panel')).toContainText('脱壳完成! DEX: 2, SO: 1')
  const params = await page.evaluate(() => window.__fixture.params)
  expect(params).toMatchObject({ package: 'com.example.fixture', mode: 'dex',
    outputDir: './fixture-output', watch: true, dryLimit: 3, maxSeconds: 120,
    maxRounds: 60, stealth2: true, relaxed: true, jniMap: true,
    jniLib: 'libfixture.so', jniMin: 1 })
  await expect(page.locator('.progress-panel')).toContainText('com.example.fixture')
  await page.getByRole('button', { name: '生成 jadx 分析 APK', exact: true }).click()
  await expect(page.locator('.log-panel')).toContainText('fixture-output/analysis.apk')
})

test('optional configuration visibility remains reactive', async ({ page }) => {
  const watch = page.getByLabel('启用watch监听(推荐)', { exact: true })
  await watch.uncheck()
  await expect(page.getByText('最大运行秒数:', { exact: true })).not.toBeVisible()
  await watch.check()
  await expect(page.getByText('最大运行秒数:', { exact: true })).toBeVisible()
  await page.getByLabel('JNIMAP(Native方法扫描)', { exact: true }).check()
  await expect(page.getByPlaceholder('留空=全部扫描, 如 libnative-lib.so')).toBeVisible()
})

test('list failures are visible and do not enable dumping', async ({ page }) => {
  await page.evaluate(() => { window.__fixture.failApps = true })
  await page.getByRole('button', { name: '刷新', exact: true }).click()
  await expect(page.locator('.log-panel')).toContainText('fixture list failure')
  await expect(page.getByRole('button', { name: 'DUMP!', exact: true })).toBeDisabled()
})

test('capture errors recover controls without claiming success', async ({ page }) => {
  await page.getByRole('button', { name: '刷新', exact: true }).click()
  await page.getByText('com.example.fixture', { exact: true }).click()
  await page.evaluate(() => { window.__fixture.failDump = true })
  await page.getByRole('button', { name: 'DUMP!', exact: true }).click()
  await expect(page.locator('.log-panel')).toContainText('fixture capture failure')
  await expect(page.getByRole('button', { name: 'DUMP!', exact: true })).toBeEnabled()
  await expect(page.getByRole('button', { name: '生成 jadx 分析 APK', exact: true })).not.toBeVisible()
})
