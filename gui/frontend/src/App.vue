<template>
  <div class="app">
    <!-- Header: Logo + ADB settings -->
    <header class="header">
      <div class="logo">
        <h1>NHDD</h1>
        <span class="tagline">No-Hook DEX/SO Dumper</span>
      </div>
      <div class="adb-row">
        <label>ADB路径:</label>
        <input v-model="adbPath" placeholder="adb" />
        <label>Host:Port:</label>
        <input v-model="hostPort" placeholder="192.168.238.1:5037" />
        <button class="btn btn-primary" @click="connectADB" :disabled="connecting">
          {{ connecting ? '连接中...' : '连接' }}
        </button>
        <span class="device-status" :class="{ connected: deviceLabel !== '未连接' }">
          {{ deviceLabel }}
        </span>
      </div>
    </header>

    <!-- Main content -->
    <div class="main">
      <!-- Left: App list -->
      <div class="app-list-panel">
        <div class="search-row">
          <input v-model="searchText" placeholder="搜索应用包名..." @input="filterApps" />
          <button class="btn" @click="refreshApps" :disabled="refreshing">
            {{ refreshing ? '加载中...' : '刷新' }}
          </button>
        </div>
        <div class="app-list">
          <div
            v-for="pkg in filteredPackages"
            :key="pkg"
            class="app-item"
            :class="{ selected: selectedPkg === pkg }"
            @click="selectedPkg = pkg"
          >
            {{ pkg }}
          </div>
          <div v-if="filteredPackages.length === 0" class="empty-hint">
            {{ packages.length === 0 ? '点击刷新加载应用列表' : '无匹配结果' }}
          </div>
        </div>
      </div>

      <!-- Right: Config panel -->
      <div class="config-panel">
        <h3>脱壳配置</h3>
        <div class="form-group">
          <label>SU命令:</label>
          <input v-model="suCmd" placeholder="留空=普通shell, 或 su -c / kp -c / ksud -c" />
        </div>
        <div class="form-group">
          <label>PC输出目录:</label>
          <div class="dir-input">
            <input v-model="outputDir" placeholder="./nhdd_output" />
            <button class="btn btn-sm" @click="selectDir">浏览</button>
          </div>
        </div>
        <div class="form-group">
          <label>Dump模式:</label>
          <div class="radio-group">
            <label><input type="radio" v-model="mode" value="dex" /> DEX</label>
            <label><input type="radio" v-model="mode" value="so" /> SO</label>
            <label><input type="radio" v-model="mode" value="all" /> ALL</label>
          </div>
        </div>
        <div class="form-group">
          <label><input type="checkbox" v-model="restart" /> 重启app再扫</label>
          <span class="hint">强对抗壳建议不重启，直接扫当前进程</span>
        </div>
        <div class="form-group">
          <label><input type="checkbox" v-model="watch" /> 启用watch监听(推荐)</label>
        </div>
        <div v-if="watch" class="sub-config">
          <div class="form-group">
            <label>连续几轮无新DEX停止:</label>
            <input type="number" v-model.number="dryLimit" min="1" max="20" />
          </div>
          <div class="form-group">
            <label>最大运行秒数:</label>
            <input type="number" v-model.number="maxSeconds" min="10" max="600" />
          </div>
          <div class="form-group">
            <label>最大轮数:</label>
            <input type="number" v-model.number="maxRounds" min="1" max="200" />
          </div>
        </div>
        <div class="form-group">
          <label><input type="checkbox" v-model="stealth" /> 启用stealth(区域间延时)</label>
        </div>
        <div v-if="stealth" class="sub-config">
          <div class="form-group">
            <label>区域延时(ms):</label>
            <input type="number" v-model.number="regionDelayMs" min="0" max="100" />
          </div>
        </div>
        <div class="form-group">
          <label><input type="checkbox" v-model="stealth2" /> stealth2(process_vm_readv反检测)</label>
          <span class="hint">避免壳检测/proc/pid/mem被打开，二代壳推荐</span>
        </div>
        <div class="form-group">
          <label><input type="checkbox" v-model="relaxed" /> relaxed(宽松DEX验证)</label>
          <span class="hint">通过endian_tag验证，不依赖被抹除的magic</span>
        </div>
        <div class="form-group">
          <label><input type="checkbox" v-model="anon" /> anon(仅扫描匿名映射)</label>
        </div>

        <div class="info-section">
          <span class="info-label">nhdd: {{ nhddPath }}</span>
        </div>

        <div class="disclaimer">
          免责声明：本工具仅用于合法授权的安全研究、逆向分析与自有应用调试。
        </div>
      </div>
    </div>

    <!-- Watch progress panel -->
    <div v-if="showProgress" class="progress-panel">
      <div class="progress-stats">
        <div class="stat-item">
          <span class="stat-label">目标</span>
          <span class="stat-value">{{ selectedPkg }}</span>
        </div>
        <div class="stat-item">
          <span class="stat-label">进程数</span>
          <span class="stat-value">{{ progress.processes }}</span>
        </div>
        <div class="stat-item">
          <span class="stat-label">当前轮次</span>
          <span class="stat-value">{{ progress.round }}</span>
        </div>
        <div class="stat-item">
          <span class="stat-label">本轮新增</span>
          <span class="stat-value highlight">+{{ progress.newThis }}</span>
        </div>
        <div class="stat-item">
          <span class="stat-label">累计唯一DEX</span>
          <span class="stat-value highlight">{{ progress.total }}</span>
        </div>
        <div class="stat-item">
          <span class="stat-label">去重跳过</span>
          <span class="stat-value">{{ progress.dedup }}</span>
        </div>
        <div class="stat-item">
          <span class="stat-label">稳定集dry</span>
          <span class="stat-value" :class="progress.dry > 0 ? 'warning' : ''">
            {{ progress.dry }}/{{ progress.dryLimit }}
          </span>
        </div>
      </div>
      <div class="progress-bar-container">
        <div
          class="progress-bar"
          :style="{ width: Math.min(progress.dry / progress.dryLimit * 100, 100) + '%' }"
        ></div>
      </div>
    </div>

    <!-- Bottom: DUMP button + Log -->
    <div class="bottom">
      <button
        class="btn btn-dump"
        :disabled="dumping || !selectedPkg"
        @click="startDump"
      >
        {{ dumping ? '脱壳中...' : 'DUMP!' }}
      </button>
      <div class="log-panel" ref="logPanel">
        <div v-for="(line, i) in logLines" :key="i" class="log-line">{{ line }}</div>
        <div v-if="logLines.length === 0" class="log-empty">等待操作...</div>
      </div>
    </div>
  </div>
</template>

<script>
import { ConnectADB, GetAppList, StartDump, SelectDirectory, GetNhddPath } from '../wailsjs/go/main/App.js'
import { EventsOn } from '../wailsjs/runtime/runtime.js'

export default {
  data() {
    return {
      // ADB
      adbPath: 'adb',
      hostPort: '',
      deviceLabel: '未连接',
      connecting: false,

      // App list
      packages: [],
      filteredPackages: [],
      searchText: '',
      selectedPkg: '',
      refreshing: false,

      // Config
      suCmd: 'su -c',
      outputDir: './nhdd_output',
      mode: 'dex',
      restart: false,
      watch: true,
      dryLimit: 3,
      maxSeconds: 120,
      maxRounds: 60,
      stealth: false,
      stealth2: false,
      relaxed: false,
      anon: false,
      regionDelayMs: 2,

      // State
      dumping: false,
      logLines: [],
      showProgress: false,
      progress: {
        round: 0,
        newThis: 0,
        total: 0,
        dedup: 0,
        dry: 0,
        dryLimit: 3,
        processes: 0,
        dexFiles: 0,
        soFiles: 0,
        done: false,
      },
      nhddPath: '',
    }
  },

  mounted() {
    // 监听后端日志事件
    EventsOn('log', (msg) => {
      this.logLines.push(msg)
      this.$nextTick(() => {
        const panel = this.$refs.logPanel
        if (panel) panel.scrollTop = panel.scrollHeight
      })
    })

    // 监听 watch 进度事件
    EventsOn('watch-progress', (p) => {
      this.progress = { ...p }
      this.showProgress = true
    })

    // 获取 nhdd 路径
    GetNhddPath().then(p => { this.nhddPath = p })
  },

  methods: {
    async connectADB() {
      this.connecting = true
      try {
        const devices = await ConnectADB(this.adbPath, this.hostPort)
        if (devices && devices.length > 0) {
          this.deviceLabel = '已连接: ' + devices[0]
          this.addLog('已连接 ' + devices.length + ' 个设备: ' + devices.join(', '))
        } else {
          this.deviceLabel = '无设备'
          this.addLog('未发现设备')
        }
      } catch (e) {
        this.deviceLabel = '连接失败'
        this.addLog('连接失败: ' + e)
      }
      this.connecting = false
    },

    async refreshApps() {
      this.refreshing = true
      try {
        const result = await GetAppList(this.adbPath, this.hostPort)
        if (result.error) {
          this.addLog('加载应用失败: ' + result.error)
        } else {
          this.packages = result.packages || []
          this.filteredPackages = [...this.packages]
          this.addLog('已加载 ' + this.packages.length + ' 个第三方应用')
        }
      } catch (e) {
        this.addLog('加载应用失败: ' + e)
      }
      this.refreshing = false
    },

    filterApps() {
      const search = this.searchText.toLowerCase()
      if (!search) {
        this.filteredPackages = [...this.packages]
      } else {
        this.filteredPackages = this.packages.filter(p => p.toLowerCase().includes(search))
      }
    },

    async selectDir() {
      try {
        const dir = await SelectDirectory()
        if (dir) this.outputDir = dir
      } catch (e) {
        // 用户取消
      }
    },

    async startDump() {
      if (!this.selectedPkg) return
      this.dumping = true
      this.showProgress = true
      this.progress = {
        round: 0, newThis: 0, total: 0, dedup: 0, dry: 0, dryLimit: this.dryLimit,
        processes: 0, dexFiles: 0, soFiles: 0, done: false,
      }

      try {
        const result = await StartDump({
          package: this.selectedPkg,
          suCmd: this.suCmd,
          outputDir: this.outputDir,
          adbPath: this.adbPath,
          hostPort: this.hostPort,
          mode: this.mode,
          restart: this.restart,
          watch: this.watch,
          dryLimit: this.dryLimit,
          maxSeconds: this.maxSeconds,
          maxRounds: this.maxRounds,
          stealth: this.stealth,
          stealth2: this.stealth2,
          relaxed: this.relaxed,
          anon: this.anon,
          regionDelayMs: this.regionDelayMs,
        })

        if (result.success) {
          this.addLog('脱壳完成! DEX: ' + result.dexCount + ', SO: ' + result.soCount + ', 输出: ' + result.outputDir)
        } else {
          this.addLog('脱壳失败: ' + result.message)
        }
      } catch (e) {
        this.addLog('脱壳异常: ' + e)
      }

      this.dumping = false
    },

    addLog(msg) {
      const now = new Date()
      const ts = now.toTimeString().slice(0, 8)
      this.logLines.push('[' + ts + '] ' + msg)
      this.$nextTick(() => {
        const panel = this.$refs.logPanel
        if (panel) panel.scrollTop = panel.scrollHeight
      })
    },
  },
}
</script>
