import { createApp } from 'vue'
import App from './App.vue'
import { saveOverride } from './lib/mock-dns.js'
import './styles/main.css'

/**
 * 启动时把样例邮件对应的真实 DKIM 公钥装入 mock DNS 覆盖层。
 * 失败(如离线构建环境)不影响应用启动,内置占位记录仍可演示"无有效公钥"分支。
 */
async function bootstrap() {
  try {
    const resp = await fetch('samples/dkim-keys.json')
    if (resp.ok) {
      const keys = await resp.json()
      const existing = JSON.parse(localStorage.getItem('pmc.mock-dns.v1') || '{}')
      let changed = false
      for (const [name, record] of Object.entries(keys)) {
        if (!existing[name]) {
          existing[name] = { TXT: [record] }
          changed = true
        }
      }
      if (changed) saveOverride(existing)
    }
  } catch {
    /* 忽略,使用内置基线 */
  }
  createApp(App).mount('#app')
}

bootstrap()
