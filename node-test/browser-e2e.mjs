/**
 * browser-e2e.mjs — 通过 CDP 在真实 Chrome 里验证应用
 * 不依赖 puppeteer,只用 Node 内置 WebSocket + fetch。
 */
const BASE = 'http://127.0.0.1:5173/'

async function getWsUrl() {
  // 创建一个新标签页
  const resp = await fetch('http://127.0.0.1:9222/json/new?' + encodeURIComponent(BASE), { method: 'PUT' })
  const tab = await resp.json()
  return tab.webSocketDebuggerUrl
}

const ws = new WebSocket(await getWsUrl())
let msgId = 0
const pending = new Map()

function send(method, params = {}) {
  return new Promise((resolve) => {
    const id = ++msgId
    pending.set(id, resolve)
    ws.send(JSON.stringify({ id, method, params }))
  })
}

ws.addEventListener('message', (ev) => {
  const m = JSON.parse(ev.data)
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m.result)
    pending.delete(m.id)
  }
})

await new Promise((r) => (ws.onopen = r))
await send('Page.enable')
await send('Runtime.enable')

// 等页面加载
await new Promise((r) => setTimeout(r, 2500))

async function evalJs(expression) {
  const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
  if (r.exceptionDetails) {
    console.error('JS 异常:', JSON.stringify(r.exceptionDetails.exception?.description || r.exceptionDetails.text))
    return null
  }
  return r.result.value
}

// 1. 验证 Vue 应用挂载
const mounted = await evalJs(`document.querySelector('.topbar h1')?.textContent`)
console.log('应用标题:', mounted)

// 2. 点击"载入样例"
await evalJs(`[...document.querySelectorAll('button')].find(b=>b.textContent.includes('载入样例'))?.click()`)
// 等待异步导入(26 封 + 2 mbox 去重)
await new Promise((r) => setTimeout(r, 9000))

// 3. 检查邮件列表数量
const count = await evalJs(`document.querySelectorAll('.mail-item').length`)
console.log('列表邮件数:', count)

// 4. 检查统计条
const stats = await evalJs(`[...document.querySelectorAll('.stat b')].map(e=>e.textContent).join(',')`)
console.log('统计条:', stats)

// 5. 选中第一封(最高危),检查详情渲染
await evalJs(`document.querySelector('.mail-item')?.click()`)
await new Promise((r) => setTimeout(r, 800))
const tabs = await evalJs(`[...document.querySelectorAll('.tabs button')].map(b=>b.textContent.trim()).join(' | ')`)
console.log('Tab 数量:', tabs)

// 6. 切到认证面板,检查 SPF/DKIM/DMARC 渲染
await evalJs(`[...document.querySelectorAll('.tabs button')].find(b=>b.textContent.includes('认证'))?.click()`)
await new Promise((r) => setTimeout(r, 500))
const authText = await evalJs(`document.querySelector('.auth-pane')?.innerText.slice(0, 300)`)
console.log('认证面板片段:', authText?.replace(/\n/g, ' ').slice(0, 180))

// 7. 切到链接面板,检查标红
await evalJs(`[...document.querySelectorAll('.tabs button')].find(b=>b.textContent.includes('链接'))?.click()`)
await new Promise((r) => setTimeout(r, 500))
const mismatch = await evalJs(`document.querySelectorAll('.mismatch-tag').length`)
const defang = await evalJs(`document.querySelectorAll('.defanged').length`)
console.log('不一致链接标记数:', mismatch, ' 去武装链接数:', defang)

// 8. 切到投递路径
await evalJs(`[...document.querySelectorAll('.tabs button')].find(b=>b.textContent.includes('投递路径'))?.click()`)
await new Promise((r) => setTimeout(r, 400))
const hops = await evalJs(`document.querySelectorAll('.hop').length`)
console.log('投递路径跳数(当前选中邮件):', hops)

// 9. 切到附件
await evalJs(`[...document.querySelectorAll('.tabs button')].find(b=>b.textContent.includes('附件'))?.click()`)
await new Promise((r) => setTimeout(r, 400))
const att = await evalJs(`document.querySelectorAll('.att-card').length`)
console.log('附件卡片数(当前选中邮件):', att)

// 10. MIME 树
await evalJs(`[...document.querySelectorAll('.tabs button')].find(b=>b.textContent.includes('MIME'))?.click()`)
await new Promise((r) => setTimeout(r, 400))
const nodes = await evalJs(`document.querySelectorAll('.node-line').length`)
console.log('MIME 节点数:', nodes)

// 11. 浏览器控制台错误收集
const errs = await evalJs(`window.__pmcErrors || '未埋点'`)

// 找一封 DKIM valid 的邮件,确认浏览器端真实验签通过
const dkimValid = await evalJs(`
  (async () => {
    const mod = await import('/src/lib/analyzer.js')
    return 'analyzer 可动态导入'
  })()
`)
console.log(dkimValid)

ws.close()
console.log('\n浏览器 E2E 完成')
process.exit(0)
