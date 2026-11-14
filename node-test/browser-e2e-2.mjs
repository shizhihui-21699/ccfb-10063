/**
 * browser-e2e-2.mjs — 针对钓鱼样本的专项浏览器验证 + 控制台错误捕获
 */
const BASE = 'http://127.0.0.1:5173/'
const resp = await fetch('http://127.0.0.1:9222/json/new?' + encodeURIComponent(BASE), { method: 'PUT' })
const tab = await resp.json()
const ws = new WebSocket(tab.webSocketDebuggerUrl)
let msgId = 0
const pending = new Map()
const consoleErrors = []
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
  if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') {
    consoleErrors.push(m.params.args.map((a) => a.value || a.description).join(' '))
  }
  if (m.method === 'Runtime.exceptionThrown') {
    consoleErrors.push('未捕获异常: ' + (m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text))
  }
})
await new Promise((r) => (ws.onopen = r))
await send('Page.enable')
await send('Runtime.enable')
await new Promise((r) => setTimeout(r, 2000))
const evalJs = async (expression) => (await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })).result.value

await evalJs(`[...document.querySelectorAll('button')].find(b=>b.textContent.includes('载入样例'))?.click()`)
await new Promise((r) => setTimeout(r, 9000))

// 选中标红样本 06
await evalJs(`
  const items=[...document.querySelectorAll('.mail-item')]
  const t=items.find(e=>e.textContent.includes('链接显示与真实地址不符'))
  t?.click()
`)
await new Promise((r) => setTimeout(r, 600))
const subj = await evalJs(`document.querySelector('.head-info h2')?.textContent`)
console.log('选中邮件:', subj)

// 链接面板
await evalJs(`[...document.querySelectorAll('.tabs button')].find(b=>b.textContent.includes('链接'))?.click()`)
await new Promise((r) => setTimeout(r, 500))
const mismatch = await evalJs(`document.querySelectorAll('.mismatch-tag').length`)
const redLinks = await evalJs(`document.querySelectorAll('.real-url.red').length`)
const defang = await evalJs(`document.querySelectorAll('.defanged').length`)
const highBadges = await evalJs(`document.querySelectorAll('.link-card .badge.high, .link-card .badge.critical').length`)
console.log(`链接: 不一致标记=${mismatch} 标红真实地址=${redLinks} 去武装=${defang} 高危徽章=${highBadges}`)
const sampleDefang = await evalJs(`document.querySelector('.defanged')?.textContent`)
console.log('去武装示例:', sampleDefang)

// 宏文档样本 08
await evalJs(`
  const items=[...document.querySelectorAll('.mail-item')]
  items.find(e=>e.textContent.includes('VBA宏'))?.click()
`)
await new Promise((r) => setTimeout(r, 500))
await evalJs(`[...document.querySelectorAll('.tabs button')].find(b=>b.textContent.includes('附件'))?.click()`)
await new Promise((r) => setTimeout(r, 500))
const macroHit = await evalJs(`document.querySelector('.att-card')?.innerText.includes('VBA 宏')`)
const sha = await evalJs(`document.querySelector('.hashes')?.innerText.replace(/\\n/g,' ').slice(0,80)`)
console.log('宏特征检出:', macroHit)
console.log('哈希:', sha)

// 深嵌套样本 12 的 MIME 树深度
await evalJs(`
  const items=[...document.querySelectorAll('.mail-item')]
  items.find(e=>e.textContent.includes('五层multipart'))?.click()
`)
await new Promise((r) => setTimeout(r, 500))
await evalJs(`[...document.querySelectorAll('.tabs button')].find(b=>b.textContent.includes('MIME'))?.click()`)
await new Promise((r) => setTimeout(r, 400))
const depth = await evalJs(`Math.max(...[...document.querySelectorAll('.part-id')].map(e=>e.textContent.split('.').length))`)
console.log('MIME 最大嵌套深度(partId 段数):', depth)

// 伪造发件人样本 04 的标签
await evalJs(`
  const items=[...document.querySelectorAll('.mail-item')]
  items.find(e=>e.textContent.includes('显示名内嵌假邮箱'))?.click()
`)
await new Promise((r) => setTimeout(r, 500))
const spoofTag = await evalJs(`[...document.querySelectorAll('.tag')].some(e=>e.textContent.includes('伪造发件人'))`)
console.log('伪造发件人标签:', spoofTag)

// 导出按钮存在性
const exportBtns = await evalJs(`[...document.querySelectorAll('.head-actions button')].map(b=>b.textContent).join('|')`)
console.log('导出按钮:', exportBtns)

console.log('\n控制台错误数:', consoleErrors.length)
consoleErrors.slice(0, 10).forEach((e) => console.log('  !', e.slice(0, 160)))
ws.close()
process.exit(consoleErrors.length ? 1 : 0)
