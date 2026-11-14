/**
 * urls.js — 链接提取 / 去武装 / 欺骗识别
 *
 * - 从 HTML 与纯文本中提取 URL,解析 <a href> 与可见文本
 * - 去武装(defang): http→hxxp、.→[.]、@ 等,便于安全复制
 * - 显示文本与真实 href 不一致 → 标红
 * - IDN/punycode 同形异义、IP 直连、用户名混淆、短链、可疑 TLD 检测
 */
import { analyzeIdn } from './encoding.js'

const SUSPICIOUS_TLDS = new Set(['top', 'xyz', 'zip', 'mov', 'click', 'link', 'country', 'work', 'review', 'kim', 'loan', 'tg'])
const URL_REGEX = /\b(?:https?|ftp):\/\/[^\s<>"'\\)\]}]+/gi
const HREF_RE = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi
const TAG_RE = /<[^>]+>/g

/** 去武装一个 URL 字符串 */
export function defang(url) {
  return String(url)
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^ftp:\/\//i, 'fxxp://')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]')
}

function stripTags(html) {
  return html.replace(TAG_RE, '').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').trim()
}

/** 从可见文本里抽出"看起来像链接"的字符串 */
function extractTextUrls(text) {
  const out = []
  let m
  URL_REGEX.lastIndex = 0
  while ((m = URL_REGEX.exec(text)) !== null) {
    out.push(m[0].replace(/[.,;:!?)]+$/, ''))
  }
  return out
}

function safeParse(u) {
  try {
    return new URL(u)
  } catch {
    return null
  }
}

/** 单链接风险评估 */
export function analyzeUrl(rawUrl, visibleText = null) {
  const flags = []
  let severity = 'info' // info / low / medium / high
  const push = (level, text) => {
    flags.push({ level, text })
    const rank = { info: 0, low: 1, medium: 2, high: 3 }
    if (rank[level] > rank[severity]) severity = level
  }

  const parsed = safeParse(rawUrl)
  if (!parsed) {
    push('medium', 'URL 无法解析,可能被刻意混淆')
    return { url: rawUrl, defanged: defang(rawUrl), flags, severity, visibleText, mismatch: false }
  }

  const host = parsed.hostname
  const idn = analyzeIdn(host)
  if (idn.homograph) {
    push('high', `IDN 同形异义域名:展示 "${idn.unicode}" / 实际 ${idn.ascii},可能用相似字符仿冒`)
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
    push('high', `使用 IP 直连(${host}),正规站点极少如此`)
  }
  if (parsed.username) {
    push('high', `URL 含用户名段 "${parsed.username}@",经典地址栏混淆(真实主机在 @ 之后)`)
  }
  const tld = host.split('.').pop().toLowerCase()
  if (SUSPICIOUS_TLDS.has(tld)) {
    push('medium', `高风险 TLD ".${tld}"`)
  }
  if (/^\d+$/.test(host.split('.')[0]) || /^xn--/.test(host)) {
    // 已在上面覆盖
  }
  // 端口异常
  if (parsed.port && !['80', '443'].includes(parsed.port)) {
    push('low', `非标准端口 ${parsed.port}`)
  }
  // 可疑查询参数
  const paramKeys = [...parsed.searchParams.keys()].map((k) => k.toLowerCase())
  if (paramKeys.some((k) => /(?:token|password|passwd|ssn|card|cvv|account|login|redirect|url|next)/.test(k))) {
    push('medium', '查询参数含凭据/跳转类敏感字段')
  }
  // 多层 URL 编码
  if (/%25|%2f|%3a/i.test(parsed.search)) {
    push('low', '查询串存在嵌套编码,可能用于绕过过滤')
  }
  // 数据 IP/十六进制 IP
  if (/^0x[0-9a-f]+$/i.test(host) || host.includes('0x')) {
    push('high', '十六进制形式 IP,刻意隐藏真实地址')
  }

  // 可见文本 vs 真实地址
  let mismatch = false
  if (visibleText) {
    const text = stripTags(visibleText)
    const textUrls = extractTextUrls(text)
    const bareText = text.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase()
    const realHost = host.toLowerCase()
    if (textUrls.length) {
      for (const tu of textUrls) {
        const tp = safeParse(tu)
        if (tp && tp.hostname.toLowerCase() !== realHost) {
          mismatch = true
          push('high', `链接文字指向 ${tp.hostname},实际跳往 ${realHost}`)
        }
      }
    } else if (bareText && /[a-z0-9.-]+\.[a-z]{2,}/.test(bareText) && bareText !== realHost) {
      // 可见文本是一个域名但与真实主机不符
      if (!realHost.endsWith(bareText) && !bareText.endsWith(realHost)) {
        mismatch = true
        push('high', `显示文字 "${text}" 与真实地址主机 ${realHost} 不一致`)
      }
    }
  }

  return {
    url: rawUrl,
    defanged: defang(rawUrl),
    scheme: parsed.protocol.replace(':', ''),
    host,
    idn: idn.homograph ? idn : null,
    port: parsed.port || null,
    path: parsed.pathname,
    query: parsed.search,
    flags,
    severity,
    visibleText: visibleText ? stripTags(visibleText) : null,
    mismatch
  }
}

/** 从邮件 HTML + text 中汇总全部链接 */
export function extractLinks({ html, text }) {
  const seen = new Map() // url -> 分析结果(合并可见文本)
  const add = (url, visible) => {
    const clean = url?.trim()
    if (!clean || clean.startsWith('mailto:') || clean.startsWith('javascript:') || clean.startsWith('data:')) {
      if (clean?.startsWith('javascript:')) {
        seen.set(clean, analyzeUrl('http://invalid.local/', visible || clean))
        const item = seen.get(clean)
        item.url = clean
        item.defanged = clean.replace(/javascript:/i, 'java[removed]script:')
        item.flags = [{ level: 'high', text: 'javascript: 伪链接,点击可执行脚本' }]
        item.severity = 'high'
      }
      if (clean?.startsWith('data:')) {
        seen.set(clean, {
          url: clean.slice(0, 60) + '…',
          defanged: 'data:[...]',
          flags: [{ level: 'high', text: 'data: URI 内联内容,常用于钓鱼/绕过' }],
          severity: 'high',
          visibleText: visible,
          mismatch: false
        })
      }
      return
    }
    if (!seen.has(clean)) seen.set(clean, analyzeUrl(clean, visible))
    else if (visible) {
      const existing = seen.get(clean)
      if (!existing.visibleText) existing.visibleText = stripTags(visible)
    }
  }

  if (html) {
    let m
    HREF_RE.lastIndex = 0
    while ((m = HREF_RE.exec(html)) !== null) {
      const href = m[1] || m[2] || m[3]
      add(href, m[4])
    }
  }
  const body = text || (html ? stripTags(html) : '')
  for (const u of extractTextUrls(body)) add(u, null)

  const list = [...seen.values()]
  const rank = { high: 3, medium: 2, low: 1, info: 0 }
  list.sort((a, b) => rank[b.severity] - rank[a.severity])
  return list
}
