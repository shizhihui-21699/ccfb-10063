/**
 * encoding.js — 邮件编码还原工具
 *
 * 覆盖:
 *  - RFC 2047 encoded-word: =?UTF-8?B?...?= / =?GBK?Q?...?=
 *  - RFC 2231 续行参数: filename*0*=utf-8''%xx; filename*1*=...
 *  - base64 / quoted-printable 实体解码
 *  - 多字符集 (UTF-8 / GBK / GB2312 / Big5 / Shift_JIS / ISO-8859-1 / KOI8-R / EUC-KR)
 *  - Punycode IDN 域名还原
 */

const TEXT_DECODER_SUPPORT = (() => {
  try {
    // eslint-disable-next-line no-new
    new TextDecoder('gbk')
    return true
  } catch {
    return false
  }
})()

/** 用 TextDecoder 做字符集转换,浏览器/Node 均支持主流中文编码 */
export function decodeBytes(bytes, charset = 'utf-8') {
  const cs = (charset || 'utf-8').toLowerCase().replace(/[^a-z0-9]/g, '')
  const alias = {
    utf8: 'utf-8',
    gb2312: 'gbk',
    gbk2312: 'gbk',
    csiso88591: 'iso-8859-1',
    latin1: 'iso-8859-1',
    l1: 'iso-8859-1',
    sjis: 'shift_jis',
    xsjis: 'shift_jis',
    euckr: 'euc-kr',
    cskoi8r: 'koi8-r',
    win1251: 'windows-1251',
    win1252: 'windows-1252'
  }
  const label = alias[cs] || cs
  try {
    return new TextDecoder(label).decode(bytes)
  } catch {
    if (!TEXT_DECODER_SUPPORT) {
      // 极端环境退化为 latin1,不抛异常
      return new TextDecoder('iso-8859-1').decode(bytes)
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes)
  }
}

export function base64ToBytes(b64) {
  const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '')
  const bin = atob(clean)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** RFC 2045 quoted-printable 解码 */
export function quotedPrintableToBytes(qp) {
  const out = []
  // 统一软换行
  const normalized = qp.replace(/[ \t]?\r?\n/g, (m) => (/=\r?\n$/.test(m) ? '=' : '\r\n'))
  for (let i = 0; i < normalized.length; i++) {
    const c = normalized[i]
    if (c === '=') {
      const hex = normalized.slice(i + 1, i + 3)
      if (hex === '\r\n' || hex === '\n') {
        // 软换行,跳过
        i += hex.length - 1
        continue
      }
      if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
        out.push(parseInt(hex, 16))
        i += 2
        continue
      }
    }
    out.push(c.charCodeAt(0) & 0xff)
  }
  return new Uint8Array(out)
}

/** 解码单个 encoded-word =?charset?enc?payload?= */
function decodeEncodedWord(token) {
  const m = /^=\?([^?]+)\?([bBqQ])\?([^?]*)\?=$/.exec(token)
  if (!m) return token
  const [, charset, enc, payload] = m
  const bytes =
    enc.toLowerCase() === 'b'
      ? base64ToBytes(payload)
      : quotedPrintableToBytes(payload.replace(/_/g, ' '))
  return decodeBytes(bytes, charset)
}

/**
 * 解码头字段中的所有 encoded-word。
 * 相邻 encoded-word 之间的空白按 RFC 2616/2047 规则吞掉。
 */
export function decodeEncodedWords(input) {
  if (input == null) return ''
  let s = String(input)
  if (!s.includes('=?')) return s
  // 连续 encoded-word(可被空白/折叠换行分隔)整体匹配
  const re = /(=\?[^?]+\?[bBqQ]\?[^?]*\?=)(?:[ \t]*\r?\n[ \t]*|[ \t]+)?(?==\?[^?]+\?[bBqQ]\?[^?]*\?=)?/g
  // 分步处理:先找出所有 token,普通文本原样保留
  let result = ''
  let lastIndex = 0
  const tokenRe = /=\?[^?]+?\?[bBqQ]\?[^?]*?\?=/g
  let match
  while ((match = tokenRe.exec(s)) !== null) {
    result += s.slice(lastIndex, match.index)
    // 向后吞并相邻 encoded-word 之间的空白
    let end = tokenRe.lastIndex
    while (true) {
      const gap = /^(?:[ \t]*\r?\n[ \t]*|[ \t]+)/.exec(s.slice(end))
      if (!gap) break
      const nextRe = /^=\?[^?]+?\?[bBqQ]\?[^?]*?\?=/
      if (!nextRe.test(s.slice(end + gap[0].length))) break
      end += gap[0].length
      const next = nextRe.exec(s.slice(end))[0]
      end += next.length
    }
    const group = s.slice(match.index, end)
    const words = group.match(/=\?[^?]+?\?[bBqQ]\?[^?]*?\?=/g) || []
    result += words.map(decodeEncodedWord).join('')
    lastIndex = end
    tokenRe.lastIndex = end
  }
  result += s.slice(lastIndex)
  // 折叠换行还原为空格
  result = result.replace(/\r?\n[ \t]+/g, ' ')
  // 嵌套 encoded-word:解码后文本里仍含 =?...?= 时再解一层(钓鱼邮件常用的深层混淆)
  let guard = 0
  while (result.includes('=?') && guard < 5) {
    const next = decodePass(result)
    if (next === result) break
    result = next
    guard++
  }
  return result
}

/** 单轮解码,供嵌套迭代复用 */
function decodePass(s) {
  let result = ''
  let lastIndex = 0
  const tokenRe = /=\?[^?]+?\?[bBqQ]\?[^?]*?\?=/g
  let match
  while ((match = tokenRe.exec(s)) !== null) {
    result += s.slice(lastIndex, match.index)
    result += decodeEncodedWord(match[0])
    lastIndex = tokenRe.lastIndex
  }
  result += s.slice(lastIndex)
  return result
}

/**
 * 解析 Content-Type / Content-Disposition 头的参数,还原 RFC 2231 文件名。
 * 兼容三种写法:
 *   filename="plain.doc"
 *   filename*=utf-8''%E4%B8%AD.doc
 *   filename*0*=utf-8''a; filename*1*=b; ...(可与不带 * 的续段混用)
 * 返回 { value, params: { 小写参数名: 还原后的字符串 } }
 */
export function parseHeaderParams(rawHeaderValue) {
  const segments = splitTopLevel(rawHeaderValue, ';')
  const value = segments.shift().trim()
  const plain = {}
  // 续段收集: name -> Map<序号, {charset?, bytes}>
  const continuations = new Map()
  const extended = new Map()

  for (const part of segments) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const rawKey = part.slice(0, eq).trim()
    const val = part.slice(eq + 1).trim().replace(/^"(.*)"$/s, '$1')
    const starAt = rawKey.indexOf('*')

    if (starAt < 0) {
      plain[rawKey.toLowerCase()] = val
      continue
    }
    const name = rawKey.slice(0, starAt).toLowerCase()
    const tail = rawKey.slice(starAt + 1)

    if (tail === '') {
      // name*=charset'lang'%xx
      const d = decodeExtendedValue(val)
      extended.set(name, d)
      continue
    }
    // name*0*= / name*0= 续段
    const idx = parseInt(tail, 10)
    if (Number.isNaN(idx)) continue
    if (!continuations.has(name)) continuations.set(name, new Map())
    const map = continuations.get(name)
    if (tail.endsWith('*')) {
      const d = decodeExtendedValue(val)
      map.set(idx, d)
    } else {
      map.set(idx, { charset: null, bytes: new TextEncoder().encode(val) })
    }
  }

  // 合并续段
  for (const [name, map] of continuations) {
    const indices = [...map.keys()].sort((a, b) => a - b)
    const first = map.get(indices[0])
    const charset = first.charset || 'utf-8'
    const total = indices.reduce((n, i) => n + map.get(i).bytes.length, 0)
    const merged = new Uint8Array(total)
    let off = 0
    for (const i of indices) {
      const b = map.get(i).bytes
      merged.set(b, off)
      off += b.length
    }
    plain[name] = decodeBytes(merged, charset)
  }
  // 单段扩展值优先级最高(RFC 2231 §4.1)
  for (const [name, d] of extended) plain[name] = d.value

  return { value, params: plain }
}

function decodeExtendedValue(value) {
  // charset'lang'percent-encoded
  const m = /^([^']*)'([^']*)'(.*)$/s.exec(value)
  if (m) {
    const [, charset, , payload] = m
    const bytes = percentDecode(payload)
    return { charset: charset || 'utf-8', bytes, value: decodeBytes(bytes, charset || 'utf-8') }
  }
  const bytes = percentDecode(value)
  return { charset: 'utf-8', bytes, value: decodeBytes(bytes, 'utf-8') }
}

function percentDecode(s) {
  const bytes = []
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '%' && /^[0-9A-Fa-f]{2}/.test(s.slice(i + 1, i + 3))) {
      bytes.push(parseInt(s.slice(i + 1, i + 3), 16))
      i += 2
    } else {
      bytes.push(s.charCodeAt(i) & 0xff)
    }
  }
  return new Uint8Array(bytes)
}

/** 顶层分隔(忽略引号内分隔符) */
export function splitTopLevel(s, sep) {
  const out = []
  let depth = 0
  let quote = false
  let cur = ''
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (c === '\\' && quote) {
      cur += c + (s[i + 1] || '')
      i++
      continue
    }
    if (c === '"') quote = !quote
    if (!quote && (c === '(' || c === '[')) depth++
    if (!quote && (c === ')' || c === ']')) depth--
    if (!quote && depth === 0 && c === sep) {
      out.push(cur)
      cur = ''
    } else {
      cur += c
    }
  }
  out.push(cur)
  return out
}

/** IDN 域名:unicode -> punycode(用于去武装展示真实 ASCII 形态) */
export function toAsciiDomain(domain) {
  try {
    const url = new URL('http://' + domain)
    return url.hostname
  } catch {
    return domain
  }
}

/** IDN 域名:punycode -> unicode(用于展示仿冒同形异义字) */
export function toUnicodeDomain(domain) {
  try {
    const parts = domain.split('.').map((label) => {
      if (!label.toLowerCase().startsWith('xn--')) return label
      try {
        return new URL(`http://${label}.example`).hostname.split('.')[0]
      } catch {
        return label
      }
    })
    return parts.join('.')
  } catch {
    return domain
  }
}

/** 检测域名中是否包含 punycode / 非 ASCII 同形异义字符 */
export function analyzeIdn(domain) {
  const ascii = toAsciiDomain(domain)
  const unicode = toUnicodeDomain(domain)
  const hasPuny = ascii.toLowerCase().includes('xn--')
  const hasNonAscii = /[^\x00-\x7f]/.test(domain)
  return {
    ascii,
    unicode,
    hasPuny,
    hasNonAscii,
    homograph: hasPuny || hasNonAscii
  }
}
