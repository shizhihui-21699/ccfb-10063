/**
 * dkim.js — DKIM 签名校验(RFC 6376)
 *
 * 使用 Web Crypto 做真实的 RSA-SHA256 / RSASSA-PKCS1-v1_5 验证,
 * 公钥来自 mock DNS 的 selector._domainkey.<d> TXT 记录(p= 字段)。
 *
 * 支持:
 *  - relaxed / simple 头部与正文规范化(c= 标签,默认 simple/relaxed→这里两档都实现)
 *  - bh= 正文哈希校验、b= 签名校验
 *  - 多 DKIM-Signature 头逐一验证
 *  - 过期(x=)、域与 i= 不一致、公钥撤销(k 不支持 / p 空)等失败场景
 */
import { dnsTxt } from './mock-dns.js'

const enc = new TextEncoder()

function sha256(data) {
  return crypto.subtle.digest('SHA-256', data)
}

function b64(bytes) {
  let bin = ''
  const CHUNK = 0x8000
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  for (let i = 0; i < u8.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK))
  }
  return btoa(bin)
}

function b64ToBytes(s) {
  const clean = s.replace(/\s+/g, '')
  const bin = atob(clean)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** 解析 tag=value 列表(分号分隔)。b= 等 base64 值只去折叠空白,普通值去首尾空白 */
export function parseTagList(raw) {
  const tags = {}
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const k = part.slice(0, eq).trim().toLowerCase()
    let v = part.slice(eq + 1)
    if (k === 'b') {
      // 签名本体:删掉折叠产生的所有空白(CRLF/空格/Tab),保留 base64 字符
      v = v.replace(/\s+/g, '')
    } else {
      v = v.replace(/\r?\n[ \t]+/g, ' ').trim()
    }
    if (!(k in tags)) tags[k] = v
  }
  return tags
}

/* ---------------- 规范化(字节级) ---------------- */

const CR = 0x0d
const LF = 0x0a
const SP = 0x20
const TAB = 0x09

/**
 * relaxed body 规范化,直接在原始字节上操作。
 * 规则(RFC 6376 §3.4.4):
 *  - 裸 LF 归一为 CRLF
 *  - 行尾 WSP 删除;行内连续 WSP 压一个空格
 *  - 结尾所有 CRLF 裁剪后补回单个 CRLF;空正文规范化为空(长度 0)
 *  - 保留多字节 UTF-8 序列原样不动
 */
function relaxedBodyBytes(input) {
  const CR = 0x0d
  const LF = 0x0a
  const SP = 0x20
  const TAB = 0x09
  if (!input.length) return new Uint8Array(0)

  // 1. 裸 LF → CRLF
  const normalized = []
  for (let i = 0; i < input.length; i++) {
    if (input[i] === LF && (i === 0 || input[i - 1] !== CR)) normalized.push(CR, LF)
    else normalized.push(input[i])
  }

  // 2. 切成逻辑行(不含行尾 CRLF)
  const lines = []
  let line = []
  for (let i = 0; i < normalized.length; i++) {
    if (normalized[i] === CR && normalized[i + 1] === LF) {
      lines.push(line)
      line = []
      i++
    } else {
      line.push(normalized[i])
    }
  }
  lines.push(line)

  // 3. 逐行规范化后用 CRLF 连接
  // RFC 6376 §3.4.4 relaxed body,与字符串正则 /[ \t]{2,}/ -> ' ' 严格等价:
  //   - 删除行尾所有 WSP(空格/Tab)
  //   - 行内长度≥2 的连续 WSP run(空格/Tab 混合)压成单个空格
  //   - 单个 WSP(含单个 Tab、行首 Tab)原样保留
  const out = []
  for (const ln of lines) {
    let end = ln.length
    while (end > 0 && (ln[end - 1] === SP || ln[end - 1] === TAB)) end-- // 去行尾 WSP
    let j = 0
    while (j < end) {
      if (ln[j] === SP || ln[j] === TAB) {
        let k = j
        while (k < end && (ln[k] === SP || ln[k] === TAB)) k++
        if (k - j >= 2) out.push(SP) // 连续 run 压一个空格
        else out.push(ln[j]) // 单个 WSP 原样保留
        j = k
      } else {
        out.push(ln[j])
        j++
      }
    }
    out.push(CR, LF)
  }

  // 4. 裁掉结尾全部 CRLF(每个占 2 字节),再补回一个
  while (out.length >= 2 && out[out.length - 1] === LF && out[out.length - 2] === CR) {
    out.pop()
    out.pop()
  }
  if (out.length) out.push(CR, LF)
  return new Uint8Array(out)
}

function simpleBodyBytes(input) {
  // 归一裸 LF,结尾保证恰好一个 CRLF
  const normalized = []
  for (let i = 0; i < input.length; i++) {
    if (input[i] === LF && (i === 0 || input[i - 1] !== CR)) normalized.push(CR, LF)
    else normalized.push(input[i])
  }
  if (normalized.length < 2 || normalized[normalized.length - 1] !== LF || normalized[normalized.length - 2] !== CR) {
    normalized.push(CR, LF)
  }
  return new Uint8Array(normalized)
}

function relaxedHeaderLine(name, value) {
  const n = name.toLowerCase()
  let v = value.replace(/\r?\n[ \t]+/g, ' ') // 展开折叠
  v = v.trim().replace(/[ \t]{2,}/g, ' ')
  return `${n}:${v}\r\n`
}

function simpleHeaderLine(name, value) {
  // 仅展开折叠,保留原始空白;名字保留原样
  return `${name}:${value.replace(/\r?\n[ \t]+/g, ' ')}\r\n`
}

/* ---------------- 主入口 ---------------- */

/**
 * 验证一封邮件的全部 DKIM 签名。
 * @param {{headers: {key:string, value:string}[], rawBodyBytes: Uint8Array}} message
 *   headers: 已展开折叠的头数组(顺序保留,重复头保留)
 *   rawBodyBytes: 头部之后的原始正文字节(真实 UTF-8/二进制字节)
 */
export async function verifyDkim(message) {
  const sigHeaders = message.headers.filter((h) => h.key === 'dkim-signature')
  if (!sigHeaders.length) {
    return { verified: false, signatures: [], summary: '无 DKIM 签名' }
  }
  const results = []
  for (const sig of sigHeaders) {
    results.push(await verifyOne(sig, message))
  }
  const anyValid = results.some((r) => r.status === 'valid')
  return {
    verified: anyValid,
    signatures: results,
    summary: anyValid
      ? `${results.filter((r) => r.status === 'valid').length}/${results.length} 个签名有效`
      : `${results.length} 个签名全部无效`
  }
}

async function verifyOne(sigHeader, message) {
  const trace = []
  const tags = parseTagList(sigHeader.value)
  const required = ['v', 'a', 'b', 'bh', 'd', 'h', 's']
  for (const r of required) {
    if (!(r in tags)) return fail(tags, `缺少必需标签 ${r}`, trace)
  }
  if (tags.v !== '1') return fail(tags, `不支持的 DKIM 版本 v=${tags.v}`, trace)

  const algo = tags.a.toLowerCase()
  const hashName = algo.includes('sha256') ? 'SHA-256' : algo.includes('sha1') ? 'SHA-1' : null
  if (!hashName) return fail(tags, `不支持的签名算法 ${tags.a}`, trace)

  // 过期检查
  if (tags.x) {
    const exp = Number(tags.x)
    const now = Date.now() / 1000
    if (Number.isFinite(exp) && now > exp) {
      trace.push({ step: 'error', text: `签名已过期:x=${new Date(exp * 1000).toISOString()}` })
      return fail(tags, '签名已过期', trace)
    }
  }

  // 取公钥
  const dnsName = `${tags.s}._domainkey.${tags.d}`
  const txts = dnsTxt(dnsName)
  trace.push({ step: 'dns', text: `TXT ${dnsName} → ${txts.length ? '已获取公钥记录' : '无记录'}` })
  if (!txts.length) return fail(tags, `公钥记录不存在(${dnsName})`, trace)
  const keyTags = parseTagList(txts[0])
  if (!keyTags.p) return fail(tags, '公钥已被撤销(p= 为空)', trace)
  if (keyTags.k && keyTags.k !== 'rsa') return fail(tags, `不支持的密钥类型 k=${keyTags.k}`, trace)

  // 规范化模式
  const [headerCanon, bodyCanon] = (tags.c || 'simple/relaxed').split('/').map((x) => x.trim())
  const bodyNormBytes =
    (bodyCanon || 'relaxed') === 'simple' ? simpleBodyBytes(message.rawBodyBytes) : relaxedBodyBytes(message.rawBodyBytes)

  // l= 标签:只校验正文前 l 字节
  const bodyForHash = tags.l ? bodyNormBytes.subarray(0, Number(tags.l)) : bodyNormBytes
  const bodyHash = b64(new Uint8Array(await sha256(bodyForHash)))
  trace.push({ step: 'bh', text: `计算 bh=${bodyHash}` })
  trace.push({ step: 'bh', text: `签名 bh=${tags.bh}` })
  const bodyMatch = bodyHash === tags.bh
  if (!bodyMatch) {
    trace.push({ step: 'error', text: '正文哈希 bh 不一致,正文可能被篡改' })
  }

  // 组装待签名字节:按 h= 顺序取头,最后追加 b= 置空的 DKIM-Signature 头
  const signerHeaders = tags.h.split(':').map((x) => x.trim().toLowerCase())
  let signedData = ''
  const headerIndex = new Map()
  for (const h of message.headers) {
    if (!headerIndex.has(h.key)) headerIndex.set(h.key, [])
    headerIndex.get(h.key).push(h)
  }
  const consumed = new Map()
  const missing = []
  for (const name of signerHeaders) {
    const list = headerIndex.get(name)
    if (!list || !list.length) {
      missing.push(name)
      continue
    }
    // RFC:重复头从最后一个往前取
    const idx = (consumed.get(name) || 0) + 1
    consumed.set(name, idx)
    const h = list[list.length - idx] || list[0]
    signedData += (headerCanon === 'relaxed' ? relaxedHeaderLine : simpleHeaderLine)(h.key, h.value)
  }
  if (missing.includes('from')) {
    return fail(tags, '签名未覆盖 From 头(RFC 要求必须覆盖)', trace)
  }
  // DKIM 签名头自身(b= 置空,保留尾部 \r\n)
  const sigForSigning = sigHeader.value.replace(/(b=)[^;]+/i, '$1')
  const selfLine =
    (headerCanon === 'relaxed' ? relaxedHeaderLine('dkim-signature', sigForSigning) : simpleHeaderLine('DKIM-Signature', sigForSigning))
  signedData += selfLine.replace(/\r\n$/, '')

  let sigValid = false
  let cryptoError = null
  try {
    const spki = b64ToBytes(keyTags.p)
    const key = await crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: hashName }, false, ['verify'])
    sigValid = await crypto.subtle.verify(
      { name: 'RSASSA-PKCS1-v1_5' },
      key,
      b64ToBytes(tags.b),
      enc.encode(signedData)
    )
    trace.push({ step: 'verify', text: `RSA 签名验证 → ${sigValid ? '通过' : '失败'}` })
  } catch (e) {
    cryptoError = e.message
    trace.push({ step: 'error', text: `公钥/签名解析失败:${e.message}` })
  }

  // i= 与 d= 域对齐检查
  let domainAligned = true
  if (tags.i) {
    const iDomain = tags.i.includes('@') ? tags.i.split('@')[1].toLowerCase() : tags.i.toLowerCase()
    domainAligned = iDomain === tags.d.toLowerCase() || iDomain.endsWith('.' + tags.d.toLowerCase())
    if (!domainAligned) trace.push({ step: 'error', text: `i= 域 ${iDomain} 与 d=${tags.d} 不对齐` })
  }

  const status = sigValid && bodyMatch && domainAligned && !cryptoError ? 'valid' : 'invalid'
  return {
    status,
    domain: tags.d,
    selector: tags.s,
    algorithm: tags.a,
    headerCanon,
    bodyCanon: bodyCanon || 'relaxed',
    bodyHashMatch: bodyMatch,
    signatureMatch: sigValid,
    domainAligned,
    signedHeaders: signerHeaders,
    expiration: tags.x ? new Date(Number(tags.x) * 1000).toISOString() : null,
    dnsKey: txts[0],
    trace
  }
}

function fail(tags, reason, trace) {
  trace.push({ step: 'error', text: reason })
  return {
    status: 'invalid',
    domain: tags?.d || null,
    selector: tags?.s || null,
    algorithm: tags?.a || null,
    headerCanon: null,
    bodyCanon: null,
    bodyHashMatch: false,
    signatureMatch: false,
    domainAligned: false,
    signedHeaders: tags?.h ? tags.h.split(':').map((x) => x.trim()) : [],
    expiration: tags?.x ? new Date(Number(tags.x) * 1000).toISOString() : null,
    dnsKey: null,
    reason,
    trace
  }
}
