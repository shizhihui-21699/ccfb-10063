/**
 * analyzer.js — 邮件分析主编排
 *
 * 输入一封 eml 字节,输出完整分析报告:
 * 基础信息 / MIME 树 / Received 路径 / SPF / DKIM / DMARC / 链接 / 附件 / 信头检测 / 威胁评分
 */
import PostalMime from 'postal-mime'
import { parseMimeNode, flattenParts } from './mime-tree.js'
import { parseReceivedChain } from './received.js'
import { evaluateSpf } from './spf.js'
import { verifyDkim } from './dkim.js'
import { evaluateDmarc } from './dmarc.js'
import { extractLinks } from './urls.js'
import { analyzeAttachment } from './attachment.js'
import { analyzeHeaders, scoreThreat } from './headers.js'
import { decodeEncodedWords } from './encoding.js'

function bytesToLatin1(bytes) {
  let s = ''
  const CHUNK = 0x8000
  for (let i = 0; i < bytes.length; i += CHUNK) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK))
  return s
}

function splitHeaderBodyLatin1(latin) {
  const idx = latin.search(/\r?\n\r?\n/)
  if (idx < 0) return [latin, '']
  const head = latin.slice(0, idx)
  const sepLen = latin[idx] === '\r' ? 4 : 2
  return [head, latin.slice(idx + sepLen)]
}

/** 在真实字节上定位头/体分隔,返回 body 字节(跳过空行分隔符) */
function splitBodyBytes(bytes) {
  for (let i = 0; i < bytes.length - 3; i++) {
    if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a && bytes[i + 2] === 0x0d && bytes[i + 3] === 0x0a) {
      return bytes.subarray(i + 4)
    }
    if (bytes[i] === 0x0a && bytes[i + 1] === 0x0a) {
      return bytes.subarray(i + 2)
    }
  }
  return new Uint8Array(0)
}

function parseRawHeaders(headerLatin) {
  const map = {}
  const ordered = []
  const lines = headerLatin.split(/\r?\n/)
  let cur = null
  for (const line of lines) {
    if (!line) continue
    if (/^[ \t]/.test(line) && cur) {
      map[cur][map[cur].length - 1] += ' ' + line.trim()
      continue
    }
    const colon = line.indexOf(':')
    if (colon < 0) continue
    const key = line.slice(0, colon).trim().toLowerCase()
    const val = line.slice(colon + 1).trim()
    if (!(key in map)) {
      map[key] = []
      ordered.push(key)
    }
    map[key].push(val)
    cur = key
  }
  return { map, ordered }
}

export async function analyzeEmail(bytes, sourceName = 'unknown.eml') {
  const startedAt = performance.now()
  const latin = bytesToLatin1(bytes)
  const [headerLatin] = splitHeaderBodyLatin1(latin)
  const { map: rawHeaderMap, ordered: headerOrder } = parseRawHeaders(headerLatin)

  // 1. postal-mime 负责字段/正文/附件的稳健解析
  const parsed = await PostalMime.parse(bytes, { attachmentEncoding: 'arraybuffer' })

  // 2. 自建 MIME 树
  const mimeTree = parseMimeNode(bytes, '1')

  // 3. Received 投递路径
  const receivedRaw = rawHeaderMap['received'] || []
  const chain = parseReceivedChain(receivedRaw)

  // 4. 身份域
  const fromAddr = parsed.from?.address || (parsed.from?.group?.[0]?.address) || ''
  const headerFromDomain = fromAddr.includes('@') ? fromAddr.split('@')[1].toLowerCase() : null
  const returnPath = (parsed.returnPath || '').replace(/^<|>$/g, '')
  const mailFromDomain = returnPath.includes('@') ? returnPath.split('@')[1].toLowerCase() : headerFromDomain

  // 5. SPF(用最早一跳的连接 IP + HELO)
  const spf = evaluateSpf({
    ip: chain.originIp,
    heloDomain: chain.originHelo,
    mailFromDomain
  })

  // 6. DKIM(真实加密验证,基于原始字节规范化)
  const dkimHeaders = headerOrder.flatMap((k) =>
    (rawHeaderMap[k] || []).map((v) => ({ key: k, value: v }))
  )
  const rawBodyBytes = splitBodyBytes(bytes)
  const dkim = await verifyDkim({ headers: dkimHeaders, rawBodyBytes })

  // 7. DMARC
  const dmarc = evaluateDmarc({
    headerFromDomain,
    spfResult: spf,
    spfAuthDomain: spf.result === 'pass' ? mailFromDomain : null,
    dkimResult: dkim
  })

  // 8. 链接
  const links = extractLinks({ html: parsed.html, text: parsed.text })

  // 9. 附件静态分析
  const attachments = []
  for (const att of parsed.attachments || []) {
    const content = att.content instanceof ArrayBuffer ? new Uint8Array(att.content) : att.content
    attachments.push(
      await analyzeAttachment({
        filename: att.filename,
        mimeType: att.mimeType,
        content
      })
    )
  }

  // 10. 信头伪造检测
  const headerAnalysis = analyzeHeaders(parsed, rawHeaderMap)

  // 11. 威胁评分
  const threat = scoreThreat({
    headerFindings: headerAnalysis.findings,
    links,
    attachments,
    auth: { spf, dkim, dmarc }
  })

  // 12. 自动标签建议
  const autoTags = suggestTags({ spf, dkim, dmarc, links, attachments, headerAnalysis, chain })

  return {
    id: await hashId(bytes),
    sourceName,
    analyzedAt: new Date().toISOString(),
    elapsedMs: Math.round(performance.now() - startedAt),
    size: bytes.length,
    envelope: {
      subject: decodeEncodedWords(parsed.subject || '(无主题)'),
      from: parsed.from,
      to: parsed.to,
      cc: parsed.cc,
      sender: parsed.sender,
      replyTo: parsed.replyTo,
      returnPath: parsed.returnPath,
      date: parsed.date,
      messageId: parsed.messageId
    },
    rawHeaderMap,
    headerOrder,
    mimeTree,
    flatParts: flattenParts(mimeTree),
    bodies: {
      text: parsed.text || '',
      html: parsed.html || ''
    },
    chain,
    auth: { spf, dkim, dmarc, headerFromDomain, mailFromDomain, clientIp: chain.originIp },
    links,
    attachments,
    headerAnalysis,
    threat,
    autoTags,
    userTags: [],
    notes: ''
  }
}

async function hashId(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes.subarray(0, Math.min(bytes.length, 65536)))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16)
}

function suggestTags({ spf, dkim, dmarc, links, attachments, headerAnalysis, chain }) {
  const tags = new Set()
  if (dmarc.result === 'fail') tags.add('认证失败')
  if (headerAnalysis.findings.some((f) => f.code === 'SPOOF_SENDER' || f.code === 'DISPLAY_NAME_SPOOF' || f.code === 'FREE_MAIL_IMPERSONATION')) {
    tags.add('伪造发件人')
  }
  if (headerAnalysis.findings.some((f) => f.code === 'REPLYTO_EXTERNAL')) tags.add('回复劫持')
  if (links.some((l) => l.mismatch)) tags.add('链接欺骗')
  if (links.some((l) => l.idn?.homograph)) tags.add('同形异义域名')
  if (links.some((l) => l.severity === 'high')) tags.add('恶意链接')
  if (attachments.some((a) => a.findings.some((f) => f.text.includes('VBA 宏') || f.text.includes('vbaProject')))) tags.add('宏文档')
  if (attachments.some((a) => a.severity === 'high')) tags.add('危险附件')
  if (attachments.some((a) => a.findings.some((f) => f.text.includes('双扩展名')))) tags.add('扩展名伪装')
  if (chain.anomalies.length) tags.add('投递异常')
  if (spf.result === 'none' && !dkim.signatures.length) tags.add('无防护域名')
  if (headerAnalysis.findings.some((f) => f.code === 'BULK_MAILER')) tags.add('群发工具')
  return [...tags]
}
