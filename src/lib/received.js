/**
 * received.js — Received 头解析与投递路径还原
 *
 * RFC 5322 Received 格式(自由文本,常见形态):
 *   Received: from HELO (rDNS [IP]) by MAILHOST with ESMTPS id xxx; DATE
 * 邮件中 Received 顺序 = 最外层(最后接收方)在最前,
 * 投递路径要反着读:最早的一跳在最底部。
 */
import { decodeEncodedWords } from './encoding.js'
import { dnsPtr, dnsA } from './mock-dns.js'

const IP_RE = /(?:'?\[)?(?<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)(?:\]|')?/
const FROM_RE = /from\s+([^\s;(]+(?:\s*\([^)]*\))?)/i
const BY_RE = /by\s+([^\s;]+)/i
const WITH_RE = /with\s+([A-Z0-9-]+)/i
const ID_RE = /\bid\s+([^\s;]+)/i
const FOR_RE = /\bfor\s+<?([^\s;>]+)>?/i
const DATE_RE = /;\s*(.+?)\s*$/

/**
 * @typedef {Object} Hop
 * @property {number} index          从发件侧开始编号 0..n
 * @property {string|null} helo      EHLO/HELO 宣告名
 * @property {string|null} reverseDns 括号中的 rDNS 名
 * @property {string|null} ip
 * @property {string|null} by        接收主机
 * @property {string|null} protocol  ESMTP/SMTPS/...
 * @property {string|null} queueId
 * @property {string|null} forMailbox
 * @property {string|null} dateRaw
 * @property {number|null} ts
 * @property {{ptrMatch:boolean, ptrName:string|null, forward:string[]}} dnsCheck
 * @property {string} raw
 */

function parseOne(rawLine) {
  // 折叠头先展开成空格,保证 by/with/date 在同一逻辑行上可被正则命中
  const raw = decodeEncodedWords(rawLine.trim().replace(/\r?\n[ \t]+/g, ' '))
  const fromMatch = FROM_RE.exec(raw)
  let helo = null
  let reverseDns = null
  let ip = null
  if (fromMatch) {
    const seg = fromMatch[1]
    // helo (rDNS [ip]) / helo (ip) / helo [ip]
    const paren = /^([^\s(]+)(?:\s*\(([^)]*)\))?/.exec(seg)
    if (paren) {
      helo = paren[1]
      const inside = paren[2] || ''
      const ipInParen = IP_RE.exec(inside)
      const bracket = /\[([^\]]+)\]/.exec(seg)
      if (bracket) ip = bracket[1]
      else if (ipInParen && /[.:]/.test(ipInParen.groups?.ip || '')) ip = ipInParen.groups.ip
      if (inside) {
        const namePart = inside.split('[')[0].replace(/[()]/g, '').trim()
        if (namePart && !/^\d+\.\d+\.\d+\.\d+$/.test(namePart)) reverseDns = namePart
      }
    }
  }
  // 兜底:全文找 [x.x.x.x]
  if (!ip) {
    const m = /\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)\]/.exec(raw)
    if (m) ip = m[1]
  }

  const dateMatch = DATE_RE.exec(raw)
  const dateRaw = dateMatch ? dateMatch[1].trim() : null
  const ts = dateRaw ? Date.parse(dateRaw) : null

  return {
    helo,
    reverseDns,
    ip,
    by: BY_RE.exec(raw)?.[1] || null,
    protocol: WITH_RE.exec(raw)?.[1]?.toUpperCase() || null,
    queueId: ID_RE.exec(raw)?.[1] || null,
    forMailbox: FOR_RE.exec(raw)?.[1] || null,
    dateRaw,
    ts: Number.isFinite(ts) ? ts : null,
    raw
  }
}

/** 对一跳做 mock DNS 反查校验:rDNS 名与 IP 是否互相印证 */
function dnsCheckFor(hop) {
  if (!hop.ip || !/^\d+\.\d+\.\d+\.\d+$/.test(hop.ip)) {
    return { ptrMatch: false, ptrName: null, forward: [], note: '无 IPv4,跳过反查' }
  }
  const ptrNames = dnsPtr(hop.ip)
  const ptrName = ptrNames[0] || null
  let ptrMatch = false
  let forward = []
  if (ptrName) {
    forward = dnsA(ptrName)
    ptrMatch = forward.includes(hop.ip)
  }
  // 头里声称的 rDNS 与 DNS 反查不一致也是可疑点
  const claimedMismatch = hop.reverseDns && ptrName && hop.reverseDns.toLowerCase() !== ptrName.toLowerCase()
  return {
    ptrMatch,
    ptrName,
    forward,
    claimedMismatch: !!claimedMismatch,
    claimed: hop.reverseDns
  }
}

/**
 * @param {string[]} receivedHeaderValues 按邮件原文顺序(最后接收方在前)
 */
export function parseReceivedChain(receivedHeaderValues) {
  const hops = receivedHeaderValues.map(parseOne)
  // 反转为投递方向:最早一跳排最前
  const ordered = hops.reverse()
  ordered.forEach((h, i) => {
    h.index = i
    h.dnsCheck = dnsCheckFor(h)
  })

  // 时间线异常检测
  const anomalies = []
  for (let i = 1; i < ordered.length; i++) {
    const prev = ordered[i - 1]
    const cur = ordered[i]
    if (prev.ts && cur.ts && cur.ts < prev.ts) {
      anomalies.push(`第 ${i + 1} 跳时间早于上一跳(时钟异常或伪造痕迹)`)
    }
  }
  // 声称名与反查不符
  ordered.forEach((h) => {
    if (h.dnsCheck?.claimedMismatch) {
      anomalies.push(`第 ${h.index + 1} 跳 HELO/rDNS 声称 "${h.dnsCheck.claimed}" 与 DNS 反查 "${h.dnsCheck.ptrName}" 不一致`)
    }
    if (h.ip && !h.dnsCheck?.ptrName) {
      anomalies.push(`第 ${h.index + 1} 跳 IP ${h.ip} 无 PTR 记录`)
    }
  })

  return {
    hops: ordered,
    anomalies,
    /** 最靠近发件人的 IP,用于 SPF */
    originIp: ordered[0]?.ip || null,
    originHelo: ordered[0]?.helo || null,
    finalMta: ordered[ordered.length - 1]?.by || null
  }
}
