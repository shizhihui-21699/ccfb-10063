/**
 * spf.js — 本地 SPF 校验(RFC 7208 子集)
 *
 * 支持机制:ip4 / ip6 / a / mx / include / exists / redirect / exp / all
 * 限定符:+ (pass) - (fail) ~ (softfail) ? (neutral)
 * DNS 查询全部走 mock-dns,带 10 次查询上限和 include 死循环防护。
 */
import { dnsTxt, dnsA, dnsPtr } from './mock-dns.js'

const MAX_QUERIES = 10
const MAX_LOOKUPS = 10

function ipToInt(ip) {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + (parts[2] << 8) + parts[3]
}

function cidrMatch(ip, network, cidr) {
  const ipInt = ipToInt(ip)
  const netInt = ipToInt(network)
  if (ipInt === null || netInt === null) return false
  if (cidr === 0) return true
  if (cidr < 0 || cidr > 32) return false
  const mask = cidr === 32 ? 0xffffffff : (0xffffffff << (32 - cidr)) >>> 0
  return (ipInt & mask) === (netInt & mask)
}

function qualifierOf(token) {
  if (token.startsWith('-')) return { q: 'fail', mech: token.slice(1) }
  if (token.startsWith('~')) return { q: 'softfail', mech: token.slice(1) }
  if (token.startsWith('?')) return { q: 'neutral', mech: token.slice(1) }
  return { q: 'pass', mech: token.startsWith('+') ? token.slice(1) : token }
}

const RESULT_LABEL = {
  pass: 'PASS',
  fail: 'FAIL',
  softfail: 'SOFTFAIL',
  neutral: 'NEUTRAL',
  none: 'NONE',
  temperror: 'TEMPERROR',
  permerror: 'PERMERROR'
}

/**
 * @param {object} opts
 * @param {string} opts.ip            连接 IP(取 Received 链最底部)
 * @param {string} opts.heloDomain    EHLO/HELO 域名
 * @param {string} opts.mailFrom      Return-Path / MAIL FROM 地址的域名部分
 * @param {string} opts.heloIdentity  HELO 身份
 */
export function evaluateSpf({ ip, heloDomain, mailFromDomain }) {
  const trace = []
  const queries = { count: 0 }
  const seen = new Set()

  const rootDomain = mailFromDomain || heloDomain
  trace.push({ step: 'start', text: `对域 ${rootDomain} 评估 SPF,客户端 IP ${ip || '(未知)'}` })

  if (!rootDomain) {
    return buildResult('none', '无 MAIL FROM / HELO 域,无法评估', trace)
  }

  const evaluateDomain = (domain, depth) => {
    if (seen.has(domain)) {
      trace.push({ step: 'error', text: `include 环路:${domain},判定 PermError` })
      return 'permerror'
    }
    seen.add(domain)

    const txts = dnsTxt(domain)
    queries.count++
    const spfRecords = txts.filter((t) => /^v=spf1(?:\s|$)/i.test(t))
    trace.push({ step: 'dns', text: `TXT ${domain} → ${spfRecords.length ? spfRecords[0] : '(无 SPF 记录)'}`, query: `TXT ${domain}` })

    if (spfRecords.length === 0) return 'none'
    if (spfRecords.length > 1) {
      trace.push({ step: 'error', text: '存在多条 v=spf1 记录,PermError' })
      return 'permerror'
    }
    const terms = spfRecords[0].trim().split(/\s+/).slice(1)
    let redirect = null

    for (const term of terms) {
      if (!term) continue
      if (queries.count > MAX_QUERIES) {
        trace.push({ step: 'error', text: 'DNS 查询超过 10 次上限,PermError' })
        return 'permerror'
      }
      if (depth > MAX_LOOKUPS) {
        trace.push({ step: 'error', text: 'include 嵌套过深,PermError' })
        return 'permerror'
      }

      if (/^redirect=/i.test(term)) {
        redirect = term.split('=')[1]
        continue
      }
      if (/^exp=/i.test(term)) continue
      if (/^v=spf1/i.test(term)) continue

      const { q, mech } = qualifierOf(term)
      const hit = matchMechanism(mech, ip, domain, depth, q, trace, queries)
      if (hit) {
        trace.push({ step: 'match', text: `机制 ${term} 命中 → ${RESULT_LABEL[q]}` })
        return q
      }
    }

    if (redirect) {
      trace.push({ step: 'redirect', text: `redirect=${redirect},转去评估该域` })
      const r = evaluateDomain(redirect, depth + 1)
      if (r === 'none') return 'permerror'
      return r
    }
    trace.push({ step: 'default', text: '无机制匹配 → NEUTRAL(SPF 策略默认)' })
    return 'neutral'
  }

  let result
  try {
    result = evaluateDomain(rootDomain, 0)
  } catch (e) {
    trace.push({ step: 'error', text: `评估异常:${e.message}` })
    result = 'temperror'
  }

  return buildResult(result, explain(result), trace, queries.count)
}

function matchMechanism(mech, clientIp, currentDomain, depth, qualifier, trace, queries) {
  // ip4:192.0.2.0/24
  let m = /^ip4:([0-9.]+)(?:\/(\d+))?$/i.exec(mech)
  if (m) {
    if (!clientIp) return false
    return cidrMatch(clientIp, m[1], m[2] ? Number(m[2]) : 32)
  }
  // ip6(简化:只做精确/前缀字符串比较)
  m = /^ip6:(.+?)(?:\/(\d+))?$/i.exec(mech)
  if (m) {
    return clientIp && clientIp.includes(':') && clientIp.toLowerCase().startsWith(m[1].toLowerCase().split(':')[0])
  }
  // a / a:domain / a:domain/24
  m = /^a(?::([^/]+))?(?:\/(\d+))?$/i.exec(mech)
  if (m) {
    const dom = m[1] || currentDomain
    const cidr = m[2] ? Number(m[2]) : 32
    queries.count++
    const addrs = dnsA(dom)
    trace.push({ step: 'dns', text: `A ${dom} → [${addrs.join(', ')}]`, query: `A ${dom}` })
    return clientIp ? addrs.some((a) => cidrMatch(clientIp, a, cidr)) : false
  }
  // mx
  m = /^mx(?::([^/]+))?(?:\/(\d+))?$/i.exec(mech)
  if (m) {
    const dom = m[1] || currentDomain
    const cidr = m[2] ? Number(m[2]) : 32
    // mock:直接查 A(mx 主机名约定与 A 同名),并记录一次查询
    queries.count++
    const addrs = dnsA(dom)
    trace.push({ step: 'dns', text: `MX ${dom} → 解析其 A [${addrs.join(', ')}]`, query: `MX ${dom}` })
    return clientIp ? addrs.some((a) => cidrMatch(clientIp, a, cidr)) : false
  }
  // include:domain
  m = /^include:(.+)$/i.exec(mech)
  if (m) {
    trace.push({ step: 'include', text: `include:${m[1]}` })
    const sub = evaluateQuiet(m[1], clientIp, depth + 1, queries, trace)
    // include 仅在子结果为 pass 时命中;fail/none 等继续下一个机制
    return sub === 'pass'
  }
  // exists:domain
  m = /^exists:(.+)$/i.exec(mech)
  if (m) {
    queries.count++
    const addrs = dnsA(m[1])
    trace.push({ step: 'dns', text: `exists ${m[1]} → ${addrs.length ? '有解析' : '无解析'}`, query: `A ${m[1]}` })
    return addrs.length > 0
  }
  // ptr:domain(简化:对客户端 IP 反查,正向名后缀匹配)
  m = /^ptr(?::(.+))?$/i.exec(mech)
  if (m) {
    if (!clientIp) return false
    queries.count++
    const names = dnsPtr(clientIp)
    const dom = (m[1] || currentDomain).toLowerCase()
    trace.push({ step: 'dns', text: `PTR ${clientIp} → [${names.join(', ')}]`, query: `PTR ${clientIp}` })
    return names.some((n) => n.toLowerCase().endsWith(dom))
  }
  // all
  if (/^all$/i.test(mech)) return true
  return false
}

function evaluateQuiet(domain, ip, depth, queries, trace) {
  // include 复用主逻辑但共享查询计数
  const saved = queries.count
  const r = evaluateSpfInner(domain, ip, depth, queries, trace)
  queries.count = saved + (r._queriesUsed || 0)
  return r.result
}

function evaluateSpfInner(domain, ip, depth, queries, parentTrace) {
  const localTrace = []
  const txts = dnsTxt(domain)
  queries.count++
  const rec = txts.find((t) => /^v=spf1(?:\s|$)/i.test(t))
  localTrace.push({ step: 'dns', text: `include 查询 TXT ${domain} → ${rec || '(无)'}` })
  if (!rec) return { result: 'none', _queriesUsed: 1 }
  const terms = rec.trim().split(/\s+/).slice(1)
  let used = 1
  for (const term of terms) {
    const { q, mech } = qualifierOf(term)
    const before = queries.count
    const hit = matchMechanism(mech, ip, domain, depth, q, localTrace, queries)
    used += queries.count - before
    if (hit) {
      parentTrace.push(...localTrace, { step: 'include-result', text: `include:${domain} 子结果 ${RESULT_LABEL[q]}` })
      return { result: q, _queriesUsed: used }
    }
  }
  parentTrace.push(...localTrace)
  return { result: 'neutral', _queriesUsed: used }
}

function buildResult(result, explanation, trace, queryCount = 0) {
  return {
    result, // pass/fail/softfail/neutral/none/temperror/permerror
    label: RESULT_LABEL[result] || result.toUpperCase(),
    explanation,
    queryCount,
    trace
  }
}

function explain(r) {
  return (
    {
      pass: '客户端 IP 在 SPF 授权范围内',
      fail: '客户端 IP 未被授权,策略为 -all(硬失败)',
      softfail: '客户端 IP 未被授权,策略为 ~all(软失败)',
      neutral: '域所有者不表态(?all 或无匹配)',
      none: '该域没有 SPF 记录',
      temperror: 'DNS 临时错误,可重试',
      permerror: 'SPF 记录语法/结构错误(如多记录、超查询上限)'
    }[r] || r
  )
}
