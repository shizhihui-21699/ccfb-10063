/**
 * dmarc.js — DMARC 本地评估(RFC 7489)
 *
 * 输入 SPF / DKIM 结果与 Header From 域,做标识符对齐检查,
 * 再按 _dmarc 记录的 p= 给出处置建议。DNS 走 mock。
 */
import { dnsTxt } from './mock-dns.js'

function parentDomain(domain) {
  const parts = domain.split('.')
  if (parts.length <= 2) return domain
  return parts.slice(1).join('.')
}

function aligned(authDomain, headerFrom, mode) {
  const a = authDomain.toLowerCase().replace(/\.$/, '')
  const h = headerFrom.toLowerCase().replace(/\.$/, '')
  if (!a || !h) return false
  if (mode === 's') return a === h // strict
  return a === h || a.endsWith('.' + h) || h.endsWith('.' + a) // relaxed(默认)
}

export function parseDmarcRecord(raw) {
  const tags = {}
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const k = part.slice(0, eq).trim().toLowerCase()
    const v = part.slice(eq + 1).trim()
    if (!(k in tags)) tags[k] = v
  }
  return tags
}

/**
 * @param {object} opts
 * @param {string} opts.headerFromDomain   From 头地址的域
 * @param {object} opts.spfResult          spf.js 的结果
 * @param {string} [opts.spfAuthDomain]    SPF 通过时的授权域(MAIL FROM 域)
 * @param {object} opts.dkimResult         dkim.js 的结果
 * @param {string} [opts.spfMode]          aspf: r/s
 * @param {string} [opts.dkimMode]         adkim: r/s
 */
export function evaluateDmarc({ headerFromDomain, spfResult, spfAuthDomain, dkimResult, spfMode, dkimMode }) {
  const trace = []
  if (!headerFromDomain) {
    return base('none', '缺少 Header From 域,无法评估 DMARC', [], trace)
  }

  // 1. 找 DMARC 记录:先精确 _dmarc.<域>,再按组织域上溯
  let dmarcDomain = `_dmarc.${headerFromDomain}`
  let txts = dnsTxt(dmarcDomain)
  let record = txts.find((t) => /^v=DMARC1/i.test(t))
  if (!record) {
    const org = parentDomain(headerFromDomain)
    if (org !== headerFromDomain) {
      dmarcDomain = `_dmarc.${org}`
      txts = dnsTxt(dmarcDomain)
      record = txts.find((t) => /^v=DMARC1/i.test(t))
      if (record) trace.push({ step: 'dns', text: `本域无记录,上溯组织域 ${dmarcDomain}` })
    }
  }
  trace.push({ step: 'dns', text: `TXT ${dmarcDomain} → ${record || '(无 DMARC 记录)'}` })

  if (!record) {
    return base('none', `域 ${headerFromDomain} 未发布 DMARC 记录`, [], trace)
  }
  if (txts.filter((t) => /^v=DMARC1/i.test(t)).length > 1) {
    trace.push({ step: 'error', text: '存在多条 DMARC 记录,按规范策略评估失败' })
  }

  const tags = parseDmarcRecord(record)
  const policy = (tags.p || 'none').toLowerCase()
  const subPolicy = (tags.sp || policy).toLowerCase()
  const isSubdomain = headerFromDomain !== parentDomain(headerFromDomain)
  const effectivePolicy = isSubdomain ? subPolicy : policy
  const aSpf = (spfMode || tags.aspf || 'r').toLowerCase()
  const aDkim = (dkimMode || tags.adkim || 'r').toLowerCase()
  const pct = Number(tags.pct ?? 100)

  // 2. SPF 认证 + 对齐
  const spfAligned =
    spfResult && spfResult.result === 'pass' && spfAuthDomain ? aligned(spfAuthDomain, headerFromDomain, aSpf) : false
  trace.push({
    step: 'align',
    text: `SPF 结果 ${spfResult?.label || 'N/A'} ${spfAuthDomain ? `(授权域 ${spfAuthDomain})` : ''}, ${aSpf === 's' ? '严格' : '宽松'}对齐 → ${spfAligned ? '是' : '否'}`
  })

  // 3. DKIM 认证 + 对齐
  const dkimDetails = []
  let dkimAligned = false
  if (dkimResult?.signatures?.length) {
    for (const sig of dkimResult.signatures) {
      const ok = sig.status === 'valid' && aligned(sig.domain, headerFromDomain, aDkim)
      dkimDetails.push({
        domain: sig.domain,
        valid: sig.status === 'valid',
        aligned: ok,
        mode: aDkim
      })
      if (ok) dkimAligned = true
    }
  }
  trace.push({
    step: 'align',
    text: `DKIM ${dkimResult?.signatures?.length || 0} 个签名,${aDkim === 's' ? '严格' : '宽松'}对齐 → ${dkimAligned ? '存在对齐签名' : '无对齐签名'}`
  })

  const authenticated = spfAligned || dkimAligned
  const dmarcResult = authenticated ? 'pass' : 'fail'

  // 4. 处置建议
  let disposition = 'none'
  if (dmarcResult === 'fail') {
    if (effectivePolicy === 'reject') disposition = 'reject'
    else if (effectivePolicy === 'quarantine') disposition = 'quarantine'
    else disposition = 'none'
  }

  const reasons = []
  if (!spfAligned) reasons.push('SPF 未通过或未对齐')
  if (!dkimAligned) reasons.push('DKIM 无有效且对齐的签名')

  return {
    result: dmarcResult,
    disposition,
    policy: effectivePolicy,
    publishedPolicy: policy,
    subdomainPolicy: subPolicy,
    isSubdomain,
    pct,
    record,
    recordDomain: dmarcDomain,
    spfAligned,
    dkimAligned,
    dkimDetails,
    alignment: { spf: aSpf, dkim: aDkim },
    rua: tags.rua || null,
    reason: authenticated ? 'SPF 或 DKIM 至少一项与 Header From 对齐' : reasons.join(';'),
    trace
  }
}

function base(result, reason, dkimDetails, trace) {
  return {
    result,
    disposition: 'none',
    policy: null,
    publishedPolicy: null,
    subdomainPolicy: null,
    isSubdomain: false,
    pct: 100,
    record: null,
    recordDomain: null,
    spfAligned: false,
    dkimAligned: false,
    dkimDetails,
    alignment: { spf: 'r', dkim: 'r' },
    rua: null,
    reason,
    trace
  }
}
