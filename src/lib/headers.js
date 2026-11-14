/**
 * headers.js — 信头层面的身份伪造与可疑特征检测
 */
import { decodeEncodedWords } from './encoding.js'

const FREE_MAIL_DOMAINS = new Set(['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'qq.com', '163.com', '126.com', 'aol.com', 'proton.me', 'protonmail.com', 'mail.ru'])

function addrDomain(addr) {
  if (!addr) return null
  const m = /@([^>\s]+)>?$/.exec(addr.trim())
  return (m ? m[1] : addr.split('@').pop()).toLowerCase().replace(/[<>]/g, '')
}

function asList(v) {
  return Array.isArray(v) ? v : v ? [v] : []
}

function mailboxOf(addr) {
  // postal-mime 地址对象 {name, address} 或地址组 {group:[]}
  if (!addr) return []
  if (addr.group) return addr.group.flatMap(mailboxOf)
  return [{ name: addr.name || '', address: (addr.address || '').toLowerCase() }]
}

/**
 * @param {object} parsed  postal-mime 解析结果
 * @param {object} rawHeaders  原始头 Map(小写 key -> string[])
 */
export function analyzeHeaders(parsed, rawHeaders) {
  const findings = []
  const add = (severity, code, text) => findings.push({ severity, code, text })

  const fromList = mailboxOf(parsed.from)
  const from = fromList[0] || null
  const senderList = mailboxOf(parsed.sender)
  const sender = senderList[0] || null
  const replyToList = (parsed.replyTo || []).flatMap(mailboxOf)
  const returnPath = (parsed.returnPath || '').replace(/^<|>$/g, '').toLowerCase()

  const fromDomain = from ? addrDomain(from.address) : null
  const senderDomain = sender ? addrDomain(sender.address) : null
  const replyDomains = replyToList.map((r) => addrDomain(r.address))
  const returnDomain = returnPath ? addrDomain(returnPath) : null

  // 1. From 与 Sender 域不一致
  if (fromDomain && senderDomain && senderDomain !== fromDomain) {
    add('high', 'SPOOF_SENDER', `From 域 ${fromDomain} 与 Sender 域 ${senderDomain} 不一致,Sender 是实际投递方`)
  }

  // 2. Return-Path 与 From 域不一致(SPF 对齐也会失败)
  if (fromDomain && returnDomain && returnDomain !== fromDomain && !returnDomain.endsWith('.' + fromDomain) && !fromDomain.endsWith('.' + returnDomain)) {
    add('medium', 'ENVELOPE_MISMATCH', `Return-Path 域 ${returnDomain} 与 From 域 ${fromDomain} 不一致(信封/信头身份分离)`)
  }

  // 3. Reply-To 指向外部/免费邮箱
  for (const rd of replyDomains) {
    if (fromDomain && rd !== fromDomain && !rd.endsWith('.' + fromDomain)) {
      const level = FREE_MAIL_DOMAINS.has(rd) ? 'high' : 'medium'
      add(level, 'REPLYTO_EXTERNAL', `Reply-To 指向 ${rd},与发件域 ${fromDomain} 不同,回复可能被劫持到攻击者邮箱`)
    }
  }

  // 4. 显示名仿冒:From 显示名里写着别的机构/邮箱
  if (from?.name) {
    const display = decodeEncodedWords(from.name)
    const emailInName = /[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/i.exec(display)
    if (emailInName && addrDomain(emailInName[0]) !== fromDomain) {
      add('high', 'DISPLAY_NAME_SPOOF', `显示名 "${display}" 内嵌邮箱 ${emailInName[0]},与真实地址 ${from.address} 不符`)
    }
    if (/(?:service|support|admin|security|it|helpdesk|postmaster|财务|客服|管理员|支持)/i.test(display) && FREE_MAIL_DOMAINS.has(fromDomain)) {
      add('high', 'FREE_MAIL_IMPERSONATION', `显示名冒充职能账号("${display}"),但使用免费公共邮箱 ${fromDomain}`)
    }
  }

  // 5. 免费邮箱却声称企业身份(结合显示名)
  if (fromDomain && FREE_MAIL_DOMAINS.has(fromDomain) && /(?:invoice|payment| payroll|hr|采购|发票|工资)/i.test(parsed.subject || '')) {
    add('medium', 'FREE_MAIL_BIZ', '免费邮箱发送业务/财务类主题邮件')
  }

  // 6. X-Mailer / User-Agent 异常
  const xMailer = (rawHeaders['x-mailer']?.[0] || rawHeaders['user-agent']?.[0] || '')
  if (/php|python|swiftmailer|mail\(\)|bulk|mass/i.test(xMailer)) {
    add('medium', 'BULK_MAILER', `X-Mailer 为脚本/群发工具:${xMailer}`)
  }

  // 7. Message-ID 域与 From 不一致或缺失
  const msgId = parsed.messageId || ''
  const idDomain = /@([^>]+)>?$/.exec(msgId)?.[1]?.toLowerCase()
  if (msgId && idDomain && fromDomain && idDomain !== fromDomain && !idDomain.endsWith('.' + fromDomain)) {
    add('low', 'MSGID_MISMATCH', `Message-ID 域 ${idDomain} 与 From 域 ${fromDomain} 不一致`)
  }
  if (!msgId) add('low', 'NO_MSGID', '缺少 Message-ID,正规邮件系统通常都会生成')

  // 8. 多 From / 多 Subject 等畸形头
  if ((rawHeaders['from']?.length || 0) > 1) add('high', 'MULTI_FROM', `存在 ${rawHeaders.from.length} 个 From 头,属于畸形/攻击邮件`)
  if ((rawHeaders['subject']?.length || 0) > 1) add('medium', 'MULTI_SUBJECT', `存在多个 Subject 头`)

  // 9. Date 异常
  if (parsed.date) {
    const t = Date.parse(parsed.date)
    if (Number.isFinite(t) && t > Date.now() + 24 * 3600 * 1000) {
      add('low', 'FUTURE_DATE', `发件时间在未来(${parsed.date}),可能是伪造或时区错误`)
    }
  }

  // 10. X-Originating-IP 与 Received 起点比对(辅助)
  const xOriginIp = rawHeaders['x-originating-ip']?.[0]?.replace(/[[\]]/g, '')
  const xForwarded = rawHeaders['x-forwarded-for']?.[0]

  // 11. 优先级/自动提交滥用
  if (/urgent|high/i.test(rawHeaders['x-priority']?.[0] || '') && /urgent|紧急|立即/i.test(parsed.subject || '')) {
    add('low', 'URGENCY', '高优先级 + 紧急措辞,社工催促特征')
  }

  return {
    findings,
    identities: {
      from: from || null,
      fromDomain,
      sender: sender || null,
      senderDomain,
      replyTo: replyToList,
      replyDomains,
      returnPath,
      returnDomain,
      messageId: msgId,
      idDomain,
      xMailer,
      xOriginIp: xOriginIp || null,
      xForwardedFor: xForwarded || null
    }
  }
}

/** 综合评分:把各模块结果折算成 0-100 威胁分 */
export function scoreThreat({ headerFindings, links, attachments, auth }) {
  let score = 0
  const reasons = []
  const bump = (pts, reason) => {
    score += pts
    reasons.push({ pts, reason })
  }

  for (const f of headerFindings) {
    if (f.severity === 'high') bump(18, `信头:${f.text}`)
    else if (f.severity === 'medium') bump(8, `信头:${f.text}`)
    else bump(3, `信头:${f.text}`)
  }
  for (const l of links) {
    if (l.severity === 'high') bump(20, `高危链接:${l.host || l.url}`)
    else if (l.severity === 'medium') bump(8, `可疑链接:${l.host || l.url}`)
    else if (l.severity === 'low') bump(3, `链接风险:${l.url}`)
  }
  for (const a of attachments) {
    if (a.severity === 'high') bump(25, `危险附件:${a.filename}`)
    else if (a.severity === 'medium') bump(10, `可疑附件:${a.filename}`)
    else if (a.severity === 'low') bump(3, `附件提示:${a.filename}`)
  }
  if (auth) {
    if (auth.dmarc?.result === 'fail') bump(22, 'DMARC 校验失败')
    if (auth.spf?.result === 'fail') bump(12, 'SPF 硬失败')
    else if (auth.spf?.result === 'softfail') bump(6, 'SPF 软失败')
    else if (auth.spf?.result === 'none' || auth.spf?.result === 'neutral') bump(3, `SPF ${auth.spf.label}`)
    if (auth.dkim?.signatures?.length && !auth.dkim.verified) bump(12, 'DKIM 签名无效')
    if (!auth.dkim?.signatures?.length) bump(4, '无 DKIM 签名')
  }

  return { score: Math.min(100, score), level: score >= 60 ? 'critical' : score >= 35 ? 'high' : score >= 15 ? 'medium' : score > 0 ? 'low' : 'safe', reasons }
}
