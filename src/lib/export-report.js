/**
 * export-report.js — 分析结果导出
 *
 * 支持:
 *  - JSON:完整结构化报告
 *  - TXT:人工可读的文本摘要(工单/IM 粘贴友好)
 *  - HTML:独立单文件报告(内联样式,可直接发同事)
 *  - 批量导出:多封邮件合并 JSON / 汇总 CSV
 */

export function downloadBlob(content, filename, mime = 'application/octet-stream') {
  const blob = content instanceof Blob ? content : new Blob([content], { type: `${mime};charset=utf-8` })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export function exportJson(report) {
  const clean = JSON.parse(
    JSON.stringify(report, (k, v) => {
      // 导出时去掉大体量原始字节字段
      if (k === 'rawBody' || k === 'body' || k === 'headerRaw') return undefined
      return v
    })
  )
  downloadBlob(JSON.stringify(clean, null, 2), `${safeName(report.envelope.subject)}-report.json`, 'application/json')
}

export function exportTxt(r) {
  const L = []
  const push = (x = '') => L.push(x)
  push('====== 钓鱼邮件分析报告 ======')
  push(`来源文件:${r.sourceName}`)
  push(`分析时间:${r.analyzedAt}  耗时 ${r.elapsedMs}ms  大小 ${r.size} 字节`)
  push()
  push('-- 基本信息 --')
  push(`主题:${r.envelope.subject}`)
  push(`From:${formatMb(r.envelope.from)}`)
  push(`Sender:${formatMb(r.envelope.sender)}`)
  push(`Reply-To:${(r.envelope.replyTo || []).map(formatMb).join('; ')}`)
  push(`Return-Path:${r.envelope.returnPath}`)
  push(`To:${(r.envelope.to || []).map(formatMb).join('; ')}`)
  push(`Message-ID:${r.envelope.messageId}`)
  push(`Date:${r.envelope.date}`)
  push()
  push('-- 威胁评分 --')
  push(`${r.threat.score}/100 [${r.threat.level.toUpperCase()}]  标签:${[...r.autoTags, ...r.userTags].join(', ') || '(无)'}`)
  for (const x of r.threat.reasons) push(`  +${x.pts} ${x.reason}`)
  push()
  push('-- 认证结果 --')
  push(`SPF:${r.auth.spf.label} — ${r.auth.spf.explanation}(客户端 IP ${r.auth.clientIp || '未知'})`)
  if (r.auth.dkim.signatures.length === 0) push('DKIM:无签名')
  for (const s of r.auth.dkim.signatures) {
    push(`DKIM:${s.status.toUpperCase()} d=${s.domain} s=${s.selector} a=${s.algorithm} bh=${s.bodyHashMatch ? '匹配' : '不匹配'} b=${s.signatureMatch ? '匹配' : '不匹配'}`)
  }
  push(`DMARC:${r.auth.dmarc.result.toUpperCase()} 策略 p=${r.auth.dmarc.publishedPolicy || '无记录'} 处置建议=${r.auth.dmarc.disposition}(${r.auth.dmarc.reason})`)
  push()
  push('-- 投递路径(Received) --')
  for (const h of r.chain.hops) {
    push(`#${h.index + 1} ${h.helo || '?'} ${h.ip ? '[' + h.ip + ']' : ''} → by ${h.by || '?'} ${h.protocol || ''} ${h.dateRaw || ''}`)
    if (h.dnsCheck?.ptrName) push(`     PTR:${h.dnsCheck.ptrName} 正向校验:${h.dnsCheck.ptrMatch ? '一致' : '不一致'}`)
  }
  for (const a of r.chain.anomalies) push(`  [!] ${a}`)
  push()
  push('-- 链接 --')
  if (!r.links.length) push('(无)')
  for (const u of r.links) {
    push(`[${u.severity.toUpperCase()}] ${u.visibleText ? `显示="${u.visibleText}" ` : ''}真实=${u.url}`)
    push(`  去武装:${u.defanged}`)
    for (const f of u.flags) push(`  - ${f.text}`)
  }
  push()
  push('-- 附件(静态分析,未执行) --')
  if (!r.attachments.length) push('(无)')
  for (const a of r.attachments) {
    push(`[${a.severity.toUpperCase()}] ${a.filename} (${a.size}B, 声明 ${a.declaredMime}/.${a.declaredExt}, 实测 ${a.realType})`)
    push(`  SHA-256:${a.sha256}`)
    push(`  MD5:${a.md5}  熵:${a.entropy}`)
    for (const f of a.findings) push(`  - [${f.severity}] ${f.text}`)
    if (a.zipEntries?.length) push(`  压缩包条目:${a.zipEntries.join(' | ')}`)
  }
  push()
  push('-- 信头检测 --')
  if (!r.headerAnalysis.findings.length) push('(无异常)')
  for (const f of r.headerAnalysis.findings) push(`[${f.severity}] ${f.text}`)
  if (r.notes) {
    push()
    push('-- 分析师备注 --')
    push(r.notes)
  }
  downloadBlob(L.join('\n'), `${safeName(r.envelope.subject)}-report.txt`, 'text/plain')
}

export function exportHtml(r) {
  const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))
  const sevColor = { high: '#c0392b', medium: '#d68910', low: '#7d6608', safe: '#1e8449', critical: '#7b241c', info: '#5d6d7e' }
  const badge = (s) => `<span class="b" style="background:${sevColor[s] || '#5d6d7e'}">${esc(s)}</span>`
  const authColor = { pass: '#1e8449', valid: '#1e8449', fail: '#c0392b', invalid: '#c0392b', none: '#7f8c8d', softfail: '#d68910', neutral: '#7f8c8d' }

  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>${esc(r.envelope.subject)} - 分析报告</title>
<style>
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;margin:24px;color:#222;background:#f7f8fa}
h1{font-size:20px}h2{font-size:15px;margin:22px 0 8px;border-left:4px solid #2c3e50;padding-left:8px}
table{border-collapse:collapse;width:100%;background:#fff;font-size:13px}
td,th{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}
.b{color:#fff;padding:1px 8px;border-radius:10px;font-size:11px;text-transform:uppercase}
.card{background:#fff;border:1px solid #ddd;border-radius:8px;padding:14px;margin-bottom:12px}
.score{font-size:34px;font-weight:700;color:${sevColor[r.threat.level]}}
.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
.flag{color:#c0392b}.muted{color:#7f8c8d}
.path span{display:inline-block;background:#eaf2f8;border:1px solid #aed6f1;border-radius:6px;padding:3px 8px;margin:2px;font-size:12px}
.auth{font-weight:700}
</style></head><body>
<h1>钓鱼邮件分析报告</h1>
<div class="card"><table>
<tr><th>主题</th><td>${esc(r.envelope.subject)}</td></tr>
<tr><th>From</th><td>${esc(formatMb(r.envelope.from))}</td></tr>
<tr><th>Sender</th><td>${esc(formatMb(r.envelope.sender))}</td></tr>
<tr><th>Reply-To</th><td>${esc((r.envelope.replyTo || []).map(formatMb).join('; '))}</td></tr>
<tr><th>Return-Path</th><td class="mono">${esc(r.envelope.returnPath)}</td></tr>
<tr><th>时间</th><td>${esc(r.envelope.date)}</td></tr>
<tr><th>来源</th><td>${esc(r.sourceName)} / ${r.size} 字节</td></tr>
</table></div>
<div class="card">威胁评分 <span class="score">${r.threat.score}</span>/100 ${badge(r.threat.level)}
<p>标签:${[...r.autoTags, ...r.userTags].map((t) => `<span class="b" style="background:#2c3e50">${esc(t)}</span>`).join(' ')}</p></div>
<h2>认证 (SPF / DKIM / DMARC)</h2>
<div class="card"><table>
<tr><th>SPF</th><td class="auth" style="color:${authColor[r.auth.spf.result] || '#333'}">${esc(r.auth.spf.label)}</td><td>${esc(r.auth.spf.explanation)}</td></tr>
${r.auth.dkim.signatures
  .map(
    (s) =>
      `<tr><th>DKIM</th><td class="auth" style="color:${authColor[s.status]}">${esc(s.status.toUpperCase())}</th><td>d=${esc(s.domain)} s=${esc(s.selector)} a=${esc(s.algorithm)} 正文哈希 ${s.bodyHashMatch ? '✓' : '✗'} 签名 ${s.signatureMatch ? '✓' : '✗'}</td></tr>`
  )
  .join('') || '<tr><th>DKIM</th><td colspan="2" class="muted">无签名</td></tr>'}
<tr><th>DMARC</th><td class="auth" style="color:${authColor[r.auth.dmarc.result]}">${esc(r.auth.dmarc.result.toUpperCase())}</th><td>p=${esc(r.auth.dmarc.publishedPolicy || '无记录')} → 处置 ${esc(r.auth.dmarc.disposition)};${esc(r.auth.dmarc.reason)}</td></tr>
</table></div>
<h2>投递路径</h2>
<div class="card path">${r.chain.hops
  .map((h) => `<span>#${h.index + 1} ${esc(h.helo || '?')} ${h.ip ? '[' + esc(h.ip) + ']' : ''} → ${esc(h.by || '?')}</span>`)
  .join(' → ')}</div>
<h2>链接 (${r.links.length})</h2>
<div class="card"><table><tr><th>级别</th><th>显示文字 / 真实地址 / 去武装</th><th>检测</th></tr>
${r.links
  .map(
    (u) =>
      `<tr><td>${badge(u.severity)}</td><td>${u.visibleText ? `显示:<b class="${u.mismatch ? 'flag' : ''}">${esc(u.visibleText)}</b><br>` : ''}<span class="mono">${esc(u.url)}</span><br><span class="muted mono">${esc(u.defanged)}</span></td><td>${u.flags
        .map((f) => esc(f.text))
        .join('<br>')}</td></tr>`
  )
  .join('') || '<tr><td colspan="3" class="muted">无</td></tr>'}</table></div>
<h2>附件 (${r.attachments.length}, 仅静态分析)</h2>
<div class="card"><table><tr><th>级别</th><th>文件 / 类型</th><th>哈希与发现</th></tr>
${r.attachments
  .map(
    (a) =>
      `<tr><td>${badge(a.severity)}</td><td><b>${esc(a.filename)}</b><br>${a.size}B<br>声明 .${esc(a.declaredExt)} / ${esc(a.declaredMime)}<br>实测 ${esc(a.realType)}</td><td class="mono">SHA-256 ${esc(a.sha256)}<br>熵 ${a.entropy}${a.findings
        .map((f) => `<br><span class="flag">[${esc(f.severity)}] ${esc(f.text)}</span>`)
        .join('')}</td></tr>`
  )
  .join('') || '<tr><td colspan="3" class="muted">无</td></tr>'}</table></div>
<h2>信头检测</h2>
<div class="card"><table>${r.headerAnalysis.findings
  .map((f) => `<tr><td>${badge(f.severity)}</td><td>${esc(f.text)}</td></tr>`)
  .join('') || '<tr><td class="muted">无异常</td></tr>'}</table></div>
${r.notes ? `<h2>分析师备注</h2><div class="card">${esc(r.notes).replace(/\n/g, '<br>')}</div>` : ''}
<p class="muted" style="font-size:11px">由本地钓鱼邮件分析台生成,DNS 数据为本地 Mock,附件仅做静态检查未执行。</p>
</body></html>`
  downloadBlob(html, `${safeName(r.envelope.subject)}-report.html`, 'text/html')
}

export function exportBatchCsv(reports) {
  const rows = [
    ['文件名', '主题', 'From', '评分', '级别', 'SPF', 'DKIM', 'DMARC', '链接数', '高危链接', '附件数', '危险附件', '标签', 'Message-ID']
  ]
  for (const r of reports) {
    rows.push([
      r.sourceName,
      r.envelope.subject,
      formatMb(r.envelope.from),
      r.threat.score,
      r.threat.level,
      r.auth.spf.label,
      r.auth.dkim.verified ? 'VALID' : r.auth.dkim.signatures.length ? 'INVALID' : 'NONE',
      r.auth.dmarc.result.toUpperCase(),
      r.links.length,
      r.links.filter((l) => l.severity === 'high').length,
      r.attachments.length,
      r.attachments.filter((a) => a.severity === 'high').length,
      [...new Set([...r.autoTags, ...r.userTags])].join('|'),
      r.envelope.messageId || ''
    ])
  }
  const csv = rows
    .map((row) => row.map((c) => `"${String(c ?? '').replace(/"/g, '""')}"`).join(','))
    .join('\r\n')
  // BOM 保证 Excel 正确识别 UTF-8
  downloadBlob('﻿' + csv, `邮件分析汇总-${stamp()}.csv`, 'text/csv')
}

export function exportBatchJson(reports) {
  const clean = reports.map((r) =>
    JSON.parse(JSON.stringify(r, (k, v) => (k === 'rawBody' || k === 'body' || k === 'headerRaw' ? undefined : v)))
  )
  downloadBlob(JSON.stringify(clean, null, 2), `邮件分析批量-${stamp()}.json`, 'application/json')
}

function formatMb(addr) {
  if (!addr) return ''
  if (addr.group) return addr.group.map(formatMb).join('; ')
  return addr.name ? `${addr.name} <${addr.address}>` : addr.address || ''
}
function safeName(s) {
  return String(s || 'email').replace(/[\\/:*?"<>|\s]+/g, '_').slice(0, 60)
}
function stamp() {
  return new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
}
