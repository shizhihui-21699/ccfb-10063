/**
 * node-test/run-tests.mjs — 在 Node 下跑通完整分析链路
 * 用法: node --experimental-vm-modules node-test/run-tests.mjs
 * 仅用于开发期自测,不参与前端构建。
 */
import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { webcrypto } from 'node:crypto'

// 浏览器 API 兜底(Node 26 已内置 crypto/atob/btoa/performance)
if (!globalThis.crypto) globalThis.crypto = webcrypto
if (!globalThis.atob) globalThis.atob = (s) => Buffer.from(s, 'base64').toString('binary')
if (!globalThis.btoa) globalThis.btoa = (s) => Buffer.from(s, 'binary').toString('base64')
if (!globalThis.performance) globalThis.performance = { now: () => Date.now() }

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..')

// 装载 mock DKIM 公钥(覆盖内置占位公钥)
const pubkeys = JSON.parse(readFileSync(join(ROOT, 'public/samples/dkim-keys.json'), 'utf8'))
const { saveOverride } = await import('../src/lib/mock-dns.js')
const override = {}
for (const [name, record] of Object.entries(pubkeys)) {
  override[name] = { TXT: [record] }
}
saveOverride(override)

const { analyzeEmail } = await import('../src/lib/analyzer.js')
const { splitMbox } = await import('../src/lib/mbox.js')

const sampleDir = join(ROOT, 'public/samples')
const files = readdirSync(sampleDir).filter((f) => f.endsWith('.eml')).sort()

let pass = 0
let fail = 0
const expectations = {
  '01': { spf: 'pass', dmarc: 'pass', dkimValid: true, maxScore: 15 },
  '02': { spf: 'pass', dmarc: 'pass', dkimValid: true, maxScore: 15 },
  '03': { spf: 'softfail', dmarc: 'fail', dkimValid: false, minScore: 40 }, // bank 域是 ~all,未授权 IP → softfail;DMARC 仍 fail
  '04': { tag: '伪造发件人', minScore: 20 },
  '05': { tag: '回复劫持', minScore: 20 },
  '06': { mismatchLink: true, tag: '链接欺骗' },
  '07': { tag: '同形异义域名' },
  '08': { tag: '宏文档', highAttachment: true },
  '09': { tag: '扩展名伪装', highAttachment: true },
  '10': { subjectDecoded: true, highAttachment: true },
  '11': { nestedRfc822: true },
  '12': { deepMime: true },
  '13': { dkimExpired: true },
  '14': { dkimInvalid: true },
  '15': { spf: 'softfail', dmarc: 'fail', dmarcDisposition: 'none' }, // p=none:认证失败但不处置
  '16': { spf: 'none', tag: '无防护域名' },
  '17': { highAttachment: true },
  '18': { highAttachment: true },
  '19': { highAttachment: true },
  '20': { spf: 'pass', dkimValid: true, subjectDecoded: true },
  '21': { spf: 'pass', dkimValid: true },
  '22': { dkimValid: true },
  '23': { tag: '群发工具' },
  '24': { chainAnomaly: true },
  '25': { highLink: true },
  '26': { spf: 'pass', dkimValid: true }
}

for (const file of files) {
  const id = file.slice(0, 2)
  const bytes = new Uint8Array(readFileSync(join(sampleDir, file)))
  let report
  try {
    report = await analyzeEmail(bytes, file)
  } catch (e) {
    console.log(`❌ ${file} 分析抛异常: ${e.stack}`)
    fail++
    continue
  }
  const exp = expectations[id] || {}
  const errors = []
  const check = (cond, msg) => {
    if (!cond) errors.push(msg)
  }

  if (exp.spf) check(report.auth.spf.result === exp.spf, `SPF 期望 ${exp.spf}, 实际 ${report.auth.spf.result}`)
  if (exp.dmarc) check(report.auth.dmarc.result === exp.dmarc, `DMARC 期望 ${exp.dmarc}, 实际 ${report.auth.dmarc.result}`)
  if (exp.dmarcDisposition) check(report.auth.dmarc.disposition === exp.dmarcDisposition, `DMARC 处置期望 ${exp.dmarcDisposition}, 实际 ${report.auth.dmarc.disposition}`)
  if (exp.dkimValid === true) check(report.auth.dkim.verified, `DKIM 应有效, 实际 ${report.auth.dkim.summary}`)
  if (exp.dkimInvalid) check(!report.auth.dkim.verified && report.auth.dkim.signatures.length > 0, 'DKIM 应无效但有签名')
  if (exp.dkimExpired) check(report.auth.dkim.signatures.some((s) => s.trace.some((t) => t.text.includes('过期'))), 'DKIM 应过期')
  if (exp.tag) check([...report.autoTags, ...report.userTags].includes(exp.tag), `缺少标签 ${exp.tag}, 实际 ${report.autoTags.join('/')}`)
  if (exp.mismatchLink) check(report.links.some((l) => l.mismatch), '应有显示/真实不一致链接')
  if (exp.highAttachment) check(report.attachments.some((a) => a.severity === 'high'), '应有高危附件')
  if (exp.highLink) check(report.links.some((l) => l.severity === 'high'), '应有高危链接')
  if (exp.subjectDecoded) check(!/=\?/.test(report.envelope.subject), `主题未解码: ${report.envelope.subject}`)
  if (exp.nestedRfc822) check(JSON.stringify(report.mimeTree).includes('message/rfc822'), 'MIME 树应含 message/rfc822')
  if (exp.deepMime) {
    let depth = 0
    const countDepth = (n) => {
      depth = Math.max(depth, n.partId.split('.').length)
      n.children.forEach(countDepth)
    }
    countDepth(report.mimeTree)
    check(depth >= 6, `MIME 嵌套深度应≥6 层, 实际 ${depth}`)
  }
  if (exp.chainAnomaly) check(report.chain.anomalies.length > 0, '应检出 Received 异常')
  if (exp.minScore) check(report.threat.score >= exp.minScore, `评分应≥${exp.minScore}, 实际 ${report.threat.score}`)
  if (exp.maxScore) check(report.threat.score <= exp.maxScore, `正常邮件评分应≤${exp.maxScore}, 实际 ${report.threat.score}`)

  if (errors.length) {
    fail++
    console.log(`❌ ${file}`)
    for (const e of errors) console.log(`    - ${e}`)
    console.log(`    SPF=${report.auth.spf.result} DKIM=${report.auth.dkim.verified} DMARC=${report.auth.dmarc.result} 评分=${report.threat.score} 标签=${report.autoTags.join(',')}`)
  } else {
    pass++
    console.log(
      `✅ ${file} | 评分 ${String(report.threat.score).padStart(3)} ${report.threat.level.padEnd(8)} SPF=${report.auth.spf.result.padEnd(9)} DKIM=${(report.auth.dkim.signatures.length ? (report.auth.dkim.verified ? 'valid' : 'invalid') : 'none').padEnd(7)} DMARC=${report.auth.dmarc.result.padEnd(4)} 链接${report.links.length} 附件${report.attachments.length}`
    )
  }
}

// mbox 切分测试
const mboxFile = join(sampleDir, 'batches', '钓鱼样本批次A-前8封.mbox')
const mboxBytes = new Uint8Array(readFileSync(mboxFile))
const split = splitMbox(mboxBytes)
if (split.length === 8) {
  pass++
  console.log(`✅ mbox 切分: 批次A 正确切出 8 封`)
} else {
  fail++
  console.log(`❌ mbox 切分: 期望 8 封, 实际 ${split.length}`)
}

// 编码还原专项
const { decodeEncodedWords, parseHeaderParams } = await import('../src/lib/encoding.js')
const { ENCODERS } = await import('../tools/charset-tables.js')
const gbkB64 = Buffer.from(ENCODERS.gbk('采购合同')).toString('base64')
const encCases = [
  ['=?UTF-8?B?5rWL6K+V?=', '测试'],
  ['=?gbk?B?' + gbkB64 + '?=', '采购合同'],
  ['普通文本无编码', '普通文本无编码']
]
for (const [input, want] of encCases) {
  const got = decodeEncodedWords(input)
  if (got === want) {
    pass++
    console.log(`✅ encoded-word 解码: ${want}`)
  } else {
    fail++
    console.log(`❌ encoded-word 解码: 输入 ${input}, 期望 ${want}, 得到 ${got}`)
  }
}

console.log(`\n==== 结果: ${pass} 通过 / ${fail} 失败 ====`)
process.exit(fail ? 1 : 0)
