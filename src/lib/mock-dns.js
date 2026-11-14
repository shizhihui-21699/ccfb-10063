/**
 * mock-dns.js — 本地 Mock DNS
 *
 * 所有"DNS 查询"都走这份内置数据,不发任何真实网络请求。
 * 配套样例邮件(tools/generate-samples.js)中的域名与这里一一对应。
 * 用户也可以在界面上编辑/导入这份记录(存 localStorage)。
 *
 * 记录类型:TXT / A / AAAA / MX / PTR / CNAME
 */

const STORAGE_KEY = 'pmc.mock-dns.v1'

/** @typedef {{type:string, value:string, ttl?:number}} DnsRecord */

/** 内置基线数据 */
export const BUILTIN_RECORDS = {
  // ---------- 合法域名:SPF/DKIM/DMARC 齐全且对齐 ----------
  'corp.example.com': {
    TXT: [
      'v=spf1 include:_spf.mail.corp.example.com ip4:203.0.113.10 ip4:203.0.113.11 -all',
      'MS=ms1234567 verification token'
    ],
    MX: [{ value: 'mx1.corp.example.com', priority: 10 }],
    A: ['203.0.113.10'],
    _dmarc: {
      TXT: ['v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:dmarc@corp.example.com; adkim=s; aspf=s']
    }
  },
  '_spf.mail.corp.example.com': {
    TXT: ['v=spf1 ip4:203.0.113.20 -all']
  },
  'mx1.corp.example.com': { A: ['203.0.113.10'], PTR: ['mx1.corp.example.com'] },
  'selector1._domainkey.corp.example.com': {
    TXT: ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest-corp-key-placeholder']
  },
  // ---------- 银行(被仿冒对象):严格 reject ----------
  'bank.example.net': {
    TXT: ['v=spf1 ip4:198.51.100.40 ~all'],
    MX: [{ value: 'mail.bank.example.net', priority: 10 }],
    _dmarc: {
      TXT: ['v=DMARC1; p=reject; pct=100; rua=mailto:rua-bank@example.net; adkim=r; aspf=r; fo=1']
    }
  },
  'mail.bank.example.net': { A: ['198.51.100.40'] },
  'dkim._domainkey.bank.example.net': {
    TXT: ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAbank-key-placeholder']
  },
  // ---------- 宽松域名:DMARC p=none,SPF softfail ----------
  'shop.example.org': {
    TXT: ['v=spf1 include:sendgrid.example.org ~all'],
    _dmarc: {
      TXT: ['v=DMARC1; p=none; rua=mailto:dmarc@shop.example.org']
    }
  },
  'sendgrid.example.org': {
    TXT: ['v=spf1 ip4:192.0.2.50 ip4:192.0.2.51 -all']
  },
  's1._domainkey.shop.example.org': {
    TXT: ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAcustomer-key']
  },
  // ---------- 完全没防护的小域名 ----------
  'smallco.example.io': {
    MX: [{ value: 'mbx.smallco.example.io', priority: 20 }],
    A: ['192.0.2.200']
    // 无 SPF / DKIM / DMARC
  },
  // ---------- 攻击者基础设施 ----------
  'bulk-mailer.evil.test': {
    TXT: ['v=spf1 ip4:45.9.148.0/24 -all'],
    A: ['45.9.148.77']
  },
  'phish-login.example.top': { A: ['45.9.148.91'] },
  'secure-bank.example.top': { A: ['45.9.148.92'] },
  'invoice-cdn.example.xyz': { A: ['103.45.67.89'] },
  // 仿冒同形异义:punycode
  'xn--bnak-5qa.example.net': { A: ['45.9.148.93'] },
  // ---------- PTR 区(反向) ----------
  '10.113.0.203.in-addr.arpa': { PTR: ['mx1.corp.example.com'] },
  '77.148.9.45.in-addr.arpa': { PTR: ['bulk-mailer.evil.test'] },
  '91.148.9.45.in-addr.arpa': { PTR: ['unknown-hosting.evil.test'] },
  '40.100.51.198.in-addr.arpa': { PTR: ['mail.bank.example.net'] }
}

/** 把嵌套 _dmarc 拍平成完整查询名 */
function flattenBuiltin() {
  const out = {}
  for (const [name, rec] of Object.entries(BUILTIN_RECORDS)) {
    for (const [type, val] of Object.entries(rec)) {
      if (type === '_dmarc') {
        out[`_dmarc.${name}`] = out[`_dmarc.${name}`] || {}
        out[`_dmarc.${name}`].TXT = val.TXT
      } else {
        out[name] = out[name] || {}
        out[name][type] = val
      }
    }
  }
  return out
}

let overrideRecords = null

function loadOverride() {
  if (overrideRecords !== null) return overrideRecords
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    overrideRecords = raw ? JSON.parse(raw) : {}
  } catch {
    overrideRecords = {}
  }
  return overrideRecords
}

export function saveOverride(records) {
  overrideRecords = records
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(records))
  } catch {
    /* 隐私模式等场景静默失败 */
  }
}

export function resetDns() {
  overrideRecords = {}
  try {
    localStorage.removeItem(STORAGE_KEY)
  } catch {
    /* ignore */
  }
}

/** 当前生效的全量记录(覆盖层优先,可新增/删除某名字的记录) */
export function currentRecords() {
  const base = flattenBuiltin()
  const over = loadOverride()
  const merged = JSON.parse(JSON.stringify(base))
  for (const [name, rec] of Object.entries(over)) {
    if (rec === null) {
      delete merged[name]
    } else {
      merged[name] = rec
    }
  }
  return merged
}

function normalizeName(name) {
  return String(name || '')
    .toLowerCase()
    .replace(/\.$/, '')
}

/**
 * 查询 DNS(模拟)
 * @param {string} name
 * @param {'TXT'|'A'|'AAAA'|'MX'|'PTR'|'CNAME'} type
 * @returns {{found:boolean, records:any[], source:'builtin'|'override'|'none'}}
 */
export function dnsQuery(name, type = 'TXT') {
  const q = normalizeName(name)
  const over = loadOverride()
  if (q in over) {
    const rec = over[q]
    if (rec === null) return { found: false, records: [], source: 'override' }
    return { found: !!rec[type], records: rec[type] ? JSON.parse(JSON.stringify(rec[type])) : [], source: 'override' }
  }
  const all = flattenBuiltin()
  const rec = all[q]
  if (!rec || !rec[type]) return { found: false, records: [], source: 'none' }
  return { found: true, records: JSON.parse(JSON.stringify(rec[type])), source: 'builtin' }
}

/** 便捷:查 TXT 并合并成字符串列表 */
export function dnsTxt(name) {
  const r = dnsQuery(name, 'TXT')
  return r.records.map((x) => (typeof x === 'string' ? x : x.value || ''))
}

/** 便捷:查 A 记录地址列表 */
export function dnsA(name) {
  return dnsQuery(name, 'A').records
}

/** 模拟反向解析 */
export function dnsPtr(ip) {
  const rev =
    ip
      .split('.')
      .reverse()
      .join('.') + '.in-addr.arpa'
  return dnsQuery(rev, 'PTR').records
}
