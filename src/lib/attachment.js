/**
 * attachment.js — 附件静态分析(绝不执行任何附件内容)
 *
 * 检查项:
 *  - 真实文件类型(魔数)与声明扩展名/MIME 是否一致
 *  - 双扩展名伪装(发票.pdf.exe)、空格伪装
 *  - Office OLE 复合文档中的 VBA 宏(OLE 签名 D0 CF 11 E0 + 宏流特征)
 *  - 可疑脚本/可执行/快捷方式类型
 *  - ZIP 内条目名扫描(嵌套钓鱼载荷)
 *  - SHA-256 / MD5(展示用)、大小、熵估算
 */

const enc = new TextEncoder()

/* 魔数签名表(签名 -> 真实类型/扩展名) */
const MAGIC = [
  { sig: [0x4d, 0x5a], type: 'Windows PE 可执行文件', ext: 'exe/dll' },
  { sig: [0x7f, 0x45, 0x4c, 0x46], type: 'ELF 可执行文件', ext: 'elf' },
  { sig: [0xfe, 0xed, 0xfa, 0xce], type: 'Mach-O 二进制', ext: 'macho' },
  { sig: [0xfe, 0xed, 0xfa, 0xcf], type: 'Mach-O 64 位二进制', ext: 'macho' },
  { sig: [0xcf, 0xfa, 0xed, 0xfe], type: 'Mach-O 二进制', ext: 'macho' },
  { sig: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], type: 'OLE2 复合文档(旧 Office/msi/lnk)', ext: 'ole' },
  { sig: [0x50, 0x4b, 0x03, 0x04], type: 'ZIP 容器(含 docx/xlsx/zip/jar/apk)', ext: 'zip' },
  { sig: [0x50, 0x4b, 0x05, 0x06], type: '空 ZIP', ext: 'zip' },
  { sig: [0x50, 0x4b, 0x07, 0x08], type: '跨片 ZIP', ext: 'zip' },
  { sig: [0x25, 0x50, 0x44, 0x46], type: 'PDF 文档', ext: 'pdf' },
  { sig: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], type: 'RAR 压缩包', ext: 'rar' },
  { sig: [0x1f, 0x8b, 0x08], type: 'GZIP 压缩包', ext: 'gz' },
  { sig: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], type: '7z 压缩包', ext: '7z' },
  { sig: [0x42, 0x4d], type: 'BMP 位图', ext: 'bmp' },
  { sig: [0xff, 0xd8, 0xff], type: 'JPEG 图片', ext: 'jpg' },
  { sig: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], type: 'PNG 图片', ext: 'png' },
  { sig: [0x47, 0x49, 0x46, 0x38], type: 'GIF 图片', ext: 'gif' },
  { sig: [0x23, 0x21], type: 'Shebang 脚本', ext: 'sh' }
]

const SCRIPT_EXTS = new Set(['js', 'jse', 'vbs', 'vbe', 'ws', 'wsf', 'wsh', 'ps1', 'psm1', 'bat', 'cmd', 'hta', 'scr', 'jar', 'lnk', 'sh', 'py', 'rb', 'mac', 'xlm', 'slk'])
const EXEC_EXTS = new Set(['exe', 'dll', 'sys', 'msi', 'com', 'cpl', 'ocx', 'apk', 'app', 'deb', 'rpm'])
const DANGEROUS_ARCHIVE_ENTRIES = /\.(?:exe|dll|scr|js|vbs|ps1|bat|cmd|hta|lnk|jar|wsf|jse|vbe|macro|bin)$/i

function matchMagic(bytes) {
  for (const m of MAGIC) {
    if (bytes.length < m.sig.length) continue
    if (m.sig.every((b, i) => bytes[i] === b)) return m
  }
  return null
}

function extOf(name) {
  const m = /\.([a-z0-9]+)$/i.exec(name || '')
  return m ? m[1].toLowerCase() : null
}

export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export async function md5Hex(bytes) {
  // 轻量 MD5 实现(展示用,不引第三方)
  return md5(bytes)
}

/* ---------- 极简 MD5(RFC 1321) ---------- */
function md5(bytes) {
  const toWord = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24))
  const rotl = (x, c) => (x << c) | (x >>> (32 - c))
  const add32 = (a, b) => (a + b) & 0xffffffff
  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ]
  const K = new Array(64)
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) & 0xffffffff

  // 填充
  const origLen = bytes.length
  const bitLen = origLen * 8
  const padLen = (origLen % 64 < 56 ? 56 - (origLen % 64) : 120 - (origLen % 64))
  const buf = new Uint8Array(origLen + padLen + 8)
  buf.set(bytes)
  buf[origLen] = 0x80
  const dv = new DataView(buf.buffer)
  dv.setUint32(buf.length - 4, Math.floor(bitLen / 0x100000000), true)
  dv.setUint32(buf.length - 8, bitLen >>> 0, true)

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476
  for (let off = 0; off < buf.length; off += 64) {
    const M = new Array(16)
    for (let i = 0; i < 16; i++) M[i] = dv.getInt32(off + i * 4, true)
    let A = a0, B = b0, C = c0, D = d0
    for (let i = 0; i < 64; i++) {
      let F, g
      if (i < 16) { F = (B & C) | (~B & D); g = i }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16 }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16 }
      else { F = C ^ (B | ~D); g = (7 * i) % 16 }
      F = add32(F, add32(add32(A, K[i]), M[g]))
      A = D; D = C; C = B
      B = add32(B, rotl(F, S[i]))
    }
    a0 = add32(a0, A); b0 = add32(b0, B); c0 = add32(c0, C); d0 = add32(d0, D)
  }
  const out = new Uint8Array(16)
  const ov = new DataView(out.buffer)
  ;[a0, b0, c0, d0].forEach((w, i) => ov.setInt32(i * 4, w, true))
  return [...out].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** 香农熵(0-8),高熵提示加密/压缩/加壳 */
function shannonEntropy(bytes) {
  if (!bytes.length) return 0
  const freq = new Array(256).fill(0)
  for (const b of bytes) freq[b]++
  let e = 0
  for (const f of freq) {
    if (!f) continue
    const p = f / bytes.length
    e -= p * Math.log2(p)
  }
  return e
}

/** 在字节里找 ASCII 关键词(宏/脚本特征) */
function findStrings(bytes, needles) {
  const latin = bytes.length > 200000 ? bytes.subarray(0, 200000) : bytes
  let s = ''
  const CHUNK = 0x8000
  for (let i = 0; i < latin.length; i += CHUNK) s += String.fromCharCode.apply(null, latin.subarray(i, i + CHUNK))
  const lower = s.toLowerCase()
  return needles.filter((n) => lower.includes(n.toLowerCase()))
}

/** 极简 ZIP 中央目录条目名扫描(不解压、不执行) */
function scanZipEntries(bytes) {
  const entries = []
  // EOCD 0x06054b50
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
      const dv = new DataView(bytes.buffer, bytes.byteOffset)
      const count = dv.getUint16(i + 10, true)
      let off = dv.getUint32(i + 16, true)
      for (let n = 0; n < count && n < 500; n++) {
        if (bytes[off] !== 0x50 || bytes[off + 1] !== 0x4b || bytes[off + 2] !== 0x01 || bytes[off + 3] !== 0x02) break
        const nameLen = dv.getUint16(off + 28, true)
        const extraLen = dv.getUint16(off + 30, true)
        const commentLen = dv.getUint16(off + 32, true)
        const nameBytes = bytes.subarray(off + 46, off + 46 + nameLen)
        entries.push(new TextDecoder('utf-8', { fatal: false }).decode(nameBytes))
        off += 46 + nameLen + extraLen + commentLen
      }
      break
    }
  }
  return entries
}

/**
 * 分析单个附件
 * @param {{filename:string, mimeType:string, content:Uint8Array|ArrayBuffer|string}} att
 */
export async function analyzeAttachment(att) {
  const findings = []
  const add = (severity, text) => findings.push({ severity, text })
  const filename = att.filename || '(unnamed)'
  const bytes = normalizeBytes(att.content)
  const declaredExt = extOf(filename)
  const magic = matchMagic(bytes)

  // 文件名伪装
  if (/\.[a-z0-9]+\s+$/.test(filename)) add('medium', `文件名以空格结尾,可能用于隐藏真实扩展名`)
  const doubleExt = /\.[a-z0-9]{2,4}\.([a-z0-9]{2,4})$/i.exec(filename)
  if (doubleExt && (EXEC_EXTS.has(doubleExt[1].toLowerCase()) || SCRIPT_EXTS.has(doubleExt[1].toLowerCase()))) {
    add('high', `双扩展名伪装:${filename}(最终扩展名 .${doubleExt[1]} 才是系统实际执行的类型)`)
  }
  if (/\.(?:pdf|docx?|xlsx?|png|jpg)\.(?:exe|scr|js|vbs|lnk|hta|cmd|bat)$/i.test(filename)) {
    add('high', '常见钓鱼命名:文档/图片名 + 可执行后缀')
  }
  // RTLO 反转字符
  if (filename.includes(' ') || filename.includes(' ') || filename.includes('‮')) {
    add('high', '文件名含 Unicode 控制字符(如 RTLO U+202E),用于视觉反转扩展名')
  }

  // 声明类型 vs 真实魔数
  let realType = magic ? magic.type : '未知(无匹配魔数)'
  if (magic) {
    const honest = typeMatchesExt(magic, declaredExt, att.mimeType)
    if (!honest) {
      add('high', `类型伪装:扩展名 .${declaredExt || '?'} / MIME ${att.mimeType || '?'},但文件头显示「${magic.type}」`)
    }
    // 特例:ZIP 头但叫 .zip 之外的可执行
    if (magic.ext === 'zip' && declaredExt && ['jar', 'apk'].includes(declaredExt)) {
      add('low', `${declaredExt.toUpperCase()} 本质是 ZIP 容器,确认来源后再打开`)
    }
  } else if (declaredExt && (EXEC_EXTS.has(declaredExt) || SCRIPT_EXTS.has(declaredExt))) {
    add('medium', '未识别到文件头魔数,但扩展名属于可执行/脚本类')
  }

  // 脚本/可执行扩展名
  if (declaredExt && SCRIPT_EXTS.has(declaredExt)) {
    add('high', `可疑脚本类型 .${declaredExt},邮件客户端默认阻止或应严格隔离`)
  }
  if (declaredExt && EXEC_EXTS.has(declaredExt)) {
    add('high', `可执行文件 .${declaredExt},绝不应直接打开`)
  }

  // 宏检测:OLE 复合文档
  if (magic?.ext === 'ole') {
    const macroHits = findStrings(bytes, ['_VBA_PROJECT', 'AutoOpen', 'Auto_Open', 'Document_Open', 'Workbook_Open', 'ThisDocument', 'macrosheet', 'Shell(', 'WScript.Shell', 'CreateObject', 'powershell', 'cmd.exe'])
    if (macroHits.length) {
      add('high', `OLE 文档内含 VBA 宏/自动执行特征:${[...new Set(macroHits)].slice(0, 6).join(', ')}`)
    } else {
      add('low', '旧版 OLE Office 文档(支持宏),即使未检出特征也建议受保护视图打开')
    }
  }
  // OOXML(docxl/xlsx 等)中的宏标记
  if (magic?.ext === 'zip' && declaredExt && ['docm', 'xlsm', 'pptm', 'dotm', 'xltm'].includes(declaredExt)) {
    const hits = findStrings(bytes, ['vbaProject.bin', 'xlm', 'macroSettings'])
    if (hits.length) add('high', `启用宏的 OpenXML 文档(.${declaredExt}),内含 vbaProject 等宏部件`)
    else add('medium', `.${declaredExt} 是支持宏的 Office 格式`)
  }
  // 纯脚本内容特征
  const scriptHits = findStrings(bytes, ['powershell -enc', 'frombase64string', 'wscript.shell', 'shell.application', 'downloadstring', 'mshta', 'certutil -decode', 'regsvr32 /s /u /i:'])
  if (scriptHits.length) {
    add('high', `内容含可疑脚本/LOLBin 调用:${[...new Set(scriptHits)].slice(0, 6).join(', ')}`)
  }
  // LNK 快捷方式特征
  if (declaredExt === 'lnk' || magic?.ext === 'ole') {
    const lnkHits = findStrings(bytes, ['.exe', '.dll', 'cmd.exe', 'powershell', '.js', '.vbs', 'AppData', 'Temp'])
    if (declaredExt === 'lnk' && lnkHits.length) {
      add('high', `快捷方式指向脚本/临时目录:${[...new Set(lnkHits)].slice(0, 5).join(', ')}`)
    }
  }

  // ZIP 条目扫描
  let zipEntries = []
  if (magic?.ext === 'zip' || declaredExt === 'zip') {
    zipEntries = scanZipEntries(bytes)
    const bad = zipEntries.filter((n) => DANGEROUS_ARCHIVE_ENTRIES.test(n))
    if (bad.length) add('high', `压缩包内有危险条目:${bad.slice(0, 5).join(', ')}`)
    if (zipEntries.some((n) => n.includes('../') || n.includes('..\\'))) {
      add('medium', '压缩包条目含路径穿越(../),解压可能覆盖系统文件(Zip Slip)')
    }
  }

  const entropy = shannonEntropy(bytes)
  if (entropy > 7.4) add('low', `熵值 ${entropy.toFixed(2)}/8 很高,内容可能被加密/加壳`)

  const [sha256, md5hash] = await Promise.all([sha256Hex(bytes), md5Hex(bytes)])
  const severity = findings.some((f) => f.severity === 'high') ? 'high' : findings.some((f) => f.severity === 'medium') ? 'medium' : findings.length ? 'low' : 'safe'

  return {
    filename,
    size: bytes.length,
    declaredMime: att.mimeType,
    declaredExt,
    realType,
    entropy: Number(entropy.toFixed(2)),
    sha256,
    md5: md5hash,
    zipEntries,
    findings,
    severity,
    previewText: previewable(declaredExt, magic) ? safeTextPreview(bytes) : null
  }
}

function normalizeBytes(content) {
  if (content instanceof Uint8Array) return content
  if (content instanceof ArrayBuffer) return new Uint8Array(content)
  if (typeof content === 'string') {
    // postal-mime base64 字符串形态
    try {
      const bin = atob(content.replace(/\s+/g, ''))
      const out = new Uint8Array(bin.length)
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
      return out
    } catch {
      return new TextEncoder().encode(content)
    }
  }
  if (content?.buffer) return new Uint8Array(content.buffer)
  return new Uint8Array(0)
}

function typeMatchesExt(magic, ext, mime) {
  const map = {
    pdf: ['pdf'],
    zip: ['zip', 'jar', 'apk', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'ods', 'odt'],
    ole: ['doc', 'xls', 'ppt', 'msi', 'lnk', 'msg'],
    png: ['png'],
    jpg: ['jpg', 'jpeg'],
    gif: ['gif'],
    bmp: ['bmp'],
    gz: ['gz', 'tgz'],
    rar: ['rar'],
    '7z': ['7z']
  }
  const allowed = map[magic.ext] || []
  if (ext && allowed.length && !allowed.includes(ext)) return false
  if (mime && (mime.startsWith('image/') || mime.includes('pdf') || mime.includes('zip') || mime.includes('word') || mime.includes('sheet'))) {
    // 交叉验证 MIME 与魔数
    if (magic.ext === 'pdf' && !mime.includes('pdf')) return false
    if (magic.ext === 'zip' && !(mime.includes('zip') || mime.includes('officedocument') || mime.includes('jar') || mime.includes('apk'))) return false
    if (['png', 'jpg', 'gif', 'bmp'].includes(magic.ext) && !mime.startsWith('image/')) return false
  }
  return true
}

function previewable(ext, magic) {
  return ['txt', 'csv', 'log', 'html', 'htm', 'js', 'vbs', 'ps1', 'bat', 'cmd', 'xml', 'json'].includes(ext) || magic === null
}

function safeTextPreview(bytes) {
  const head = bytes.subarray(0, 4000)
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(head).replace(/[^\x09\x0a\x0d\x20-\x7e\u0080-￿]/g, '').slice(0, 2000)
  } catch {
    return null
  }
}
