/**
 * mbox.js — mbox/mboxrd 格式切分(纯字节级,不做任何字符集转码)
 *
 * 一封邮件以行首 "From " 分隔;邮件体内被 mboxrd 转义的 ">From " 还原。
 * 兼容只有一封、且没有 mbox 封套的纯 eml。
 * 全程在 Uint8Array 上操作,避免 latin1 字符串 ↔ UTF-8 往返导致的双重编码。
 */

const LF = 0x0a
const CR = 0x0d
const SP = 0x20
const G = 0x3e // '>'
const F = 0x46 // 'F'
const R = 0x72 // 'r'
const O = 0x6f // 'o'
const M = 0x6d // 'm'

/** 判断一行(不含行尾)是否以 "From " 开头 */
function isFromSeparator(line) {
  return line.length >= 5 && line[0] === F && line[1] === R && line[2] === O && line[3] === M && line[4] === SP
}

/** 判断一行是否以一个或多个 ">" 后接 "From " 开头(mboxrd 转义) */
function isEscapedFrom(line) {
  let i = 0
  while (i < line.length && line[i] === G) i++
  if (i === 0 || i >= line.length - 5) return false
  return line[i] === F && line[i + 1] === R && line[i + 2] === O && line[i + 3] === M && line[i + 4] === SP
}

/** 按 LF 切成字节行(保留 CR) */
function splitLines(bytes) {
  const lines = []
  let start = 0
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === LF) {
      lines.push(bytes.subarray(start, i)) // 不含 LF,可能尾部带 CR
      start = i + 1
    }
  }
  if (start < bytes.length) lines.push(bytes.subarray(start))
  return lines
}

function looksLikeEnvelope(line) {
  // 字节级粗略判断:From 后跟非空白 token(足够区分普通正文)
  return line.length > 5
}

/**
 * @param {Uint8Array} bytes
 * @returns {{name:string, bytes:Uint8Array}[]}
 */
export function splitMbox(bytes) {
  const lines = splitLines(bytes)
  const messages = []
  let current = null
  let count = 0

  const pushCurrent = () => {
    if (!current) return
    // 重组:行间用 LF 连接(原始 CRLF 的 CR 保留在行尾),去掉末尾空行
    const bodyLines = current.body
    while (bodyLines.length && bodyLines[bodyLines.length - 1].length === 0) bodyLines.pop()
    const total = bodyLines.reduce((n, l) => n + l.length + 1, 0)
    const out = new Uint8Array(total)
    let off = 0
    for (const l of bodyLines) {
      out.set(l, off)
      off += l.length
      out[off++] = LF
    }
    const sender = current.envelope ? readAsciiToken(current.envelope) : ''
    messages.push({
      name: `mbox-message-${count}.eml${sender ? ' (' + sender + ')' : ''}`,
      bytes: out
    })
  }

  for (const line of lines) {
    if (isFromSeparator(line) && (current === null || looksLikeEnvelope(line))) {
      pushCurrent()
      count++
      current = { envelope: line, body: [] }
      continue
    }
    if (current === null) {
      current = { envelope: null, body: [] }
    }
    // mboxrd 反转义:去掉前导的一个 '>'
    if (isEscapedFrom(line)) {
      current.body.push(line.subarray(1))
    } else {
      current.body.push(line)
    }
  }
  pushCurrent()

  return messages.filter((m) => m.bytes.length > 0)
}

/** 从 "From sender@host ..." 封套行提取发件人 token(ASCII) */
function readAsciiToken(line) {
  // 跳过 "From "
  let i = 5
  let end = i
  while (end < line.length && line[end] !== SP && line[end] !== CR) end++
  let s = ''
  for (let j = i; j < end; j++) s += String.fromCharCode(line[j])
  return s
}
