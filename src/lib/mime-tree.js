/**
 * mime-tree.js — 原始 MIME 结构树解析器
 *
 * postal-mime 会把多部件打平成 attachments 列表,丢失了嵌套层级。
 * 这里直接对原始字节做 RFC 2045 解析,保留完整的 multipart 嵌套树,
 * 供前端「MIME 结构」视图渲染。
 */
import { base64ToBytes, quotedPrintableToBytes, decodeBytes, decodeEncodedWords, parseHeaderParams } from './encoding.js'

/**
 * @typedef {Object} MimeNode
 * @property {string} partId           序号,如 1 / 1.2 / 1.2.3
 * @property {Object<string, string[]>} headers 原始(已折叠)头,值为原始字符串数组
 * @property {string} contentType      小写 mime type
 * @property {Object} ctParams         Content-Type 参数(文件名/字符集已还原)
 * @property {string|null} disposition content-disposition 值
 * @property {Object} cdParams
 * @property {string} transferEncoding content-transfer-encoding 小写
 * @property {Uint8Array} rawBody      未做 CTE 解码的原始 body 字节
 * @property {Uint8Array|null} body    CTE 解码后的字节
 * @property {string|null} charset
 * @property {MimeNode[]} children     multipart 子节点
 * @property {boolean} isMultipart
 * @property {number} size             解码后字节数
 * @property {string} [filename]       还原后的附件名
 */

const encoder = new TextEncoder()

/** 切分 header/body,返回 [headerBytes, bodyBytes] */
function splitHeaderBody(bytes) {
  // 找第一个空行 \r\n\r\n(兼容 \n\n)
  for (let i = 0; i < bytes.length - 3; i++) {
    if (bytes[i] === 0x0d && bytes[i + 1] === 0x0a && bytes[i + 2] === 0x0d && bytes[i + 3] === 0x0a) {
      return [bytes.subarray(0, i), bytes.subarray(i + 4)]
    }
    if (bytes[i] === 0x0a && bytes[i + 1] === 0x0a) {
      return [bytes.subarray(0, i), bytes.subarray(i + 2)]
    }
  }
  return [bytes, new Uint8Array(0)]
}

function bytesToLatin1(bytes) {
  let s = ''
  const CHUNK = 0x8000
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK))
  }
  return s
}

/** 解析头区块为有序 Map(保留重复头) */
function parseHeaders(headerBytes) {
  const text = bytesToLatin1(headerBytes)
  const lines = text.split(/\r?\n/)
  const headers = {}
  const order = []
  let current = null
  for (const line of lines) {
    if (!line) continue
    if (/^[ \t]/.test(line) && current) {
      // 折叠续行
      headers[current.key][headers[current.key].length - 1] += ' ' + line.trim()
      continue
    }
    const colon = line.indexOf(':')
    if (colon < 0) continue
    const key = line.slice(0, colon).trim().toLowerCase()
    const value = line.slice(colon + 1).trim()
    if (!(key in headers)) {
      headers[key] = []
      order.push(key)
    }
    headers[key].push(value)
    current = { key }
  }
  return { headers, order }
}

/** CTE 解码 */
function decodeTransfer(body, encoding) {
  const enc = (encoding || '7bit').toLowerCase()
  switch (enc) {
    case 'base64':
      try {
        return base64ToBytes(bytesToLatin1(body))
      } catch {
        return body
      }
    case 'quoted-printable':
      return quotedPrintableToBytes(bytesToLatin1(body))
    case '7bit':
    case '8bit':
    case 'binary':
    case '':
      return body
    default:
      return body
  }
}

/** 在 multipart body 中按 boundary 切分(字节级) */
function splitBoundary(body, boundary) {
  const dash = encoder.encode('--' + boundary)
  const parts = []
  const positions = []
  let i = 0
  while (i <= body.length - dash.length) {
    let match = true
    for (let j = 0; j < dash.length; j++) {
      if (body[i + j] !== dash[j]) {
        match = false
        break
      }
    }
    if (match) {
      // boundary 前必须位于行首
      const atLineStart = i === 0 || body[i - 1] === 0x0a
      if (atLineStart) positions.push(i)
    }
    i++
  }
  // positions 指向每个 boundary 起点;取相邻 boundary 之间的内容
  for (let k = 0; k < positions.length - 1; k++) {
    const start = positions[k] + dash.length
    // 跳过 boundary 后的 CRLF(或 "--" 结束标记)
    let contentStart = start
    if (body[start] === 0x2d && body[start + 1] === 0x2d) break // 结束
    if (body[start] === 0x0d && body[start + 1] === 0x0a) contentStart = start + 2
    else if (body[start] === 0x0a) contentStart = start + 1
    // 去掉结尾 CRLF
    let contentEnd = positions[k + 1]
    if (body[contentEnd - 2] === 0x0d && body[contentEnd - 1] === 0x0a) contentEnd -= 2
    else if (body[contentEnd - 1] === 0x0a) contentEnd -= 1
    const slice = body.subarray(contentStart, contentEnd)
    if (slice.length) parts.push(slice)
  }
  return parts
}

/**
 * 递归解析 MIME 节点
 * @param {Uint8Array} bytes
 * @param {string} partId
 * @returns {MimeNode}
 */
export function parseMimeNode(bytes, partId = '1') {
  const [headerBytes, rawBody] = splitHeaderBody(bytes)
  const { headers } = parseHeaders(headerBytes)

  const ctRaw = (headers['content-type']?.[0]) || 'text/plain'
  const ct = parseHeaderParams(ctRaw)
  const contentType = ct.value.toLowerCase().trim()
  const ctParams = ct.params

  const cdRaw = headers['content-disposition']?.[0]
  const cd = cdRaw ? parseHeaderParams(cdRaw) : { value: null, params: {} }
  const disposition = cd.value ? cd.value.toLowerCase() : null
  const cdParams = cd.params

  const transferEncoding = (headers['content-transfer-encoding']?.[0] || '7bit').toLowerCase()
  const charset = (ctParams.charset || '').toLowerCase() || null
  const body = decodeTransfer(rawBody, transferEncoding)

  const isMultipart = contentType.startsWith('multipart/')
  const node = {
    partId,
    headers,
    headerRaw: bytesToLatin1(headerBytes),
    contentType,
    ctParams,
    disposition,
    cdParams,
    transferEncoding,
    charset,
    rawBody,
    body,
    size: body.length,
    isMultipart,
    children: [],
    filename: cdParams.filename || ctParams.name || null
  }
  if (node.filename) node.filename = decodeEncodedWords(node.filename)

  if (isMultipart && ctParams.boundary) {
    const partBytes = splitBoundary(rawBody, ctParams.boundary)
    partBytes.forEach((pb, idx) => {
      node.children.push(parseMimeNode(pb, `${partId}.${idx + 1}`))
    })
  } else if (contentType === 'message/rfc822' && body.length) {
    // 嵌套邮件整体当作一个子 MIME 树
    try {
      node.children.push(parseMimeNode(body, `${partId}.1`))
    } catch {
      /* 解析失败则保留为普通附件体 */
    }
  }

  return node
}

/** 取节点的文本内容(按声明字符集) */
export function nodeText(node) {
  if (!node.body) return ''
  return decodeBytes(node.body, node.charset || 'utf-8')
}

/** 扁平化所有叶子节点 */
export function flattenParts(node, acc = []) {
  if (!node.isMultipart && node.contentType !== 'message/rfc822') {
    acc.push(node)
  }
  for (const c of node.children) flattenParts(c, acc)
  return acc
}

/** 树遍历 */
export function walkTree(node, fn, depth = 0) {
  fn(node, depth)
  for (const c of node.children) walkTree(c, fn, depth + 1)
}
