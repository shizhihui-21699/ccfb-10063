/**
 * charset-tables.js — 样例生成器专用的多字节编码器
 *
 * 思路:Node 内置 TextDecoder(ICU)能正确解码 gbk/big5/shift_jis/euc-kr,
 * 但没有对应的 TextEncoder。这里在模块加载时穷举双字节空间,用解码器
 * 反向构建「字符 → 字节」映射,得到与 ICU 完全一致的编码表。
 * 每张表构建一次(几万次解码,毫秒级),之后纯查表。
 */

function buildDoubleByteTable(charset, leadRanges) {
  const decoder = new TextDecoder(charset)
  const map = new Map()
  for (const [lo, hi] of leadRanges) {
    for (let lead = lo; lead <= hi; lead++) {
      for (let trail = 0x40; trail <= 0xfe; trail++) {
        if (trail === 0x7f) continue
        const bytes = new Uint8Array([lead, trail])
        const ch = decoder.decode(bytes)
        // 解码器对无效序列会输出 U+FFFD,跳过
        if (ch && ch !== '�' && ch.codePointAt(0) !== 0xfffd && !map.has(ch)) {
          map.set(ch, bytes)
        }
      }
    }
  }
  return map
}

function makeEncoder(charset, leadRanges) {
  let table = null
  return (text) => {
    if (!table) table = buildDoubleByteTable(charset, leadRanges)
    const out = []
    for (const ch of text) {
      if (ch === ' ') {
        out.push(0x20)
        continue
      }
      const code = ch.codePointAt(0)
      if (code < 0x80) {
        out.push(code)
        continue
      }
      const hit = table.get(ch)
      if (hit) out.push(hit[0], hit[1])
      else {
        // 回退:UTF-8 字节(样例字符已全覆盖,正常不会走到)
        for (const b of new TextEncoder().encode(ch)) out.push(b)
      }
    }
    return new Uint8Array(out)
  }
}

// GBK: 首字节 0x81-0xFE
const gbk = makeEncoder('gbk', [[0x81, 0xfe]])
// Big5: 首字节 0xA1-0xF9
const big5 = makeEncoder('big5', [[0xa1, 0xf9]])
// Shift_JIS: 首字节 0x81-0x9F 与 0xE0-0xEF
const shiftJis = makeEncoder('shift_jis', [
  [0x81, 0x9f],
  [0xe0, 0xef]
])
// EUC-KR: 首字节 0x81-0xFE
const eucKr = makeEncoder('euc-kr', [[0x81, 0xfe]])

export const ENCODERS = {
  gbk,
  gb2312: gbk,
  big5,
  'shift_jis': shiftJis,
  sjis: shiftJis,
  'euc-kr': eucKr,
  euckr: eucKr
}
