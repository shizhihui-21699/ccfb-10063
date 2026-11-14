/**
 * sample-loader.js — 从 public/samples 拉取内置样例并走标准导入流程
 */
import { importFile } from './store.js'

async function fetchAsFile(path, name) {
  const resp = await fetch(path)
  if (!resp.ok) throw new Error(`拉取失败 ${path}: ${resp.status}`)
  const blob = await resp.blob()
  return new File([blob], name, { type: blob.type })
}

/** 载入全部 26 封 eml + 2 个 mbox(去重由 store 负责) */
export async function loadSampleBundles() {
  const manifest = await (await fetch('samples/manifest.json')).json()
  // 优先用两个 mbox(覆盖前 18 封),再补剩余 eml,减少请求数
  const mboxFiles = manifest.mbox || []
  for (const mb of mboxFiles) {
    const f = await fetchAsFile(`samples/batches/${mb}`, mb)
    await importFile(f)
  }
  // mbox 已含前 18 封,这里只导入 19-26
  const remaining = manifest.files.filter((f) => {
    const n = parseInt(f.slice(0, 2), 10)
    return n >= 19
  })
  for (const em of remaining) {
    const f = await fetchAsFile(`samples/${em}`, em)
    await importFile(f)
  }
}

/** 仅载入单封指定样例 */
export async function loadOneSample(filename) {
  const f = await fetchAsFile(`samples/${filename}`, filename)
  await importFile(f)
}
