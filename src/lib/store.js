/**
 * store.js — 全局分析状态(响应式 + localStorage 持久化)
 */
import { reactive, computed, readonly } from 'vue'
import { analyzeEmail } from './analyzer.js'
import { splitMbox } from './mbox.js'

const STORAGE_KEY = 'pmc.state.v1'
const NOTES_KEY = 'pmc.notes.v1'

function loadPersisted() {
  try {
    return JSON.parse(localStorage.getItem(NOTES_KEY) || '{}')
  } catch {
    return {}
  }
}

const state = reactive({
  reports: [], // 分析报告列表
  selectedId: null,
  loading: false,
  progress: { done: 0, total: 0, name: '' },
  filter: {
    keyword: '',
    severity: 'all', // all/critical/high/medium/low/safe
    tag: 'all'
  },
  lastError: null
})

// 恢复用户标签/备注(报告本身不持久化原始字节,只持久化人工标注)
const persisted = loadPersisted()

export async function importFile(file) {
  state.loading = true
  state.lastError = null
  try {
    const buf = new Uint8Array(await file.arrayBuffer())
    const name = file.name.toLowerCase()
    let messages
    if (name.endsWith('.mbox') || looksLikeMbox(buf)) {
      messages = splitMbox(buf)
    } else {
      messages = [{ name: file.name, bytes: buf }]
    }
    state.progress.total = messages.length
    state.progress.done = 0
    for (const msg of messages) {
      state.progress.name = msg.name
      await addReport(msg.bytes, msg.name)
      state.progress.done++
    }
  } catch (e) {
    state.lastError = `导入失败:${e.message}`
    console.error(e)
  } finally {
    state.loading = false
    state.progress = { done: 0, total: 0, name: '' }
  }
}

function looksLikeMbox(bytes) {
  // 文件以 "From " 起始视为 mbox
  return bytes.length > 5 && bytes[0] === 0x46 && bytes[1] === 0x72 && bytes[2] === 0x6f && bytes[3] === 0x6d && bytes[4] === 0x20
}

async function addReport(bytes, name) {
  // 同内容去重(按 id)
  const report = await analyzeEmail(bytes, name)
  const saved = persisted[report.id]
  if (saved) {
    report.userTags = saved.userTags || []
    report.notes = saved.notes || ''
  }
  const existing = state.reports.findIndex((r) => r.id === report.id)
  if (existing >= 0) state.reports[existing] = report
  else state.reports.unshift(report)
  if (!state.selectedId) state.selectedId = report.id
  return report
}

export function selectReport(id) {
  state.selectedId = id
}

export function removeReport(id) {
  const idx = state.reports.findIndex((r) => r.id === id)
  if (idx >= 0) state.reports.splice(idx, 1)
  if (state.selectedId === id) {
    state.selectedId = state.reports[0]?.id || null
  }
}

export function clearAll() {
  state.reports.splice(0, state.reports.length)
  state.selectedId = null
}

export function addUserTag(id, tag) {
  const r = state.reports.find((x) => x.id === id)
  if (!r || !tag) return
  const t = tag.trim()
  if (!r.userTags.includes(t)) r.userTags.push(t)
  persistNote(r)
}

export function removeUserTag(id, tag) {
  const r = state.reports.find((x) => x.id === id)
  if (!r) return
  r.userTags = r.userTags.filter((t) => t !== tag)
  persistNote(r)
}

export function setNotes(id, notes) {
  const r = state.reports.find((x) => x.id === id)
  if (!r) return
  r.notes = notes
  persistNote(r)
}

function persistNote(r) {
  persisted[r.id] = { userTags: r.userTags, notes: r.notes, sourceName: r.sourceName }
  try {
    localStorage.setItem(NOTES_KEY, JSON.stringify(persisted))
  } catch {
    /* ignore */
  }
}

export function setFilter(patch) {
  Object.assign(state.filter, patch)
}

export const allTags = computed(() => {
  const s = new Set()
  for (const r of state.reports) {
    r.autoTags.forEach((t) => s.add(t))
    r.userTags.forEach((t) => s.add(t))
  }
  return [...s].sort()
})

export const filteredReports = computed(() => {
  const kw = state.filter.keyword.trim().toLowerCase()
  return state.reports.filter((r) => {
    if (state.filter.severity !== 'all' && r.threat.level !== state.filter.severity) return false
    if (state.filter.tag !== 'all' && ![...r.autoTags, ...r.userTags].includes(state.filter.tag)) return false
    if (kw) {
      const hay = `${r.envelope.subject} ${r.sourceName} ${r.envelope.from?.address || ''} ${r.envelope.from?.name || ''}`.toLowerCase()
      if (!hay.includes(kw)) return false
    }
    return true
  })
})

export const stats = computed(() => {
  const total = state.reports.length
  const byLevel = { critical: 0, high: 0, medium: 0, low: 0, safe: 0 }
  let authFail = 0
  let dangerousAttach = 0
  let spoof = 0
  for (const r of state.reports) {
    byLevel[r.threat.level]++
    if (r.auth.dmarc.result === 'fail') authFail++
    if (r.attachments.some((a) => a.severity === 'high')) dangerousAttach++
    if ([...r.autoTags].includes('伪造发件人')) spoof++
  }
  return { total, byLevel, authFail, dangerousAttach, spoof }
})

export const selectedReport = computed(() => state.reports.find((r) => r.id === state.selectedId) || null)

export function useStore() {
  return {
    state: readonly(state),
    filteredReports,
    selectedReport,
    allTags,
    stats
  }
}
