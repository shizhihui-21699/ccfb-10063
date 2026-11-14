<template>
  <div class="dns-overlay" @click.self="$emit('close')">
    <div class="dns-modal card">
      <div class="modal-head">
        <h3 class="section-title">本地 Mock DNS 记录</h3>
        <button class="ghost" @click="$emit('close')">✕</button>
      </div>
      <p class="dim desc">
        SPF / DKIM / DMARC / PTR 查询全部读取这里的数据,不发真实 DNS 请求。可直接编辑覆盖层(存浏览器 localStorage),用于演练不同记录组合。
      </p>

      <div class="modal-actions">
        <button @click="loadSampleKeys" class="primary">装载样例 DKIM 公钥</button>
        <button @click="onReset" class="danger ghost">重置为内置基线</button>
        <input v-model="filterName" placeholder="按域名过滤…" />
      </div>

      <div class="records">
        <div v-for="rec in filtered" :key="rec.name" class="rec">
          <div class="rec-name mono">{{ rec.name }}</div>
          <div v-for="(vals, type) in rec.data" :key="type" class="rec-line">
            <span class="rec-type">{{ type }}</span>
            <span class="rec-val mono">{{ formatVal(vals) }}</span>
          </div>
        </div>
      </div>

      <div class="override-editor">
        <h4>添加 / 覆盖记录</h4>
        <input v-model="editName" placeholder="完整查询名,如 _dmarc.example.com 或 selector._domainkey.example.com" />
        <select v-model="editType">
          <option>TXT</option>
          <option>A</option>
          <option>MX</option>
          <option>PTR</option>
        </select>
        <textarea v-model="editValue" rows="2" placeholder="TXT 直接填字符串;A 填 IP(多个用英文逗号分隔)"></textarea>
        <div class="editor-actions">
          <button @click="saveRecord" class="primary">保存覆盖</button>
          <button @click="deleteRecord" class="danger ghost">删除该名字(置空)</button>
        </div>
        <p v-if="msg" class="msg">{{ msg }}</p>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { currentRecords, saveOverride, resetDns } from '../lib/mock-dns.js'

const emit = defineEmits({ close: null })
const filterName = ref('')
const editName = ref('')
const editType = ref('TXT')
const editValue = ref('')
const msg = ref('')
const refreshKey = ref(0)

const records = computed(() => {
  refreshKey.value
  return currentRecords()
})
const filtered = computed(() =>
  Object.entries(records.value)
    .filter(([name]) => name.includes(filterName.value.toLowerCase().trim()))
    .map(([name, data]) => ({ name, data }))
)

function formatVal(vals) {
  if (Array.isArray(vals)) {
    return vals
      .map((v) => (typeof v === 'string' ? v : JSON.stringify(v)))
      .join(' | ')
  }
  return String(vals)
}

async function loadSampleKeys() {
  const resp = await fetch('samples/dkim-keys.json')
  const keys = await resp.json()
  const over = JSON.parse(localStorage.getItem('pmc.mock-dns.v1') || '{}')
  for (const [name, record] of Object.entries(keys)) over[name] = { TXT: [record] }
  saveOverride(over)
  refreshKey.value++
  msg.value = `已装载 ${Object.keys(keys).length} 条样例 DKIM 公钥`
}

function saveRecord() {
  if (!editName.value.trim()) {
    msg.value = '请填写查询名'
    return
  }
  const over = JSON.parse(localStorage.getItem('pmc.mock-dns.v1') || '{}')
  const name = editName.value.trim().toLowerCase()
  const raw = editValue.value
  const val = editType.value === 'TXT' ? [raw] : raw.split(',').map((x) => x.trim()).filter(Boolean)
  over[name] = { [editType.value]: val }
  saveOverride(over)
  refreshKey.value++
  msg.value = `已覆盖 ${name} 的 ${editType.value} 记录`
}

function deleteRecord() {
  if (!editName.value.trim()) return
  const over = JSON.parse(localStorage.getItem('pmc.mock-dns.v1') || '{}')
  over[editName.value.trim().toLowerCase()] = null
  saveOverride(over)
  refreshKey.value++
  msg.value = '已置空该名字的记录'
}

function onReset() {
  if (!confirm('重置会清除全部自定义覆盖,恢复内置基线数据。继续?')) return
  resetDns()
  refreshKey.value++
  msg.value = '已重置为内置基线'
}
</script>

<style scoped>
.dns-overlay {
  position: fixed;
  inset: 0;
  background: rgba(10, 14, 18, 0.75);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 200;
}
.dns-modal {
  width: min(860px, 92vw);
  max-height: 86vh;
  overflow-y: auto;
  padding: 20px 24px;
}
.modal-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.desc {
  font-size: 11.5px;
}
.modal-actions {
  display: flex;
  gap: 8px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
.modal-actions input {
  flex: 1;
  min-width: 180px;
}
.records {
  border: 1px solid var(--border);
  border-radius: 6px;
  max-height: 320px;
  overflow-y: auto;
  margin-bottom: 18px;
}
.rec {
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
}
.rec-name {
  color: var(--accent);
  font-weight: 700;
  margin-bottom: 3px;
}
.rec-line {
  display: flex;
  gap: 9px;
  font-size: 11px;
  padding: 1px 0;
}
.rec-type {
  background: var(--bg-elev);
  border-radius: 4px;
  padding: 0 7px;
  color: var(--medium);
  min-width: 42px;
  text-align: center;
  height: fit-content;
}
.rec-val {
  color: var(--text-dim);
  word-break: break-all;
}
.override-editor {
  background: var(--bg);
  border-radius: 8px;
  padding: 14px;
}
.override-editor h4 {
  margin: 0 0 10px;
}
.override-editor input,
.override-editor select,
.override-editor textarea {
  width: 100%;
  margin-bottom: 8px;
}
.editor-actions {
  display: flex;
  gap: 8px;
}
.msg {
  color: var(--low);
  font-size: 11.5px;
  margin-bottom: 0;
}
</style>
