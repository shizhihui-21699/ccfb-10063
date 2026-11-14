<template>
  <div class="mail-list">
    <div class="filter-bar">
      <input v-model="kw" placeholder="搜索主题/发件人/文件名…" @input="onFilter" />
      <select v-model="severity" @change="onFilter">
        <option value="all">全部级别</option>
        <option value="critical">严重</option>
        <option value="high">高危</option>
        <option value="medium">中危</option>
        <option value="low">低危</option>
        <option value="safe">安全</option>
      </select>
      <select v-model="tag" @change="onFilter">
        <option value="all">全部标签</option>
        <option v-for="t in store.allTags.value" :key="t" :value="t">{{ t }}</option>
      </select>
    </div>

    <div v-if="!reports.length" class="no-data">
      <p>暂无邮件</p>
      <p class="faint">导入 eml / mbox 或载入样例</p>
    </div>

    <div
      v-for="r in reports"
      :key="r.id"
      class="mail-item"
      :class="{ active: r.id === store.state.selectedId }"
      @click="selectReport(r.id)"
    >
      <div class="item-top">
        <span class="badge" :class="r.threat.level">{{ r.threat.score }}</span>
        <span class="auth">
          <span class="auth-dot" :class="r.auth.spf.result" :title="`SPF ${r.auth.spf.label}`"></span>
          <span
            class="auth-dot"
            :class="dkimClass(r)"
            :title="dkimTitle(r)"
          ></span>
          <span class="auth-dot" :class="r.auth.dmarc.result" :title="`DMARC ${r.auth.dmarc.result}`"></span>
        </span>
      </div>
      <div class="item-subject" :title="r.envelope.subject">{{ r.envelope.subject }}</div>
      <div class="item-from">
        <span class="from-name">{{ fromName(r) }}</span>
        <span class="from-addr mono">{{ fromAddr(r) }}</span>
      </div>
      <div class="item-meta">
        <span class="faint">{{ shortName(r.sourceName) }}</span>
        <span v-if="r.links.length" class="chip">🔗{{ r.links.length }}</span>
        <span v-if="r.attachments.length" class="chip">📎{{ r.attachments.length }}</span>
      </div>
      <div class="item-tags">
        <span v-for="t in r.autoTags.slice(0, 3)" :key="t" class="tag auto mini">{{ t }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useStore, selectReport, setFilter } from '../lib/store.js'

const store = useStore()
const reports = store.filteredReports
const kw = ref(store.state.filter.keyword)
const severity = ref(store.state.filter.severity)
const tag = ref(store.state.filter.tag)

function onFilter() {
  setFilter({ keyword: kw.value, severity: severity.value, tag: tag.value })
}

function fromName(r) {
  return r.envelope.from?.name || r.headerAnalysis.identities.fromDomain || '(无发件人)'
}
function fromAddr(r) {
  return r.envelope.from?.address || ''
}
function shortName(n) {
  return n.length > 26 ? n.slice(0, 25) + '…' : n
}
function dkimClass(r) {
  if (!r.auth.dkim.signatures.length) return 'none'
  return r.auth.dkim.verified ? 'valid' : 'invalid'
}
function dkimTitle(r) {
  return r.auth.dkim.signatures.length ? `DKIM ${r.auth.dkim.summary}` : 'DKIM 无签名'
}
</script>

<style scoped>
.mail-list {
  padding: 10px;
}
.filter-bar {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-bottom: 10px;
  position: sticky;
  top: 0;
  background: var(--bg);
  padding-bottom: 8px;
  z-index: 2;
}
.no-data {
  text-align: center;
  padding: 40px 10px;
}
.mail-item {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 10px 12px;
  margin-bottom: 8px;
  cursor: pointer;
  background: var(--bg-panel);
  transition: border-color 0.15s, background 0.15s;
}
.mail-item:hover {
  border-color: var(--accent-dim);
}
.mail-item.active {
  border-color: var(--accent);
  background: var(--bg-elev);
  box-shadow: 0 0 0 1px var(--accent-dim);
}
.item-top {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 5px;
}
.auth {
  display: inline-flex;
  gap: 4px;
}
.item-subject {
  font-weight: 600;
  font-size: 12.5px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-bottom: 3px;
}
.item-from {
  display: flex;
  flex-direction: column;
  gap: 1px;
}
.from-name {
  font-size: 11.5px;
}
.from-addr {
  font-size: 10.5px;
  color: var(--text-faint);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.item-meta {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-top: 6px;
  font-size: 10.5px;
}
.chip {
  background: var(--bg-elev);
  border-radius: 8px;
  padding: 0 6px;
  color: var(--text-dim);
}
.item-tags {
  margin-top: 6px;
}
.tag.mini {
  font-size: 10px;
  padding: 0 7px;
  margin: 1px 3px 1px 0;
}
</style>
