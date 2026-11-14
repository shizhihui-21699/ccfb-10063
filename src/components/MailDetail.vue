<template>
  <div class="detail">
    <!-- 顶部:概要 + 威胁分 + 操作 -->
    <div class="detail-head card">
      <div class="head-main">
        <div class="score-ring" :class="report.threat.level">
          <span class="score-num">{{ report.threat.score }}</span>
          <span class="score-max">/100</span>
        </div>
        <div class="head-info">
          <h2>{{ report.envelope.subject }}</h2>
          <div class="head-meta">
            <span class="badge" :class="report.threat.level">{{ levelText }}</span>
            <span class="mono faint">{{ report.sourceName }}</span>
            <span class="faint">{{ report.size }} 字节 · 分析耗时 {{ report.elapsedMs }}ms</span>
          </div>
          <div class="tag-row">
            <span v-for="t in report.autoTags" :key="'a' + t" class="tag auto" :title="自动标签">{{ t }}</span>
            <span v-for="t in report.userTags" :key="'u' + t" class="tag">
              {{ t }}<span class="x" @click="removeUserTag(report.id, t)">✕</span>
            </span>
            <input
              v-model="newTag"
              class="tag-input"
              placeholder="+ 打标签回车"
              @keydown.enter.prevent="submitTag"
            />
          </div>
        </div>
      </div>
      <div class="head-actions">
        <button @click="exportJson(report)">导出 JSON</button>
        <button @click="exportTxt(report)">导出 TXT</button>
        <button class="primary" @click="exportHtml(report)">导出 HTML 报告</button>
        <button class="danger ghost" @click="removeReport(report.id)">删除</button>
      </div>
    </div>

    <!-- Tab 导航 -->
    <div class="tabs">
      <button v-for="t in tabs" :key="t.key" :class="{ active: activeTab === t.key }" @click="activeTab = t.key">
        {{ t.label }}
        <i v-if="t.badge" class="tab-badge" :class="t.badgeClass">{{ t.badge }}</i>
      </button>
    </div>

    <div class="tab-body">
      <OverviewPane v-if="activeTab === 'overview'" :report="report" />
      <AuthPane v-else-if="activeTab === 'auth'" :report="report" />
      <ReceivedPane v-else-if="activeTab === 'received'" :report="report" />
      <LinksPane v-else-if="activeTab === 'links'" :report="report" />
      <AttachmentPane v-else-if="activeTab === 'attachment'" :report="report" />
      <MimePane v-else-if="activeTab === 'mime'" :report="report" />
      <HeaderPane v-else-if="activeTab === 'header'" :report="report" />
      <BodyPane v-else-if="activeTab === 'body'" :report="report" />
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { addUserTag, removeUserTag } from '../lib/store.js'
import { exportJson, exportTxt, exportHtml } from '../lib/export-report.js'
import OverviewPane from './panes/OverviewPane.vue'
import AuthPane from './panes/AuthPane.vue'
import ReceivedPane from './panes/ReceivedPane.vue'
import LinksPane from './panes/LinksPane.vue'
import AttachmentPane from './panes/AttachmentPane.vue'
import MimePane from './panes/MimePane.vue'
import HeaderPane from './panes/HeaderPane.vue'
import BodyPane from './panes/BodyPane.vue'

const props = defineProps({ report: { type: Object, required: true } })
const activeTab = ref('overview')
const newTag = ref('')

const levelText = computed(() => ({ critical: '严重', high: '高危', medium: '中危', low: '低危', safe: '安全' }[props.report.threat.level]))

const tabs = computed(() => [
  { key: 'overview', label: '综合概览' },
  { key: 'auth', label: '认证 SPF/DKIM/DMARC' },
  { key: 'received', label: '投递路径', badge: props.report.chain.anomalies.length || null, badgeClass: 'warn' },
  { key: 'links', label: `链接(${props.report.links.length})`, badge: props.report.links.filter((l) => l.severity === 'high').length || null, badgeClass: 'danger' },
  { key: 'attachment', label: `附件(${props.report.attachments.length})`, badge: props.report.attachments.filter((a) => a.severity === 'high').length || null, badgeClass: 'danger' },
  { key: 'mime', label: 'MIME 结构' },
  { key: 'header', label: '原始信头' },
  { key: 'body', label: '正文' }
])

function submitTag() {
  if (newTag.value.trim()) {
    addUserTag(props.report.id, newTag.value.trim())
    newTag.value = ''
  }
}
</script>

<style scoped>
.detail {
  padding: 14px 18px 30px;
  max-width: 1180px;
  margin: 0 auto;
}
.detail-head {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 14px;
}
.head-main {
  display: flex;
  gap: 16px;
  min-width: 0;
}
.score-ring {
  width: 74px;
  height: 74px;
  border-radius: 50%;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  border: 3px solid;
  background: var(--bg);
}
.score-ring.critical {
  border-color: var(--critical);
  color: var(--critical);
}
.score-ring.high {
  border-color: var(--high);
  color: var(--high);
}
.score-ring.medium {
  border-color: var(--medium);
  color: var(--medium);
}
.score-ring.low {
  border-color: var(--low);
  color: var(--low);
}
.score-ring.safe {
  border-color: var(--safe);
  color: var(--safe);
}
.score-num {
  font-size: 24px;
  font-weight: 800;
  line-height: 1;
}
.score-max {
  font-size: 10px;
  color: var(--text-faint);
}
.head-info {
  min-width: 0;
}
.head-info h2 {
  margin: 0 0 6px;
  font-size: 16px;
  word-break: break-all;
}
.head-meta {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.tag-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 2px;
}
.tag-input {
  width: 130px;
  padding: 2px 8px;
  font-size: 11px;
  border-style: dashed;
}
.head-actions {
  display: flex;
  flex-direction: column;
  gap: 6px;
  flex-shrink: 0;
}
.tabs {
  display: flex;
  gap: 4px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 16px;
  flex-wrap: wrap;
}
.tabs button {
  border: none;
  background: transparent;
  border-bottom: 2px solid transparent;
  border-radius: 0;
  padding: 9px 13px;
  color: var(--text-dim);
  position: relative;
}
.tabs button:hover {
  color: var(--text);
  background: transparent;
}
.tabs button.active {
  color: var(--accent);
  border-bottom-color: var(--accent);
}
.tab-badge {
  font-style: normal;
  display: inline-block;
  min-width: 16px;
  padding: 0 5px;
  border-radius: 9px;
  font-size: 10px;
  margin-left: 4px;
  color: #fff;
}
.tab-badge.danger {
  background: var(--critical);
}
.tab-badge.warn {
  background: var(--medium);
}
.tab-body {
  animation: fadein 0.18s ease;
}
@keyframes fadein {
  from {
    opacity: 0;
    transform: translateY(4px);
  }
  to {
    opacity: 1;
    transform: none;
  }
}
</style>
