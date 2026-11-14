<template>
  <div class="app">
    <header class="topbar">
      <div class="brand">
        <span class="logo">🛡️</span>
        <div>
          <h1>钓鱼邮件分析台</h1>
          <span class="subtitle">PhishMail Console · 本地分析 · DNS Mock · 附件不执行</span>
        </div>
      </div>
      <div class="topbar-actions">
        <button class="ghost" @click="showDns = true">⚙️ Mock DNS</button>
        <button class="ghost" @click="loadSamples">📥 载入样例</button>
        <label class="btn-upload primary">
          ＋ 导入 eml / mbox
          <input type="file" multiple accept=".eml,.mbox,message/rfc822,application/mbox" @change="onUpload" hidden />
        </label>
        <button v-if="store.state.reports.length" class="ghost danger" @click="onClearAll">清空</button>
      </div>
    </header>

    <div class="stat-strip" v-if="store.stats.value.total">
      <div class="stat"><b>{{ store.stats.value.total }}</b><span>邮件总数</span></div>
      <div class="stat crit"><b>{{ store.stats.value.byLevel.critical }}</b><span>严重</span></div>
      <div class="stat high"><b>{{ store.stats.value.byLevel.high }}</b><span>高危</span></div>
      <div class="stat"><b>{{ store.stats.value.authFail }}</b><span>DMARC 失败</span></div>
      <div class="stat"><b>{{ store.stats.value.spoof }}</b><span>伪造发件人</span></div>
      <div class="stat"><b>{{ store.stats.value.dangerousAttach }}</b><span>危险附件</span></div>
    </div>

    <main class="layout">
      <MailList class="pane-list" />
      <MailDetail v-if="selected" class="pane-detail" :report="selected" />
      <div v-else class="pane-empty">
        <div class="empty-inner">
          <div class="empty-icon">📨</div>
          <h2>导入邮件开始分析</h2>
          <p>支持 .eml 单封与 .mbox 批量;可点右上角「载入样例」获取 26 封演示样本</p>
          <div class="empty-feats">
            <span>MIME 结构解析</span><span>SPF / DKIM / DMARC</span><span>Received 投递路径</span>
            <span>链接去武装</span><span>附件静态分析</span><span>标签与导出</span>
          </div>
        </div>
      </div>
    </main>

    <div v-if="store.state.loading" class="loading-mask">
      <div class="loading-box">
        <div class="spinner"></div>
        <p>正在分析 {{ store.state.progress.name || '...' }}</p>
        <p class="dim">{{ store.state.progress.done }} / {{ store.state.progress.total }}</p>
      </div>
    </div>

    <DnsPanel v-if="showDns" @close="showDns = false" />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useStore, importFile, clearAll, selectReport } from './lib/store.js'
import MailList from './components/MailList.vue'
import MailDetail from './components/MailDetail.vue'
import DnsPanel from './components/DnsPanel.vue'
import { loadSampleBundles } from './lib/sample-loader.js'

const store = useStore()
const showDns = ref(false)
const selected = computed(() => store.selectedReport.value)

async function onUpload(e) {
  const files = [...e.target.files]
  for (const f of files) await importFile(f)
  e.target.value = ''
}

async function loadSamples() {
  await loadSampleBundles()
}

function onClearAll() {
  if (confirm('确定清空当前全部分析结果?(人工标签保留在本地)')) clearAll()
}

// 暴露给子组件直接选报告
defineExpose({ selectReport })

onMounted(() => {
  // 首次访问提示,不自动加载
})
</script>

<style scoped>
.app {
  display: flex;
  flex-direction: column;
  height: 100%;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 18px;
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
}
.logo {
  font-size: 26px;
}
.brand h1 {
  margin: 0;
  font-size: 16px;
}
.subtitle {
  color: var(--text-faint);
  font-size: 11px;
}
.topbar-actions {
  display: flex;
  gap: 8px;
  align-items: center;
}
.btn-upload {
  display: inline-flex;
  align-items: center;
  border-radius: 6px;
  padding: 6px 12px;
  font-size: 12px;
  border: 1px solid var(--accent);
}
.stat-strip {
  display: flex;
  gap: 0;
  background: var(--bg-panel);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.stat {
  display: flex;
  flex-direction: column;
  padding: 8px 22px;
  border-right: 1px solid var(--border);
}
.stat b {
  font-size: 18px;
}
.stat span {
  font-size: 11px;
  color: var(--text-dim);
}
.stat.crit b {
  color: var(--critical);
}
.stat.high b {
  color: var(--high);
}
.layout {
  flex: 1;
  display: flex;
  min-height: 0;
}
.pane-list {
  width: 340px;
  flex-shrink: 0;
  border-right: 1px solid var(--border);
  overflow-y: auto;
}
.pane-detail {
  flex: 1;
  min-width: 0;
  overflow-y: auto;
}
.pane-empty {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
}
.empty-inner {
  text-align: center;
  max-width: 480px;
}
.empty-icon {
  font-size: 52px;
  opacity: 0.6;
}
.empty-inner h2 {
  font-weight: 600;
  margin-bottom: 8px;
}
.empty-inner p {
  color: var(--text-dim);
}
.empty-feats {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
  margin-top: 18px;
}
.empty-feats span {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 4px 13px;
  font-size: 11.5px;
  color: var(--text-dim);
}
.loading-mask {
  position: fixed;
  inset: 0;
  background: rgba(10, 14, 18, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}
.loading-box {
  background: var(--bg-panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 26px 38px;
  text-align: center;
}
.spinner {
  width: 34px;
  height: 34px;
  border: 3px solid var(--border);
  border-top-color: var(--accent);
  border-radius: 50%;
  margin: 0 auto 14px;
  animation: spin 0.8s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
