<template>
  <div class="body-pane">
    <div class="card">
      <div class="body-tabs">
        <button :class="{ active: mode === 'safe' }" @click="mode = 'safe'">🔒 安全视图(剥离脚本/外链)</button>
        <button :class="{ active: mode === 'html' }" @click="mode = 'html'" v-if="report.bodies.html">HTML 源码</button>
        <button :class="{ active: mode === 'text' }" @click="mode = 'text'" v-if="report.bodies.text">纯文本</button>
      </div>

      <div v-if="mode === 'safe'" class="safe-html" v-html="sanitizedHtml"></div>

      <pre v-else-if="mode === 'html'" class="src mono">{{ report.bodies.html }}</pre>
      <pre v-else class="src mono">{{ report.bodies.text || '(无纯文本正文)' }}</pre>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
const props = defineProps({ report: { type: Object, required: true } })
const mode = ref('safe')

/** 极简 HTML 安全处理:去 script/事件/外链资源,仅保留结构与文本用于研判 */
const sanitizedHtml = computed(() => {
  let html = props.report.bodies.html || ''
  if (!html) {
    return `<pre class="fallback">${(props.report.bodies.text || '(无 HTML 正文)').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]))}</pre>`
  }
  // 去 script/style/iframe/object/embed 整块
  html = html.replace(/<(script|style|iframe|object|embed|link|meta)[^>]*>[\s\S]*?<\/\1[^>]*>/gi, '')
  html = html.replace(/<(script|iframe|object|embed|link|meta)[^>]*\/?>/gi, '')
  // 去所有事件属性 on*=
  html = html.replace(/\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, '')
  // 去 javascript: / data: 协议
  html = html.replace(/(href|src)\s*=\s*("|')?\s*(javascript|data|vbscript):[^"'>\s]*/gi, '$1="#"')
  // 封锁外部资源加载(图片等),改成占位
  html = html.replace(/<img[^>]*>/gi, '<span class="blocked-img">[图片已拦截]</span>')
  return html
})
</script>

<style scoped>
.body-tabs {
  display: flex;
  gap: 6px;
  margin-bottom: 14px;
}
.body-tabs button.active {
  background: var(--accent-dim);
  border-color: var(--accent);
  color: #fff;
}
.safe-html {
  background: #fff;
  color: #1a1a1a;
  border-radius: 6px;
  padding: 18px 22px;
  line-height: 1.7;
  overflow-x: auto;
}
.safe-html :deep(a) {
  color: #b8294a;
  text-decoration: underline;
}
.safe-html :deep(.blocked-img) {
  display: inline-block;
  background: #eee;
  border: 1px dashed #999;
  color: #777;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
}
.safe-html :deep(.fallback) {
  white-space: pre-wrap;
  font-family: inherit;
  margin: 0;
}
.src {
  background: var(--bg);
  border-radius: 6px;
  padding: 13px;
  max-height: 70vh;
  overflow: auto;
  color: var(--text-dim);
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
