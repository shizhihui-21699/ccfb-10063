<template>
  <div class="att-pane">
    <div class="notice card">
      🔒 所有附件仅做<b>静态分析</b>(文件头魔数、特征字符串、哈希、熵),全程不执行、不解压运行任何内容。
    </div>

    <div v-if="!attachments.length" class="card faint">该邮件没有附件</div>

    <div v-for="(a, i) in attachments" :key="i" class="card att-card">
      <div class="att-head">
        <div class="att-icon" :class="a.severity">{{ icon(a) }}</div>
        <div class="att-title">
          <div class="att-name">{{ a.filename }}</div>
          <div class="att-sub mono faint">
            {{ a.size }} 字节 · 声明 {{ a.declaredMime || '?' }}<span v-if="a.declaredExt"> / .{{ a.declaredExt }}</span>
          </div>
        </div>
        <span class="badge" :class="a.severity">{{ sevText(a.severity) }}</span>
      </div>

      <div class="type-compare">
        <div><span class="dim">声明类型:</span> {{ a.declaredMime || '?' }}<span v-if="a.declaredExt"> (.{{ a.declaredExt }})</span></div>
        <div><span class="dim">实测类型:</span>
          <span :class="typeMismatch(a) ? 'bad' : 'ok'">{{ a.realType }}</span>
        </div>
        <div class="entropy"><span class="dim">香农熵:</span> {{ a.entropy }} / 8</div>
      </div>

      <div v-if="a.findings.length" class="findings">
        <div v-for="(f, j) in a.findings" :key="j" class="finding" :class="f.severity">
          <span class="sev">{{ sevText(f.severity) }}</span>{{ f.text }}
        </div>
      </div>
      <div v-else class="no-finding ok">✓ 未发现静态可疑特征</div>

      <details v-if="a.zipEntries?.length" class="zip">
        <summary>压缩包条目 ({{ a.zipEntries.length }})</summary>
        <div v-for="(e, k) in a.zipEntries" :key="k" class="zip-entry mono" :class="{ danger: /\.(exe|scr|js|vbs|ps1|bat|cmd|hta|lnk|jar)$/i.test(e) || e.includes('../') }">
          {{ e }}
        </div>
      </details>

      <details v-if="a.previewText" class="preview">
        <summary>文本预览(前 2000 字符)</summary>
        <pre class="preview-body mono">{{ a.previewText }}</pre>
      </details>

      <div class="hashes mono">
        <div>SHA-256: <b>{{ a.sha256 }}</b></div>
        <div>MD5:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <b>{{ a.md5 }}</b></div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ report: { type: Object, required: true } })
const attachments = computed(() => props.report.attachments)

function sevText(s) {
  return { high: '高危', medium: '中危', low: '低危', safe: '安全', info: '信息' }[s] || s
}
function icon(a) {
  if (a.severity === 'high') return '☣️'
  if (a.severity === 'medium') return '⚠️'
  if (a.declaredExt === 'pdf') return '📕'
  if (['doc', 'docx', 'docm', 'dotm'].includes(a.declaredExt)) return '📘'
  if (['xls', 'xlsx', 'xlsm'].includes(a.declaredExt)) return '📗'
  if (['zip', 'rar', '7z', 'gz'].includes(a.declaredExt)) return '🗜️'
  return '📄'
}
function typeMismatch(a) {
  return a.findings.some((f) => f.text.includes('类型伪装'))
}
</script>

<style scoped>
.notice {
  background: rgba(61, 169, 252, 0.08);
  border-color: var(--accent-dim);
  color: var(--text-dim);
  font-size: 12px;
  margin-bottom: 14px;
}
.att-card {
  margin-bottom: 13px;
}
.att-head {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 12px;
}
.att-icon {
  width: 42px;
  height: 42px;
  border-radius: 8px;
  background: var(--bg);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 21px;
}
.att-icon.high {
  background: rgba(255, 71, 87, 0.15);
}
.att-title {
  flex: 1;
  min-width: 0;
}
.att-name {
  font-weight: 700;
  word-break: break-all;
}
.type-compare {
  display: flex;
  gap: 22px;
  flex-wrap: wrap;
  background: var(--bg);
  border-radius: 6px;
  padding: 9px 12px;
  font-size: 12px;
  margin-bottom: 10px;
}
.ok {
  color: var(--safe);
}
.bad {
  color: var(--critical);
  font-weight: 700;
}
.findings {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.finding {
  font-size: 12px;
  padding: 5px 9px;
  border-radius: 5px;
  background: var(--bg);
}
.finding.high {
  color: var(--critical);
  border-left: 3px solid var(--critical);
}
.finding.medium {
  color: var(--medium);
  border-left: 3px solid var(--medium);
}
.finding.low {
  color: var(--low);
  border-left: 3px solid var(--low);
}
.sev {
  display: inline-block;
  min-width: 26px;
  font-weight: 700;
}
.no-finding {
  font-size: 12px;
}
.zip,
.preview {
  margin-top: 9px;
  font-size: 12px;
}
summary {
  cursor: pointer;
  color: var(--accent);
}
.zip-entry {
  padding: 3px 8px;
  color: var(--text-dim);
}
.zip-entry.danger {
  color: var(--critical);
  font-weight: 600;
}
.preview-body {
  background: var(--bg);
  border-radius: 6px;
  padding: 10px;
  max-height: 280px;
  overflow: auto;
  color: var(--text-dim);
  white-space: pre-wrap;
  word-break: break-all;
}
.hashes {
  margin-top: 11px;
  border-top: 1px dashed var(--border);
  padding-top: 9px;
  color: var(--text-dim);
  word-break: break-all;
}
.hashes b {
  color: var(--text);
  font-weight: 500;
}
</style>
