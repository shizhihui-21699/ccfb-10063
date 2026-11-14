<template>
  <div class="mime-pane">
    <div class="card">
      <h3 class="section-title">MIME 结构树(保留完整 multipart 嵌套)</h3>
      <div class="tree">
        <MimeNodeView :node="report.mimeTree" :depth="0" />
      </div>
    </div>

    <div class="card">
      <h3 class="section-title">扁平化部件清单 ({{ report.flatParts.length }} 个叶子)</h3>
      <table>
        <thead>
          <tr><th>Part</th><th>Content-Type</th><th>编码</th><th>字符集</th><th>大小</th><th>文件名</th></tr>
        </thead>
        <tbody>
          <tr v-for="p in report.flatParts" :key="p.partId">
            <td class="mono">{{ p.partId }}</td>
            <td>{{ p.contentType }}</td>
            <td class="mono dim">{{ p.transferEncoding }}</td>
            <td class="mono dim">{{ p.charset || '—' }}</td>
            <td class="mono dim">{{ p.size }}B</td>
            <td>{{ p.filename || '—' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup>
import MimeNodeView from '../widgets/MimeNodeView.vue'
defineProps({ report: { type: Object, required: true } })
</script>

<style scoped>
.card {
  margin-bottom: 14px;
}
.tree {
  background: var(--bg);
  border-radius: 6px;
  padding: 12px;
  overflow-x: auto;
}
table {
  font-size: 11.5px;
}
</style>
