<template>
  <div class="header-pane">
    <div class="card">
      <h3 class="section-title">完整信头(已展开折叠,重复头保留)</h3>
      <div class="hdr-list">
        <div v-for="(key, i) in report.headerOrder" :key="i" class="hdr-group">
          <div v-for="(val, j) in report.rawHeaderMap[key]" :key="j" class="hdr-line">
            <span class="hdr-key mono">{{ key }}:</span>
            <span class="hdr-val mono" :class="{ dkim: key === 'dkim-signature' }">{{ val }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
defineProps({ report: { type: Object, required: true } })
</script>

<style scoped>
.hdr-list {
  background: var(--bg);
  border-radius: 6px;
  padding: 10px 12px;
  max-height: 70vh;
  overflow: auto;
}
.hdr-line {
  padding: 4px 0;
  border-bottom: 1px dotted var(--border);
  display: flex;
  gap: 8px;
}
.hdr-key {
  color: var(--accent);
  min-width: 150px;
  flex-shrink: 0;
  word-break: break-all;
}
.hdr-val {
  color: var(--text-dim);
  word-break: break-all;
}
.hdr-val.dkim {
  color: var(--medium);
}
</style>
