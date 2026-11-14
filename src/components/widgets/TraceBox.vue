<template>
  <div class="trace">
    <button class="trace-toggle ghost" @click="open = !open">
      {{ open ? '▾' : '▸' }} 评估过程追溯 ({{ trace.length }} 步)
    </button>
    <div v-if="open" class="trace-body">
      <div v-for="(t, i) in trace" :key="i" class="trace-line" :class="stepClass(t.step)">
        <span class="step-idx">{{ i + 1 }}</span>
        <span class="step-tag">{{ t.step }}</span>
        <span class="step-text mono">{{ t.text }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
defineProps({ trace: { type: Array, default: () => [] } })
const open = ref(false)
function stepClass(step) {
  if (step === 'error') return 'err'
  if (step === 'match' || step === 'verify' || step === 'align') return 'ok'
  if (step === 'dns' || step === 'include' || step === 'redirect') return 'dns'
  return ''
}
</script>

<style scoped>
.trace {
  margin-top: 10px;
}
.trace-toggle {
  font-size: 11px;
  padding: 3px 9px;
}
.trace-body {
  margin-top: 8px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 9px 11px;
  max-height: 320px;
  overflow-y: auto;
}
.trace-line {
  display: flex;
  gap: 8px;
  padding: 3px 0;
  font-size: 11px;
  align-items: baseline;
}
.step-idx {
  color: var(--text-faint);
  min-width: 18px;
}
.step-tag {
  min-width: 62px;
  color: var(--accent);
  text-transform: uppercase;
  font-size: 10px;
}
.step-text {
  color: var(--text-dim);
  word-break: break-all;
}
.trace-line.err .step-text {
  color: var(--critical);
}
.trace-line.ok .step-text {
  color: var(--safe);
}
.trace-line.dns .step-tag {
  color: var(--medium);
}
</style>
