<template>
  <div class="finding" :class="f.severity">
    <span class="sev-badge">{{ sevText }}</span>
    <span class="f-text">{{ f.text }}</span>
  </div>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ f: { type: Object, required: true } })
const sevText = computed(() => ({ high: '高', medium: '中', low: '低', info: '信息' }[props.f.severity] || props.f.severity))
</script>

<style scoped>
.finding {
  display: flex;
  gap: 8px;
  align-items: baseline;
  padding: 5px 0;
  border-bottom: 1px dashed var(--border);
  font-size: 12px;
}
.finding:last-child {
  border-bottom: none;
}
.sev-badge {
  flex-shrink: 0;
  width: 20px;
  height: 20px;
  border-radius: 5px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  font-weight: 700;
  color: #fff;
}
.finding.high .sev-badge {
  background: var(--critical);
}
.finding.medium .sev-badge {
  background: var(--medium);
  color: #222;
}
.finding.low .sev-badge {
  background: var(--low);
  color: #1a2a14;
}
.finding.high .f-text {
  color: var(--critical);
}
</style>
