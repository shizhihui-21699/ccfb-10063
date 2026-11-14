<template>
  <div class="received">
    <div class="card">
      <h3 class="section-title">投递路径(从发件端 → 收件端,共 {{ hops.length }} 跳)</h3>
      <div v-if="anomalies.length" class="anomaly-box">
        <div v-for="(a, i) in anomalies" :key="i" class="anomaly">⚠️ {{ a }}</div>
      </div>

      <div class="path-flow">
        <template v-for="(h, i) in hops" :key="i">
          <div class="hop" :class="{ origin: i === 0 }">
            <div class="hop-index">#{{ i + 1 }}</div>
            <div class="hop-body">
              <div class="hop-helo">
                <span class="helo-name">{{ h.helo || '未知主机' }}</span>
                <span v-if="h.ip" class="hop-ip mono">[{{ h.ip }}]</span>
              </div>
              <div class="hop-meta">
                <span v-if="h.reverseDns" class="mono dim">rDNS: {{ h.reverseDns }}</span>
                <span v-if="h.protocol" class="proto">{{ h.protocol }}</span>
                <span v-if="h.by" class="dim">→ by {{ h.by }}</span>
              </div>
              <div class="hop-dns">
                <template v-if="h.ip && /^\d+\.\d+\.\d+\.\d+$/.test(h.ip)">
                  <span v-if="h.dnsCheck.ptrName" class="ptr" :class="h.dnsCheck.ptrMatch ? 'ok' : 'bad'">
                    {{ h.dnsCheck.ptrMatch ? '✓ 正向确认' : '✗ 正向不匹配' }}
                    <span class="mono">{{ h.dnsCheck.ptrName }}</span>
                  </span>
                  <span v-else class="ptr bad">✗ 无 PTR 记录</span>
                  <span v-if="h.dnsCheck.claimedMismatch" class="ptr bad">✗ 头中声称名与反查不符</span>
                </template>
                <span v-else class="faint">非 IPv4,跳过反查</span>
              </div>
              <div class="hop-date mono faint">{{ h.dateRaw || '(无时间)' }}</div>
            </div>
          </div>
          <div v-if="i < hops.length - 1" class="arrow" :class="{ backwards: isBackwards(h, hops[i + 1]) }">
            {{ isBackwards(h, hops[i + 1]) ? '↑ 时间倒流' : '↓' }}
          </div>
        </template>
      </div>
    </div>

    <div class="card">
      <h3 class="section-title">原始 Received 头(邮件中的物理顺序,最新一跳在最前)</h3>
      <div v-for="(h, i) in rawOrder" :key="i" class="raw-hdr mono">{{ h.raw }}</div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
const props = defineProps({ report: { type: Object, required: true } })
const hops = computed(() => props.report.chain.hops)
const anomalies = computed(() => props.report.chain.anomalies)
// 原始顺序 = 投递方向反转
const rawOrder = computed(() => [...hops.value].reverse())
function isBackwards(prev, cur) {
  return prev.ts && cur.ts && cur.ts < prev.ts
}
</script>

<style scoped>
.card {
  margin-bottom: 14px;
}
.anomaly-box {
  background: rgba(255, 176, 32, 0.1);
  border: 1px solid var(--medium);
  border-radius: 6px;
  padding: 8px 12px;
  margin-bottom: 14px;
}
.anomaly {
  color: var(--medium);
  font-size: 12px;
  padding: 2px 0;
}
.path-flow {
  display: flex;
  flex-direction: column;
}
.hop {
  display: flex;
  gap: 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 11px 14px;
}
.hop.origin {
  border-color: var(--high);
  background: rgba(255, 107, 53, 0.07);
}
.hop-index {
  font-weight: 800;
  color: var(--accent);
  font-size: 15px;
}
.hop-body {
  flex: 1;
}
.hop-helo {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 4px;
}
.helo-name {
  font-weight: 700;
}
.hop-ip {
  color: var(--medium);
}
.hop-meta {
  display: flex;
  gap: 10px;
  font-size: 11.5px;
  margin-bottom: 4px;
  flex-wrap: wrap;
}
.proto {
  background: var(--bg-elev);
  border-radius: 8px;
  padding: 0 7px;
  font-size: 10.5px;
}
.hop-dns {
  margin-bottom: 3px;
}
.ptr {
  font-size: 11px;
  margin-right: 12px;
}
.ptr.ok {
  color: var(--safe);
}
.ptr.bad {
  color: var(--critical);
}
.hop-date {
  font-size: 10.5px;
}
.arrow {
  text-align: center;
  color: var(--text-faint);
  padding: 3px 0;
  font-size: 13px;
}
.arrow.backwards {
  color: var(--critical);
  font-weight: 700;
}
.raw-hdr {
  background: var(--bg);
  border-radius: 6px;
  padding: 8px 11px;
  margin-bottom: 6px;
  color: var(--text-dim);
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 11px;
}
</style>
