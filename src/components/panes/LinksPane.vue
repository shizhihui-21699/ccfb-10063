<template>
  <div class="links-pane">
    <div class="card summary-bar">
      <span>共 {{ links.length }} 个链接</span>
      <span class="crit">高危 {{ count.high }}</span>
      <span class="med">中危 {{ count.medium }}</span>
      <span class="low">低危 {{ count.low }}</span>
      <span :class="{ crit: mismatchCount }">显示/真实不一致 {{ mismatchCount }}</span>
      <label class="copy-mode">
        <input type="checkbox" v-model="copyDefang" /> 复制时使用去武装形式
      </label>
    </div>

    <div v-if="!links.length" class="card faint">邮件中未发现链接</div>

    <div v-for="(u, i) in links" :key="i" class="card link-card" :class="{ mismatch: u.mismatch }">
      <div class="link-head">
        <span class="badge" :class="u.severity">{{ sevText(u.severity) }}</span>
        <span v-if="u.mismatch" class="mismatch-tag">⛔ 显示地址与真实地址不一致</span>
        <span v-if="u.idn?.homograph" class="idn-tag">🔤 IDN 同形异义</span>
        <span class="scheme mono faint">{{ u.scheme || '?' }}</span>
      </div>

      <div v-if="u.visibleText" class="visible-row">
        <span class="lbl">显示文字:</span>
        <span class="visible-text" :class="{ red: u.mismatch }">{{ u.visibleText }}</span>
      </div>

      <div class="real-row">
        <span class="lbl">真实地址:</span>
        <span class="real-url mono" :class="{ red: u.mismatch }">{{ u.url }}</span>
        <button class="mini-btn" @click="copy(u)">复制</button>
      </div>

      <div class="defang-row">
        <span class="lbl">去武装:</span>
        <span class="defanged mono">{{ u.defanged }}</span>
      </div>

      <div v-if="u.idn?.homograph" class="idn-detail">
        <div>Unicode 形态:<b class="red">{{ u.idn.unicode }}</b></div>
        <div class="mono">Punycode:<b>{{ u.idn.ascii }}</b></div>
      </div>

      <div v-if="u.flags.length" class="flags">
        <div v-for="(f, j) in u.flags" :key="j" class="flag" :class="'flag-' + f.level">
          <span class="flag-dot"></span>{{ f.text }}
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
const props = defineProps({ report: { type: Object, required: true } })
const links = computed(() => props.report.links)
const copyDefang = ref(true)

const count = computed(() => ({
  high: links.value.filter((l) => l.severity === 'high').length,
  medium: links.value.filter((l) => l.severity === 'medium').length,
  low: links.value.filter((l) => l.severity === 'low').length
}))
const mismatchCount = computed(() => links.value.filter((l) => l.mismatch).length)

function sevText(s) {
  return { high: '高危', medium: '中危', low: '低危', info: '信息' }[s] || s
}
async function copy(u) {
  const text = copyDefang.value ? u.defanged : u.url
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
}
</script>

<style scoped>
.summary-bar {
  display: flex;
  gap: 18px;
  align-items: center;
  font-size: 12px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.crit {
  color: var(--critical);
  font-weight: 700;
}
.med {
  color: var(--medium);
}
.low {
  color: var(--low);
}
.copy-mode {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 5px;
  color: var(--text-dim);
}
.link-card {
  margin-bottom: 11px;
}
.link-card.mismatch {
  border-color: var(--critical);
  box-shadow: 0 0 0 1px rgba(255, 71, 87, 0.4);
}
.link-head {
  display: flex;
  gap: 9px;
  align-items: center;
  margin-bottom: 9px;
}
.mismatch-tag {
  color: #fff;
  background: var(--critical);
  border-radius: 10px;
  padding: 1px 10px;
  font-size: 11px;
  font-weight: 700;
}
.idn-tag {
  background: var(--high);
  color: #fff;
  border-radius: 10px;
  padding: 1px 10px;
  font-size: 11px;
}
.lbl {
  color: var(--text-dim);
  font-size: 11px;
  min-width: 64px;
  flex-shrink: 0;
}
.visible-row,
.real-row,
.defang-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 0;
}
.visible-text,
.real-url,
.defanged {
  word-break: break-all;
}
.red {
  color: var(--critical);
  font-weight: 700;
}
.defanged {
  color: var(--medium);
}
.mini-btn {
  padding: 2px 9px;
  font-size: 10.5px;
  margin-left: auto;
  flex-shrink: 0;
}
.idn-detail {
  background: var(--bg);
  border-radius: 6px;
  padding: 8px 11px;
  margin: 7px 0;
  font-size: 12px;
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.flags {
  margin-top: 7px;
  border-top: 1px dashed var(--border);
  padding-top: 7px;
}
.flag {
  font-size: 11.5px;
  padding: 2px 0;
  display: flex;
  align-items: center;
  gap: 7px;
}
.flag-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
}
.flag-high {
  color: var(--critical);
}
.flag-high .flag-dot {
  background: var(--critical);
}
.flag-medium {
  color: var(--medium);
}
.flag-medium .flag-dot {
  background: var(--medium);
}
.flag-low {
  color: var(--low);
}
.flag-low .flag-dot {
  background: var(--low);
}
</style>
